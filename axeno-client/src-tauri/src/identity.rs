//! Identity vault: generation, encryption, unlock, and in-memory mutation.
//!
//! Security architecture:
//! - The passphrase is used ONLY during unlock to derive a KEK via Argon2id.
//! - The derived KEK lives in Rust memory inside a ZeroizeOnDrop wrapper.
//! - The decrypted vault contents live in Rust memory and never cross the IPC boundary.
//! - Every re-encryption generates a fresh random nonce. Salt is rotated on
//!   passphrase change only (the KEK is deterministic over passphrase+salt).
//! - All randomness comes from the OS via getrandom; failures propagate as errors.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PrivateKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- Public-on-disk shell --------------------------------------------------

/// On-disk format. Contains only public material plus encrypted secrets.
/// Safe to back up; safe to copy. Cannot be decrypted without the passphrase.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedIdentity {
    pub kdf_salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
    pub registration_id: u16,
    pub signed_prekey_id: u32,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub opks_public: Vec<OpkPublic>,
}

// --- Inner secrets (encrypted) ---------------------------------------------

/// The decrypted contents of the vault. Held in Rust memory while unlocked.
/// All sensitive byte buffers are wiped on drop.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultSecrets {
    pub identity_priv: Vec<u8>,
    pub spk_priv: Vec<u8>,
    pub opks_secret: Vec<OpkSecret>,
    pub display_name: String,
}

impl Drop for VaultSecrets {
    fn drop(&mut self) {
        self.identity_priv.zeroize();
        self.spk_priv.zeroize();
        for opk in self.opks_secret.iter_mut() {
            opk.private_key.zeroize();
        }
        // display_name is not a secret; let normal drop handle it.
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OpkPublic {
    pub id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpkSecret {
    pub id: u32,
    pub private_key: Vec<u8>,
}

// --- Errors ---------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong passphrase or corrupted vault)")]
    Decrypt,
    #[error("signal protocol error: {0}")]
    Signal(String),
    #[error("OS randomness unavailable: {0}")]
    Random(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

// --- Derived key wrapper --------------------------------------------------

/// 32-byte key derived from a passphrase + salt. Wiped on drop.
#[derive(Debug, ZeroizeOnDrop)]
pub struct DerivedKey(pub(crate) [u8; 32]);

impl DerivedKey {
    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }
}

// --- Helpers --------------------------------------------------------------

const ARGON2_MEM_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const KEY_LEN: usize = 32;

/// Registration IDs in Signal Protocol are 14-bit values: 1..=16380.
const MAX_REGISTRATION_ID: u16 = 16_380;

/// Signed-PreKey IDs are non-negative 31-bit values.
const SPK_ID_MASK: u32 = 0x7FFF_FFFF;

const OPK_COUNT: u32 = 100;

fn fill_random(buf: &mut [u8]) -> Result<(), IdentityError> {
    getrandom::getrandom(buf).map_err(|e| IdentityError::Random(e.to_string()))
}

fn fresh_rng() -> Result<StdRng, IdentityError> {
    let mut seed = [0u8; 32];
    fill_random(&mut seed)?;
    Ok(StdRng::from_seed(seed))
}

fn derive_key(passphrase: &str, salt: &[u8; 32]) -> Result<DerivedKey, IdentityError> {
    let params = Params::new(
        ARGON2_MEM_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| IdentityError::Kdf(e.to_string()))?;

    let mut out = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| IdentityError::Kdf(e.to_string()))?;

    Ok(DerivedKey(out))
}

fn encrypt_vault(
    key: &DerivedKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), IdentityError> {
    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = key
        .cipher()
        .encrypt(nonce, plaintext)
        .map_err(|_| IdentityError::Encrypt)?;
    Ok((ciphertext, nonce_bytes))
}

fn decrypt_vault(
    key: &DerivedKey,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let nonce = Nonce::from_slice(nonce);
    key.cipher()
        .decrypt(nonce, ciphertext)
        .map_err(|_| IdentityError::Decrypt)
}

// --- Public API -----------------------------------------------------------

/// The full output of creating a new identity: the on-disk blob plus the
/// derived key used to encrypt it. The caller is expected to persist the blob
/// and store the DerivedKey in protected memory for the duration of the session.
pub struct CreatedIdentity {
    pub blob: EncryptedIdentity,
    pub secrets: VaultSecrets,
    pub key: DerivedKey,
}

/// Generate a fresh identity, encrypt the secrets with a KEK derived from the
/// passphrase, and return the on-disk blob, the in-memory secrets, and the KEK.
///
/// The passphrase is used here and then dropped; the caller never needs to
/// hold it again. Re-encryption later uses the returned `DerivedKey`.
pub fn create_identity(
    passphrase: &str,
    display_name: &str,
) -> Result<CreatedIdentity, IdentityError> {
    let mut rng = fresh_rng()?;

    // 1. Identity keypair
    let identity_keypair = IdentityKeyPair::generate(&mut rng);
    let identity_pub_bytes = identity_keypair.public_key().serialize().to_vec();
    let identity_priv_bytes = identity_keypair.private_key().serialize().to_vec();

    // 2. Registration ID (1..=16380, per Signal spec)
    let mut b2 = [0u8; 2];
    fill_random(&mut b2)?;
    let registration_id = (u16::from_le_bytes(b2) % MAX_REGISTRATION_ID) + 1;

    // 3. Signed PreKey
    let mut b4 = [0u8; 4];
    fill_random(&mut b4)?;
    let signed_prekey_id = u32::from_le_bytes(b4) & SPK_ID_MASK;

    let spk_pair = KeyPair::generate(&mut rng);
    let spk_pub_bytes = spk_pair.public_key.serialize().to_vec();
    let spk_priv_bytes = spk_pair.private_key.serialize().to_vec();

    let spk_signature = identity_keypair
        .private_key()
        .calculate_signature(&spk_pub_bytes, &mut rng)
        .map_err(|e| IdentityError::Signal(e.to_string()))?
        .to_vec();

    // 4. One-Time PreKeys
    let mut opks_public = Vec::with_capacity(OPK_COUNT as usize);
    let mut opks_secret = Vec::with_capacity(OPK_COUNT as usize);
    for id in 1..=OPK_COUNT {
        let pair = KeyPair::generate(&mut rng);
        opks_public.push(OpkPublic {
            id,
            public_key: pair.public_key.serialize().to_vec(),
        });
        opks_secret.push(OpkSecret {
            id,
            private_key: pair.private_key.serialize().to_vec(),
        });
    }

    // 5. Bundle secrets
    let secrets = VaultSecrets {
        identity_priv: identity_priv_bytes,
        spk_priv: spk_priv_bytes,
        opks_secret,
        display_name: display_name.to_string(),
    };

    // 6. Derive KEK and encrypt
    let mut salt = [0u8; 32];
    fill_random(&mut salt)?;
    let key = derive_key(passphrase, &salt)?;

    let mut vault_bytes =
        serde_json::to_vec(&secrets).map_err(|e| IdentityError::Serde(e.to_string()))?;
    let (ciphertext, nonce) = encrypt_vault(&key, &vault_bytes)?;
    vault_bytes.zeroize();

    let blob = EncryptedIdentity {
        kdf_salt: salt,
        nonce,
        ciphertext,
        public_key: identity_pub_bytes,
        registration_id,
        signed_prekey_id,
        signed_prekey_public: spk_pub_bytes,
        signed_prekey_signature: spk_signature,
        opks_public,
    };

    Ok(CreatedIdentity {
        blob,
        secrets,
        key,
    })
}

/// Output of a successful unlock: the in-memory secrets plus the KEK.
#[derive(Debug)]
pub struct UnlockedIdentity {
    pub secrets: VaultSecrets,
    pub key: DerivedKey,
}

/// Unlock an on-disk identity. The passphrase is used only to derive the KEK;
/// after this returns, the passphrase can be dropped.
pub fn unlock_identity(
    blob: &EncryptedIdentity,
    passphrase: &str,
) -> Result<UnlockedIdentity, IdentityError> {
    let key = derive_key(passphrase, &blob.kdf_salt)?;
    let mut plaintext = decrypt_vault(&key, &blob.nonce, &blob.ciphertext)?;
    let secrets: VaultSecrets = serde_json::from_slice(&plaintext)
        .map_err(|e| IdentityError::Serde(e.to_string()))?;
    plaintext.zeroize();
    Ok(UnlockedIdentity { secrets, key })
}

/// Re-encrypt the vault with the existing KEK and a fresh random nonce.
/// MUST be called after any mutation to the secrets. The salt is unchanged
/// because the KEK has not changed; the nonce is always fresh.
pub fn reseal_vault(
    blob: &mut EncryptedIdentity,
    key: &DerivedKey,
    secrets: &VaultSecrets,
) -> Result<(), IdentityError> {
    let mut bytes = serde_json::to_vec(secrets).map_err(|e| IdentityError::Serde(e.to_string()))?;
    let (ciphertext, nonce) = encrypt_vault(key, &bytes)?;
    bytes.zeroize();
    blob.ciphertext = ciphertext;
    blob.nonce = nonce;
    Ok(())
}

/// Change the passphrase. Generates a fresh salt, derives a new KEK, and
/// re-encrypts with a fresh nonce. Returns the new KEK for caching.
pub fn change_passphrase(
    blob: &mut EncryptedIdentity,
    secrets: &VaultSecrets,
    new_passphrase: &str,
) -> Result<DerivedKey, IdentityError> {
    let mut new_salt = [0u8; 32];
    fill_random(&mut new_salt)?;
    let new_key = derive_key(new_passphrase, &new_salt)?;

    let mut bytes = serde_json::to_vec(secrets).map_err(|e| IdentityError::Serde(e.to_string()))?;
    let (ciphertext, nonce) = encrypt_vault(&new_key, &bytes)?;
    bytes.zeroize();

    blob.kdf_salt = new_salt;
    blob.nonce = nonce;
    blob.ciphertext = ciphertext;
    Ok(new_key)
}

/// Hex-encoded fingerprint of the public identity key.
pub fn fingerprint(blob: &EncryptedIdentity) -> String {
    hex::encode(&blob.public_key)
}

/// Validate that a stored blob can be reconstructed into a libsignal IdentityKey.
/// Useful as a smoke test after loading from disk.
pub fn verify_blob_structure(blob: &EncryptedIdentity) -> Result<(), IdentityError> {
    IdentityKey::decode(&blob.public_key).map_err(|e| IdentityError::Signal(e.to_string()))?;
    for opk in &blob.opks_public {
        PrivateKey::deserialize(&opk.public_key)
            .map_err(|e| IdentityError::Signal(e.to_string()))?;
    }
    Ok(())
}

// --- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_create_unlock() {
        let created = create_identity("correct horse battery staple", "Alice").unwrap();
        let unlocked = unlock_identity(&created.blob, "correct horse battery staple").unwrap();
        assert_eq!(unlocked.secrets.display_name, "Alice");
        assert_eq!(
            unlocked.secrets.identity_priv,
            created.secrets.identity_priv
        );
        assert_eq!(unlocked.secrets.opks_secret.len(), OPK_COUNT as usize);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let created = create_identity("correct horse", "Alice").unwrap();
        let err = unlock_identity(&created.blob, "wrong horse").unwrap_err();
        assert!(matches!(err, IdentityError::Decrypt));
    }

    #[test]
    fn mutated_ciphertext_fails() {
        let mut created = create_identity("correct horse", "Alice").unwrap();
        // Flip a bit in the ciphertext
        created.blob.ciphertext[5] ^= 0x01;
        let err = unlock_identity(&created.blob, "correct horse").unwrap_err();
        assert!(matches!(err, IdentityError::Decrypt));
    }

    #[test]
    fn reseal_uses_fresh_nonce() {
        let mut created = create_identity("pw", "Alice").unwrap();
        let original_nonce = created.blob.nonce;
        reseal_vault(&mut created.blob, &created.key, &created.secrets).unwrap();
        assert_ne!(created.blob.nonce, original_nonce);
        // And the vault still decrypts
        let unlocked = unlock_identity(&created.blob, "pw").unwrap();
        assert_eq!(unlocked.secrets.display_name, "Alice");
    }

    #[test]
    fn reseal_after_display_name_change_works() {
        let mut created = create_identity("pw", "Alice").unwrap();
        let mut secrets = unlock_identity(&created.blob, "pw").unwrap().secrets;
        secrets.display_name = "Bob".to_string();
        reseal_vault(&mut created.blob, &created.key, &secrets).unwrap();

        let unlocked = unlock_identity(&created.blob, "pw").unwrap();
        assert_eq!(unlocked.secrets.display_name, "Bob");
    }

    #[test]
    fn change_passphrase_rotates_salt_and_decrypts_with_new() {
        let mut created = create_identity("old", "Alice").unwrap();
        let old_salt = created.blob.kdf_salt;
        let secrets = unlock_identity(&created.blob, "old").unwrap().secrets;
        let _new_key = change_passphrase(&mut created.blob, &secrets, "new").unwrap();

        assert_ne!(created.blob.kdf_salt, old_salt);
        assert!(unlock_identity(&created.blob, "old").is_err());
        let unlocked = unlock_identity(&created.blob, "new").unwrap();
        assert_eq!(unlocked.secrets.display_name, "Alice");
    }

    #[test]
    fn registration_id_in_range() {
        let created = create_identity("pw", "x").unwrap();
        assert!(created.blob.registration_id >= 1);
        assert!(created.blob.registration_id <= MAX_REGISTRATION_ID);
    }

    #[test]
    fn fingerprint_is_hex_of_pub_key() {
        let created = create_identity("pw", "x").unwrap();
        let fp = fingerprint(&created.blob);
        assert_eq!(fp, hex::encode(&created.blob.public_key));
    }
}