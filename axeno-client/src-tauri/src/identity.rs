use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce, Key};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, PrivateKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// The outer shell. The public fields are safe to send to a server.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedIdentity {
    pub kdf_salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
    pub registration_id: u16,
    pub signed_prekey_id: u32,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub opks_public: Vec<OpkPublic>, // The 100 One-Time PreKeys
}

// The inner highly-sensitive data
#[derive(Serialize, Deserialize)]
pub struct VaultSecrets {
    pub identity_priv: Vec<u8>,
    pub spk_priv: Vec<u8>,
    pub opks_secret: Vec<OpkSecret>,
    pub display_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OpkPublic {
    pub id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OpkSecret {
    pub id: u32,
    pub private_key: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    #[error("KDF error: {0}")] Kdf(String),
    #[error("Encryption failed")] Encrypt,
    #[error("Decryption failed")] Decrypt,
    #[error("Signal error: {0}")] Signal(String),
}

#[derive(ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

fn derive_key(passphrase: &str, salt: &[u8; 32]) -> Result<DerivedKey, IdentityError> {
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| IdentityError::Kdf(e.to_string()))?;
    let mut derived_bytes = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived_bytes)
        .map_err(|e| IdentityError::Kdf(e.to_string()))?;
    Ok(DerivedKey(derived_bytes))
}

fn generate_clamped_keypair() -> (PrivateKey, Vec<u8>) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    seed[0] &= 248;
    seed[31] &= 127;
    seed[31] |= 64;
    let priv_key = PrivateKey::deserialize(&seed).unwrap();
    let pub_key = priv_key.public_key().unwrap().serialize().to_vec();
    (priv_key, pub_key)
}

pub fn create_encrypted_identity(passphrase: &str, display_name: &str) -> Result<EncryptedIdentity, IdentityError> {
    // 1. Identity Key & Registration ID
    let (identity_priv, identity_pub_bytes) = generate_clamped_keypair();
    let identity_key = IdentityKey::decode(&identity_pub_bytes).unwrap();
    let _identity_keypair = IdentityKeyPair::new(identity_key, identity_priv.clone());
    
    let mut b2 = [0u8; 2]; getrandom::getrandom(&mut b2).unwrap();
    let reg_id = (u16::from_le_bytes(b2) % 16380) + 1;

    // 2. Signed PreKey
    let mut b4 = [0u8; 4]; getrandom::getrandom(&mut b4).unwrap();
    let spk_id = u32::from_le_bytes(b4) & 0x7FFFFFFF;
    let (spk_priv, spk_pub_bytes) = generate_clamped_keypair();
    
    use rand::SeedableRng;
    let mut signal_rng = rand::rngs::StdRng::from_os_rng();
    let signature = identity_priv.calculate_signature(&spk_pub_bytes, &mut signal_rng)
        .map_err(|e| IdentityError::Signal(e.to_string()))?;

    // 3. Generate 100 One-Time PreKeys (OPKs)
    let mut opks_public = Vec::with_capacity(100);
    let mut opks_secret = Vec::with_capacity(100);
    for i in 1..=100 {
        let (priv_k, pub_k) = generate_clamped_keypair();
        opks_public.push(OpkPublic { id: i, public_key: pub_k });
        opks_secret.push(OpkSecret { id: i, private_key: priv_k.serialize().to_vec() });
    }

    // 4. Bundle Inner Secrets
    let secrets = VaultSecrets {
        identity_priv: identity_priv.serialize().to_vec(),
        spk_priv: spk_priv.serialize().to_vec(),
        opks_secret,
        display_name: display_name.to_string(),
    };
    let mut vault_content = serde_json::to_vec(&secrets).map_err(|_| IdentityError::Encrypt)?;

    // 5. Encrypt
    let mut salt = [0u8; 32]; getrandom::getrandom(&mut salt).unwrap();
    let mut nonce_bytes = [0u8; 12]; getrandom::getrandom(&mut nonce_bytes).unwrap();
    
    let derived = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived.0));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), vault_content.as_slice())
        .map_err(|_| IdentityError::Encrypt)?;

    vault_content.zeroize();

    Ok(EncryptedIdentity {
        kdf_salt: salt,
        nonce: nonce_bytes,
        ciphertext,
        public_key: identity_pub_bytes,
        registration_id: reg_id,
        signed_prekey_id: spk_id,
        signed_prekey_public: spk_pub_bytes,
        signed_prekey_signature: signature.to_vec(),
        opks_public,
    })
}

pub fn unlock_identity(
    blob: &EncryptedIdentity,
    passphrase: &str,
) -> Result<(String, String), IdentityError> {
    let key = derive_key(passphrase, &blob.kdf_salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = Nonce::from_slice(&blob.nonce);

    let mut plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_slice())
        .map_err(|_| IdentityError::Decrypt)?;

    let secrets: VaultSecrets = serde_json::from_slice(&plaintext)
        .map_err(|_| IdentityError::Decrypt)?;

    let fingerprint = hex::encode(&blob.public_key);
    let display_name = secrets.display_name.clone();

    plaintext.zeroize();

    Ok((fingerprint, display_name))
}

pub fn update_display_name(
    blob: &mut EncryptedIdentity,
    passphrase: &str,
    new_name: &str,
) -> Result<(), IdentityError> {
    let key = derive_key(passphrase, &blob.kdf_salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = Nonce::from_slice(&blob.nonce);

    let mut plaintext = cipher.decrypt(nonce, blob.ciphertext.as_slice())
        .map_err(|_| IdentityError::Decrypt)?;

    let mut secrets: VaultSecrets = serde_json::from_slice(&plaintext)
        .map_err(|_| IdentityError::Decrypt)?;

    secrets.display_name = new_name.to_string();
    
    let new_vault_content = serde_json::to_vec(&secrets).map_err(|_| IdentityError::Encrypt)?;
    blob.ciphertext = cipher.encrypt(nonce, new_vault_content.as_slice())
        .map_err(|_| IdentityError::Encrypt)?;

    plaintext.zeroize();
    Ok(())
}

pub fn fingerprint(blob: &EncryptedIdentity) -> String {
    hex::encode(&blob.public_key)
}