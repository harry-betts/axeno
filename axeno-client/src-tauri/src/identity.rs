use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key
};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, PrivateKey};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedIdentity {
    pub kdf_salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
    pub registration_id: u16,
}

#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("Encryption failed")]
    Encrypt,
    #[error("Decryption failed")]
    Decrypt,
    #[error("Signal error: {0}")]
    Signal(String),
}

#[derive(ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

fn derive_key(passphrase: &str, salt: &[u8; 32]) -> Result<DerivedKey, IdentityError> {
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| IdentityError::Kdf(e.to_string()))?;
    let mut derived_bytes = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived_bytes)
        .map_err(|e| IdentityError::Kdf(e.to_string()))?;
    Ok(DerivedKey(derived_bytes))
}

pub fn create_encrypted_identity(passphrase: &str) -> Result<EncryptedIdentity, IdentityError> {
    let mut rng = OsRng;

    // Generate Signal Registration ID (14-bit integer, 1-16380)
    let reg_id = (rng.gen::<u16>() % 16380) + 1;

    // Generate random seed and apply Curve25519 clamping manually
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed[0] &= 248;
    seed[31] &= 127;
    seed[31] |= 64;

    let private_key = PrivateKey::deserialize(&seed)
        .map_err(|e| IdentityError::Signal(e.to_string()))?;
    
    let pub_key = private_key.public_key()
        .map_err(|e| IdentityError::Signal(e.to_string()))?;
        
    let identity_key = IdentityKey::new(pub_key);
    let keypair = IdentityKeyPair::new(identity_key, private_key);

    let mut priv_bytes = keypair.private_key().serialize();
    let pub_bytes = keypair.identity_key().serialize();

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, priv_bytes.as_ref())
        .map_err(|_| IdentityError::Encrypt)?;

    priv_bytes.zeroize();
    seed.zeroize();

    Ok(EncryptedIdentity {
        kdf_salt: salt,
        nonce: nonce_bytes,
        ciphertext,
        public_key: pub_bytes.to_vec(),
        registration_id: reg_id,
    })
}

pub fn decrypt_identity(
    blob: &EncryptedIdentity,
    passphrase: &str,
) -> Result<IdentityKeyPair, IdentityError> {
    let key = derive_key(passphrase, &blob.kdf_salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = Nonce::from_slice(&blob.nonce);

    let mut decrypted_priv_bytes = cipher
        .decrypt(nonce, blob.ciphertext.as_slice())
        .map_err(|_| IdentityError::Decrypt)?;

    let public_key = IdentityKey::decode(&blob.public_key)
        .map_err(|e| IdentityError::Signal(e.to_string()))?;

    let private_key = PrivateKey::deserialize(&decrypted_priv_bytes)
        .map_err(|e| IdentityError::Signal(e.to_string()))?;

    decrypted_priv_bytes.zeroize();

    Ok(IdentityKeyPair::new(public_key, private_key))
}

pub fn fingerprint(blob: &EncryptedIdentity) -> String {
    hex::encode(&blob.public_key)
}