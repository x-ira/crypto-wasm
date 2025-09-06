use std::{array::TryFromSliceError, fmt::Display};
use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use rand_core::TryRngCore;
use ed25519_dalek::{ed25519::Error, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type CryptoResult<T> = Result<T, CryptoErr>;

pub fn b64_to_bytes(key_b64: &str) -> CryptoResult<[u8;PUBLIC_KEY_LENGTH]> {
    let pk_vec = Base64::decode_vec(key_b64).map_err(|e| CryptoErr::DecodeBase64Err(e.to_string()))?;
    pk_vec.try_into().map_err(|e: Vec<u8>| CryptoErr::InvalidKey(format!("Invalid key length: {}", e.len())))
}

// --- x25519 ---
#[derive(Debug)]
pub enum CryptoErr{
    InvalidKey(String),
    DecodeBase64Err(String),
    SignatureErr(String),
    EcdsaErr(String),
    CipherErr(String),
}
impl From<Error> for CryptoErr{
    fn from(value: Error) -> Self {
        Self::EcdsaErr(value.to_string())
    }
}
impl From<TryFromSliceError> for CryptoErr{
    fn from(err: TryFromSliceError) -> Self {
        Self::InvalidKey(err.to_string())
    }
}
impl From<chacha20poly1305::aead::Error> for CryptoErr{
    fn from(err: chacha20poly1305::aead::Error) -> Self {
        Self::CipherErr(err.to_string())
    }
}
impl From<rand_core::OsError> for CryptoErr {
    fn from(err: rand_core::OsError) -> Self {
        Self::CipherErr(err.to_string())
    }
}
impl Display for CryptoErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{self:?}")
    }
}
pub fn ecdh_gen_kp() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random();
    let pub_key = PublicKey::from(&secret);
    (secret, pub_key)
}

// --- ed25519 --- 
pub fn ecdsa_gen_kp() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng.unwrap_err();
    let sign_k = SigningKey::generate(&mut csprng);
    let verify_k = sign_k.verifying_key();
    (sign_k, verify_k)
}
