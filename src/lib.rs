pub mod util;
pub mod cipher;

use base64ct::{Base64, Encoding};
use ed25519_dalek::{ed25519::signature::AsyncSigner, Signature, SigningKey, Verifier, VerifyingKey};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::js_sys::Uint8Array;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{cipher::AeadCipher, util::{b64_to_bytes, CryptoErr, CryptoResult}};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Ecdsa {
    sign_key: SigningKey,
    verify_key: VerifyingKey,
}

#[wasm_bindgen]
impl Ecdsa {
    #[wasm_bindgen(constructor)]
    pub fn init(sk_opt: Option<Box<[u8]>>) -> CryptoResult<Self> {
        let (sign_key, verify_key) = match sk_opt {
            Some(sk) => {
                let sign_key_arr: [u8;32] = sk.as_ref().try_into()?;
                let signing_key = SigningKey::from_bytes(&sign_key_arr);
                let verifying_key = signing_key.verifying_key();
                (signing_key, verifying_key)
            },
            None => {
                util::ecdsa_gen_kp()
            }
        };
        let ecdsa = Self { sign_key, verify_key };
        Ok(ecdsa)
    }
    #[wasm_bindgen(getter)]
    pub fn sign_key(&self) -> String {
        Base64::encode_string(self.sign_key.to_bytes().as_slice())
    }
    #[wasm_bindgen(getter)]
    pub fn verify_key(&self) -> String {
        Base64::encode_string(self.verify_key.to_bytes().as_slice())
    }
    #[wasm_bindgen(getter)]
    pub fn sk(&self) -> Box<[u8]> {
        self.sign_key.to_bytes().into()
    }
    #[wasm_bindgen(getter)]
    pub fn vk(&self) -> Box<[u8]> {
        self.verify_key.to_bytes().into()
    }
    pub async fn sign(&self, msg_hash: Box<[u8]>) -> CryptoResult<Box<[u8]>> {
        let signature = self.sign_key.sign_async(&msg_hash).await?;
        Ok(signature.to_bytes().into())
    }
    pub async fn sign_by(sign_key: Box<[u8]>, msg_hash: &str) -> CryptoResult<Box<[u8]>> {
        let sign_key_arr: [u8;32] = sign_key.as_ref().try_into()?;
        let signing_key = SigningKey::from_bytes(&sign_key_arr);
        let signature = signing_key.sign_async(msg_hash.as_bytes()).await?;
        Ok(signature.to_bytes().into())
    }
    pub fn verify(rival_pk: Box<[u8]>, msg_hash: Box<[u8]>, sign: Box<[u8]>) -> CryptoResult<bool> {
        let rival_pk_arr = rival_pk.as_ref().try_into()?;
        let rival_verify_key = VerifyingKey::from_bytes(&rival_pk_arr)?;
        let signature = Signature::from_slice(&sign)?;
        rival_verify_key.verify(&msg_hash, &signature)?;
        Ok(true)
    }
}

#[wasm_bindgen]
pub struct Cipher(AeadCipher);

#[wasm_bindgen]
impl Cipher {
    #[wasm_bindgen(constructor)]
    pub fn init(key: &[u8]) -> CryptoResult<Self> {
        let key_arr: [u8;32] = key.as_ref().try_into()?;
        Ok(Self(AeadCipher::from_key(&key_arr)))
    }
    pub fn encrypt(&self, data: &[u8]) -> CryptoResult<Box<[u8]>> {
        self.0.encrypt_bytes(data).map(|r| r.into())   // Uint8Array::from(r.as_slice())
    }
    pub fn decrypt(&self, enc_data: &[u8], nonce_len: usize) -> CryptoResult<Box<[u8]>> {
        let nonce = &enc_data[..nonce_len];
        let cipher_data = &enc_data[nonce_len..];
        self.0.decrypt_bytes(nonce, cipher_data).map(|r| r.into())
    }
}
#[wasm_bindgen]
pub struct Ecdh {
    secret: EphemeralSecret,
    pub_key: PublicKey,
}
#[wasm_bindgen]
impl Ecdh {
    #[wasm_bindgen(constructor)]
    pub fn init() -> Self {
        let (secret, pub_key) = util::ecdh_gen_kp();
        Self { secret, pub_key }
    }
    pub fn exchange(self, rival_pk: Box<[u8]>) -> CryptoResult<Box<[u8]>> {
        let rival_pk_arr: [u8;32] = rival_pk.as_ref().try_into()?;
        self.dh_share(rival_pk_arr)
    }
    fn dh_share(self, rival_pk_arr: [u8;32]) -> CryptoResult<Box<[u8]>> {
        let rival_pub_key = PublicKey::from(rival_pk_arr);
        let shared_key = self.secret.diffie_hellman(&rival_pub_key);
        Ok(shared_key.as_ref().into())
    }
    pub fn exchange_b64(self, rival_pk_b64: &str) -> CryptoResult<Box<[u8]>> {
        let rival_pk_arr = b64_to_bytes(rival_pk_b64)?;
        self.dh_share(rival_pk_arr)
    }
    #[wasm_bindgen(getter)]
    pub fn pub_key(&self) -> Box<[u8]> {
        self.pub_key.as_ref().into()
    }
}
#[wasm_bindgen]
pub struct StaticEcdh {
    secret: StaticSecret, //EphemeralSecret is good, but sometimes we have to serialize the secret.
}
#[wasm_bindgen]
impl StaticEcdh {
    #[wasm_bindgen(constructor)]
    pub fn init() -> Self {
        let secret = StaticSecret::random();
        Self { secret }
    }
    pub fn to_bytes(&self) -> Box<[u8]>{
        self.secret.to_bytes().into()
    }
    pub fn from_bytes(ecdh_bytes: &[u8]) -> CryptoResult<Self>{
        let secret_arr: [u8;32] = ecdh_bytes.try_into()?;
        let secret = StaticSecret::from(secret_arr);
        Ok(Self { secret })
    }
    pub fn exchange(self, rival_pk: Box<[u8]>) -> CryptoResult<Box<[u8]>> {
        let rival_pk_arr: [u8;32] = rival_pk.as_ref().try_into()?;
        self.dh_share(rival_pk_arr)
    }
    fn dh_share(self, rival_pk_arr: [u8;32]) -> CryptoResult<Box<[u8]>> {
        let rival_pub_key = PublicKey::from(rival_pk_arr);
        let shared_key = self.secret.diffie_hellman(&rival_pub_key);
        Ok(shared_key.as_ref().into())
    }
    pub fn exchange_b64(self, rival_pk_b64: &str) -> CryptoResult<Box<[u8]>> {
        let rival_pk_arr = b64_to_bytes(rival_pk_b64)?;
        self.dh_share(rival_pk_arr)
    }
    #[wasm_bindgen(getter)]
    pub fn pub_key(&self) -> Box<[u8]> {
        let pub_key = PublicKey::from(&self.secret);
        pub_key.as_ref().into()
    }
}

impl From<CryptoErr> for JsValue{
    fn from(value: CryptoErr) -> Self {
        Self::from_str(&value.to_string())
    }
}

#[wasm_bindgen]
pub fn derive_key(ctx: &str, key_material: &str) -> Box<[u8]> { // .as_slice().into() -> js_sys::Uint8Array
    blake3::derive_key(ctx, key_material.as_bytes()).into()   
}
#[wasm_bindgen]
pub fn gen_key_b64(ctx: &str, key_material: &str) -> String {
    let key = blake3::derive_key(ctx, key_material.as_bytes());
    Base64::encode_string(&key)
}
#[wasm_bindgen]
pub fn hash_hex(cont: &str) -> String {
    blake3::hash(cont.as_bytes()).to_string()
}
#[wasm_bindgen]
pub fn hash_b64(cont: &str) -> String {
    let hash = blake3::hash(cont.as_bytes());
    Base64::encode_string(hash.as_bytes())
}
#[wasm_bindgen]
pub fn hash(parts: Vec<Uint8Array>) -> Box<[u8]> {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&part.to_vec());
    }
    hasher.finalize().as_bytes().as_slice().into()
}

#[cfg(test)]
mod tests {
    use crate::{derive_key, gen_key_b64, hash_b64, hash_hex};
    #[test]
    fn test_derive_key() {
        derive_key("pin-code-str", "kind-of-salt");
    }
    #[test]
    fn test_gen_key() {
        let key = gen_key_b64("pin-code-str", "kind-of-salt");
        println!("{key}");
    }
    #[test]
    fn test_hash() {
        let cont = "this is a text";
        println!("{:?}", hash_b64(cont));
        println!("{:?}", hash_hex(cont));
    }
}
