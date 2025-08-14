pub mod util;

use base64ct::{Base64, Encoding};
use util::EcdhErr;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


#[wasm_bindgen]
pub struct Ecdh {
    secret: StaticSecret,
    pub_key: PublicKey,
}
#[wasm_bindgen]
impl Ecdh {
    #[wasm_bindgen(constructor)]
    pub fn init() -> Self {
        let (secret, pub_key) = util::gen_key_pair();
        Self { secret, pub_key }
    }
    pub fn exchange(&self, rival_pubk_b64: &str) -> Result<Box<[u8]>, EcdhErr> {
        let rival_pk = Base64::decode_vec(rival_pubk_b64).map_err(|e| EcdhErr::DecodeBase64Err(e.to_string()))?;
        let rival_pk_arr: [u8; 32] = rival_pk.try_into().map_err(|e: Vec<u8>| EcdhErr::InvalidPubKey(format!("Invalid key length: {}", e.len())))?;
        let rival_pub_key = PublicKey::from(rival_pk_arr);
        let shared_key = self.secret.diffie_hellman(&rival_pub_key);
        Ok(shared_key.as_ref().into())
    }
    #[wasm_bindgen(getter)]
    pub fn pub_key(&self) -> Box<[u8]> {
        self.pub_key.as_ref().into()
    }
}

impl From<EcdhErr> for JsValue{
    fn from(value: EcdhErr) -> Self {
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
pub fn hash(cont: &str) -> Box<[u8]> {
    blake3::hash(cont.as_bytes()).as_bytes().as_slice().into()
}

#[cfg(test)]
mod tests {
    use crate::{derive_key, gen_key_b64, hash, hash_b64, hash_hex};
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
        println!("{:?}", hash(cont));
        println!("{:?}", hash_b64(cont));
        println!("{:?}", hash_hex(cont));
    }
}
