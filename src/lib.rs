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
#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn it_works() {
    }
}
