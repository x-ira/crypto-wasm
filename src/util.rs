use std::fmt::Display;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub enum EcdhErr{
    InvalidPubKey(String),
    DecodeBase64Err(String),
}
impl Display for EcdhErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{self:?}")
    }
}
pub fn gen_key_pair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random();
    let pub_key = PublicKey::from(&secret);
    (secret, pub_key)
}
