use chacha20poly1305::{aead::{Aead, Nonce}, AeadCore, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

use crate::util::CryptoErr;

pub struct AeadCipher<C=XChaCha20Poly1305>(C); // Aes256Gcm, xchacha20poly1305

impl AeadCipher<XChaCha20Poly1305>{
    pub fn from_key(key: &[u8;32]) -> Self{
        let cipher = XChaCha20Poly1305::new(key.into());
        Self(cipher)
    }
}
impl<C> AeadCipher<C> 
where C: AeadCore + Aead,
{
    /// nonce: 24 bytes(192 bits) for Chacha20; 12 bytes(96 bits) for Aes256GCM, unique per message
    pub fn encrypt_bytes(&self, data:&[u8]) -> Result<Vec<u8>, CryptoErr> {
        let nonce = C::generate_nonce()?; 
        let cipher_data = self.0.encrypt(&nonce, data)?;
        let enc_result = [nonce.to_vec(), cipher_data].concat();
        Ok(enc_result)
    }
    /// nonce: 24 bytes(192 bits) for Chacha20; 12 bytes(96 bits) for Aes256GCM, unique per message
    pub fn decrypt_bytes(&self, nonce:&[u8], cipher_data: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let nonce = Nonce::<C>::try_from(nonce)?;
        let dec_result = self.0.decrypt(&nonce, cipher_data)?;
        Ok(dec_result)
    }
}
