use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};

use crate::SESSION_ID_LENGTH_BYTES;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SessionId(Vec<u8>);

impl SessionId {
    pub fn from_encrypted(enc: SessionIdEncrypted, rsa_priv: &RsaPrivateKey) -> Self {
        let token = rsa_priv.decrypt(Pkcs1v15Encrypt, &enc.0).expect("failed to encrypt");
        Self(token.to_vec())
    }
}

#[derive(Debug, Default, Clone)]
pub struct SessionIdEncrypted(Vec<u8>);

impl SessionIdEncrypted {
    pub fn new(rsa_public: &RsaPublicKey) -> (Self, SessionId) {
        let mut rng = rand::thread_rng();

        let mut token = [0u8; SESSION_ID_LENGTH_BYTES];
        rng.fill_bytes(&mut token);

        let enc_token = rsa_public.encrypt(&mut rng, Pkcs1v15Encrypt, &token).expect("failed to encrypt");

        (Self(enc_token.to_vec()), SessionId(token.to_vec()))
    }
    
}
