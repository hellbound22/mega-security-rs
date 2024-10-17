use rand::prelude::*;

use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

use crate::{errors::ClientError, keys::{KeysDecrypted, KeysPayload}, session::{SessionId, SessionIdEncrypted}, utils::{_compute_derived_key, _salt}};

#[derive(Debug, Clone)]
pub struct ClientRegistration {
    pub id: String,
    random_number: Vec<u8>,
    hashed_auth_key: Vec<u8>,
    pub rsa_public_key: RsaPublicKey,
    pub encrypted_keys: KeysPayload,
}

impl ClientRegistration {
    pub fn new_from_creds(id: &str, password: &str, domain: Option<&str>) -> Result<Self, ClientError> {
        let mut rng = rand::thread_rng();

        let mut master_key = [0u8;16];
        rng.fill_bytes(&mut master_key);

        let mut random_value = [0u8;16];
        rng.fill_bytes(&mut random_value);

        let salt = if let Some(d) = domain { 
            _salt(d, &random_value)
        } else {
            _salt(id, &random_value)
        };

        let derived_key = _compute_derived_key(&salt, password);

        let derived_encryption_key = &derived_key[0..16];
        let second_half = &derived_key[17..32];

        let mut auth_key_hasher = Sha256::new();
        auth_key_hasher.update(second_half);
        let hashed_auth_key = &auth_key_hasher.finalize()[..16];

        let (encrypted_keys, rsa_public_key) = KeysPayload::new(&master_key, &derived_encryption_key)?;

        Ok(Self {
            id: id.to_owned(),
            random_number: random_value.to_vec(),
            hashed_auth_key: hashed_auth_key.to_vec(),
            encrypted_keys,
            rsa_public_key,
        })
    }


    pub fn random_number(&self) -> &Vec<u8> {
        &self.random_number
    }

    pub fn hashed_auth_key(&self) -> &Vec<u8> {
        &self.hashed_auth_key
    }
}


#[derive(Debug, Default)]
pub struct AuthClient {
    pub id: String,
    password: String,
    salt: Option<Vec<u8>>,
    derived_encryption_key: Option<Vec<u8>>,
    autentication_key: Option<Vec<u8>>,
    decrypted_keys: Option<KeysDecrypted>,
    pub session: Option<SessionId>,
}

impl AuthClient {
    pub fn new_from_creds(id: &str, password: &str) -> Self {
        Self {
            id: id.to_owned(),
            password: password.to_owned(),
            ..Default::default()
        }
    }

    pub fn compute_derived_key(&mut self, salt: &[u8]) {
        let derived_key = _compute_derived_key(salt, &self.password);
        self.salt = Some(salt.to_vec());
        self.derived_encryption_key = Some(derived_key[..16].to_vec());
        self.autentication_key = Some(derived_key[17..32].to_vec());
    }

    pub fn autentication_key(&self) -> &Option<Vec<u8>> {
        &self.autentication_key
    }

    pub fn decrypt_keys(&mut self, mut encrypted_keys: KeysPayload, session_id_enc: SessionIdEncrypted) -> Result<(), ClientError> {
        let dek = if let Some(dek) = &self.derived_encryption_key { dek } 
            else { return Err( ClientError::KeyNotPresent("Derived Encryption Key".to_owned())) } ;


        self.decrypted_keys = 
            Some(
                KeysDecrypted::from_encrypted(
                    &mut encrypted_keys, 
                    dek
                )?
            );

        let uneck = if let Some(uneck) = &self.decrypted_keys { uneck } 
            else { return Err( ClientError::KeyNotPresent("decrypted keys".to_owned())) } ;

        let pk = uneck.rsa.clone();
        self.session = Some(
            SessionId::from_encrypted(
                session_id_enc, 
                &pk
            ));
        Ok(())
    }
}

