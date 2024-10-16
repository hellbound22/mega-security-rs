use rand::prelude::*;

use sha2::{Digest, Sha256};
use aes_gcm::aes;
use aes::cipher::{
    BlockEncrypt, KeyInit, generic_array::GenericArray,
};

use crate::utils::{_compute_derived_key, _salt};

#[derive(Debug, Clone)]
pub struct Client {
    pub id: String,
    random_number: Vec<u8>,
    _encryped_master_key: Vec<u8>,
    hashed_auth_key: Vec<u8>,
}

impl Client {
    pub fn new_from_creds(id: &str, password: &str) -> Self {
        let mut rng = rand::thread_rng();

        let mut master_key = [0u8;16];
        rng.fill_bytes(&mut master_key);

        let mut random_value = [0u8;16];
        rng.fill_bytes(&mut random_value);

        let salt = _salt(id, &random_value);

        let derived_key = _compute_derived_key(&salt, password);

        let first_half = &derived_key[0..16];
        let second_half = &derived_key[17..32];

        let aes_key_array = GenericArray::from_slice(first_half);
        let mut aes_block_array = GenericArray::clone_from_slice(&master_key);

        let cipher = aes::Aes128::new(&aes_key_array);
        cipher.encrypt_block(&mut aes_block_array);

        let mut auth_key_hasher = Sha256::new();
        auth_key_hasher.update(second_half);
        let hashed_auth_key = &auth_key_hasher.finalize()[..16];

        Self {
            id: id.to_owned(),
            random_number: random_value.to_vec(),
            _encryped_master_key: aes_block_array.as_slice().to_vec(),
            hashed_auth_key: hashed_auth_key.to_vec(),
        }
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
}

