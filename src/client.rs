use rand::prelude::*;

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha512, Sha256};
use aes_gcm::aes;
use aes::cipher::{
    BlockEncrypt, KeyInit, generic_array::GenericArray,
};

#[derive(Debug)]
pub struct Client {
    id: String,
    client_random_number: Vec<u8>,
    encryped_master_key: Vec<u8>,
    hashed_auth_key: Vec<u8>,
}

impl Client {
    pub fn new_from_creds(id: &str, password: &str) -> Self {
        let mut rng = rand::thread_rng();

        let mut master_key = [0u8;16];
        rng.fill_bytes(&mut master_key);

        let mut random_value = [0u8;16];
        rng.fill_bytes(&mut random_value);

        let mut hasher = Sha256::new();
        let mut padding = vec!['P' as u8; 200 - id.len()];

        let mut salt: Vec<u8> = Vec::new();
        salt.append(&mut id.as_bytes().to_vec());
        salt.append(&mut padding);
        salt.append(&mut random_value.to_vec());
                
        hasher.update(&salt);

        let salt_hash = hasher.finalize();

        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt_hash, 100000, &mut derived_key);
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
            client_random_number: random_value.to_vec(),
            encryped_master_key: aes_block_array.as_slice().to_vec(),
            hashed_auth_key: hashed_auth_key.to_vec(),
        }
    }
}
