use crate::PBKDF2_ITER_NUM;

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};

pub fn _compute_derived_key(salt_hash: &[u8], password: &str) -> Vec<u8> {
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt_hash, PBKDF2_ITER_NUM, &mut derived_key);
    derived_key.to_vec()
}

pub fn _salt(id: &str, random_value: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut padding = vec!['P' as u8; 200 - id.len()];

    let mut salt: Vec<u8> = Vec::new();
    salt.append(&mut id.as_bytes().to_vec());
    salt.append(&mut padding);
    salt.append(&mut random_value.to_vec());
            
    hasher.update(&salt);

    hasher.finalize().to_vec()
}
