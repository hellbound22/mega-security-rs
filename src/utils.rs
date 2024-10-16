use crate::PBKDF2_ITER_NUM;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

pub fn _compute_derived_key(salt_hash: &[u8], password: &str) -> Vec<u8> {
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt_hash, PBKDF2_ITER_NUM, &mut derived_key);
    derived_key.to_vec()
}
