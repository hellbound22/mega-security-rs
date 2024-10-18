use rand::prelude::*;

use mega_security_rs::data::{DataDecrypt, DataEncrypt};

#[test]
fn encrypt_small() {
    let enc = DataEncrypt::new(b"teste", b"asdfasdfasdfasdf");
    assert!(enc.is_ok());
}


#[test]
fn encrypt_large() {
    let enc = DataEncrypt::new(b"Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit", b"asdfasdfasdfasdf");
    assert!(enc.is_ok());
}


#[test]
fn full_enc_dec_small() {
    let mut rng = rand::thread_rng();
    let mut key_128 = [0u8;16];
    rng.fill_bytes(&mut key_128);

    let data = b"Nice hops!"; 

    let enc = DataEncrypt::new(data, &key_128);
    assert!(enc.is_ok());
    let enc = enc.unwrap();

    let dec = DataDecrypt::decrypt(enc, &key_128);
    assert!(dec.is_ok());
    let dec = dec.unwrap();
    assert_eq!(dec, data);
}
