use mega_security_rs::data::{DataDecrypt, DataEncrypt};

#[test]
fn encrypt_small() {
    let enc = DataEncrypt::new(b"teste", b"asdfasdfasdfasdf");
}


#[test]
fn encrypt_large() {
    let enc = DataEncrypt::new(b"Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit", b"asdfasdfasdfasdf");
}


#[test]
fn full_enc_dec_small() {
    let enc = DataEncrypt::new(b"teste", b"asdfasdfasdfasdf");

    let dec = DataDecrypt::decrypt(enc, b"asdfasdfasdfasdf");
    dbg!(String::from_utf8(dec).unwrap());
}
