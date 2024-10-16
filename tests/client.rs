use mega_security_rs::ClientRegistration;

#[test]
fn new_client() {
    let _client = ClientRegistration::new_from_creds("test.com", "12345", None);
}
