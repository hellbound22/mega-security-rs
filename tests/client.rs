use mega_security_rs::Client;

#[test]
fn new_client() {
    let _client = Client::new_from_creds("test.com", "12345", None);
}
