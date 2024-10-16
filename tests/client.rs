use mega_security_rs::Client;

#[test]
fn new_client() {
    let client = Client::new_from_creds("test.com", "12345");
    dbg!(client);
}
