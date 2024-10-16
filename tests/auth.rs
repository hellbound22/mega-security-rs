use mega_security_rs::{Client, Server, AuthClient};

#[test]
fn full_process_correct() {
    let id = "test.com";
    let pssw = "12345";

    let client = Client::new_from_creds(id, pssw);
    let mut server = Server::new();

    assert_eq!(server.register_client(&client), Ok(()));

    let mut non_auth_client = AuthClient::new_from_creds(id, pssw);
    let non_auth_client_salt_given = server.get_salt_from_id(id);

    non_auth_client.compute_derived_key(&non_auth_client_salt_given.unwrap());

    assert_eq!(server.auth_client(id, &non_auth_client.autentication_key().as_ref().unwrap()), Ok(()));
}
