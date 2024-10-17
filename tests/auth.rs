use mega_security_rs::{errors::ServerError, AuthClient, ClientRegistration, Server};

#[test]
fn full_process_correct() {
    let id = "test.com";
    let pssw = "12345";

    let client = ClientRegistration::new_from_creds(id, pssw, None);
    assert!(client.is_ok());
    let client = client.unwrap();

    let mut server = Server::new(None);
    assert!(server.register_client(&client).is_ok());

    let mut non_auth_client = AuthClient::new_from_creds(id, pssw);
    let non_auth_client_salt_given = server.get_salt_from_id(&non_auth_client.id);

    non_auth_client.compute_derived_key(&non_auth_client_salt_given.unwrap());

    let keys = server.auth_client(id, &non_auth_client.autentication_key().as_ref().unwrap());
    assert!(keys.is_ok());
    let (keys, session_id_enc) = keys.unwrap();
    
    // At this point in the exchange, the session is already established as far as the server is
    // concerned 
    let mut authed_client = non_auth_client;

    let decryption_res = authed_client.decrypt_keys(keys, session_id_enc);
    assert!(decryption_res.is_ok());

    let check = server.check_session_id(&authed_client.session.unwrap());
    assert!(check.is_ok())
}

#[test]
fn auth_failure_pssw() {
    let id = "test.com";
    let pssw = "12345";
    let wrong_pssw = "67890";

    let client = ClientRegistration::new_from_creds(id, pssw, None);
    assert!(client.is_ok());
    let client = client.unwrap();

    let mut server = Server::new(None);

    assert!(server.register_client(&client).is_ok());

    let mut non_auth_client = AuthClient::new_from_creds(id, wrong_pssw);
    let non_auth_client_salt_given = server.get_salt_from_id(&non_auth_client.id);

    non_auth_client.compute_derived_key(&non_auth_client_salt_given.unwrap());

    assert!(server.auth_client(id, &non_auth_client.autentication_key().as_ref().unwrap()).is_err());
}


#[test]
fn auth_failure_email() {
    let id = "test.com";
    let pssw = "12345";
    let wrong_id = "wrong.net";

    let client = ClientRegistration::new_from_creds(id, pssw, None);
    assert!(client.is_ok());
    let client = client.unwrap();

    let mut server = Server::new(None);

    assert!(server.register_client(&client).is_ok());

    let non_auth_client = AuthClient::new_from_creds(wrong_id, pssw);
    let non_auth_client_salt_given = server.get_salt_from_id(&non_auth_client.id);

    assert_eq!(non_auth_client_salt_given, Err(ServerError::ClientNotFound(wrong_id.to_owned())))
}
