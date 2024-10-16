use crate::{errors::ServerError, utils::_salt, ClientRegistration};

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use rand::prelude::*;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

#[derive(Debug, Default)]
pub struct Server {
    confirm_code: Option<String>,
    clients_registered: HashMap<String, ClientRegistration>,
}

impl Server {
    pub fn new(confirm_code: Option<String>) -> Self {
        Self {
            confirm_code,
            ..Default::default()
        }
    }

    // TODO: this needs to return a confirmation token
    pub fn register_client(&mut self, client: &ClientRegistration) -> Result<String, ServerError> {
        if let Some(_) = self.clients_registered.get(&client.id) {
            return Err(ServerError::ClientAlreadyRegistred(client.id.to_owned()))
        }

        self.clients_registered.insert(client.id.to_owned(), client.clone());
        
        let mut token = [0u8; 16];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut token);

        let complete_token = match self.confirm_code.clone() {
            Some(code) => { 
                let mut t = Vec::new();

                t.append(&mut code.as_bytes().to_vec());
                t.append(&mut token.to_vec());
                t.append(&mut client.id.as_bytes().to_vec());

                t
            },
            None => { 
                let mut t = Vec::new();

                t.append(&mut token.to_vec());
                t.append(&mut client.id.as_bytes().to_vec());

                t
            }
        };

        let b64_token = URL_SAFE.encode(complete_token);

        Ok(b64_token)
    }

    pub fn get_salt_from_id(&self, id: &str) -> Result<Vec<u8>, ServerError> {
        let client = if let Some(c) = self.clients_registered.get(id) { c } 
            else { return Err(ServerError::ClientNotFound(id.to_owned()))};
        
        Ok(_salt(id, client.random_number()))
    }

    pub fn auth_client(&self, id: &str, autentication_key: &[u8]) -> Result<(), ServerError>{
        let mut auth_key_hasher = Sha256::new();
        auth_key_hasher.update(autentication_key);
        let hashed_auth_key = &auth_key_hasher.finalize()[..16];

        let client = if let Some(c) = self.clients_registered.get(id) { c } 
            else { return Err(ServerError::ClientNotFound(id.to_owned()))};

        if client.hashed_auth_key() == hashed_auth_key { Ok(()) } 
            else { return Err(ServerError::AutenticationFailed(id.to_owned())) }
    } 
}
