use crate::{errors::ServerError, utils::_compute_derived_key, Client};

use std::collections::HashMap;

use sha2::{Digest, Sha256};

#[derive(Debug, Default)]
pub struct Server {
    clients_registered: HashMap<String, Client>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    // TODO: populate server clients

    pub fn get_salt_from_id(&self, id: &str, password: &str) -> Result<Vec<u8>, ServerError> {
        let client = if let Some(c) = self.clients_registered.get(id) { c } 
            else { return Err(ServerError::ClientNotFound(id.to_owned()))};
        
        Ok(_compute_derived_key(client.random_number(), password))
    }

    pub fn auth_client(&self, id: &str, autentication_key: &[u8; 16]) -> Result<(), ServerError>{
        let mut auth_key_hasher = Sha256::new();
        auth_key_hasher.update(autentication_key);
        let hashed_auth_key = &auth_key_hasher.finalize()[..16];

        let client = if let Some(c) = self.clients_registered.get(id) { c } 
            else { return Err(ServerError::ClientNotFound(id.to_owned()))};

        if client.hashed_auth_key() == hashed_auth_key { Ok(()) } 
            else { return Err(ServerError::AutenticationFailed(id.to_owned())) }
    } 
}
