use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ServerError {
    #[error("client with id `{0}` is not registered")]
    ClientNotFound(String),
    #[error("autentication of user with id `{0}` failed")]
    AutenticationFailed(String),
    #[error("client with id `{0}` already exists")]
    ClientAlreadyRegistred(String),
    #[error("session id does not exist")]
    SessionIdNotFound,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("could not decrypt keys")]
    FailureToDecrypt,
}
