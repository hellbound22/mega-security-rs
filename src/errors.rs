use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("client with id `{0}` is not registered")]
    ClientNotFound(String),
    #[error("autentication of user with id `{0}` failed")]
    AutenticationFailed(String),
}
