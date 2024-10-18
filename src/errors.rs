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
    #[error("could not decrypt data")]
    FailureToDecryptData,
    #[error("could not encrypt data")]
    FailureToEncryptData,
    
    #[error("could not decode RSA key")]
    RsaKeyDecodeFailed,
    #[error("could not encode RSA key")]
    RsaKeyEncodeFailed,
    #[error("could not generate RSA key")]
    RsaKeyGenerationFailed,

    #[error("required key '{0}' are not present")]
    KeyNotPresent(String),
}
