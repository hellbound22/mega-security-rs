use rsa::{pkcs8::{DecodePrivateKey, EncodePrivateKey}, RsaPrivateKey, RsaPublicKey};
use aes_gcm::aes::{self};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut,KeyInit, generic_array::GenericArray,};

use crate::{errors::ClientError, RSA_LENGTH};


type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;


#[derive(Debug, Clone)]
pub struct KeysPayload {
    pub rsa: Vec<u8>,
    pub master: Vec<u8>,
}

impl KeysPayload {
    pub fn new(master_key: &[u8], derived_encryption_key: &[u8]) -> Result<(Self, RsaPublicKey), ClientError> {
        let mut rng = rand::thread_rng();

        let aes_master_key_array = GenericArray::clone_from_slice(master_key);
        
        // RSA
        let rsa_priv_key = if let Ok(pk) = RsaPrivateKey::new(&mut rng, RSA_LENGTH) { pk } 
            else { return Err(ClientError::RsaKeyGenerationFailed) };
        let rsa_pub_key = RsaPublicKey::from(&rsa_priv_key);
        let rsa_encoded = if let Ok(der) = rsa_priv_key.to_pkcs8_der() {
            der
        } else { return Err(ClientError::RsaKeyEncodeFailed) };

        let rsa_ct = Aes128EcbEnc::new(&aes_master_key_array)
            .encrypt_padded_vec_mut::<Pkcs7>(&mut rsa_encoded.as_bytes());

        // Master key
        let aes_derived_enc_key_array = GenericArray::from_slice(derived_encryption_key);

        let mut master_key_c = master_key;
        let master_ct = Aes128EcbEnc::new(&aes_derived_enc_key_array)
            .encrypt_padded_vec_mut::<Pkcs7>(&mut master_key_c);

        Ok((Self {
            rsa: rsa_ct.to_vec(),
            master: master_ct.to_vec(),
        }, rsa_pub_key))
    }

}

#[derive(Debug)]
pub struct KeysDecrypted {
    pub rsa: RsaPrivateKey,
    pub master: Vec<u8>,
}

impl KeysDecrypted {
    pub fn from_encrypted(payload: &mut KeysPayload, derived_encryption_key: &[u8]) -> Result<Self, ClientError> {
        let derived_encryption_key_array = GenericArray::from_slice(&derived_encryption_key);

        let master = if let Ok(x) = Aes128EcbDec::new(&derived_encryption_key_array)
            .decrypt_padded_vec_mut::<Pkcs7>(&mut payload.master) {
                x
            } else {
                return Err(ClientError::FailureToDecrypt);
        };
        let master = GenericArray::from_slice(&master);

        let rsa = if let Ok(x) = Aes128EcbDec::new(&master)
            .decrypt_padded_vec_mut::<Pkcs7>(&mut payload.rsa) {
                x
            } else {
                return Err(ClientError::FailureToDecrypt);
        };

        let rsa = if let Ok(pk) = RsaPrivateKey::from_pkcs8_der(&rsa) {
            pk
        } else { return Err(ClientError::RsaKeyDecodeFailed) };
        let master = master.to_vec();

        Ok(Self { rsa, master })
    }
}
