use rand::prelude::*;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut,KeyInit, generic_array::GenericArray,};

use aes::Aes128;
use ccm::{
    aead::AeadMutInPlace,
    consts::{U8, U16},
    Ccm, Nonce,
};

type Aes128Ccm = Ccm<Aes128, U16, U8>;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

#[derive(Debug, Clone)]
pub struct DataEncrypt{
    enc_data: Vec<u8>,
    data_key_ct: Vec<u8>,
}

impl DataEncrypt {
    pub fn new(data: &[u8], master_key: &[u8]) -> Self {
        let mut rng = rand::thread_rng();

        let mut data_key = [0u8;16];
        rng.fill_bytes(&mut data_key);

        let mut nonce = [0u8;8];
        rng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let mut cipher = Aes128Ccm::new(&data_key.into());

        let chunks = data.chunks(16);
        let mut ct = Vec::new();
        let mut mac_tags = Vec::new();
        
        for blk in chunks {
            let mut buf: Vec<u8> = Vec::new().into();
            let mac = cipher.encrypt_in_place_detached(nonce, blk , &mut buf).unwrap();
            
            ct.push(blk.to_vec());
            mac_tags.push(mac.to_vec());
        }

        let enc_data = ct.into_iter().flatten().collect();
        
        let mut condensed_mac = [0u8; 16];

        for tag in mac_tags {
            assert_eq!(condensed_mac.len(), tag.len(), "Slices must have the same length");
            for (x, y) in condensed_mac.iter_mut().zip(tag.iter()) {
                *x ^= y;
            }
        }


        let iv: [u8; 8] = nonce.clone().into();
        let mut obs_data_key = obfuscate_file_key(data_key, iv, condensed_mac);

        let data_key_ct = Aes128EcbEnc::new(&GenericArray::clone_from_slice(&master_key))
            .encrypt_padded_vec_mut::<Pkcs7>(&mut obs_data_key);

        Self{
            enc_data,
            data_key_ct,
        }
    }
}

fn obfuscate_file_key(
    file_key: [u8; 16],
    iv: [u8; 8],
    condensed_mac: [u8; 16],
) -> [u8; 16] {
    let mut obfuscated_key = [0u8; 16];

    obfuscated_key[0] = file_key[0] ^ iv[0];
    obfuscated_key[1] = file_key[1] ^ iv[1];
    obfuscated_key[2] = file_key[2] ^ condensed_mac[0] ^ condensed_mac[1];
    obfuscated_key[3] = file_key[3] ^ condensed_mac[2] ^ condensed_mac[3];

    obfuscated_key[4] = iv[0];
    obfuscated_key[5] = iv[1];
    obfuscated_key[6] = condensed_mac[0] ^ condensed_mac[1];
    obfuscated_key[7] = condensed_mac[2] ^ condensed_mac[3];

    obfuscated_key[8] = iv[0];
    obfuscated_key[9] = iv[1];
    obfuscated_key[10] = condensed_mac[0];
    obfuscated_key[11] = condensed_mac[1];
    obfuscated_key[12] = condensed_mac[2];
    obfuscated_key[13] = condensed_mac[3];

    obfuscated_key
}
