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

pub struct DataDecrypt;

impl DataDecrypt {
    pub fn decrypt(enc_data: DataEncrypt, master_key: &[u8]) -> Vec<u8> {
        let mut data_key_ct = enc_data.data_key_ct.clone();
        let data_key = Aes128EcbDec::new(&GenericArray::clone_from_slice(&master_key))
            .decrypt_padded_vec_mut::<Pkcs7>(&mut data_key_ct).unwrap();

        let (data_key, nonce) = deobfuscate_file_key(&data_key, &enc_data.condensed_mac);

        let condensed_mac = enc_data.condensed_mac.clone();
        let enc_data = enc_data.enc_data.clone();

        let mut cipher = Aes128Ccm::new(&GenericArray::clone_from_slice(&data_key));
        
        let chunks = enc_data.chunks(16);
        let mut res = Vec::new();

        let nonce = Nonce::from_slice(&nonce);
    
        for blk in chunks {
            let mut buf: Vec<u8> = Vec::new().into();
            cipher.decrypt_in_place_detached(nonce, blk , &mut buf, condensed_mac.as_slice().into()).unwrap();
            
            res.push(blk.to_vec());
        }
        
        res.into_iter().flatten().collect()
    }
}

#[derive(Debug, Clone)]
pub struct DataEncrypt{
    pub enc_data: Vec<u8>,
    pub data_key_ct: Vec<u8>,
    pub condensed_mac: Vec<u8>,
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
            //TODO: encrypt condensed_mac with AES-ECB
        }


        let iv: [u8; 8] = nonce.clone().into();
        let mut obs_data_key = obfuscate_file_key(data_key, iv, condensed_mac);

        let data_key_ct = Aes128EcbEnc::new(&GenericArray::clone_from_slice(&master_key))
            .encrypt_padded_vec_mut::<Pkcs7>(&mut obs_data_key);

        Self{
            enc_data,
            data_key_ct,
            condensed_mac: condensed_mac.to_vec(),
        }
    }
}

fn xor_slices(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for (x, y) in a.iter().zip(b.iter()) {
        v.push(x ^ y);
    }
    v 
}

fn obfuscate_file_key(
    file_key: [u8; 16],
    iv: [u8; 8],
    condensed_mac: [u8; 16],
) -> Vec<u8> {
    let file_key_chunks: Vec<&[u8]> = file_key.chunks(4).into_iter().collect();
    let iv_chunks: Vec<&[u8]> = iv.chunks(4).into_iter().collect();
    let condensed_mac_chunks: Vec<&[u8]> = condensed_mac.chunks(4).into_iter().collect();

    let xcm0 = xor_slices(condensed_mac_chunks[0], condensed_mac_chunks[1]);
    let xcm1 = xor_slices(condensed_mac_chunks[2], condensed_mac_chunks[3]);
    let k = vec![
        xor_slices(file_key_chunks[0], iv_chunks[0]),
        xor_slices(file_key_chunks[1], iv_chunks[1]),
        xor_slices(file_key_chunks[2], xcm0.as_slice()),
        xor_slices(file_key_chunks[3], xcm1.as_slice()),
        iv_chunks[0].to_vec(),
        iv_chunks[1].to_vec(),
        xcm0,
        xcm1,
    ];

    k.into_iter().flatten().collect()
}

fn deobfuscate_file_key(
    obfuscated_key: &[u8],
    condensed_mac: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let obfuscated_key_chunks: Vec<&[u8]> = obfuscated_key.chunks(4).into_iter().collect();
    let condensed_mac_chunks: Vec<&[u8]> = condensed_mac.chunks(4).into_iter().collect();

    let xcm0 = xor_slices(condensed_mac_chunks[0], condensed_mac_chunks[1]);
    let xcm1 = xor_slices(condensed_mac_chunks[2], condensed_mac_chunks[3]);

    let iv = vec![obfuscated_key_chunks[4].to_vec(), obfuscated_key_chunks[5].to_vec()];

    let fk = vec![
        xor_slices(&iv[0], obfuscated_key_chunks[0]),
        xor_slices(&iv[1], obfuscated_key_chunks[1]),
        xor_slices(&xcm0, obfuscated_key_chunks[2]),
        xor_slices(&xcm1, obfuscated_key_chunks[3]),
    ];

    (fk.into_iter().flatten().collect(), iv.into_iter().flatten().collect())
}

