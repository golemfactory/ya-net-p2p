use crate::error::{CryptoError, Error};
use crate::Result;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::{thread_rng, Rng};

pub const KEY_SIZE: usize = 256 / 8;
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const PREFIX_SIZE: usize = IV_SIZE + TAG_SIZE;

pub fn encrypt<T: AsRef<[u8]>>(key: T, msg: T) -> Result<Vec<u8>> {
    let (key, msg) = (key.as_ref(), msg.as_ref());

    if key.len() != KEY_SIZE {
        return Err(err("Invalid key size"));
    }

    let mut iv = [0u8; IV_SIZE];
    let mut tag = [0u8; TAG_SIZE];
    let cipher = Cipher::aes_256_gcm();

    thread_rng().fill(&mut iv);
    match encrypt_aead(cipher, key, Some(&iv), &[], msg, &mut tag) {
        Ok(vec) => {
            let mut out = Vec::with_capacity(PREFIX_SIZE + vec.len());
            out.extend(iv.iter());
            out.extend(tag.iter());
            out.extend(vec);
            Ok(out)
        }
        Err(error) => Err(err(format!("{:?}", error))),
    }
}

pub fn decrypt<T: AsRef<[u8]>>(key: T, msg: T) -> Result<Vec<u8>> {
    let (key, msg) = (key.as_ref(), msg.as_ref());

    if key.len() != KEY_SIZE {
        return Err(err("Invalid key size"));
    }
    if msg.len() < PREFIX_SIZE {
        return Err(err("Invalid message size"));
    }

    let iv = &msg[..IV_SIZE];
    let tag = &msg[IV_SIZE..PREFIX_SIZE];
    let encrypted = &msg[PREFIX_SIZE..];
    let cipher = Cipher::aes_256_gcm();

    match decrypt_aead(cipher, key, Some(&iv), &[], encrypted, tag) {
        Ok(vec) => Ok(vec),
        Err(error) => Err(err(format!("{:?}", error))),
    }
}

#[inline]
fn err(e: impl ToString) -> Error {
    CryptoError::CipherError(e.to_string()).into()
}
