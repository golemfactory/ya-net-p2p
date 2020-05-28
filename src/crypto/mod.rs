use crate::error::Error;
use crate::identity::Slot;
use crate::{Identity, Result};
use futures::future::LocalBoxFuture;
use serde::{Deserialize, Serialize};

pub mod aes;

pub trait Crypto: Clone + Unpin {
    fn derive_keys<'a>(
        &mut self,
        identity: &Identity,
    ) -> LocalBoxFuture<'a, Result<(Vec<u8>, Vec<u8>)>>;

    fn derive_shared_secret<'a>(
        &mut self,
        remote_key: &[u8],
        local_secret_key: &[u8],
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>>;

    fn encrypt(&self, key: &[u8], payload: &[u8]) -> Result<Vec<u8>>;

    fn decrypt(&self, secret_key: &[u8], payload: &[u8]) -> Result<Vec<u8>>;

    fn sign<'a>(&self, secret_key: &[u8], payload: &[u8]) -> LocalBoxFuture<'a, Result<Signature>>;

    fn verify(&self, key: Option<&[u8]>, signature: &mut Signature, payload: &[u8])
        -> Result<bool>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signature {
    ECDSA(SignatureECDSA),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignatureECDSA {
    P256K1 { data: Vec<u8>, key: Option<Vec<u8>> },
}

impl Signature {
    pub fn data(&self) -> &Vec<u8> {
        match self {
            Signature::ECDSA(ecdsa) => ecdsa.data(),
        }
    }

    pub fn set_data(&mut self, vec: Vec<u8>) {
        match self {
            Signature::ECDSA(ecdsa) => ecdsa.set_data(vec),
        }
    }

    pub fn key(&self) -> Option<Vec<u8>> {
        match self {
            Signature::ECDSA(ecdsa) => ecdsa.key(),
        }
    }

    pub fn set_key(&mut self, vec: Vec<u8>) {
        match self {
            Signature::ECDSA(ecdsa) => ecdsa.set_key(vec),
        }
    }
}

impl SignatureECDSA {
    pub fn data(&self) -> &Vec<u8> {
        match self {
            SignatureECDSA::P256K1 { data, key: _ } => &data,
        }
    }

    pub fn set_data(&mut self, vec: Vec<u8>) {
        match self {
            SignatureECDSA::P256K1 { data, key: _ } => *data = vec,
        }
    }

    pub fn key(&self) -> Option<Vec<u8>> {
        match self {
            SignatureECDSA::P256K1 { data: _, key } => key.clone(),
        }
    }

    pub fn set_key(&mut self, vec: Vec<u8>) {
        match self {
            SignatureECDSA::P256K1 { data: _, key } => {
                key.replace(vec);
            }
        }
    }
}
