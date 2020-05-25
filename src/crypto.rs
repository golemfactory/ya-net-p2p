use crate::error::Error;
use crate::Result;
use futures::future::LocalBoxFuture;
use serde::{Deserialize, Serialize};

pub trait Crypto<Key>: Unpin {
    fn encrypt<'a, P: AsRef<[u8]>>(
        &self,
        key: &Key,
        payload: P,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>>;

    fn decrypt<'a, P: AsRef<[u8]>>(
        &self,
        key: &Key,
        payload: P,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>>;

    fn sign<'a>(&self, key: &Key, hash: Vec<u8>) -> LocalBoxFuture<'a, Result<Signature>>;

    fn verify<H: AsRef<[u8]>>(
        &self,
        key: Option<&Key>,
        signature: &mut Signature,
        hash: H,
    ) -> Result<bool>;
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
