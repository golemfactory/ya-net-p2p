use super::Crypto;
use super::Result;
use crate::crypto::Signature;
use futures::prelude::*;
use futures::FutureExt;

struct NoCrypto;

impl<Key: AsRef<[u8]>> Crypto<Key> for NoCrypto {
    fn encrypt<'a, P: AsRef<[u8]>>(
        &self,
        key: &Key,
        payload: P,
    ) -> future::LocalBoxFuture<'a, Result<Vec<u8>>> {
        future::ok(Vec::from(payload.as_ref())).boxed_local()
    }

    fn decrypt<'a, P: AsRef<[u8]>>(
        &self,
        key: &Key,
        payload: P,
    ) -> future::LocalBoxFuture<'a, Result<Vec<u8>>> {
        future::ok(Vec::from(payload.as_ref())).boxed_local()
    }

    fn sign<'a>(&self, key: &Key, hash: Vec<u8>) -> future::LocalBoxFuture<'a, Result<Signature>> {
        future::ok(Signature::Plain(key.as_ref().into())).boxed_local()
    }

    fn verify<H: AsRef<[u8]>>(
        &self,
        key: Option<&Key>,
        signature: &mut Signature,
        hash: H,
    ) -> Result<bool> {
        //eprintln!("verify: {:?} <-> {:?}", key.map(AsRef::as_ref), signature);
        let sig_key = signature.key();
        Ok(key.is_none() || sig_key.as_ref().map(AsRef::as_ref) == key.map(AsRef::as_ref))
    }
}

pub fn no_crypto<Key: AsRef<[u8]>>() -> impl Crypto<Key> {
    NoCrypto
}
