use super::Crypto;
use super::Result;
use crate::crypto::Signature;
use futures::prelude::*;
use futures::{FutureExt, StreamExt};
use ya_net_kad::Key;
use futures::future::LocalBoxFuture;
use crate::Identity;

#[derive(Clone)]
struct NoCrypto;

impl Crypto for NoCrypto {
    fn derive_keys<'a>(&mut self, identity: &Identity) -> LocalBoxFuture<'a, Result<(Vec<u8>, Vec<u8>)>> {
        future::ok((identity.to_vec(), identity.to_vec())).boxed_local()
    }

    fn derive_shared_secret<'a>(&mut self, remote_key: &[u8], local_secret_key: &[u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        future::ok(local_secret_key.to_vec()).boxed_local()
    }

    fn encrypt(&self, key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::from(payload.as_ref()))
    }

    fn decrypt(&self, secret_key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::from(payload.as_ref()))
    }

    fn sign<'a>(&self, secret_key: &[u8], payload: &[u8]) -> LocalBoxFuture<'a, Result<Signature>> {
        future::ok(Signature::Plain(secret_key.to_vec())).boxed_local()
    }

    fn verify(&self, key: Option<&[u8]>, signature: &mut Signature, payload: &[u8]) -> Result<bool> {
        let sig_key = signature.key();
        Ok(key.is_none() || sig_key.as_ref().map(AsRef::as_ref) == key.map(AsRef::as_ref))
    }
}

pub fn no_crypto() -> impl Crypto {
    NoCrypto
}
