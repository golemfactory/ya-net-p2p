use crate::error::{CryptoError, Error};
use crate::Result;
use ethsign::{PublicKey, Signature};
use futures::future::LocalBoxFuture;

pub trait Crypto<Key>: Unpin {
    const SIGNATURE_SIZE: usize;

    fn encrypt<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>>;
    fn decrypt<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>>;
    fn sign<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>>;
    fn verify(&self, key: Key, payload: Vec<u8>, signature: Vec<u8>) -> Result<bool>;
}

pub fn verify_secp256k1<Key: AsRef<[u8]>>(
    key: Key,
    payload: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool> {
    let key = PublicKey::from_slice(key.as_ref()).map_err(|_| CryptoError::InvalidKey)?;
    let data: &[u8] = payload.as_ref();
    let sig: &[u8] = signature.as_ref();

    let sig = if sig.len() == std::mem::size_of::<Signature>() {
        let v = sig[0];
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&sig[1..33]);
        s.copy_from_slice(&sig[33..65]);

        Signature { v, r, s }
    } else {
        return Err(Error::sig("invalid signature size"));
    };

    let result = key.verify(&sig, data).map_err(ethsign::Error::Secp256k1)?;
    Ok(result)
}

#[cfg(feature = "yagna")]
pub mod ya_identity {
    use super::Crypto;
    use crate::error::Error;
    use crate::Result;
    use ethsign::PublicKey;
    use futures::future::LocalBoxFuture;
    use futures::FutureExt;
    use std::marker::PhantomData;
    use ya_core_model::ethaddr::NodeId;
    use ya_core_model::identity;
    use ya_service_bus::{typed as bus, RpcEndpoint};

    pub struct IdentityCrypto<Key>
    where
        Key: Unpin + AsRef<[u8]>,
    {
        phantom: PhantomData<Key>,
    }

    impl<Key> Crypto<Key> for IdentityCrypto<Key>
    where
        Key: Unpin + AsRef<[u8]>,
    {
        const SIGNATURE_SIZE: usize = 32;

        fn encrypt<'a>(&self, _key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
            // FIXME: encrypt
            async move { Ok(payload) }.boxed_local()
        }

        fn decrypt<'a>(&self, _key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
            // FIXME: decrypt
            async move { Ok(payload) }.boxed_local()
        }

        fn sign<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
            let public_key = match PublicKey::from_slice(key.as_ref()) {
                Ok(public_key) => public_key,
                _ => return async move { Err(Error::key()) }.boxed_local(),
            };
            let node_id = NodeId::from(public_key.address().as_ref());

            async move {
                bus::service(identity::BUS_ID)
                    .send(identity::Sign { node_id, payload })
                    .await?
                    .map_err(Error::from)
            }
            .boxed_local()
        }

        #[inline]
        fn verify(&self, key: Key, payload: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
            super::verify_secp256k1(key, payload, signature)
        }
    }
}
