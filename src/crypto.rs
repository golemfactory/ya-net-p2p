use crate::error::Error;
use crate::Result;
use futures::future::LocalBoxFuture;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signature {
    ECDSA(SignatureECDSA),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignatureECDSA {
    P256K1 { data: Vec<u8>, key: Option<Vec<u8>> },
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

pub trait Crypto<Key>: Unpin {
    const SIGNATURE_SIZE: usize;

    fn encrypt<'a, P: AsRef<[u8]>>(
        &self,
        key: Key,
        payload: P,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>>;

    fn decrypt<'a, P: AsRef<[u8]>>(
        &self,
        key: Key,
        payload: P,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>>;

    fn sign<'a>(&self, key: Key, hash: Vec<u8>) -> LocalBoxFuture<'a, Result<Signature>>;

    fn verify<H: AsRef<[u8]>>(
        &self,
        key: Option<Key>,
        signature: &mut Signature,
        hash: H,
    ) -> Result<bool>;
}

pub fn verify_secp256k1<Key: AsRef<[u8]>, H: AsRef<[u8]>>(
    key: Option<Key>,
    signature: &mut Signature,
    hash: H,
) -> Result<bool> {
    let sig = match signature {
        Signature::ECDSA(ecdsa) => match ecdsa {
            SignatureECDSA::P256K1 { data, key: _ } => data,
        },
    };

    if sig.len() == std::mem::size_of::<ethsign::Signature>() {
        let v = sig[0];
        let mut r = [0; 32];
        let mut s = [0; 32];

        r.copy_from_slice(&sig[1..33]);
        s.copy_from_slice(&sig[33..65]);

        let result = ethsign::Signature { v, r, s }
            .recover(hash.as_ref())
            .map_err(|e| Error::from(ethsign::Error::Secp256k1(e)))
            .map(|public_key| {
                signature.set_key(public_key.bytes().to_vec());
                public_key
            });

        match key {
            Some(key) => result.map(|rec| key.as_ref() == rec.bytes().as_ref()),
            _ => result.map(|_| true),
        }
    } else {
        Err(Error::sig("invalid signature size"))
    }
}

#[cfg(feature = "yagna")]
pub mod ya_identity {
    use super::{Crypto, Signature};
    use crate::crypto::SignatureECDSA;
    use crate::error::Error;
    use crate::Result;
    use ethsign::PublicKey;
    use futures::future::LocalBoxFuture;
    use futures::FutureExt;
    use std::marker::PhantomData;
    use ya_client_model::NodeId;
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

        fn encrypt<'a, P: AsRef<[u8]>>(
            &self,
            _key: Key,
            payload: P,
        ) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
            let payload = payload.as_ref().to_vec();
            // FIXME: encrypt
            async move { Ok(payload) }.boxed_local()
        }

        fn decrypt<'a, P: AsRef<[u8]>>(
            &self,
            _key: Key,
            payload: P,
        ) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
            let payload = payload.as_ref().to_vec();
            // FIXME: decrypt
            async move { Ok(payload) }.boxed_local()
        }

        fn sign<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Signature>> {
            let node_id = match PublicKey::from_slice(key.as_ref()) {
                Ok(public_key) => NodeId::from(public_key.address().as_ref()),
                _ => return async move { Err(Error::key()) }.boxed_local(),
            };

            let key = Some(key.as_ref().to_vec());
            async move {
                bus::service(identity::BUS_ID)
                    .send(identity::Sign { node_id, payload })
                    .await?
                    .map(|data| Signature::ECDSA(SignatureECDSA::P256K1 { data, key }))
                    .map_err(Error::from)
            }
            .boxed_local()
        }

        #[inline]
        fn verify<H: AsRef<[u8]>>(
            &self,
            key: Option<Key>,
            signature: &mut Signature,
            hash: H,
        ) -> Result<bool> {
            super::verify_secp256k1(key, signature, hash)
        }
    }
}
