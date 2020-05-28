use crate::crypto::{self, Signature};
use crate::error::Error;
use crate::event::ProcessCmd;
use crate::identity::{to_slot, IdentityManager};
use crate::identity::{Identity, Slot};
use crate::packet::payload::Body;
use crate::packet::{Packet, Payload};
use crate::Result;
use actix::prelude::*;
use futures::future::{err as future_err, ok as future_ok, LocalBoxFuture};
use futures::{FutureExt, TryFutureExt};
use hashbrown::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Not;

pub struct CryptoProcessor<Key, Crypto>
where
    Key: Hash + Eq + Clone + Debug + Unpin,
    Crypto: crypto::Crypto + 'static,
{
    crypto: Crypto,
    identities: IdentityManager<Key>,
    shared_secrets: HashMap<(Key, Key), Vec<u8>>,
}

impl<Key, Crypto> CryptoProcessor<Key, Crypto>
where
    Key: Hash + Eq + Send + Clone + Debug + Unpin + AsRef<[u8]> + 'static,
    Crypto: crypto::Crypto + 'static,
{
    pub fn new(identities: &IdentityManager<Key>, crypto: Crypto) -> Self {
        Self {
            crypto,
            identities: identities.clone(),
            shared_secrets: HashMap::new(),
        }
    }

    fn handle_inbound<'f, E>(
        &mut self,
        mut packet: Packet,
        from: Option<Key>,
        to: Option<Key>,
        actor: Addr<Self>,
    ) -> impl Future<Output = Result<Packet>> + 'f
    where
        Key: TryFrom<Vec<u8>, Error = E>,
        E: Into<Error> + 'static,
    {
        let decrypt_fut = if packet.payload.is_encrypted() {
            let remote_public = match from.clone() {
                Some(key) => key,
                _ => return future_err(Error::key("missing remote public key")).left_future(),
            };
            let local_public = match to {
                Some(key) => key,
                _ => self.identities.get_default_key().clone(),
            };
            let shared_secret_fut =
                self.get_shared_secret((local_public, remote_public), actor.clone());

            let mut crypto = self.crypto.clone();
            let body = packet.payload.body.take();
            let sig = packet.payload.signature.take();

            Some(async move {
                let shared_secret = shared_secret_fut.await?;
                let body = crypto.decrypt(&shared_secret, &body)?;
                let sig = if let Some(mut sig) = sig {
                    let data = crypto.decrypt(&shared_secret, sig.data())?;
                    sig.set_data(data);
                    Some(sig)
                } else {
                    None
                };
                Ok::<_, Error>((body, sig))
            })
        } else {
            None
        };

        let mut crypto = self.crypto.clone();
        async move {
            if let Some(f) = decrypt_fut {
                let (body, sig) = f.await?;
                packet.payload.body = Body::from(body);
                std::mem::replace(&mut packet.payload.signature, sig);
            }
            if packet.payload.is_signed() {
                let data = packet.payload.encode_for_signing();
                let sig = match packet.payload.signature.as_mut() {
                    Some(sig) => sig,
                    _ => return Err(Error::sig("inbound missing signature")),
                };
                if !crypto.verify(from.as_ref().map(|k| k.as_ref()), sig, &data)? {
                    return Err(Error::sig("inbound invalid signature"));
                }
            }
            Ok(packet)
        }
        .right_future()
    }

    fn handle_outbound<'f>(
        &mut self,
        mut packet: Packet,
        from: Option<Key>,
        to: Option<Key>,
        actor: Addr<Self>,
    ) -> impl Future<Output = Result<Packet>> + 'f {
        let sign_fut = if packet.payload.is_signed() {
            let local_public = match from.clone() {
                Some(key) => key,
                _ => return future_err(Error::key("missing local public key")).left_future(),
            };
            let local_secret = match self.identities.get_secret_key(&local_public) {
                Some(key) => key,
                _ => return future_err(Error::key("missing local secret key")).left_future(),
            };

            let data = packet.payload.encode_for_signing();
            Some(self.crypto.sign(local_secret.as_ref(), &data))
        } else {
            None
        };

        let encrypt_fut = if packet.payload.is_encrypted() {
            let remote_public = match to {
                Some(key) => key,
                _ => return future_err(Error::key("missing remote public key")).left_future(),
            };
            let local_public = match from {
                Some(key) => key,
                _ => return future_err(Error::key("missing local public key")).left_future(),
            };

            packet.payload.sender = Some(to_slot(&local_public));
            packet.payload.recipient = Some(to_slot(&remote_public));

            let shared_secret_fut =
                self.get_shared_secret((local_public, remote_public), actor.clone());

            let mut crypto = self.crypto.clone();
            let body = packet.payload.body.take();
            let sig = packet.payload.signature.take();

            Some(async move {
                let shared_secret = shared_secret_fut.await?;
                let body = crypto.encrypt(&shared_secret, &body)?;
                let sig = if let Some(mut sig) = sig {
                    let data = crypto.encrypt(&shared_secret, sig.data())?;
                    sig.set_data(data);
                    Some(sig)
                } else {
                    None
                };
                Ok::<_, Error>((body, sig))
            })
        } else {
            None
        };

        let mut crypto = self.crypto.clone();
        async move {
            if let Some(f) = sign_fut {
                packet.payload.signature = Some(f.await?);
            }
            if let Some(f) = encrypt_fut {
                let (body, sig) = f.await?;
                packet.payload.body = Body::from(body);
                std::mem::replace(&mut packet.payload.signature, sig);
            }
            Ok(packet)
        }
        .right_future()
    }

    fn get_shared_secret<'f>(
        &self,
        public_keys: (Key, Key),
        actor: Addr<Self>,
    ) -> impl Future<Output = Result<Vec<u8>>> + 'f {
        if let Some(shared_secret) = self.shared_secrets.get(&public_keys).cloned() {
            return future_ok(shared_secret).left_future();
        }

        let local_secret = self.identities.get_secret_key(&public_keys.0);
        let mut crypto = self.crypto.clone();

        async move {
            let local_secret =
                local_secret.ok_or_else(|| Error::key("missing local secret key"))?;
            let shared_secret = crypto
                .derive_shared_secret(public_keys.1.as_ref(), local_secret.as_ref())
                .await?;

            actor
                .send(internal::StoreSharedSecret {
                    local_public: public_keys.0,
                    remote_public: public_keys.1,
                    shared_secret: shared_secret.clone(),
                })
                .await?;

            Ok(shared_secret)
        }
        .right_future()
    }
}

impl<Key, Crypto> Actor for CryptoProcessor<Key, Crypto>
where
    Key: Hash + Eq + Send + Clone + Debug + Unpin + AsRef<[u8]> + 'static,
    Crypto: crypto::Crypto + 'static,
{
    type Context = Context<Self>;
}

impl<Key, Crypto, E> Handler<ProcessCmd<Key>> for CryptoProcessor<Key, Crypto>
where
    Key: Hash
        + Eq
        + Send
        + Clone
        + Debug
        + Unpin
        + AsRef<[u8]>
        + TryFrom<Vec<u8>, Error = E>
        + 'static,
    Crypto: crypto::Crypto + 'static,
    E: Into<Error> + 'static,
{
    type Result = ActorResponse<Self, Packet, Error>;

    fn handle(&mut self, msg: ProcessCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProcessCmd::Inbound { from, to, packet } => {
                let fut = self.handle_inbound(packet, from, to, ctx.address());
                ActorResponse::r#async(fut.into_actor(self))
            }
            ProcessCmd::Outbound { from, to, packet } => {
                let fut = self.handle_outbound(packet, from, to, ctx.address());
                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<Key, Crypto> Handler<internal::StoreSharedSecret<Key>> for CryptoProcessor<Key, Crypto>
where
    Key: Hash + Eq + Send + Clone + Debug + Unpin + AsRef<[u8]> + 'static,
    Crypto: crypto::Crypto + 'static,
{
    type Result = ();

    fn handle(
        &mut self,
        msg: internal::StoreSharedSecret<Key>,
        _: &mut Context<Self>,
    ) -> Self::Result {
        self.shared_secrets
            .insert((msg.local_public, msg.remote_public), msg.shared_secret);
    }
}

mod internal {
    #[derive(actix::Message)]
    #[rtype(result = "()")]
    pub(super) struct StoreSharedSecret<Key: Send> {
        pub local_public: Key,
        pub remote_public: Key,
        pub shared_secret: Vec<u8>,
    }
}
