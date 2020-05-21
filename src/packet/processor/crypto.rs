use crate::crypto;
use crate::error::Error;
use crate::event::ProcessCmd;
use crate::packet::Packet;
use actix::prelude::*;
use sha2::Digest;
use std::convert::TryFrom;
use std::fmt::Debug;

// FIXME: handle default identity changes
pub struct CryptoProcessor<Key, Crypto>
where
    Key: Unpin,
    Crypto: crypto::Crypto<Key>,
{
    default_key: Key,
    crypto: Crypto,
}

impl<Key, Crypto> CryptoProcessor<Key, Crypto>
where
    Key: Unpin,
    Crypto: crypto::Crypto<Key>,
{
    pub fn new(key: Key, crypto: Crypto) -> Self {
        Self {
            default_key: key,
            crypto,
        }
    }
}

impl<Key, Crypto> Actor for CryptoProcessor<Key, Crypto>
where
    Key: Send + Debug + Clone + Unpin + 'static,
    Crypto: crypto::Crypto<Key> + 'static,
{
    type Context = Context<Self>;
}

impl<Key, Crypto, E> Handler<ProcessCmd<Key>> for CryptoProcessor<Key, Crypto>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    Crypto: crypto::Crypto<Key> + 'static,
    E: Into<Error>,
{
    type Result = ActorResponse<Self, Packet, Error>;

    fn handle(&mut self, msg: ProcessCmd<Key>, _: &mut Context<Self>) -> Self::Result {
        match msg {
            ProcessCmd::Outbound {
                from,
                to: _,
                mut packet,
            } => {
                let key = from.unwrap_or(self.default_key.clone());
                let mut sign_fut = None;

                if packet.payload.is_signed() {
                    let data = packet.payload.signature_data();
                    let hash = sha2::Sha256::digest(&data).to_vec();
                    sign_fut = Some(self.crypto.sign(&key, hash));
                }

                let fut = async move {
                    if let Some(fut) = sign_fut {
                        packet.payload.signature.replace(fut.await?);
                    }
                    Ok(packet)
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            ProcessCmd::Inbound {
                from,
                to: _,
                mut packet,
            } => {
                if packet.payload.is_signed() {
                    let payload = &mut packet.payload;
                    let data = payload.signature_data();
                    let sig = match payload.signature() {
                        Some(sig) => sig,
                        _ => return actor_reply(Error::sig("crypto: missing signature")),
                    };

                    let digest = sha2::Sha256::digest(&data);
                    match self.crypto.verify(from.as_ref(), sig, digest.as_ref()) {
                        Ok(false) => return actor_reply(Error::sig("crypto: invalid signature")),
                        Err(err) => return actor_reply(err),
                        _ => (),
                    }
                }

                ActorResponse::reply(Ok(packet))
            }
        }
    }
}

#[inline(always)]
fn actor_reply<A, I, E>(err: E) -> ActorResponse<A, I, Error>
where
    A: Actor,
    E: Into<Error>,
{
    ActorResponse::reply(Err(err.into()))
}
