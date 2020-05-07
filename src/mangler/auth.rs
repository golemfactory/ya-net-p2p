use crate::crypto;
use crate::error::{Error, MessageError};
use crate::event::MangleCmd;
use crate::packet::Packet;
use actix::prelude::*;
use sha2::Digest;
use std::convert::TryFrom;
use std::fmt::Debug;

pub struct AuthMangler<Key, Crypto>
where
    Key: Unpin,
    Crypto: crypto::Crypto<Key>,
{
    // FIXME: handle default identity changes
    default_key: Key,
    crypto: Crypto,
}

impl<Key, Crypto> AuthMangler<Key, Crypto>
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

impl<Key, Crypto> Actor for AuthMangler<Key, Crypto>
where
    Key: Send + Debug + Clone + Unpin + 'static,
    Crypto: crypto::Crypto<Key> + 'static,
{
    type Context = Context<Self>;
}

impl<Key, Crypto, E> Handler<MangleCmd<Key>> for AuthMangler<Key, Crypto>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    Crypto: crypto::Crypto<Key> + 'static,
    E: Into<Error>,
{
    type Result = ActorResponse<Self, Packet, Error>;

    fn handle(&mut self, msg: MangleCmd<Key>, _: &mut Context<Self>) -> Self::Result {
        match msg {
            MangleCmd::Mangle {
                from,
                to: _,
                mut packet,
            } => {
                let key = from.unwrap_or(self.default_key.clone());
                let mut sign_fut = None;

                if packet.payload.with_auth() {
                    packet.payload.mangle().auth(key.as_ref().to_vec());
                }

                if packet.payload.with_signature() {
                    let data = packet.payload.mangle().signature_data();
                    let hash = sha2::Sha256::digest(&data).to_vec();
                    sign_fut = Some(self.crypto.sign(key, hash));
                }

                let fut = async move {
                    if let Some(sign_fut) = sign_fut {
                        packet.payload.mangle().sig(sign_fut.await?);
                    }
                    Ok(packet)
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            MangleCmd::Unmangle {
                from,
                to: _,
                mut packet,
            } => {
                let auth = match packet.payload.auth().cloned() {
                    Some(vec) => match Key::try_from(vec) {
                        Ok(key) => Some(key),
                        Err(err) => return actor_reply(err),
                    },
                    _ => None,
                };
                let key = match from {
                    Some(key) => match auth {
                        Some(auth) => match key.as_ref() == auth.as_ref() {
                            true => Some(key),
                            false => return actor_reply(Error::key_mismatch(key, auth)),
                        },
                        _ => Some(key),
                    },
                    _ => auth,
                };

                if let Some(sig) = packet.payload.sig().cloned() {
                    match key {
                        Some(key) => {
                            let data = packet.payload.mangle().signature_data();
                            let hash = sha2::Sha256::digest(&data).to_vec();

                            match self.crypto.verify(key, hash, sig.clone()) {
                                Ok(false) => {
                                    let err = Error::sig("verification failed");
                                    return actor_reply(err);
                                }
                                Err(err) => return actor_reply(err),
                                _ => (),
                            }
                        }
                        None => return actor_reply(MessageError::MissingAuth),
                    }

                    packet.payload.mangle().sig(sig);
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
