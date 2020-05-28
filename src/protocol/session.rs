use crate::error::{Error, MessageError, ProtocolError, SessionError};
use crate::event::{DisconnectReason, ProtocolCmd, SendCmd, SessionCmd, SessionEvt};
use crate::identity::IdentityManager;
use crate::packet::payload::Payload;
use crate::packet::{Guarantees, Packet};
use crate::protocol::{Protocol, ProtocolId, ProtocolVersion};
use crate::transport::Address;
use crate::Identity;
use actix::prelude::*;
use futures::future::err as future_err;
use futures::{FutureExt, TryFutureExt};
use hashbrown::HashMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};

pub struct ProtocolConfig {
    upkeep_interval: Duration,
    initiation_timeout: Duration,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            upkeep_interval: Duration::from_secs(60),
            initiation_timeout: Duration::from_secs(3),
        }
    }
}

pub struct SessionProtocol<Key>
where
    Key: Eq + Hash + Clone + Send + Unpin + 'static,
{
    conf: ProtocolConfig,
    packets: Recipient<SendCmd<Key>>,
    events: Recipient<SessionEvt<Key>>,
    pending: HashMap<usize, SessionEntry<Key>>,
    sequence: AtomicUsize,
    identities: IdentityManager<Key>,
}

impl<Key> SessionProtocol<Key>
where
    Key: Eq + Hash + Clone + Send + Unpin + 'static,
{
    pub fn new<R, S>(identities: &IdentityManager<Key>, packets: &R, events: &S) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
        S: Into<Recipient<SessionEvt<Key>>> + Clone,
    {
        Self::with_config(ProtocolConfig::default(), identities, packets, events)
    }

    pub fn with_config<R, S>(
        conf: ProtocolConfig,
        identities: &IdentityManager<Key>,
        packets: &R,
        events: &S,
    ) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
        S: Into<Recipient<SessionEvt<Key>>> + Clone,
    {
        SessionProtocol {
            conf,
            packets: packets.clone().into(),
            events: events.clone().into(),
            pending: HashMap::new(),
            sequence: AtomicUsize::new(0),
            identities: identities.clone(),
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        let now = Instant::now();
        let timeout = self.conf.initiation_timeout;
        self.pending.retain(|id, e| e.created_at + timeout > now)
    }
}

impl<Key> Actor for SessionProtocol<Key>
where
    Key: Eq + Hash + Send + Clone + Unpin + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.upkeep_interval, Self::upkeep)
            .finish()
            .spawn(ctx);

        log::info!("Session service started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("Session service stopped");
    }
}

impl<Key, E> Protocol for SessionProtocol<Key>
where
    Key: Eq + Hash + Clone + Send + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    const ID: ProtocolId = 5355;
    const VERSION: ProtocolVersion = 0;
}

impl<Key, E> SessionProtocol<Key>
where
    Key: Eq + Hash + Clone + Send + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    fn handle_request<'f>(
        &mut self,
        data: ProtocolData,
        address: Address,
        mut packet: Packet,
    ) -> impl Future<Output = Result<(), Error>> + 'f {
        let net = self.packets.clone();
        let events = self.events.clone();
        let identities = self.identities.clone();

        async move {
            let remote_raw = packet.signer().ok_or(MessageError::MissingAuth)?;
            let remote_identity = data.from_identity;
            let local_key = Key::try_from(data.to).map_err(Into::into)?;
            let local_identity = {
                identities
                    .borrow()
                    .get_identity(&local_key)
                    .ok_or_else(|| Error::protocol("unknown local identity"))?
            };

            let msg = ProtocolMessage::SessionResponse(ProtocolData {
                id: data.id,
                from_identity: local_identity.clone(),
                to: remote_raw.clone(),
            });
            net.send(SendCmd::Roaming {
                from: Some(local_key.clone()),
                to: address.clone(),
                packet: Packet::try_ordered::<Self, _>(&msg)?.sign(),
            })
            .await??;

            events
                .send(SessionEvt::Established {
                    from: local_key,
                    from_identity: local_identity,
                    to: Key::try_from(remote_raw).map_err(Into::into)?,
                    to_identity: remote_identity,
                    address,
                })
                .await?;

            Ok(())
        }
    }

    fn handle_response<'f>(
        &mut self,
        data: ProtocolData,
        address: Address,
        mut packet: Packet,
    ) -> impl Future<Output = Result<(), Error>> + 'f {
        let from = match packet.signer() {
            Some(key) => key,
            _ => return future_err(Error::protocol("Sender key missing")).left_future(),
        };

        match self.pending.get(&data.id) {
            Some(pending) => {
                if data.to.as_slice() != pending.from.as_ref() {
                    return future_err(Error::protocol("Recipient key mismatch")).left_future();
                }
                if data.from_identity != pending.to_identity {
                    return future_err(Error::protocol("Sender identity mismatch")).left_future();
                }
                if from.as_slice() != pending.to.as_ref() {
                    return future_err(Error::protocol("Sender key mismatch")).left_future();
                }
            }
            _ => return future_err(Error::protocol("Sender key mismatch")).left_future(),
        }

        let pending = self.pending.remove(&data.id).unwrap();
        self.events
            .send(SessionEvt::Established {
                from: pending.from,
                from_identity: pending.from_identity,
                to: pending.to,
                to_identity: pending.to_identity,
                address,
            })
            .map_err(Error::from)
            .right_future()
    }
}

impl<Key, E> Handler<SessionCmd<Key>> for SessionProtocol<Key>
where
    Key: Eq + Hash + Send + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: SessionCmd<Key>, _: &mut Context<Self>) -> Self::Result {
        match msg {
            SessionCmd::Initiate {
                from,
                from_identity,
                to,
                to_identity,
                address,
            } => {
                let id = self.sequence.fetch_add(1, SeqCst);
                let to_raw = to.as_ref().to_vec();
                let packets = self.packets.clone();

                self.pending.insert(
                    id,
                    SessionEntry::new(from.clone(), from_identity.clone(), to, to_identity),
                );
                let fut = async move {
                    let packet = Packet::try_ordered::<Self, _>(ProtocolMessage::SessionRequest(
                        ProtocolData {
                            id,
                            from_identity,
                            to: to_raw,
                        },
                    ))?
                    .sign();

                    packets
                        .send(SendCmd::Roaming {
                            from: Some(from),
                            to: address,
                            packet,
                        })
                        .await?;
                    Ok(())
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<Key, E> Handler<ProtocolCmd> for SessionProtocol<Key>
where
    Key: Eq + Hash + Send + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::RoamingPacket {
                address,
                mut packet,
            }
            | ProtocolCmd::SessionPacket {
                address,
                mut packet,
                ..
            } => {
                let payload = match packet.payload.decode_body::<ProtocolMessage>() {
                    Ok(payload) => payload,
                    Err(error) => return ActorResponse::reply(Err(error)),
                };

                match payload {
                    ProtocolMessage::SessionRequest(data) => {
                        let fut = self.handle_request(data, address, packet);
                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    ProtocolMessage::SessionResponse(data) => {
                        let fut = self.handle_response(data, address, packet);
                        ActorResponse::r#async(fut.into_actor(self))
                    }
                }
            }
            ProtocolCmd::Shutdown => ActorResponse::reply(Ok(())),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum ProtocolMessage {
    SessionRequest(ProtocolData),
    SessionResponse(ProtocolData),
}

#[derive(Clone, Serialize, Deserialize)]
struct ProtocolData {
    id: usize,
    from_identity: Identity,
    to: Vec<u8>,
}

struct SessionEntry<Key> {
    from: Key,
    from_identity: Identity,
    to: Key,
    to_identity: Identity,
    created_at: Instant,
}

impl<Key> SessionEntry<Key> {
    fn new(from: Key, from_identity: Identity, to: Key, to_identity: Identity) -> Self {
        Self {
            from,
            from_identity,
            to,
            to_identity,
            created_at: Instant::now(),
        }
    }
}
