use crate::error::{Error, MessageError};
use crate::event::{DisconnectReason, ProtocolCmd, SendCmd, SessionCmd, SessionEvt};
use crate::packet::payload::Payload;
use crate::packet::{Guarantees, Packet};
use crate::protocol::{Protocol, ProtocolId};
use crate::transport::Address;
use actix::prelude::*;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::time::Duration;

pub struct ProtocolConfig {
    upkeep_interval: Duration,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            upkeep_interval: Duration::from_secs(60),
        }
    }
}

pub struct SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + 'static,
{
    conf: ProtocolConfig,
    packets: Recipient<SendCmd<Key>>,
    events: Recipient<SessionEvt<Key>>,
}

impl<Key, E> Protocol<Key> for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    const PROTOCOL_ID: ProtocolId = 0;
}

impl<Key> SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + 'static,
{
    pub fn new<R, S>(packets: &R, events: &S) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
        S: Into<Recipient<SessionEvt<Key>>> + Clone,
    {
        Self::with_config(ProtocolConfig::default(), packets, events)
    }

    pub fn with_config<R, S>(conf: ProtocolConfig, packets: &R, events: &S) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
        S: Into<Recipient<SessionEvt<Key>>> + Clone,
    {
        SessionProtocol {
            conf,
            packets: packets.clone().into(),
            events: events.clone().into(),
        }
    }

    fn handle_auth_response<'f, E>(
        &mut self,
        address: Address,
        mut packet: Packet,
    ) -> impl Future<Output = Result<(), Error>> + 'f
    where
        Key: TryFrom<Vec<u8>, Error = E>,
        E: Into<Error>,
    {
        let sender = self.events.clone();
        async move {
            sender
                .send(SessionEvt::Established(address, extract_key(&mut packet)?))
                .await?;
            Ok(())
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {}
}

impl<Key> Actor for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + 'static,
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

impl<Key, E> Handler<SessionCmd<Key>> for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: SessionCmd<Key>, _: &mut Context<Self>) -> Self::Result {
        match msg {
            SessionCmd::Initiate(address) => {
                let payload = match Payload::new(Self::PROTOCOL_ID)
                    .encode_payload(&ProtocolMessage::AuthRequest)
                {
                    Ok(payload) => payload.with_signature(),
                    Err(error) => return ActorResponse::reply(Err(error)),
                };

                let fut = self
                    .packets
                    .send(SendCmd::Roaming {
                        from: None,
                        to: address,
                        packet: Packet {
                            payload,
                            guarantees: Guarantees::ordered_default(),
                        },
                    })
                    .map(|_| Ok(()));

                ActorResponse::r#async(fut.into_actor(self))
            }
            SessionCmd::Disconnect(key, reason) => {
                let payload = match Payload::new(Self::PROTOCOL_ID)
                    .encode_payload(&ProtocolMessage::Disconnect(reason))
                {
                    Ok(payload) => payload.with_signature(),
                    Err(error) => return ActorResponse::reply(Err(error)),
                };

                let fut = self
                    .packets
                    .send(SendCmd::Session {
                        from: None,
                        to: key,
                        packet: Packet {
                            payload,
                            guarantees: Guarantees::ordered_default(),
                        },
                    })
                    .map(|_| Ok(()));

                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<Key, E> Handler<ProtocolCmd<Key>> for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::RoamingPacket(address, mut packet) => {
                let payload = match packet.payload.decode_payload::<ProtocolMessage>() {
                    Ok(payload) => payload,
                    Err(error) => return ActorResponse::reply(Err(error)),
                };

                match &payload {
                    ProtocolMessage::AuthRequest => {
                        let key = match extract_key(&mut packet) {
                            Ok(key) => key,
                            Err(error) => return ActorResponse::reply(Err(error)),
                        };

                        let sender = self.events.clone();
                        let packets = self.packets.clone();
                        let fut = async move {
                            packets
                                .send(SendCmd::Roaming {
                                    from: None,
                                    to: address,
                                    packet: Packet {
                                        payload: Payload::new(Self::PROTOCOL_ID)
                                            .encode_payload(&ProtocolMessage::AuthResponse)?
                                            .with_signature(),
                                        guarantees: Guarantees::ordered_default(),
                                    },
                                })
                                .await??;
                            sender.send(SessionEvt::Established(address, key)).await?;
                            Ok(())
                        };
                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    ProtocolMessage::AuthResponse => {
                        let fut = self.handle_auth_response(address, packet);
                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    other => {
                        log::warn!("Unexpected roaming packet: {:?}", other);
                        ActorResponse::reply(Ok(()))
                    }
                }
            }
            ProtocolCmd::SessionPacket(address, packet, key) => {
                let payload = match packet.payload.decode_payload::<ProtocolMessage>() {
                    Ok(payload) => payload,
                    Err(error) => return ActorResponse::reply(Err(error)),
                };

                match payload {
                    ProtocolMessage::AuthResponse => {
                        let fut = self.handle_auth_response(address, packet);
                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    ProtocolMessage::Disconnect(reason) => {
                        log::info!("Disconnecting session ({:?}): {:?}", address, reason);
                        let sender = self.events.clone();
                        let fut = sender.send(SessionEvt::Disconnected(key)).map(|_| Ok(()));
                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    other => {
                        log::warn!("Unexpected session packet: {:?}", other);
                        ActorResponse::reply(Ok(()))
                    }
                }
            }
            ProtocolCmd::Shutdown => {
                ctx.stop();
                ActorResponse::reply(Ok(()))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ProtocolMessage {
    AuthRequest,
    AuthResponse,
    Disconnect(DisconnectReason),
}

fn extract_key<Key, E>(packet: &mut Packet) -> Result<Key, Error>
where
    Key: TryFrom<Vec<u8>, Error = E>,
    E: Into<Error>,
{
    let sig = packet.payload.signature();
    match sig.map(|sig| sig.key()).flatten() {
        Some(key_vec) => match Key::try_from(key_vec) {
            Ok(key) => Ok(key),
            Err(e) => Err(e.into()),
        },
        _ => Err(MessageError::MissingSignature.into()),
    }
}
