use crate::common::FlattenResult;
use crate::error::{DiscoveryError, Error, MessageError, NetworkError, ProtocolError};
use crate::event::{DhtCmd, DhtResponse, ProtocolCmd, SendCmd};
use crate::packet::{Guarantees, Packet, Payload};
use crate::protocol::{Protocol, ProtocolId};
use crate::transport::Address;
use crate::Result;
use actix::prelude::*;
use futures::channel::mpsc::{channel, Receiver};
use generic_array::ArrayLength;
use serde::de::DeserializeOwned;
use std::convert::TryFrom;
use std::fmt::Debug;
use ya_net_kad::event::*;
use ya_net_kad::*;

const CHANNEL_BUFFER_SIZE: usize = 128;

pub trait NodeDataExt: NodeData + Unpin + DeserializeOwned {
    fn from_address(address: Address) -> Self;
    fn primary_address(&self) -> Option<Address>;
    fn addresses(&self) -> Vec<Address>;
}

pub struct KadProtocol<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    net: Recipient<SendCmd<Key<N>>>,
    kad: KadState<N, D>,
}

impl<N, D> Protocol<Key<N>> for KadProtocol<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    const PROTOCOL_ID: ProtocolId = 1000;
}

impl<N, D> KadProtocol<N, D>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    pub fn new<R>(node: Node<N, D>, net: &R) -> Self
    where
        R: Into<Recipient<SendCmd<Key<N>>>> + Clone,
    {
        Self::with_config(node, net, KadConfig::default())
    }

    pub fn with_config<R>(node: Node<N, D>, net: &R, conf: KadConfig) -> Self
    where
        R: Into<Recipient<SendCmd<Key<N>>>> + Clone,
    {
        KadProtocol {
            kad: KadState::new(node, conf),
            net: net.clone().into(),
        }
    }
}

impl<N, D> Actor for KadProtocol<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        match self.kad.spawn() {
            Ok(receiver) => {
                Self::add_stream(receiver, ctx);
                log::info!("Kad protocol started");
            }
            Err(err) => {
                log::error!("Error spawning Kad service: {}", err);
            }
        }
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("Kad protocol stopped");
    }
}

impl<N, D> Handler<DhtCmd<Key<N>>> for KadProtocol<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    type Result = ActorResponse<Self, DhtResponse, Error>;

    fn handle(&mut self, msg: DhtCmd<Key<N>>, _: &mut Context<Self>) -> Self::Result {
        let kad = match self.kad.addr() {
            Ok(kad) => kad,
            Err(err) => return actor_reply(err),
        };

        match msg {
            DhtCmd::ResolveNode(key) => {
                log::debug!("Resolving node: {}", key);

                let fut = async move {
                    let result = kad
                        .send(KadFindNode::new(key.clone()))
                        .await??
                        .ok_or(Error::from(DiscoveryError::NotFound))?;

                    let addresses = result.data.addresses();
                    match addresses.is_empty() {
                        true => Ok(DhtResponse::Empty),
                        false => {
                            log::debug!("Resolved node {}: {:?}", key, addresses);
                            Ok(DhtResponse::Addresses(addresses))
                        }
                    }
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            DhtCmd::ResolveValue(key) => {
                let hex_key = hex::encode(&key);
                log::debug!("Resolving value: {}", hex_key);

                let fut = async move {
                    let (_, value) = kad
                        .send(KadFindValue { key })
                        .await??
                        .ok_or(Error::from(DiscoveryError::NotFound))?;

                    log::debug!("Resolved value {}: {:?}", hex_key, value);
                    Ok(DhtResponse::Value(value))
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            DhtCmd::PublishValue(key, value) => {
                let hex_key = hex::encode(&key);
                log::debug!("Publishing value: {}", hex_key);

                let fut = async move {
                    kad.send(KadStore {
                        key,
                        value,
                        persistent: true,
                    })
                    .await??;

                    log::debug!("Published value {}", hex_key);
                    Ok(DhtResponse::Empty)
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            DhtCmd::Bootstrap(nodes) => {
                let kad = match self.kad.addr() {
                    Ok(kad) => kad,
                    Err(err) => return actor_reply(err),
                };

                let nodes = nodes
                    .into_iter()
                    .filter_map(|(key_vec, address)| {
                        Some(Node {
                            key: Key::try_from(key_vec).ok()?,
                            data: D::from_address(address),
                        })
                    })
                    .collect::<Vec<_>>();

                if nodes.is_empty() {
                    return actor_reply::<_, _, Error>(NetworkError::NoAddress.into());
                }

                let fut = async move {
                    kad.send(KadBootstrap {
                        nodes,
                        dormant: false,
                    })
                    .await??;

                    log::debug!("Bootstrap completed");
                    Ok(DhtResponse::Empty)
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<N, D> Handler<ProtocolCmd<Key<N>>> for KadProtocol<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd<Key<N>>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::SessionPacket(address, mut packet, _)
            | ProtocolCmd::RoamingPacket(address, mut packet) => {
                let kad = match self.kad.addr() {
                    Ok(kad) => kad,
                    Err(err) => return actor_reply(err),
                };

                let fut = async move {
                    let key_vec = packet
                        .payload
                        .signature()
                        .map(|sig| sig.key())
                        .flatten()
                        .ok_or(MessageError::MissingSignature)?;

                    kad.send(KadReceive {
                        from: Node {
                            key: Key::<N>::try_from(key_vec)?,
                            data: D::from_address(address),
                        },
                        message: packet.payload.decode_payload()?,
                    })
                    .await??;

                    Ok(())
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            ProtocolCmd::Shutdown => {
                ctx.stop();
                ActorResponse::reply(Ok(()))
            }
        }
    }
}

impl<N, D> StreamHandler<KadEvtSend<N, D>> for KadProtocol<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    fn handle(&mut self, evt: KadEvtSend<N, D>, ctx: &mut Context<Self>) {
        let from = Some(evt.from.key.clone());
        let to = match evt.to.data.primary_address() {
            Some(address) => address,
            _ => {
                log::error!("Missing primary address");
                return;
            }
        };

        let packet = match Packet::try_from(evt) {
            Ok(packet) => packet,
            Err(err) => {
                log::error!("{}", err.to_string());
                return;
            }
        };

        let send_fut = self.net.send(SendCmd::Roaming { from, to, packet });
        let fut = async move {
            if let Err(e) = send_fut.await.flatten_result() {
                log::warn!("Cannot send message: {}", Error::from(e));
            }
        };
        ctx.spawn(fut.into_actor(self));
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

enum KadState<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    New {
        kad: Kad<N, D>,
        receiver: Receiver<KadEvtSend<N, D>>,
    },
    Ready {
        kad: Addr<Kad<N, D>>,
    },
    Poisoned,
}

impl<N, D> KadState<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt,
{
    #[inline]
    fn addr(&self) -> Result<Addr<Kad<N, D>>> {
        match self {
            KadState::Ready { kad } => Ok(kad.clone()),
            _ => Err(Error::protocol_state("Kad not initialized")),
        }
    }
}

impl<N, D> KadState<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    fn new(node: Node<N, D>, conf: KadConfig) -> Self {
        let (sender, receiver) = channel(CHANNEL_BUFFER_SIZE);

        KadState::New {
            kad: Kad::with_conf(conf, node, sender),
            receiver,
        }
    }

    fn spawn(&mut self) -> Result<Receiver<KadEvtSend<N, D>>> {
        match std::mem::replace(self, KadState::Poisoned) {
            KadState::New { kad, receiver } => {
                let kad = kad.start();
                *self = KadState::Ready { kad };
                Ok(receiver)
            }
            state => {
                let err_msg = state.to_string();
                *self = state;
                Err(ProtocolError::InvalidState(err_msg).into())
            }
        }
    }
}

impl<N, D> std::fmt::Display for KadState<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            KadState::New { .. } => "New",
            KadState::Ready { .. } => "Ready",
            KadState::Poisoned => "Poisoned",
        };
        write!(f, "{}", name)
    }
}

impl From<ya_net_kad::Error> for Error {
    fn from(err: ya_net_kad::Error) -> Self {
        Error::protocol(format!("Kad error: {}", err))
    }
}

impl<N, D> TryFrom<KadEvtSend<N, D>> for Packet
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeDataExt + 'static,
{
    type Error = Error;

    fn try_from(evt: KadEvtSend<N, D>) -> std::result::Result<Self, Self::Error> {
        Ok(Packet {
            payload: Payload::new(KadProtocol::<N, D>::PROTOCOL_ID)
                .encode_payload(&evt.message)?
                .with_signature(),
            guarantees: Guarantees::unordered(),
        })
    }
}
