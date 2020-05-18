use crate::common::{FlattenResult, TriggerFut};
use crate::error::{CryptoError, DiscoveryError, Error, ProtocolError, SessionError};
use crate::event::{DhtCmd, DhtResponse, ProtocolCmd, SendCmd};
use crate::packet::{Guarantees, Packet, Payload};
use crate::protocol::{Protocol, ProtocolId};
use crate::serialize::{from_read as deser, to_vec as ser};
use crate::transport::Address;
use actix::prelude::*;
use futures::future::LocalBoxFuture;
use futures::{FutureExt, TryFutureExt};
use hashbrown::HashMap;
use serde::de::DeserializeOwned;
use serde::export::PhantomData;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use ya_client_model::NodeId;
use ya_core_model::net;
use ya_service_bus::untyped::{send as router_send, subscribe_recipient};
use ya_service_bus::{Handle, RpcRawCall};

impl From<Error> for ya_service_bus::Error {
    fn from(err: Error) -> Self {
        ya_service_bus::Error::GsbBadRequest(err.to_string())
    }
}

impl From<ya_service_bus::Error> for Error {
    fn from(err: ya_service_bus::Error) -> Self {
        Error::Service(err.to_string())
    }
}

pub struct ProtocolConfig {
    upkeep_interval: Duration,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            upkeep_interval: Duration::from_secs(3),
        }
    }
}

pub struct ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    conf: ProtocolConfig,
    net: Recipient<SendCmd<Key>>,
    dht: Recipient<DhtCmd<Key>>,
    requests: RequestMap<Result<Vec<u8>, Error>>,
    handle: Option<Handle>,
}

impl<Key> Protocol<Key> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    const PROTOCOL_ID: ProtocolId = 1002;
}

impl<Key> ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    pub fn new<R, D>(net: &R, dht: &D) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
        D: Into<Recipient<DhtCmd<Key>>> + Clone,
    {
        Self::with_config(net, dht, ProtocolConfig::default())
    }

    pub fn with_config<R, D>(net: &R, dht: &D, conf: ProtocolConfig) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
        D: Into<Recipient<DhtCmd<Key>>> + Clone,
    {
        Self {
            conf,
            net: net.clone().into(),
            dht: dht.clone().into(),
            requests: RequestMap::default(),
            handle: None,
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        self.requests.remove_ready();
    }
}

impl<Key> ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    fn build_request(request_id: usize, msg: Unicast<Key>) -> Result<SendCmd<Key>, Error> {
        let packet = Packet {
            guarantees: Guarantees::unordered(),
            payload: Payload::new(Self::PROTOCOL_ID).encode_payload(&NetRpcMessage::Request {
                request_id,
                caller: msg.caller,
                callee: msg.callee,
                addr: msg.addr,
                body: msg.body,
            })?,
        };

        Ok(SendCmd::Session {
            from: None,
            to: msg.node_key,
            packet,
        })
    }

    fn build_response(to: Key, request_id: usize, body: Vec<u8>) -> Result<SendCmd<Key>, Error> {
        let packet = Packet {
            guarantees: Guarantees::unordered(),
            payload: Payload::new(Self::PROTOCOL_ID)
                .encode_payload(&NetRpcMessage::Response { request_id, body })?,
        };

        Ok(SendCmd::Session {
            from: None,
            to,
            packet,
        })
    }
}

impl<Key> Actor for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.upkeep_interval, Self::upkeep)
            .finish()
            .spawn(ctx);

        let handle = subscribe_recipient(net::BUS_ID, ctx.address().recipient());
        self.handle.replace(handle);

        log::info!("GSB-net protocol started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("GSB-net protocol stopped");
    }
}

impl<Key> Handler<ProtocolCmd<Key>> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::SessionPacket(_, packet, key) => {
                let msg: NetRpcMessage = match packet.payload.decode_payload() {
                    Ok(msg) => msg,
                    Err(err) => return ActorResponse::reply(Err(err.into())),
                };

                match msg {
                    NetRpcMessage::Request {
                        request_id,
                        caller,
                        callee: _,
                        addr,
                        body,
                    } => {
                        let net = self.net.clone();
                        let fut = async move {
                            let response =
                                router_send(addr.as_str(), caller.as_str(), body.as_slice())
                                    .map_err(|e| e.to_string())
                                    .await;

                            let payload = ser(&response)?;
                            net.send(Self::build_response(key, request_id, payload)?)
                                .await??;
                            Ok(())
                        };

                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    NetRpcMessage::Response { request_id, body } => {
                        match self.requests.remove(&request_id) {
                            Some(mut request) => request.ready(Ok(body)),
                            None => log::warn!("Unknown request id: {}", request_id),
                        }

                        ActorResponse::reply(Ok(()))
                    }
                    NetRpcMessage::Broadcast { body: _ } => unimplemented!(),
                }
            }
            ProtocolCmd::RoamingPacket(_, _) => {
                let err = SessionError::Disconnected;
                ActorResponse::reply(Err(err.into()))
            }
            ProtocolCmd::Shutdown => {
                ctx.stop();
                ActorResponse::reply(Ok(()))
            }
        }
    }
}

impl<Key> Handler<RpcRawCall> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = ActorResponse<Self, Vec<u8>, ya_service_bus::Error>;

    fn handle(&mut self, mut msg: RpcRawCall, ctx: &mut Self::Context) -> Self::Result {
        let parsed = match parse_addr(&msg.addr) {
            Ok(res) => res,
            Err(err) => return ActorResponse::reply(Err(err.into())),
        };

        match parsed {
            ParsedAddr::Broadcast => {
                let net = self.net.clone();
                let cmd = SendCmd::Broadcast {
                    from: None,
                    packet: Packet {
                        guarantees: Guarantees::unordered(),
                        payload: Payload::new(Self::PROTOCOL_ID)
                            .with_payload(msg.body)
                            .with_signature(),
                    },
                };

                let fut = async move {
                    net.send(cmd).await??;
                    Ok(Vec::new())
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            ParsedAddr::Unicast(callee, addr) => {
                msg.addr = addr;

                let actor = ctx.address();
                let dht = self.dht.clone();

                let fut = async move {
                    let node_id = NodeId::from_str(callee.as_str())?;

                    let dht_key = node_id.into_array().to_vec();
                    let dht_value = match dht.send(DhtCmd::ResolveValue(dht_key)).await?? {
                        DhtResponse::Value(vec) => {
                            Key::try_from(vec).map_err(|_| CryptoError::InvalidKey)?
                        }
                        _ => return Err(Error::from(DiscoveryError::NotFound)),
                    };

                    actor
                        .send(Unicast {
                            caller: msg.caller,
                            callee,
                            addr: msg.addr,
                            body: msg.body,
                            node_key: dht_value,
                        })
                        .await?
                };

                ActorResponse::r#async(fut.map_err(|e| e.into()).into_actor(self))
            }
        }
    }
}

impl<Key> Handler<Unicast<Key>> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = ActorResponse<Self, Vec<u8>, Error>;

    fn handle(&mut self, mut msg: Unicast<Key>, _ctx: &mut Self::Context) -> Self::Result {
        let request_id = self.requests.next_seq();
        let cmd = match Self::build_request(request_id, msg) {
            Ok(cmd) => cmd,
            Err(err) => return ActorResponse::reply(Err(err.into())),
        };

        let trigger = self
            .requests
            .entry(request_id, TriggerFut::default())
            .clone();
        let mut trigger_err = trigger.clone();

        let net = self.net.clone();
        let fut = async move {
            net.send(cmd).await??;
            let raw = trigger.await?;
            match deser::<_, Result<Vec<u8>, String>>(raw.as_slice())? {
                Ok(vec) => Ok(vec),
                Err(err) => Err(ProtocolError::Call(err).into()),
            }
        };

        ActorResponse::r#async(
            fut.map_err(move |e: Error| {
                trigger_err.ready(Err(e.clone()));
                e
            })
            .into_actor(self),
        )
    }
}

fn parse_addr(src: &String) -> Result<ParsedAddr, Error> {
    let split: Vec<_> = src.splitn(4, '/').collect();
    let to = split[2];

    if split.len() == 3 && to == "broadcast" {
        Ok(ParsedAddr::Broadcast)
    } else if split.len() < 4 {
        Err(Error::Service(format!("Invalid address: {}", src)))
    } else {
        let endpoint = format!("/public/{}", split[3]);
        Ok(ParsedAddr::Unicast(to.to_string(), endpoint))
    }
}

enum ParsedAddr {
    Unicast(String, String),
    Broadcast,
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<Vec<u8>, Error>")]
struct Unicast<Key> {
    caller: String,
    callee: String,
    addr: String,
    body: Vec<u8>,
    node_key: Key,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetRpcMessage {
    Request {
        request_id: usize,
        caller: String,
        callee: String,
        addr: String,
        body: Vec<u8>,
    },
    Response {
        request_id: usize,
        body: Vec<u8>,
    },
    Broadcast {
        body: Vec<u8>,
    },
}

#[derive(Debug)]
struct RequestMap<T: Clone> {
    calls: HashMap<usize, TriggerFut<T>>,
    sequence: AtomicUsize,
}

impl<T: Clone> Default for RequestMap<T> {
    fn default() -> Self {
        RequestMap {
            calls: HashMap::new(),
            sequence: AtomicUsize::new(0),
        }
    }
}

impl<T: Clone> RequestMap<T> {
    #[inline]
    fn next_seq(&self) -> usize {
        self.sequence.fetch_add(1, SeqCst)
    }

    #[inline]
    fn entry(&mut self, id: usize, value: TriggerFut<T>) -> &mut TriggerFut<T> {
        self.calls.entry(id).or_insert(value)
    }

    #[inline]
    fn remove(&mut self, id: &usize) -> Option<TriggerFut<T>> {
        self.calls.remove(id)
    }

    #[inline]
    fn remove_ready(&mut self) {
        self.calls.retain(|_, t| t.is_pending());
    }
}
