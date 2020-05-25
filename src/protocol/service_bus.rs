use crate::common::{FlattenResult, TriggerFut};
use crate::error::{CryptoError, DiscoveryError, Error, ProtocolError, SessionError};
use crate::event::{DhtCmd, DhtResponse, ProtocolCmd, SendCmd};
use crate::packet::{Guarantees, Packet, Payload};
use crate::protocol::{Protocol, ProtocolId};
use crate::serialize::{from_read as deser, to_vec as ser};
use crate::transport::Address;
use actix::prelude::*;
use futures::future::LocalBoxFuture;
use futures::{FutureExt, StreamExt, TryFutureExt};
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
use ya_service_bus::untyped::{send as router_send, subscribe, RawHandler};
use ya_service_bus::{Handle, RpcRawCall};

static CALL_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

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
    requests: HashMap<usize, TriggerFut<Result<Vec<u8>, Error>>>,
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
            requests: HashMap::default(),
            handle: None,
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        self.requests.retain(|_, t| t.is_pending());
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

    fn handle_rpc_message<'a>(
        &mut self,
        key: Key,
        msg: NetRpcMessage,
    ) -> LocalBoxFuture<'a, Result<(), Error>> {
        match msg {
            NetRpcMessage::Request {
                request_id,
                caller,
                callee: _,
                addr,
                body,
            } => {
                let net = self.net.clone();
                async move {
                    let response = router_send(addr.as_str(), caller.as_str(), body.as_slice())
                        .map_err(|e| e.to_string())
                        .await;

                    let payload = ser(&response)?;
                    net.send(Self::build_response(key, request_id, payload)?)
                        .await??;
                    Ok(())
                }
                .boxed_local()
            }
            NetRpcMessage::Response { request_id, body } => {
                match self.requests.remove(&request_id) {
                    Some(mut request) => request.ready(Ok(body)),
                    None => log::warn!("Unknown request id: {}", request_id),
                }
                futures::future::ok(()).boxed_local()
            }
        }
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

        self.handle.replace(subscribe(
            "/net",
            ServiceBusHandler {
                proto: ctx.address(),
                net: self.net.clone(),
                dht: self.dht.clone(),
            },
        ));

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
                let fut = self.handle_rpc_message(key, msg);
                ActorResponse::r#async(fut.into_actor(self))
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

impl<Key> Handler<Unicast<Key>> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = ActorResponse<Self, Vec<u8>, Error>;

    fn handle(&mut self, mut msg: Unicast<Key>, _ctx: &mut Self::Context) -> Self::Result {
        let request_id = CALL_SEQUENCE.fetch_add(1, SeqCst);
        let cmd = match Self::build_request(request_id, msg) {
            Ok(cmd) => cmd,
            Err(err) => return ActorResponse::reply(Err(err.into())),
        };

        let net = self.net.clone();
        let trigger = self
            .requests
            .entry(request_id)
            .or_insert_with(TriggerFut::default)
            .clone();
        let mut trigger_err = trigger.clone();

        let fut = async move {
            net.send(cmd).await??;
            let raw = trigger.await?;
            match deser::<_, Result<Vec<u8>, String>>(raw.as_slice())? {
                Ok(vec) => Ok(vec),
                Err(err) => Err(ProtocolError::Call(err).into()),
            }
        }
        .map_err(move |e: Error| {
            trigger_err.ready(Err(e.clone()));
            e
        });

        ActorResponse::r#async(fut.into_actor(self))
    }
}

struct ServiceBusHandler<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    proto: Addr<ServiceBusProtocol<Key>>,
    net: Recipient<SendCmd<Key>>,
    dht: Recipient<DhtCmd<Key>>,
}

impl<Key> RawHandler for ServiceBusHandler<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = LocalBoxFuture<'static, std::result::Result<Vec<u8>, ya_service_bus::Error>>;

    fn handle(&mut self, caller: &str, addr: &str, msg: &[u8]) -> Self::Result {
        let parsed = match parse_addr(addr) {
            Ok(res) => res,
            Err(err) => return async move { Err(gsb_error(err)) }.boxed_local(),
        };

        let caller = caller.to_string();
        let body = msg.to_vec();
        let net = self.net.clone();

        match parsed {
            ParsedAddr::Broadcast => {
                let cmd = SendCmd::Broadcast {
                    from: None,
                    packet: Packet {
                        guarantees: Guarantees::unordered(),
                        payload: Payload::new(ServiceBusProtocol::<Key>::PROTOCOL_ID)
                            .with_payload(msg.to_vec())
                            .with_signature(),
                    },
                };

                async move {
                    net.send(cmd).await??;
                    Ok(Vec::new())
                }
                .map_err(|e: Error| gsb_error(e))
                .boxed_local()
            }
            ParsedAddr::Unicast(callee, addr) => {
                let proto = self.proto.clone();
                let dht = self.dht.clone();

                async move {
                    let dht_key = hex::decode(&callee[2..]).map_err(|e| {
                        Error::from(ProtocolError::Call(format!("Invalid address: {}", callee)))
                    })?;
                    let dht_value = match dht.send(DhtCmd::ResolveValue(dht_key)).await?? {
                        DhtResponse::Value(vec) => {
                            Key::try_from(vec).map_err(|_| CryptoError::InvalidKey)?
                        }
                        _ => return Err(Error::from(DiscoveryError::NotFound)),
                    };

                    let msg = Unicast {
                        caller,
                        callee,
                        addr,
                        body,
                        node_key: dht_value,
                    };
                    proto.send(msg).await?
                }
                .map_err(gsb_error)
                .boxed_local()
            }
        }
    }
}

fn parse_addr(src: &str) -> Result<ParsedAddr, Error> {
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

#[inline]
fn gsb_error(err: impl ToString) -> ya_service_bus::Error {
    ya_service_bus::Error::GsbBadRequest(err.to_string())
}

enum ParsedAddr {
    Unicast(String, String),
    Broadcast,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum NetRpcMessage {
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
