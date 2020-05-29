use crate::common::{FlattenResult, TriggerFut};
use crate::error::{CryptoError, DiscoveryError, Error, ProtocolError, SessionError};
use crate::event::{ProtocolCmd, SendCmd};
use crate::identity::Identity;
use crate::packet::{Guarantees, Packet, Payload};
use crate::protocol::{Protocol, ProtocolId, ProtocolVersion};
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
use ya_service_bus::untyped::{subscribe, RawHandler};
use ya_service_bus::{Handle, RpcRawCall};

static CALL_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
type RequestFut = TriggerFut<Result<Vec<u8>, Error>>;

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
    Key: Send + 'static,
{
    conf: ProtocolConfig,
    net: Recipient<SendCmd<Key>>,
    requests: RequestMap,
    handle: Option<Handle>,
}

impl<Key> ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    pub fn new<R>(net: &R) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
    {
        Self::with_config(net, ProtocolConfig::default())
    }

    pub fn with_config<R>(net: &R, conf: ProtocolConfig) -> Self
    where
        R: Into<Recipient<SendCmd<Key>>> + Clone,
    {
        Self {
            conf,
            net: net.clone().into(),
            requests: RequestMap::default(),
            handle: None,
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        self.requests.remove_finished()
    }
}

impl<Key> Protocol for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    const ID: ProtocolId = 8005;
    const VERSION: ProtocolVersion = 0;
}

impl<Key> ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    fn handle_rpc_message<'a>(
        &mut self,
        from: Identity,
        to: Identity,
        packet: Packet,
    ) -> LocalBoxFuture<'a, Result<(), Error>> {
        let msg: internal::Message = match packet.payload.decode_body() {
            Ok(msg) => msg,
            Err(err) => return futures::future::err(err).boxed_local(),
        };

        match msg {
            internal::Message::Request {
                request_id,
                addr,
                body,
            } => {
                let net = self.net.clone();
                async move {
                    let result = router_send(addr, from.to_string(), body)
                        .await
                        .map_err(|e| e.to_string());
                    let msg = internal::Message::Response {
                        request_id,
                        body: ser(&result)?,
                    };
                    let response = SendCmd::Session {
                        from: to,
                        to: from,
                        packet: Packet::try_unordered::<Self, _>(&msg)?,
                    };
                    net.send(response).await??;
                    Ok(())
                }
                .boxed_local()
            }
            internal::Message::Response { request_id, body } => {
                match self.requests.get_mut(&request_id) {
                    Some((callee, trigger)) => {
                        if *callee != from {
                            return futures::future::err(Error::protocol(
                                "invalid callee in rpc response",
                            ))
                            .boxed_local();
                        }
                        trigger.ready(Ok(body));
                        self.requests.remove(&request_id);
                    }
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
            },
        ));

        log::info!("GSB-net protocol started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("GSB-net protocol stopped");
    }
}

impl<Key> Handler<ProtocolCmd> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::SessionPacket {
                from,
                to,
                address,
                packet,
            } => {
                let fut = self.handle_rpc_message(from, to, packet);
                ActorResponse::r#async(fut.into_actor(self))
            }
            ProtocolCmd::RoamingPacket {
                address: _,
                packet: _,
            } => {
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

impl<Key> Handler<internal::Call> for ServiceBusProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = ActorResponse<Self, Vec<u8>, Error>;

    fn handle(&mut self, mut msg: internal::Call, _ctx: &mut Self::Context) -> Self::Result {
        let request_id = CALL_SEQUENCE.fetch_add(1, SeqCst);
        let callee = msg.callee.clone();

        let trigger = self.requests.new_entry(request_id, callee);
        let mut trigger_err = trigger.clone();

        let net = self.net.clone();
        let fut = async move {
            let request = internal::Message::Request {
                request_id,
                addr: msg.addr,
                body: msg.body,
            };
            let packet = Packet::try_unordered::<Self, _>(&request)?;
            net.send(SendCmd::Session {
                from: msg.caller,
                to: msg.callee,
                packet,
            })
            .await??;

            let response = trigger.await?;
            match deser::<_, Result<Vec<u8>, String>>(response.as_slice())? {
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
}

impl<Key> RawHandler for ServiceBusHandler<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + TryFrom<Vec<u8>> + 'static,
{
    type Result = LocalBoxFuture<'static, std::result::Result<Vec<u8>, ya_service_bus::Error>>;

    fn handle(&mut self, caller: &str, addr: &str, msg: &[u8]) -> Self::Result {
        let parsed = match ServiceBusAddr::try_from(addr) {
            Ok(res) => res,
            Err(err) => return async move { Err::<Vec<u8>, _>(gsb_error(err)) }.boxed_local(),
        };

        let caller = caller.to_owned();
        let body = msg.to_owned();

        match parsed {
            ServiceBusAddr::Unicast { callee, addr } => {
                let proto = self.proto.clone();
                async move {
                    proto
                        .send(internal::Call {
                            caller: caller.parse()?,
                            callee: callee.parse()?,
                            addr,
                            body,
                        })
                        .await?
                }
                .map_err(|e: Error| gsb_error(e))
                .boxed_local()
            }
            ServiceBusAddr::Broadcast { ttl: _, addr: _ } => {
                let send = self.net.send(SendCmd::Broadcast {
                    packet: Packet::unordered::<ServiceBusProtocol<Key>>(body),
                });
                async move { send.await?.map(|_| Vec::new()) }
                    .map_err(|e: Error| gsb_error(e))
                    .boxed_local()
            }
        }
    }
}

#[inline]
fn rpc_error(err: impl ToString) -> Error {
    ProtocolError::Call(err.to_string()).into()
}

#[inline]
fn gsb_error(err: impl ToString) -> ya_service_bus::Error {
    ya_service_bus::Error::GsbBadRequest(err.to_string())
}

#[inline(always)]
fn router_send<'s, S: AsRef<str>, D: AsRef<[u8]>>(
    addr: S,
    from: S,
    bytes: D,
) -> impl Future<Output = Result<Vec<u8>, ya_service_bus::Error>> + Unpin + 's {
    ya_service_bus::untyped::send(addr.as_ref(), from.as_ref(), bytes.as_ref())
}

struct RequestMap {
    inner: HashMap<usize, (Identity, RequestFut)>,
}

impl RequestMap {
    fn new_entry(&mut self, request_id: usize, callee: Identity) -> RequestFut {
        self.inner
            .entry(request_id)
            .or_insert_with(|| (callee, RequestFut::default()))
            .1
            .clone()
    }

    #[inline]
    fn get_mut(&mut self, request_id: &usize) -> Option<&mut (Identity, RequestFut)> {
        self.inner.get_mut(&request_id)
    }

    #[inline]
    fn remove(&mut self, request_id: &usize) -> Option<(Identity, RequestFut)> {
        self.inner.remove(&request_id)
    }

    #[inline]
    fn remove_finished(&mut self) {
        self.inner.retain(|_, (_, t)| t.is_pending());
    }
}

impl Default for RequestMap {
    fn default() -> Self {
        RequestMap {
            inner: HashMap::new(),
        }
    }
}

enum ServiceBusAddr {
    Unicast { callee: String, addr: String },
    Broadcast { ttl: u8, addr: String },
}

impl TryFrom<&str> for ServiceBusAddr {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let split: Vec<_> = value.splitn(4, '/').collect();
        if split.len() < 4 {
            return Err(Error::Service(format!("Invalid address: {}", value)));
        }

        let addr = format!("/public/{}", split[3]);
        let callee = split[2];

        if callee.starts_with("broadcast") {
            let broadcast: Vec<_> = callee.splitn(2, ':').collect();
            let ttl: u8 = match broadcast.get(1) {
                Some(s) => s
                    .parse()
                    .map_err(|_| Error::Service(format!("Invalid address: {}", value)))?,
                _ => 1,
            };
            Ok(ServiceBusAddr::Broadcast { ttl, addr })
        } else {
            let callee = callee.to_string();
            Ok(ServiceBusAddr::Unicast { callee, addr })
        }
    }
}

mod internal {
    use crate::identity::Identity;
    use crate::Result;
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(super) enum Message {
        Request {
            request_id: usize,
            addr: String,
            body: Vec<u8>,
        },
        Response {
            request_id: usize,
            body: Vec<u8>,
        },
    }

    #[derive(Clone, Debug, actix::Message, Serialize, Deserialize)]
    #[rtype(result = "Result<Vec<u8>>")]
    pub(super) struct Call {
        pub caller: Identity,
        pub callee: Identity,
        pub addr: String,
        pub body: Vec<u8>,
    }
}
