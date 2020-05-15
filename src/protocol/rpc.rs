use crate::common::{FlattenResult, TriggerFut};
use crate::error::{Error, SessionError};
use crate::event::{ProtocolCmd, SendCmd};
use crate::packet::{Guarantees, Packet, Payload};
use crate::protocol::ProtocolId;
use crate::serialize::{from_read as deser, to_vec as ser};
use actix::prelude::*;
use futures::future::LocalBoxFuture;
use futures::{FutureExt, TryFutureExt};
use hashbrown::HashMap;
use serde::export::PhantomData;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use ya_service_bus::{RpcEnvelope, RpcMessage};

// Temporary convenience trait
pub trait NetRpc<Key> {
    fn bind<'f, M>(
        &self,
        endpoint: impl ToString,
        recipient: Recipient<RpcEnvelope<M>>,
    ) -> LocalBoxFuture<'f, Result<(), Error>>
    where
        M: RpcMessage;

    fn bind_fn<'f, M, F>(
        &self,
        endpoint: impl ToString,
        f: F,
    ) -> LocalBoxFuture<'f, Result<(), Error>>
    where
        M: RpcMessage,
        F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>>
            + Send
            + 'static;

    fn rpc<'f, M, Id>(
        &self,
        endpoint: impl ToString,
        from: Id,
        to: Key,
        message: M,
        timeout_secs: f64,
    ) -> LocalBoxFuture<'f, Result<M::Item, NetRpcError>>
    where
        M: RpcMessage,
        Id: Clone + Debug + ToString + Send + 'static;
}

impl<Key> NetRpc<Key> for Addr<NetRpcProtocol<Key>>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
{
    #[inline]
    fn bind<'f, M>(
        &self,
        endpoint: impl ToString,
        recipient: Recipient<RpcEnvelope<M>>,
    ) -> LocalBoxFuture<'f, Result<(), Error>>
    where
        M: RpcMessage,
    {
        self.send(Bind {
            endpoint: endpoint.to_string(),
            recipient,
        })
        .map_err(Error::from)
        .boxed_local()
    }

    #[inline]
    fn bind_fn<'f, M, F>(
        &self,
        endpoint: impl ToString,
        f: F,
    ) -> LocalBoxFuture<'f, Result<(), Error>>
    where
        M: RpcMessage,
        F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>>
            + Send
            + 'static,
    {
        self.send(BindFn::new(endpoint, f))
            .map_err(Error::from)
            .boxed_local()
    }

    #[inline]
    fn rpc<'f, M, Id>(
        &self,
        endpoint: impl ToString,
        from: Id,
        to: Key,
        message: M,
        timeout_secs: f64,
    ) -> LocalBoxFuture<'f, Result<M::Item, NetRpcError>>
    where
        M: RpcMessage,
        Id: Clone + Debug + ToString + Send + 'static,
    {
        self.send(Rpc {
            endpoint: endpoint.to_string(),
            from,
            to,
            message,
            timeout_secs,
        })
        .map(|x| x.flatten_result())
        .boxed_local()
    }
}

pub struct ProtocolConfig {
    upkeep_interval: Duration,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            upkeep_interval: Duration::from_secs(2),
        }
    }
}
pub struct NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
{
    conf: ProtocolConfig,
    net: Recipient<SendCmd<Key>>,
    handlers: HashMap<String, Box<dyn NetRpcHandler>>,
    requests: Ledger<TriggerFut<Vec<u8>>>,
    responses: Ledger<TriggerFut<Vec<u8>>>,
}

impl<Key> NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
{
    pub const PROTOCOL_ID: ProtocolId = 1001;

    pub fn new(net: Recipient<SendCmd<Key>>) -> Self {
        Self::with_config(net, ProtocolConfig::default())
    }

    pub fn with_config(net: Recipient<SendCmd<Key>>, conf: ProtocolConfig) -> Self {
        Self {
            conf,
            net,
            handlers: HashMap::new(),
            requests: Ledger::default(),
            responses: Ledger::default(),
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        let now = Instant::now();
        self.requests.remove_elapsed(&now);
        self.responses.remove_elapsed(&now);
    }
}

impl<Key> NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
{
    fn response_cmd(to: Key, request_id: usize, payload: Vec<u8>) -> Result<SendCmd<Key>, Error> {
        let response = NetRpcMessage::Response {
            request_id,
            payload,
        };
        let packet = Packet {
            guarantees: Guarantees::unordered(),
            payload: Payload::new(Self::PROTOCOL_ID).encode_payload(&response)?,
        };
        let cmd = SendCmd::Session {
            from: None, // FIXME
            to,
            packet,
        };
        Ok(cmd)
    }
}

impl<Key> Actor for NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.upkeep_interval, Self::upkeep)
            .finish()
            .spawn(ctx);

        log::info!("RPC protocol started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("RPC protocol stopped");
    }
}

impl<Key> Handler<ProtocolCmd<Key>> for NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::SessionPacket(_, packet, key) => {
                // TODO: decrypt, verify signatures, etc.
                let msg: NetRpcMessage = match packet.payload.decode_payload() {
                    Ok(msg) => msg,
                    Err(err) => return ActorResponse::reply(Err(err.into())),
                };

                match msg {
                    NetRpcMessage::Request {
                        request_id,
                        endpoint,
                        payload,
                        from,
                        timeout_secs,
                    } => {
                        let net = self.net.clone();
                        let fut = match self.handlers.get_mut(&endpoint) {
                            Some(handler) => {
                                let duration = Duration::from_secs_f64(timeout_secs);
                                let handle_fut = handler.handle_rpc(payload, from);

                                async move {
                                    let response =
                                        timeout(duration, handle_fut).await.flatten_result();
                                    let payload = ser(&response)?;
                                    let cmd = Self::response_cmd(key, request_id, payload)?;

                                    net.send(cmd).await??;
                                    Ok(())
                                }
                                .left_future()
                            }
                            None => async move {
                                let response = Err::<Vec<u8>, _>(NetRpcError::Endpoint);
                                let payload = ser(&response)?;
                                let cmd = Self::response_cmd(key, request_id, payload)?;

                                net.send(cmd).await??;
                                Ok(())
                            }
                            .right_future(),
                        };

                        ActorResponse::r#async(fut.into_actor(self))
                    }
                    NetRpcMessage::Response {
                        request_id,
                        payload,
                    } => {
                        match self.requests.remove(&request_id) {
                            Some(mut request) => request.ready(payload),
                            None => log::warn!("Unknown request id: {}", request_id),
                        }

                        ActorResponse::reply(Ok(()))
                    }
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

impl<Id, Key, M> Handler<Rpc<Key, Id, M>> for NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
    M: RpcMessage,
    Id: Clone + Debug + Send + ToString,
{
    type Result = ActorResponse<Self, M::Item, NetRpcError>;

    fn handle(&mut self, msg: Rpc<Key, Id, M>, _: &mut Context<Self>) -> Self::Result {
        let seq = self.requests.next_seq();

        let message = match ser(&msg.message) {
            Ok(payload) => NetRpcMessage::Request {
                request_id: seq,
                endpoint: msg.endpoint,
                payload,
                from: msg.from.to_string(),
                timeout_secs: msg.timeout_secs,
            },
            Err(err) => return ActorResponse::reply(Err(err.into())),
        };
        let packet = match Payload::new(Self::PROTOCOL_ID).encode_payload(&message) {
            Ok(payload) => Packet {
                guarantees: Guarantees::unordered(),
                payload,
            },
            Err(err) => return ActorResponse::reply(Err(Error::from(err).into())),
        };
        let send_cmd = SendCmd::Session {
            from: None,
            to: msg.to,
            packet,
        };

        let duration = Duration::from_secs_f64(msg.timeout_secs);
        let trigger = TriggerFut::<Vec<u8>>::default();
        self.requests.insert(seq, trigger.clone(), duration);

        let net = self.net.clone();
        let fut = async move {
            net.send(send_cmd).await??;
            let raw = timeout(duration, trigger).await?;

            match deser::<_, Result<Vec<u8>, NetRpcError>>(raw.as_slice())? {
                Ok(inner) => Ok(deser::<_, M::Item>(inner.as_slice())?),
                Err(err) => Err(err),
            }
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<Key, M> Handler<Bind<M>> for NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
    M: RpcMessage,
{
    type Result = ();

    fn handle(&mut self, msg: Bind<M>, _: &mut Context<Self>) -> Self::Result {
        self.handlers.insert(msg.endpoint, Box::new(msg.recipient));
    }
}

impl<Key, M, F> Handler<BindFn<M, F>> for NetRpcProtocol<Key>
where
    Key: Hash + Eq + Clone + Debug + Unpin + Send + 'static,
    M: RpcMessage,
    F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>>,
{
    type Result = ();

    fn handle(&mut self, msg: BindFn<M, F>, _: &mut Context<Self>) -> Self::Result {
        self.handlers
            .insert(msg.endpoint, Box::new(NetRpcHandlerFn::new(msg.handler)));
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetRpcMessage {
    Request {
        request_id: usize,
        endpoint: String,
        payload: Vec<u8>,
        from: String,
        timeout_secs: f64,
    },
    Response {
        request_id: usize,
        payload: Vec<u8>,
    },
}

impl TryFrom<Vec<u8>> for NetRpcMessage {
    type Error = Error;

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        deser(value.as_slice())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetRpcError {
    Service(String),
    Rpc(Vec<u8>),
    Endpoint,
    Timeout,
}

impl NetRpcError {
    fn rpc<S: Serialize>(s: S) -> Self {
        match ser(&s) {
            Ok(vec) => NetRpcError::Rpc(vec),
            Err(err) => NetRpcError::Service(err.to_string()),
        }
    }
}

impl From<Error> for NetRpcError {
    fn from(e: Error) -> Self {
        NetRpcError::Service(e.to_string())
    }
}

impl From<actix::MailboxError> for NetRpcError {
    fn from(e: MailboxError) -> Self {
        NetRpcError::Service(e.to_string())
    }
}

impl From<tokio::time::Elapsed> for NetRpcError {
    fn from(_: tokio::time::Elapsed) -> Self {
        NetRpcError::Timeout
    }
}

trait NetRpcHandler {
    fn handle_rpc<'f>(
        &mut self,
        message: Vec<u8>,
        from: String,
    ) -> LocalBoxFuture<'f, Result<Vec<u8>, NetRpcError>>;
}

struct NetRpcHandlerFn<M, F>
where
    M: RpcMessage,
    F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>> + 'static,
{
    handler: Rc<Box<F>>,
    phantom: PhantomData<M>,
}

impl<M, F> NetRpcHandlerFn<M, F>
where
    M: RpcMessage,
    F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>> + 'static,
{
    pub fn new(f: Box<F>) -> Self {
        Self {
            handler: Rc::new(f),
            phantom: PhantomData,
        }
    }
}

impl<M, F> NetRpcHandler for NetRpcHandlerFn<M, F>
where
    M: RpcMessage,
    F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>> + 'static,
{
    fn handle_rpc<'f>(
        &mut self,
        payload: Vec<u8>,
        from: String,
    ) -> LocalBoxFuture<'f, Result<Vec<u8>, NetRpcError>> {
        let handler = self.handler.clone();

        async move {
            let message: M = deser(payload.as_slice()).map_err(Error::from)?;
            match handler(RpcEnvelope::with_caller(from, message)).await {
                Ok(reply) => Ok(ser(&reply)?),
                Err(error) => Err(NetRpcError::rpc(error)),
            }
        }
        .boxed_local()
    }
}

impl<M> NetRpcHandler for Recipient<RpcEnvelope<M>>
where
    M: RpcMessage,
{
    fn handle_rpc<'f>(
        &mut self,
        message: Vec<u8>,
        from: String,
    ) -> LocalBoxFuture<'f, Result<Vec<u8>, NetRpcError>> {
        let recipient = self.clone();

        async move {
            let message: M = deser(message.as_slice()).map_err(Error::from)?;
            match recipient
                .send(RpcEnvelope::with_caller(from, message))
                .await?
            {
                Ok(reply) => Ok(ser(&reply)?),
                Err(error) => Err(NetRpcError::rpc(error)),
            }
        }
        .boxed_local()
    }
}

#[derive(Message)]
#[rtype("Result<M::Item, NetRpcError>")]
pub struct Rpc<Key, Id, M: RpcMessage> {
    pub endpoint: String,
    pub from: Id,
    pub to: Key,
    pub message: M,
    pub timeout_secs: f64,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Bind<M>
where
    M: RpcMessage,
{
    pub endpoint: String,
    pub recipient: Recipient<RpcEnvelope<M>>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct BindFn<M, F>
where
    M: RpcMessage,
    F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>> + 'static,
{
    pub endpoint: String,
    pub handler: Box<F>,
    phantom: PhantomData<M>,
}

impl<M, F> BindFn<M, F>
where
    M: RpcMessage,
    F: Fn(RpcEnvelope<M>) -> LocalBoxFuture<'static, Result<M::Item, M::Error>> + 'static,
{
    fn new(endpoint: impl ToString, handler: F) -> Self {
        BindFn {
            endpoint: endpoint.to_string(),
            handler: Box::new(handler),
            phantom: PhantomData,
        }
    }
}

#[derive(Debug)]
struct Ledger<T> {
    calls: HashMap<usize, T>,
    active: HashMap<usize, Instant>,
    call_seq: AtomicUsize,
}

impl<T> Default for Ledger<T> {
    fn default() -> Self {
        Ledger {
            calls: HashMap::new(),
            active: HashMap::new(),
            call_seq: AtomicUsize::new(0),
        }
    }
}

impl<T> Ledger<T> {
    #[inline]
    fn next_seq(&self) -> usize {
        self.call_seq.fetch_add(1, SeqCst)
    }

    fn insert(&mut self, id: usize, value: T, duration: Duration) {
        self.calls.insert(id, value);
        self.active.insert(id, Instant::now() + duration);
    }

    fn remove(&mut self, id: &usize) -> Option<T> {
        self.active.remove(id);
        self.calls.remove(id)
    }

    fn remove_elapsed(&mut self, now: &Instant) {
        let mut active = std::mem::replace(&mut self.active, HashMap::new());
        active
            .drain_filter(|_, deadline| *deadline >= *now)
            .for_each(|(id, _)| {
                self.remove(&id);
            });
        std::mem::replace(&mut self.active, active);
    }
}
