use crate::common::FlattenResult;
use crate::error::{Error, NetworkError, SessionError};
use crate::event::*;
use crate::packet::Packet;
use crate::protocol::{Protocol, ProtocolId};
use crate::session::Session;
use crate::transport::connection::{ConnectionManager, PendingConnection};
use crate::transport::{Address, Transport, TransportId};
use crate::Result;
use actix::prelude::*;
use futures::{Future, FutureExt, StreamExt, TryFutureExt};
use hashbrown::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;
use std::net::SocketAddr;
use std::time::Duration;

pub trait NetAddrExt<Key>
where
    Key: Send + Debug + Clone,
{
    fn add_processor<A>(&self, actor: A) -> Recipient<ProcessCmd<Key>>
    where
        A: Actor<Context = Context<A>> + Handler<ProcessCmd<Key>>;

    fn add_transport<A>(&self, actor: A) -> Recipient<TransportCmd>
    where
        A: Transport;

    fn add_protocol<A>(&self, actor: A) -> Recipient<ProtocolCmd<Key>>
    where
        A: Protocol<Key>;

    fn set_dht<A>(&self, actor: A) -> Recipient<DhtCmd<Key>>
    where
        A: Protocol<Key> + Handler<DhtCmd<Key>>;

    fn set_session<A>(&self, actor: A) -> Recipient<SessionCmd<Key>>
    where
        A: Protocol<Key> + Handler<SessionCmd<Key>>;
}

#[derive(Clone, Debug)]
pub struct NetConfig {
    connection_timeout: Duration,
    session_timeout: Duration,
    session_heartbeat_interval: Duration,
    upkeep_interval: Duration,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            connection_timeout: Duration::from_secs(5),
            session_timeout: Duration::from_secs(5),
            session_heartbeat_interval: Duration::from_secs(2),
            upkeep_interval: Duration::from_secs(2),
        }
    }
}

#[derive(Debug)]
pub struct Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq,
{
    conf: NetConfig,
    addresses: HashSet<SocketAddr>,

    transports: HashMap<TransportId, Recipient<TransportCmd>>,
    protocols: HashMap<ProtocolId, Recipient<ProtocolCmd<Key>>>,
    processors: Vec<Recipient<ProcessCmd<Key>>>,

    session_protocol: Option<Recipient<SessionCmd<Key>>>,
    dht_protocol: Option<Recipient<DhtCmd<Key>>>,

    connections: ConnectionManager<Key>,
    sessions: HashMap<Key, Session<Key>>,
}

impl<Key> Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + 'static,
{
    pub fn new(addresses: Vec<SocketAddr>) -> Self {
        Self::with_config(addresses, NetConfig::default())
    }

    pub fn with_config(addresses: Vec<SocketAddr>, conf: NetConfig) -> Self {
        Net {
            conf,
            addresses: HashSet::from_iter(addresses.into_iter()),
            transports: HashMap::new(),
            protocols: HashMap::new(),
            processors: Vec::new(),
            session_protocol: None,
            dht_protocol: None,
            connections: ConnectionManager::default(),
            sessions: HashMap::new(),
        }
    }
}

impl<Key> Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + 'static,
{
    fn session(
        &mut self,
        key: Key,
        actor: Addr<Self>,
    ) -> impl Future<Output = Result<Session<Key>>> {
        if let Some(session) = self.sessions.get(&key).cloned() {
            return async move { Ok(session.await?) }.left_future();
        }

        let mut session = self
            .sessions
            .entry(key.clone())
            .or_insert(Session::new(key.clone()))
            .clone();

        let dht = self.dht_protocol.clone();
        let proto = self.session_protocol.clone();

        async move {
            let dht = dht.ok_or_else(|| Error::protocol("No discovery protocol"))?;
            let proto = proto.ok_or_else(|| Error::protocol("No session protocol"))?;
            let addresses = dht
                .send(DhtCmd::ResolveNode(key.clone()))
                .await??
                .into_addresses()?;
            let conns = actor.send(internal::Connect::new(addresses)).await??;

            session
                .add_future_connection(conns, |conn| {
                    proto
                        .send(SessionCmd::Initiate(conn.address))
                        .map(|r| r.flatten_result())
                })
                .await?;

            Ok(session.await?)
        }
        .right_future()
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        self.connections.prune_pending(self.conf.connection_timeout);
    }
}

impl<Key> Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + 'static,
{
    #[inline]
    fn process_outbound<'a>(
        &self,
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    ) -> impl Future<Output = Result<Packet>> + 'a {
        let iter = self.processors.clone().into_iter();
        futures::stream::iter(iter)
            .map(move |recipient| (recipient, from.clone(), to.clone()))
            .fold(Ok(packet), move |res, (recipient, from, to)| async move {
                match res {
                    Ok(packet) => recipient
                        .send(ProcessCmd::Outbound { from, to, packet })
                        .await
                        .flatten_result(),
                    err => err,
                }
            })
    }

    #[inline]
    fn process_inbound<'a>(
        &self,
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    ) -> impl Future<Output = Result<Packet>> + 'a {
        let iter = self.processors.clone().into_iter().rev();
        futures::stream::iter(iter)
            .map(move |recipient| (recipient, from.clone(), to.clone()))
            .fold(Ok(packet), move |res, (recipient, from, to)| async move {
                match res {
                    Ok(packet) => recipient
                        .send(ProcessCmd::Inbound { from, to, packet })
                        .await
                        .flatten_result(),
                    err => err,
                }
            })
    }
}

impl<Key> Actor for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.upkeep_interval, Self::upkeep)
            .finish()
            .spawn(ctx);

        log::info!("Net service started: {:?}", self.addresses);
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("Net service stopped");
    }
}

impl<Key> Handler<ServiceCmd<Key>> for Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: ServiceCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match evt {
            ServiceCmd::SetSessionProtocol(recipient) => {
                self.session_protocol.replace(recipient);
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::SetDhtProtocol(recipient) => {
                self.dht_protocol.replace(recipient);
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::AddTransport(transport_id, recipient) => {
                let actor = ctx.address();
                let addresses = self.addresses.iter().cloned().collect();

                let fut = async move {
                    recipient.send(TransportCmd::Bind(addresses)).await??;
                    actor
                        .send(internal::AddTransport(transport_id, recipient))
                        .await?;
                    // TODO: update DHT addresses
                    Ok(())
                };
                ActorResponse::r#async(fut.into_actor(self))
            }
            ServiceCmd::RemoveTransport(transport_id) => {
                let actor = ctx.address();
                let recipient = match self.transports.get(&transport_id) {
                    Some(recipient) => recipient.clone(),
                    None => {
                        return ActorResponse::reply(Err(NetworkError::UnknownTransport(
                            transport_id,
                        )
                        .into()))
                    }
                };

                let fut = async move {
                    recipient.send(TransportCmd::Shutdown).await??;
                    actor.send(internal::RemoveTransport(transport_id)).await?;
                    // TODO: update DHT addresses
                    Ok(())
                };
                ActorResponse::r#async(fut.into_actor(self))
            }
            ServiceCmd::AddProtocol(protocol_id, recipient) => {
                self.protocols.insert(protocol_id, recipient);
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::RemoveProtocol(protocol_id) => {
                let result = match self.protocols.remove(&protocol_id) {
                    Some(_) => Ok(()),
                    _ => Err(NetworkError::UnknownProtocol(protocol_id).into()),
                };
                ActorResponse::reply(result)
            }
            ServiceCmd::AddProcessor(recipient) => {
                self.processors.push(recipient);
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::RemoveProcessor(recipient) => {
                if let Some(idx) = self.processors.iter().position(|r| r == &recipient) {
                    self.processors.remove(idx);
                }
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::Shutdown => {
                log::info!("Shutting down...");

                let actor = ctx.address();

                std::mem::replace(&mut self.connections, ConnectionManager::default());
                std::mem::replace(&mut self.sessions, HashMap::new())
                    .into_iter()
                    .for_each(|(_, mut s)| s.terminate());

                let protocols_fut = std::mem::replace(&mut self.protocols, HashMap::new())
                    .into_iter()
                    .map(|(_, v)| v.send(ProtocolCmd::Shutdown));
                let transports_fut = std::mem::replace(&mut self.transports, HashMap::new())
                    .into_iter()
                    .map(|(_, v)| v.send(TransportCmd::Shutdown));

                let fut = async move {
                    futures::future::join_all(protocols_fut).await;
                    futures::future::join_all(transports_fut).await;

                    actor.send(internal::Shutdown).await?;
                    Ok(())
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<Key> Handler<SendCmd<Key>> for Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: SendCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match evt {
            SendCmd::Roaming {
                from,
                mut to,
                packet,
            } => {
                log::debug!("Send roaming message to: {:?}", to);

                let conn = match to.transport_id {
                    Address::ANY_TRANSPORT => {
                        let keys = self.transports.keys();
                        keys.filter_map(|id| {
                            to.transport_id = *id;
                            self.connections.get(&to)
                        })
                        .next()
                    }
                    _ => self.connections.get(&to),
                };

                let fut = match conn {
                    Some(conn) => {
                        let mut conn = conn.clone();
                        let process_fut = self.process_outbound(from, None, packet);

                        async move {
                            let packet = process_fut.await?;
                            conn.send(packet).await?;
                            Ok(())
                        }
                        .left_future()
                    }
                    None => {
                        let actor = ctx.address();
                        let addresses = vec![to.clone()];

                        async move {
                            let conns = actor.send(internal::Connect::new(addresses)).await??;
                            let conn = futures::future::select_ok(conns.into_iter()).await?.0;
                            actor
                                .send(SendCmd::Roaming {
                                    from,
                                    to: conn.address,
                                    packet,
                                })
                                .await?
                        }
                        .right_future()
                    }
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            SendCmd::Session { from, to, packet } => {
                log::debug!("Send session message to: {:?}", to);

                let actor = ctx.address();
                let fut = async move { actor.send(internal::Send { from, to, packet }).await? };

                ActorResponse::r#async(fut.into_actor(self))
            }
            SendCmd::Broadcast { from, packet } => {
                if self.sessions.is_empty() {
                    return ActorResponse::reply(Err(NetworkError::NoConnection.into()));
                }

                let actor = ctx.address();
                let futs = self
                    .sessions
                    .values()
                    .map(|s| {
                        actor.send(internal::Send {
                            from: from.clone(),
                            to: s.key(),
                            packet: packet.clone(),
                        })
                    })
                    .collect::<Vec<_>>();

                Arbiter::spawn(async move {
                    let _ = futures::future::join_all(futs.into_iter()).await;
                });
                ActorResponse::reply(Ok(()))
            }
            SendCmd::Disconnect(key, reason) => {
                if !self.sessions.contains_key(&key) {
                    return ActorResponse::reply(Ok(()));
                }

                let protocol = self.session_protocol.clone();
                let fut = async move {
                    if let Some(protocol) = protocol {
                        protocol
                            .send(SessionCmd::Disconnect(key.clone(), reason))
                            .await??;
                    }
                    Ok(())
                };
                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<Key> Handler<TransportEvt> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    type Result = ();

    fn handle(&mut self, msg: TransportEvt, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            TransportEvt::Connected(address, channel) => {
                log::debug!("Connected to {:?}", address);
                self.connections.connected(address, channel);
            }
            TransportEvt::Disconnected(address, reason) => {
                log::debug!("Disconnected from {:?}: {:?}", address, reason);
                if let Some(conn) = self.connections.disconnected(&address) {
                    if let Some(key) = conn.ctx() {
                        if let Some(session) = self.sessions.get_mut(&key) {
                            session.remove_connection(&conn);
                            if !session.is_alive() {
                                self.sessions.remove(&key);
                            }
                        }
                    }
                }
            }
            TransportEvt::Packet(address, packet) => {
                if packet.message.len() == 0 {
                    log::trace!("Received an empty packet");
                    return;
                }

                let packet = match packet.try_decode() {
                    Ok(packet) => packet,
                    Err(err) => {
                        log::warn!("Error decoding packet: {:?}", err);
                        return;
                    }
                };
                let key = self.connections.get(&address).map(|c| c.ctx()).flatten();
                let protocol_id = packet.payload.protocol_id();
                let protocol = match self.protocols.get(&protocol_id).cloned() {
                    Some(protocol) => protocol,
                    _ => {
                        log::error!(
                            "Unknown protocol {} (address: {:?}, key: {:?})",
                            protocol_id,
                            address,
                            key
                        );
                        return;
                    }
                };

                let process_fut = self.process_inbound(key.clone(), None, packet);
                let fut = async move {
                    let packet = process_fut.await?;
                    let command = match key {
                        Some(key) => ProtocolCmd::SessionPacket(address, packet, key),
                        None => ProtocolCmd::RoamingPacket(address, packet),
                    };

                    log::debug!("Protocol {} message ({:?})", protocol_id, address,);
                    protocol.send(command).await??;
                    Ok(())
                }
                .map_err(|e: Error| log::error!("Packet handler error: {}", e))
                .map(|_| ());

                ctx.spawn(fut.into_actor(self));
            }
        }
    }
}

impl<Key> Handler<SessionEvt<Key>> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    type Result = ();

    fn handle(&mut self, evt: SessionEvt<Key>, _: &mut Context<Self>) -> Self::Result {
        match evt {
            SessionEvt::Established(address, key) => match self.connections.get(&address) {
                Some(conn) => {
                    self.sessions
                        .entry(key.clone())
                        .or_insert_with(|| Session::new(key))
                        .add_connection(conn.clone());
                }
                _ => {
                    log::warn!(
                        "Connection to {:?} (key: {:?}) no longer exists",
                        address,
                        key
                    );
                }
            },
            SessionEvt::Disconnected(key) => {
                match self.sessions.remove(&key) {
                    Some(mut session) => {
                        session.addresses().into_iter().for_each(|a| {
                            self.connections.disconnected(&a);
                        });
                        session.terminate();
                    }
                    None => return,
                };
            }
        }
    }
}

impl<Key> Handler<internal::Connect<Key>> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    type Result = <internal::Connect<Key> as Message>::Result;

    fn handle(&mut self, evt: internal::Connect<Key>, ctx: &mut Context<Self>) -> Self::Result {
        let mut addresses = Vec::new();
        let mut triggers = Vec::new();
        let mut futs = Vec::new();

        evt.addresses
            .into_iter()
            .for_each(|addr| match addr.transport_id {
                Address::ANY_TRANSPORT => addresses.extend(
                    self.transports
                        .keys()
                        .map(|id| Address::new(*id, addr.socket_addr)),
                ),
                _ => addresses.push(addr),
            });

        log::debug!("Connecting to addresses: {:?}", addresses);

        addresses.into_iter().for_each(|address| {
            if let Some(recipient) = self.transports.get(&address.transport_id) {
                let pending = self.connections.pending(address);
                if let PendingConnection::New(_) = &pending {
                    log::debug!("Connecting to {:?}", address);
                    futs.push(recipient.send(TransportCmd::Connect(address.socket_addr)));
                }
                triggers.push(pending.into());
            };
        });

        match triggers.is_empty() {
            true => Err(NetworkError::NoAddress.into()),
            false => {
                if !futs.is_empty() {
                    ctx.spawn(futures::future::join_all(futs).map(|_| ()).into_actor(self));
                }
                Ok(triggers)
            }
        }
    }
}

impl<Key> Handler<internal::Send<Key>> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: internal::Send<Key>, ctx: &mut Context<Self>) -> Self::Result {
        let session_fut = self.session(evt.to.clone(), ctx.address());
        let process_fut = self.process_outbound(evt.from, Some(evt.to), evt.packet);
        let timeout = self.conf.session_timeout;

        ActorResponse::r#async(
            async move {
                let packet = process_fut.await?;
                tokio::time::timeout(timeout, session_fut)
                    .await
                    .map_err(|_| Error::from(SessionError::Timeout))??
                    .send(packet)
                    .await
                    .map(|_| Ok(()))?
            }
            .into_actor(self),
        )
    }
}

impl<Key> NetAddrExt<Key> for Addr<Net<Key>>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    fn add_processor<A>(&self, actor: A) -> Recipient<ProcessCmd<Key>>
    where
        A: Actor<Context = Context<A>> + Handler<ProcessCmd<Key>>,
    {
        let recipient = actor.start().recipient();
        self.do_send(ServiceCmd::AddProcessor(recipient.clone()));
        recipient
    }

    fn add_transport<A>(&self, actor: A) -> Recipient<TransportCmd>
    where
        A: Transport,
    {
        {
            let recipient = actor.start().recipient();
            self.do_send(ServiceCmd::AddTransport(A::TRANSPORT_ID, recipient.clone()));
            recipient
        }
    }

    fn add_protocol<A>(&self, actor: A) -> Recipient<ProtocolCmd<Key>>
    where
        A: Protocol<Key>,
    {
        let recipient = actor.start().recipient();
        self.do_send(ServiceCmd::AddProtocol(A::PROTOCOL_ID, recipient.clone()));
        recipient
    }

    fn set_dht<A>(&self, actor: A) -> Recipient<DhtCmd<Key>>
    where
        A: Protocol<Key> + Handler<DhtCmd<Key>>,
    {
        {
            let addr = actor.start();
            self.do_send(ServiceCmd::SetDhtProtocol(addr.clone().recipient()));
            self.do_send(ServiceCmd::AddProtocol(
                A::PROTOCOL_ID,
                addr.clone().recipient(),
            ));
            addr.recipient()
        }
    }

    fn set_session<A>(&self, actor: A) -> Recipient<SessionCmd<Key>>
    where
        A: Protocol<Key> + Handler<SessionCmd<Key>>,
    {
        {
            let addr = actor.start();
            self.do_send(ServiceCmd::SetSessionProtocol(addr.clone().recipient()));
            self.do_send(ServiceCmd::AddProtocol(
                A::PROTOCOL_ID,
                addr.clone().recipient(),
            ));
            addr.recipient()
        }
    }
}

macro_rules! impl_internal_handler {
    ($msg:ty, ($self:ident, $evt:ident, $ctx:ident) $impl:block) => {
        impl<Key> Handler<$msg> for Net<Key>
        where
            Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
        {
            type Result = <$msg as actix::Message>::Result;

            fn handle(&mut $self, $evt: $msg, $ctx: &mut Context<Self>) -> Self::Result $impl
        }
    };
}

impl_internal_handler!(internal::Shutdown, (self, _evt, ctx) {
    ctx.stop();
});

impl_internal_handler!(internal::AddTransport, (self, evt, _ctx) {
    let (transport_id, recipient) = (evt.0, evt.1);
    self.transports.insert(transport_id, recipient);
});

impl_internal_handler!(internal::RemoveTransport, (self, evt, _ctx) {
    let transport_id = evt.0;
    self.transports.remove(&transport_id);
});

mod internal {
    use crate::event::TransportCmd;
    use crate::packet::Packet;
    use crate::transport::connection::ConnectionFut;
    use crate::transport::Address;
    use crate::{Result, TransportId};
    use actix::prelude::*;
    use serde::export::PhantomData;
    use std::fmt::Debug;

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct AddTransport(pub TransportId, pub Recipient<TransportCmd>);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct RemoveTransport(pub TransportId);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct Shutdown;

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "Result<Vec<ConnectionFut<Key>>>")]
    pub struct Connect<Key: Clone + Debug + 'static> {
        pub addresses: Vec<Address>,
        phantom: PhantomData<Key>,
    }

    impl<Key: Clone + Debug + 'static> Connect<Key> {
        pub fn new(addresses: Vec<Address>) -> Self {
            Connect {
                addresses,
                phantom: PhantomData,
            }
        }
    }

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "Result<()>")]
    pub struct Send<Key: Clone + Debug + 'static> {
        pub from: Option<Key>,
        pub to: Key,
        pub packet: Packet,
    }
}
