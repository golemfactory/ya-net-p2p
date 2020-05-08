use crate::common::{FlattenResult, TriggerFut};
use crate::error::{Error, NetworkError, SessionError};
use crate::event::*;
use crate::packet::Packet;
use crate::protocol::ProtocolId;
use crate::session::Session;
use crate::transport::connection::{Connection, ConnectionMode};
use crate::transport::{Address, TransportId};
use crate::Result;
use actix::prelude::*;
use futures::{Future, FutureExt, StreamExt, TryFutureExt};
use hashbrown::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

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
    manglers: Vec<Recipient<MangleCmd<Key>>>,

    session_protocol: Option<Recipient<SessionCmd<Key>>>,
    dht_protocol: Option<Recipient<DhtCmd<Key>>>,

    pending_connections: HashMap<Address, (Instant, TriggerFut<Result<Address>>)>,
    connections: HashMap<Address, Connection<Key>>,
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
            manglers: Vec::new(),
            session_protocol: None,
            dht_protocol: None,
            pending_connections: HashMap::new(),
            connections: HashMap::new(),
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
        address: Addr<Self>,
    ) -> impl Future<Output = Result<Session<Key>>> {
        if let Some(session) = self.sessions.get(&key) {
            let cloned = session.clone();
            return async move { Ok(cloned.await?) }.left_future();
        }

        let session = self
            .sessions
            .entry(key.clone())
            .or_insert(Session::new(key.clone()))
            .clone();

        let dht = self.dht_protocol.clone();
        let proto = self.session_protocol.clone();

        async move {
            let dht = dht.ok_or_else(|| Error::protocol("No discovery protocol"))?;
            let proto = proto.ok_or_else(|| Error::protocol("No session protocol"))?;
            let addresses = dht.send(DhtCmd::Resolve(key.clone())).await??;
            let conns = address.send(internal::Connect(addresses)).await??;
            let (conn_address, _) = futures::future::select_ok(conns).await?;
            address
                .send(internal::AddConnectionToSession(conn_address, key))
                .await?;
            session.clone().await?;
            proto.send(SessionCmd::Initiate(conn_address)).await??;
            Ok(session)
        }
        .right_future()
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        let now = Instant::now();
        let duration = self.conf.connection_timeout;

        self.pending_connections
            .drain_filter(|_, (time, _)| duration < now - *time)
            .for_each(|(addr, (_, mut trigger))| {
                if trigger.is_pending() {
                    log::debug!(
                        "Connection to {:?} timed out after {}s",
                        addr,
                        duration.as_secs()
                    );
                    trigger.ready(Err(Error::from(NetworkError::Timeout)))
                }
            });
    }
}

impl<Key> Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + 'static,
{
    #[inline]
    fn mangle<'a>(
        &self,
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    ) -> impl Future<Output = Result<Packet>> + 'a {
        let iter = self.manglers.clone().into_iter();
        futures::stream::iter(iter)
            .map(move |recipient| (recipient, from.clone(), to.clone()))
            .fold(Ok(packet), move |res, (recipient, from, to)| async move {
                match res {
                    Ok(packet) => recipient
                        .send(MangleCmd::Mangle { from, to, packet })
                        .await
                        .flatten_result(),
                    err => err,
                }
            })
    }

    #[inline]
    fn unmangle<'a>(
        &self,
        from: Option<Key>,
        to: Option<Key>,
        packet: Packet,
    ) -> impl Future<Output = Result<Packet>> + 'a {
        let iter = self.manglers.clone().into_iter().rev();
        futures::stream::iter(iter)
            .map(move |recipient| (recipient, from.clone(), to.clone()))
            .fold(Ok(packet), move |res, (recipient, from, to)| async move {
                match res {
                    Ok(packet) => recipient
                        .send(MangleCmd::Unmangle { from, to, packet })
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
        // TODO: service bus + handlers

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
            ServiceCmd::AddMangler(recipient) => {
                self.manglers.push(recipient);
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::RemoveMangler(recipient) => {
                if let Some(idx) = self.manglers.iter().position(|r| r == &recipient) {
                    self.manglers.remove(idx);
                }
                ActorResponse::reply(Ok(()))
            }
            ServiceCmd::Shutdown => {
                log::info!("Shutting down...");

                let actor = ctx.address();

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
                    Address::ANY_TRANSPORT => self
                        .transports
                        .keys()
                        .filter_map(|id| {
                            to.transport_id = *id;
                            self.connections.get(&to)
                        })
                        .next(),
                    _ => self.connections.get(&to),
                };

                let fut = match conn {
                    Some(conn) => {
                        let mut conn = conn.clone();
                        let mangle_fut = self.mangle(from, None, packet);

                        async move {
                            let packet = mangle_fut.await?;
                            conn.send(packet).await?;
                            Ok(())
                        }
                        .left_future()
                    }
                    None => {
                        let actor = ctx.address();
                        let addresses = vec![to.clone()];

                        async move {
                            let conns = actor.send(internal::Connect(addresses)).await??;
                            futures::future::select_ok(conns.into_iter()).await?;
                            actor.send(SendCmd::Roaming { from, to, packet }).await??;
                            Ok(())
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
                let actor = ctx.address();

                let fut_vec = self
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

                match fut_vec.len() {
                    0 => ActorResponse::reply(Err(NetworkError::NoConnection.into())),
                    _ => {
                        Arbiter::spawn(async move {
                            let _ = futures::future::join_all(fut_vec.into_iter()).await;
                        });
                        ActorResponse::reply(Ok(()))
                    }
                }
            }
            SendCmd::Disconnect(key, reason) => {
                let actor = ctx.address();
                let protocol = self.session_protocol.clone();

                let fut = async move {
                    if let Some(protocol) = protocol {
                        protocol
                            .send(SessionCmd::Disconnect(key.clone(), reason))
                            .await??;
                    }
                    actor.send(internal::RemoveSession(key)).await?;
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
                // FIXME: connection mode
                let conn = Connection::new(address, channel, ConnectionMode::Direct);
                self.connections.insert(conn.address, conn);

                if let Some((_, mut pending)) = self.pending_connections.remove(&address) {
                    log::debug!("Connected to {:?} (outbound)", address);
                    pending.ready(Ok(address));
                } else {
                    log::debug!("Connected to {:?} (inbound)", address);
                }
            }
            TransportEvt::Disconnected(address, reason) => {
                if let Some((_, mut trigger)) = self.pending_connections.remove(&address) {
                    trigger.ready(Err(Error::from(NetworkError::NoConnection)));
                }

                if let Some(conn) = self.connections.remove(&address) {
                    log::debug!("Disconnected from {:?}: {:?}", address, reason);

                    if let Some(key) = conn.ctx() {
                        if let Some(session) = self.sessions.get_mut(&key) {
                            session.remove_by_address(&address);
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

                let unmangle_fut = self.unmangle(key.clone(), None, packet);
                let fut = async move {
                    let packet = unmangle_fut.await?;
                    let command = match key {
                        Some(key) => ProtocolCmd::SessionPacket(address, packet, key),
                        None => ProtocolCmd::RoamingPacket(address, packet),
                    };

                    log::debug!(
                        "Routing packet from {:?} to protocol {}",
                        address,
                        protocol_id
                    );
                    protocol.send(command).await??;
                    Ok(())
                }
                .map_err(|e: Error| log::error!("TransportEvent::Packet handler error: {:?}", e))
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
                    log::info!("Session connection with {:?} found", address);
                    self.sessions
                        .entry(key.clone())
                        .or_insert_with(|| Session::new(key))
                        .add_connection(conn.clone())
                }
                _ => {
                    log::warn!(
                        "Connection to {:?} (key: {:?}) no longer exists",
                        address,
                        key
                    );
                }
            },
        }
    }
}

impl<Key> Handler<internal::Connect> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    type Result = <internal::Connect as Message>::Result;

    fn handle(&mut self, evt: internal::Connect, ctx: &mut Context<Self>) -> Self::Result {
        let mut addresses = Vec::new();
        let mut triggers = Vec::new();
        let mut futs = Vec::new();

        evt.0.into_iter().for_each(|addr| match addr.transport_id {
            Address::ANY_TRANSPORT => {
                self.transports
                    .keys()
                    .for_each(|id| addresses.push(Address::new(*id, addr.socket_addr)));
            }
            _ => addresses.push(addr),
        });

        log::debug!("Requested connection to {:?}", addresses);

        addresses.into_iter().for_each(|address| {
            if let Some(recipient) = self.transports.get(&address.transport_id) {
                let is_pending = self.pending_connections.contains_key(&address);
                let is_connected = self.connections.contains_key(&address);

                let trigger = &mut self
                    .pending_connections
                    .entry(address)
                    .or_insert_with(|| (Instant::now(), TriggerFut::new()))
                    .1;

                match (is_connected, is_pending) {
                    (true, _) => {
                        log::debug!("Connection to {:?} already established", address);
                        trigger.ready(Ok(address));
                    }
                    (_, false) => {
                        log::debug!("Connecting to {:?}", address);
                        futs.push(recipient.send(TransportCmd::Connect(address.socket_addr)))
                    }
                    _ => {}
                }

                triggers.push(trigger.clone());
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
        let mangle_fut = self.mangle(evt.from, Some(evt.to), evt.packet);
        let timeout = self.conf.session_timeout;

        ActorResponse::r#async(
            async move {
                let packet = mangle_fut.await?;
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
impl_internal_handler!(internal::RemoveConnection, (self, evt, _ctx) {
    let address = evt.0;
    self.connections.remove(&address);
});
impl_internal_handler!(internal::AddSession<Key>, (self, evt, _ctx) {
    let session = evt.0;
    self.sessions.insert(session.key(), session);
});
impl_internal_handler!(internal::RemoveSession<Key>, (self, evt, _ctx) {
    let key = evt.0;
    if let Some(mut session) = self.sessions.remove(&key) {
        session.terminate();
    }
});
impl_internal_handler!(internal::AddConnectionToSession<Key>, (self, evt, _ctx) {
    let address = evt.0;
    let key = evt.1;
    if let Some(conn) = self.connections.get(&address) {
        if let Some(session) = self.sessions.get_mut(&key) {
            session.add_connection(conn.clone());
        }
    }
});

mod internal {
    use crate::common::TriggerFut;
    use crate::event::TransportCmd;
    use crate::packet::Packet;
    use crate::session::Session;
    use crate::transport::Address;
    use crate::{Result, TransportId};
    use actix::prelude::*;
    use std::fmt::Debug;

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct AddTransport(pub TransportId, pub Recipient<TransportCmd>);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct RemoveTransport(pub TransportId);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct RemoveConnection(pub Address);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct AddSession<Key: Clone + Debug + 'static>(pub Session<Key>);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct RemoveSession<Key: Clone + Debug + 'static>(pub Key);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct AddConnectionToSession<Key: Clone + Debug + 'static>(pub Address, pub Key);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "()")]
    pub struct Shutdown;

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "Result<Vec<TriggerFut<Result<Address>>>>")]
    pub struct Connect(pub Vec<Address>);

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "Result<()>")]
    pub struct Send<Key: Clone + Debug + 'static> {
        pub from: Option<Key>,
        pub to: Key,
        pub packet: Packet,
    }
}
