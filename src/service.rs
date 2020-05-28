use crate::common::FlattenResult;
use crate::error::{DiscoveryError, Error, MessageError, NetworkError, SessionError};
use crate::event::*;
use crate::identity::{to_slot, IdentityManager, Slot};
use crate::packet::Packet;
use crate::protocol::{Protocol, ProtocolId};
use crate::session::Session;
use crate::transport::connection::{ConnectionManager, PendingConnection};
use crate::transport::{Address, Transport, TransportId};
use crate::{Identity, Result};
use actix::prelude::*;
use futures::{Future, FutureExt, StreamExt, TryFutureExt};
use hashbrown::{HashMap, HashSet};
use std::cell::RefCell;
use std::convert::identity;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

pub trait NetAddrExt<Key>
where
    Key: Send + Debug + Clone + 'static,
{
    fn add_processor<A>(&self, actor: A) -> Recipient<ProcessCmd<Key>>
    where
        A: Actor<Context = Context<A>> + Handler<ProcessCmd<Key>>;

    fn add_transport<A>(&self, actor: A) -> Recipient<TransportCmd>
    where
        A: Transport;

    fn add_protocol<A>(&self, actor: A) -> Recipient<ProtocolCmd>
    where
        A: Protocol;

    fn set_dht<A>(&self, actor: A) -> Recipient<DhtCmd<Key>>
    where
        A: Protocol + Handler<DhtCmd<Key>>;

    fn set_session<A>(&self, actor: A) -> Recipient<SessionCmd<Key>>
    where
        A: Protocol + Handler<SessionCmd<Key>>;
}

#[derive(Clone, Debug)]
pub struct NetConfig {
    connection_timeout: Duration,
    session_init_timeout: Duration,
    session_heartbeat_interval: Duration,
    upkeep_interval: Duration,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            connection_timeout: Duration::from_secs(5),
            session_init_timeout: Duration::from_secs(5),
            session_heartbeat_interval: Duration::from_secs(2),
            upkeep_interval: Duration::from_secs(2),
        }
    }
}

pub struct Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + 'static,
{
    conf: NetConfig,
    addresses: HashSet<SocketAddr>,

    transports: HashMap<TransportId, Recipient<TransportCmd>>,
    protocols: HashMap<ProtocolId, Recipient<ProtocolCmd>>,
    processors: Vec<Recipient<ProcessCmd<Key>>>,

    session_protocol: Option<Recipient<SessionCmd<Key>>>,
    dht_protocol: Option<Recipient<DhtCmd<Key>>>,

    connections: ConnectionManager,
    sessions: Rc<RefCell<HashMap<(Slot, Slot), Session<Key>>>>,
    identities: IdentityManager<Key>,
}

impl<Key> Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    pub fn new(addresses: Vec<SocketAddr>, identities: IdentityManager<Key>) -> Self {
        Self::with_config(addresses, identities, NetConfig::default())
    }

    pub fn with_config(
        addresses: Vec<SocketAddr>,
        identities: IdentityManager<Key>,
        conf: NetConfig,
    ) -> Self {
        Net {
            conf,
            addresses: HashSet::from_iter(addresses.into_iter()),
            transports: HashMap::new(),
            protocols: HashMap::new(),
            processors: Vec::new(),
            session_protocol: None,
            dht_protocol: None,
            connections: ConnectionManager::default(),
            sessions: Rc::new(RefCell::new(HashMap::new())),
            identities,
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {
        self.connections.prune_pending(self.conf.connection_timeout);
    }
}

impl<Key> Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    #[inline]
    fn process_outbound<'f>(
        processors: Vec<Recipient<ProcessCmd<Key>>>,
        from: Option<&'f Key>,
        to: Option<&'f Key>,
        packet: Packet,
    ) -> impl Future<Output = Result<Packet>> + 'f {
        futures::stream::iter(processors.into_iter())
            .map(move |recipient| (recipient, from.cloned(), to.cloned()))
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
    fn process_inbound<'f>(
        processors: Vec<Recipient<ProcessCmd<Key>>>,
        from: Option<&'f Key>,
        to: Option<&'f Key>,
        packet: Packet,
    ) -> impl Future<Output = Result<Packet>> + 'f {
        futures::stream::iter(processors.into_iter().rev())
            .map(move |recipient| (recipient, from.cloned(), to.cloned()))
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
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
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
    Key: Clone + Unpin + Send + Debug + Hash + Eq + AsRef<[u8]> + 'static,
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

                self.sessions.borrow_mut().clear();
                std::mem::replace(&mut self.connections, ConnectionManager::default());

                let protocols_fut = std::mem::replace(&mut self.protocols, HashMap::new())
                    .into_iter()
                    .map(|(_, v)| v.send(ProtocolCmd::Shutdown));
                let transports_fut = std::mem::replace(&mut self.transports, HashMap::new())
                    .into_iter()
                    .map(|(_, v)| v.send(TransportCmd::Shutdown));

                let fut = async move {
                    futures::future::join_all(protocols_fut).await;
                    futures::future::join_all(transports_fut).await;
                    Ok(())
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
        }
    }
}

impl<Key> Handler<SendCmd<Key>> for Net<Key>
where
    Key: Clone + Unpin + Send + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: SendCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match evt {
            SendCmd::Roaming {
                from,
                mut to,
                mut packet,
            } => {
                log::debug!("Send roaming message to: {:?}", to);
                packet = packet.sign();

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

                let processors = self.processors.clone();
                let fut = match conn.cloned() {
                    Some(mut conn) => async move {
                        let packet =
                            Self::process_outbound(processors, from.as_ref(), None, packet).await?;
                        conn.send(packet).await?;
                        Ok(())
                    }
                    .left_future(),
                    None => {
                        let actor = ctx.address();
                        async move {
                            let conns = actor.send(internal::Connect(vec![to.clone()])).await??;
                            let conn = futures::future::select_ok(conns.into_iter()).await?.0;
                            let to = conn.address;
                            actor.send(SendCmd::Roaming { from, to, packet }).await?
                        }
                        .right_future()
                    }
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            SendCmd::Session {
                from,
                to,
                mut packet,
            } => {
                log::debug!("Send session message to: {}", to);
                packet = packet.encrypt();

                let actor = ctx.address();
                let dht = self.dht_protocol.clone();
                let proto = self.session_protocol.clone();
                let processors = self.processors.clone();
                let sessions = self.sessions.clone();
                let identities = self.identities.clone();
                let timeout = self.conf.session_init_timeout;

                let fut = async move {
                    let dht = dht.ok_or_else(|| Error::protocol("No discovery protocol"))?;
                    let proto = proto.ok_or_else(|| Error::protocol("No session protocol"))?;
                    let from_key = identities
                        .get_key(&from)
                        .ok_or_else(|| Error::protocol("Unknown identity"))?;

                    let dht_value = actor
                        .send(internal::ResolveIdentity::new(to.clone()))
                        .await??;
                    let packet = Self::process_outbound(
                        processors,
                        Some(&from_key),
                        Some(&dht_value.identity_key),
                        packet,
                    )
                    .await?;

                    let slots = (to_slot(&from_key), to_slot(&dht_value.identity_key));
                    let existing = { (*sessions.borrow()).get(&slots).cloned() };
                    let mut session = match existing {
                        Some(session) => session,
                        _ => {
                            let mut session = {
                                sessions
                                    .borrow_mut()
                                    .entry(slots)
                                    .or_insert(Session::new(
                                        from_key.clone(),
                                        dht_value.identity_key.clone(),
                                    ))
                                    .clone()
                            };
                            let addresses = dht
                                .send(DhtCmd::ResolveNode(dht_value.node_key.clone()))
                                .await??
                                .into_addresses()?;
                            let connections = actor.send(internal::Connect(addresses)).await??;
                            session
                                .add_future_connection(connections, |conn| {
                                    proto
                                        .send(SessionCmd::Initiate {
                                            from: from_key.clone(),
                                            from_identity: from.clone(),
                                            to: dht_value.identity_key.clone(),
                                            to_identity: to.clone(),
                                            address: conn.address,
                                        })
                                        .map(|r| r.flatten_result())
                                })
                                .await?;
                            session
                        }
                    };

                    tokio::time::timeout(timeout, session)
                        .await
                        .map_err(|_| Error::from(SessionError::Timeout))??
                        .send(packet)
                        .await
                        .map(|_| Ok(()))?
                };

                ActorResponse::r#async(fut.into_actor(self))
            }
            SendCmd::Broadcast { packet } => unimplemented!(),
        }
    }
}

impl<Key> Handler<TransportEvt> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
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
                if let Some(mut conn) = self.connections.disconnected(&address) {
                    let mut sessions = self.sessions.borrow_mut();
                    conn.take_slots().into_iter().for_each(|pair| {
                        if let Some(session) = sessions.get_mut(&pair) {
                            session.remove_connection(&conn);
                            if !session.is_alive() {
                                sessions.remove(&pair);
                            }
                        }
                    });
                }
            }
            TransportEvt::Packet(address, packet) => {
                let packet = match packet.try_decode() {
                    Ok(packet) => packet,
                    Err(err) => return log::warn!("Error decoding packet: {:?}", err),
                };
                let proto_id = packet.payload.protocol_id;
                let proto = match self.protocols.get(&proto_id) {
                    Some(protocol) => protocol.clone(),
                    _ => return log::error!("Unknown protocol {} ({:?})", proto_id, address),
                };
                let keys = packet
                    .slots()
                    .map(|(sender, recipient)| {
                        self.sessions
                            .borrow()
                            .get(&(recipient, sender))
                            .map(|s| s.keys())
                    })
                    .flatten();

                let identities = self.identities.clone();
                let processors = self.processors.clone();
                let fut = async move {
                    let command = match keys {
                        Some((local, remote)) => ProtocolCmd::SessionPacket {
                            from: identities.get_identity(&remote).ok_or_else(|| {
                                Error::protocol(format!(
                                    "Unknown remote identity for key {}",
                                    hex::encode(&remote)
                                ))
                            })?,
                            to: identities.get_identity(&local).ok_or_else(|| {
                                Error::protocol(format!(
                                    "Unknown local identity for key {}",
                                    hex::encode(&local)
                                ))
                            })?,
                            address,
                            packet: Self::process_inbound(
                                processors,
                                Some(&remote),
                                Some(&local),
                                packet,
                            )
                            .await?,
                        },
                        None => ProtocolCmd::RoamingPacket {
                            address,
                            packet: Self::process_inbound(processors, None, None, packet).await?,
                        },
                    };

                    log::debug!("Protocol {} message ({:?})", proto_id, address);
                    proto.send(command).await??;
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
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    type Result = ();

    fn handle(&mut self, evt: SessionEvt<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match evt {
            SessionEvt::Established {
                from,
                from_identity,
                to,
                to_identity,
                address,
            } => match self.connections.get(&address) {
                Some(conn) => {
                    self.sessions
                        .borrow_mut()
                        .entry((to_slot(&from), to_slot(&to)))
                        .or_insert_with(|| Session::new(from, to.clone()))
                        .add_connection(conn.clone());
                    self.identities.insert_key(to_identity, to);
                }
                _ => {
                    log::warn!(
                        "Connection to {:?} ({}) no longer exists",
                        address,
                        hex::encode(to.as_ref())
                    );
                }
            },
        }
    }
}

impl<Key> Handler<internal::ResolveIdentity<Key>> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    type Result = ActorResponse<Self, DhtValue<Key>, Error>;

    fn handle(
        &mut self,
        evt: internal::ResolveIdentity<Key>,
        ctx: &mut Context<Self>,
    ) -> Self::Result {
        if let Some(node_key) = self.identities.get_node_key(&evt.identity) {
            if let Some(identity_key) = self.identities.get_key(&evt.identity) {
                let dht_value = DhtValue {
                    identity_key,
                    node_key,
                };
                return ActorResponse::reply(Ok(dht_value));
            }
        }

        let mut identities = self.identities.clone();
        let dht = self.dht_protocol.clone();
        let fut = async move {
            let dht_value = dht
                .ok_or_else(|| Error::protocol("No discovery protocol"))?
                .send(DhtCmd::ResolveValue(evt.identity.as_ref().to_vec()))
                .await??
                .into_value()?;
            identities.insert_key(evt.identity.clone(), dht_value.identity_key.clone());
            identities.insert_node_key(evt.identity, dht_value.node_key.clone());
            Ok(dht_value)
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<Key> Handler<internal::Connect> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    type Result = <internal::Connect as Message>::Result;

    fn handle(&mut self, evt: internal::Connect, ctx: &mut Context<Self>) -> Self::Result {
        let mut addresses = Vec::new();
        let mut triggers = Vec::new();
        let mut futs = Vec::new();

        evt.0.into_iter().for_each(|a| match a.transport_id {
            Address::ANY_TRANSPORT => addresses.extend(
                self.transports
                    .keys()
                    .map(|id| Address::new(*id, a.socket_addr)),
            ),
            _ => addresses.push(a),
        });

        log::debug!("Connecting to addresses: {:?}", addresses);

        addresses.into_iter().for_each(|a| {
            if let Some(recipient) = self.transports.get(&a.transport_id) {
                let pending = self.connections.pending(a);
                if let PendingConnection::New(_) = &pending {
                    log::debug!("Connecting to {:?}", a);
                    futs.push(recipient.send(TransportCmd::Connect(a.socket_addr)));
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

impl<Key> Handler<internal::AddTransport> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    type Result = <internal::AddTransport as actix::Message>::Result;

    fn handle(&mut self, evt: internal::AddTransport, _: &mut Context<Self>) -> Self::Result {
        let (transport_id, recipient) = (evt.0, evt.1);
        self.transports.insert(transport_id, recipient);
    }
}

impl<Key> Handler<internal::RemoveTransport> for Net<Key>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
{
    type Result = <internal::RemoveTransport as actix::Message>::Result;

    fn handle(&mut self, evt: internal::RemoveTransport, _: &mut Context<Self>) -> Self::Result {
        let transport_id = evt.0;
        self.transports.remove(&transport_id);
    }
}

impl<Key> NetAddrExt<Key> for Addr<Net<Key>>
where
    Key: Unpin + Send + Clone + Debug + Hash + Eq + AsRef<[u8]> + 'static,
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

    fn add_protocol<A>(&self, actor: A) -> Recipient<ProtocolCmd>
    where
        A: Protocol,
    {
        let recipient = actor.start().recipient();
        self.do_send(ServiceCmd::AddProtocol(A::ID, recipient.clone()));
        recipient
    }

    fn set_dht<A>(&self, actor: A) -> Recipient<DhtCmd<Key>>
    where
        A: Protocol + Handler<DhtCmd<Key>>,
    {
        {
            let addr = actor.start();
            self.do_send(ServiceCmd::SetDhtProtocol(addr.clone().recipient()));
            self.do_send(ServiceCmd::AddProtocol(A::ID, addr.clone().recipient()));
            addr.recipient()
        }
    }

    fn set_session<A>(&self, actor: A) -> Recipient<SessionCmd<Key>>
    where
        A: Protocol + Handler<SessionCmd<Key>>,
    {
        {
            let addr = actor.start();
            self.do_send(ServiceCmd::SetSessionProtocol(addr.clone().recipient()));
            self.do_send(ServiceCmd::AddProtocol(A::ID, addr.clone().recipient()));
            addr.recipient()
        }
    }
}

mod internal {
    use crate::event::{DhtValue, TransportCmd};
    use crate::identity::Identity;
    use crate::packet::Packet;
    use crate::transport::connection::ConnectionFut;
    use crate::transport::{Address, TransportId};
    use crate::Result;
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
    #[rtype(result = "Result<DhtValue<Key>>")]
    pub struct ResolveIdentity<Key: Clone + Debug + 'static> {
        pub identity: Identity,
        phantom: PhantomData<Key>,
    }

    impl<Key: Clone + Debug + 'static> ResolveIdentity<Key> {
        pub fn new(identity: Identity) -> Self {
            ResolveIdentity {
                identity,
                phantom: PhantomData,
            }
        }
    }

    #[derive(Clone, Debug, Message)]
    #[rtype(result = "Result<Vec<ConnectionFut>>")]
    pub struct Connect(pub Vec<Address>);
}
