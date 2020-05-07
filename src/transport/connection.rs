use crate::error::{ChannelError, SessionError};
use crate::packet::AddressedPacket;
use crate::transport::Address;
use crate::{EncodedPacket, Result};
use futures::channel::mpsc::Sender;
use futures::{Future, SinkExt, TryFutureExt};
use hashbrown::HashMap;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub type ConnectionId = usize;

lazy_static::lazy_static! {
    static ref CONNECTION_ID_SEQ: AtomicUsize = AtomicUsize::new(0);
}

#[derive(Clone)]
pub struct Connection<Ctx: Clone + Debug> {
    pub id: ConnectionId,
    pub address: Address,
    pub created: Instant,
    channel: Sender<AddressedPacket>,
    mode: ConnectionMode<Ctx>,
    ctx: Arc<Mutex<Option<Ctx>>>,
}

impl<Ctx: Clone + Debug> Connection<Ctx> {
    pub fn new(
        address: Address,
        channel: Sender<AddressedPacket>,
        mode: ConnectionMode<Ctx>,
    ) -> Self {
        Connection {
            id: (*CONNECTION_ID_SEQ).fetch_add(1, SeqCst),
            address,
            created: Instant::now(),
            channel,
            mode,
            ctx: Arc::new(Mutex::new(None)),
        }
    }

    #[inline]
    pub fn send<'s, P: Into<EncodedPacket> + 'static>(
        &mut self,
        packet: P,
    ) -> impl Future<Output = Result<()>> + 'static {
        let address = self.address.clone();
        let mut sender = self.channel.clone();

        async move {
            sender
                .send(packet.into().addressed(address))
                .map_err(|e| ChannelError::from(e).into())
                .await
        }
    }

    #[inline]
    pub fn ctx(&self) -> Option<Ctx> {
        let ctx = self.ctx.lock().unwrap();
        (*ctx).clone()
    }

    #[inline]
    pub fn set_ctx(&mut self, new_ctx: Ctx) {
        let mut ctx = self.ctx.lock().unwrap();
        (*ctx).replace(new_ctx);
    }
}

impl<Ctx: Clone + Debug> Hash for Connection<Ctx> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state)
    }
}

impl<Ctx: Clone + Debug> PartialEq for Connection<Ctx> {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl<Ctx: Clone + Debug> Debug for Connection<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

impl<Ctx: Clone + Debug> std::fmt::Display for Connection<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Connection {{ address: {:?}, since: {:?}, id: {:?}, ctx: {:?} }}",
            self.address, self.created, self.id, self.ctx
        ))
    }
}

#[derive(Clone, Debug)]
pub enum ConnectionMode<Ctx: Clone + Debug> {
    Direct,
    Relay(Ctx),
}

#[derive(Clone, Debug)]
pub struct ConnectionMap<Ctx: Clone + Debug> {
    inner: HashMap<Address, Connection<Ctx>>,
}

impl<Ctx: Clone + Debug> ConnectionMap<Ctx> {
    #[inline]
    pub fn get(&self, address: &Address) -> Option<&Connection<Ctx>> {
        self.inner.get(address)
    }

    #[inline]
    pub fn insert(&mut self, connection: Connection<Ctx>) {
        self.inner.insert(connection.address, connection);
    }

    #[inline]
    pub fn remove(&mut self, address: &Address) -> Option<Connection<Ctx>> {
        self.inner.remove(address)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn recent(&mut self) -> Result<&mut Connection<Ctx>> {
        // FIXME: proper recent connection
        self.inner
            .iter_mut()
            .next()
            .map(|(_, conn)| conn)
            .ok_or_else(|| SessionError::Disconnected.into())
    }
}

impl<Ctx: Clone + Debug> Default for ConnectionMap<Ctx> {
    fn default() -> Self {
        ConnectionMap {
            inner: HashMap::new(),
        }
    }
}
