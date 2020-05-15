use crate::common::TriggerFut;
use crate::error::{ChannelError, Error, NetworkError};
use crate::packet::{AddressedPacket, WirePacket};
use crate::transport::Address;
use crate::Result;
use futures::channel::mpsc::Sender;
use futures::{Future, SinkExt, TryFutureExt};
use hashbrown::HashMap;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type ConnectionId = usize;
pub type ConnectionFut<Ctx> = TriggerFut<Result<Connection<Ctx>>>;

lazy_static::lazy_static! {
    static ref CONNECTION_ID_SEQ: AtomicUsize = AtomicUsize::new(0);
}

#[derive(Clone)]
pub struct Connection<Ctx: Clone + Debug> {
    pub id: ConnectionId,
    pub address: Address,
    pub created: Instant,
    channel: Sender<AddressedPacket>,
    ctx: Arc<Mutex<Option<Ctx>>>,
}

impl<Ctx: Clone + Debug> Connection<Ctx> {
    pub fn new(address: Address, channel: Sender<AddressedPacket>) -> Self {
        Connection {
            id: (*CONNECTION_ID_SEQ).fetch_add(1, SeqCst),
            address,
            created: Instant::now(),
            channel,
            ctx: Arc::new(Mutex::new(None)),
        }
    }

    #[inline]
    pub fn send<'s, P: Into<WirePacket> + 'static>(
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

pub enum PendingConnection<Ctx: Clone + Debug> {
    New(ConnectionFut<Ctx>),
    Pending(ConnectionFut<Ctx>),
    Established(ConnectionFut<Ctx>),
}

impl<Ctx: Clone + Debug> From<PendingConnection<Ctx>> for ConnectionFut<Ctx> {
    fn from(pending: PendingConnection<Ctx>) -> Self {
        match pending {
            PendingConnection::New(f)
            | PendingConnection::Pending(f)
            | PendingConnection::Established(f) => f,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionManager<Ctx: Clone + Debug> {
    pending: HashMap<Address, ConnectionFut<Ctx>>,
    established: HashMap<Address, Connection<Ctx>>,
}

impl<Ctx: Clone + Debug> Default for ConnectionManager<Ctx> {
    fn default() -> Self {
        ConnectionManager {
            pending: HashMap::new(),
            established: HashMap::new(),
        }
    }
}

impl<Ctx: Clone + Debug> ConnectionManager<Ctx> {
    #[inline]
    pub fn get(&self, address: &Address) -> Option<&Connection<Ctx>> {
        self.established.get(address)
    }

    pub fn connected(&mut self, address: Address, channel: Sender<AddressedPacket>) {
        let conn = self
            .established
            .entry(address)
            .or_insert_with(|| Connection::new(address, channel));

        if let Some(mut trigger) = self.pending.remove(&address) {
            log::debug!("Connected to {:?} (outbound)", address);
            trigger.ready(Ok(conn.clone()));
        } else {
            log::debug!("Connected to {:?} (inbound)", address);
        }
    }

    pub fn disconnected(&mut self, address: &Address) -> Option<Connection<Ctx>> {
        if let Some(mut trigger) = self.pending.remove(&address) {
            let error = Error::from(NetworkError::NoConnection);
            trigger.ready(Err(error));
        }

        self.established.remove(&address)
    }

    pub fn pending(&mut self, address: Address) -> PendingConnection<Ctx> {
        let is_pending = self.pending.contains_key(&address);
        let mut trigger = self
            .pending
            .entry(address)
            .or_insert_with(TriggerFut::default)
            .clone();

        if let Some(conn) = self.established.get(&address) {
            trigger.ready(Ok(conn.clone()));
            PendingConnection::Established(trigger)
        } else if is_pending {
            PendingConnection::Pending(trigger)
        } else {
            PendingConnection::New(trigger)
        }
    }

    #[inline]
    pub fn prune_pending(&mut self, older_than: Duration) {
        let now = Instant::now();
        self.pending
            .drain_filter(|_, trigger| older_than < now - trigger.created_at)
            .for_each(|(addr, mut trigger)| {
                if trigger.is_pending() {
                    log::debug!(
                        "Pending connection to {:?} removed after {}s",
                        addr,
                        older_than.as_secs()
                    );
                    trigger.ready(Err(Error::from(NetworkError::Timeout)))
                }
            });
    }
}
