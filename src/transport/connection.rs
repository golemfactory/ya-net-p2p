use crate::common::TriggerFut;
use crate::error::{ChannelError, Error, NetworkError};
use crate::identity::{to_slot, Slot};
use crate::packet::{AddressedPacket, WirePacket};
use crate::transport::Address;
use crate::Result;
use futures::channel::mpsc::Sender;
use futures::{Future, SinkExt, TryFutureExt};
use hashbrown::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type ConnectionId = usize;
pub type ConnectionFut = TriggerFut<Result<Connection>>;

static CONNECTION_ID_SEQ: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct Connection {
    pub id: ConnectionId,
    pub address: Address,
    pub created: Instant,
    channel: Sender<AddressedPacket>,
    slots: Arc<Mutex<HashSet<(Slot, Slot)>>>,
}

impl Connection {
    pub fn new(address: Address, channel: Sender<AddressedPacket>) -> Self {
        Connection {
            id: CONNECTION_ID_SEQ.fetch_add(1, SeqCst),
            address,
            created: Instant::now(),
            channel,
            slots: Arc::new(Mutex::new(HashSet::new())),
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
    pub fn slot<S: AsRef<[u8]>>(&mut self, local: S, remote: S) {
        let tuple = (to_slot(local), to_slot(remote));
        self.slots.lock().unwrap().insert(tuple);
    }

    #[inline]
    pub fn take_slots(&mut self) -> HashSet<(Slot, Slot)> {
        std::mem::replace(&mut (*self.slots.lock().unwrap()), HashSet::new())
    }
}

impl Hash for Connection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state)
    }
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

impl std::fmt::Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Connection {{ address: {:?}, since: {:?}, id: {:?} }}",
            self.address, self.created, self.id
        ))
    }
}

pub enum PendingConnection {
    New(ConnectionFut),
    Pending(ConnectionFut),
    Established(ConnectionFut),
}

impl From<PendingConnection> for ConnectionFut {
    fn from(pending: PendingConnection) -> Self {
        match pending {
            PendingConnection::New(f)
            | PendingConnection::Pending(f)
            | PendingConnection::Established(f) => f,
        }
    }
}

pub struct ConnectionManager {
    pending: HashMap<Address, ConnectionFut>,
    established: HashMap<Address, Connection>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        ConnectionManager {
            pending: HashMap::new(),
            established: HashMap::new(),
        }
    }
}

impl ConnectionManager {
    #[inline]
    pub fn get(&self, address: &Address) -> Option<&Connection> {
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

    pub fn disconnected(&mut self, address: &Address) -> Option<Connection> {
        if let Some(mut trigger) = self.pending.remove(&address) {
            let error = Error::from(NetworkError::NoConnection);
            trigger.ready(Err(error));
        }

        self.established.remove(&address)
    }

    pub fn pending(&mut self, address: Address) -> PendingConnection {
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
