use crate::common::FutureState;
use crate::error::SessionError;
use crate::packet::EncodedPacket;
use crate::transport::connection::{Connection, ConnectionMap};
use crate::transport::Address;
use crate::Result;
use futures::prelude::*;
use futures::task::{Context, Poll};
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Session<Key>
where
    Key: Clone + Debug,
{
    state: Arc<Mutex<SessionState<Key>>>,
    connections: Arc<Mutex<ConnectionMap<Key>>>,
    future_state: Arc<Mutex<FutureState<bool>>>,
    future_id: usize,
}

impl<Key> Session<Key>
where
    Key: Clone + Debug,
{
    pub fn new(key: Key) -> Self {
        Session {
            state: Arc::new(Mutex::new(SessionState::New(key))),
            connections: Arc::new(Mutex::new(ConnectionMap::default())),
            future_state: Arc::new(Mutex::new(FutureState::default())),
            future_id: usize::max_value(),
        }
    }

    #[inline]
    pub fn is_alive(&self) -> bool {
        match &(*self.state.lock().unwrap()) {
            SessionState::Terminated(_) | SessionState::Poisoned => false,
            _ => true,
        }
    }

    #[inline]
    pub fn is_established(&self) -> bool {
        match &(*self.state.lock().unwrap()) {
            SessionState::Established(_) => true,
            _ => false,
        }
    }
}

impl<Key> Session<Key>
where
    Key: Clone + Debug,
{
    pub fn add_connection(&mut self, mut conn: Connection<Key>) {
        let mut state = self.state.lock().unwrap();
        let mut connections = self.connections.lock().unwrap();

        *state = match std::mem::replace(&mut *state, SessionState::Poisoned) {
            SessionState::New(key) => {
                log::info!("Session established {:?}", key);
                conn.set_ctx(key.clone());
                Self::connected(&mut *connections, conn);
                self.future_state.lock().unwrap().ready(true);
                SessionState::Established(key)
            }
            SessionState::Established(key) => {
                Self::connected(&mut *connections, conn);
                SessionState::Established(key)
            }
            SessionState::Terminated(key) => {
                log::debug!("New connection for a terminated session {:?}", conn.address);
                SessionState::Terminated(key)
            }
            SessionState::Poisoned => panic!("Programming error: poisoned session state"),
        };
    }

    pub fn remove_by_address(&mut self, address: &Address) {
        let empty = {
            let mut connections = self.connections.lock().unwrap();
            if let Some(_) = connections.remove(&address) {
                log::debug!("Disconnected from {:?}", address);
            }
            connections.is_empty()
        };

        if empty && self.is_established() {
            self.terminate();
        }
    }

    pub fn terminate(&mut self) {
        let mut state = self.state.lock().unwrap();
        let key = self.key();
        log::debug!("Terminating session {:?}", key);

        match std::mem::replace(&mut (*state), SessionState::Terminated(key)) {
            SessionState::Terminated(_) => return,
            _ => {
                (*self.connections.lock().unwrap()).clear();
                (*self.future_state.lock().unwrap()).ready(false)
            }
        };
    }

    #[inline]
    fn connected(connections: &mut ConnectionMap<Key>, conn: Connection<Key>) {
        log::debug!("Connected to {:?}", conn.address);
        connections.insert(conn);
    }
}

impl<Key> Session<Key>
where
    Key: Clone + Debug + 'static,
{
    #[inline]
    pub fn send<P: Into<EncodedPacket> + 'static>(
        &self,
        packet: P,
    ) -> impl Future<Output = Result<()>> + 'static {
        match self.connections.lock().unwrap().recent() {
            Ok(conn) => conn.send(packet).left_future(),
            Err(e) => {
                log::warn!("No recent connection in session");
                futures::future::err(e).right_future()
            }
        }
    }
}

impl<Key> Session<Key>
where
    Key: Clone + Debug,
{
    #[inline]
    pub fn key(&self) -> Key {
        self.state.lock().unwrap().key().clone()
    }
}

impl<Key> Clone for Session<Key>
where
    Key: Clone + Debug,
{
    fn clone(&self) -> Self {
        Session {
            state: self.state.clone(),
            connections: self.connections.clone(),
            future_state: self.future_state.clone(),
            future_id: self.future_state.lock().unwrap().next_id(),
        }
    }
}

impl<Key> Drop for Session<Key>
where
    Key: Clone + Debug,
{
    fn drop(&mut self) {
        let mut future_state = self.future_state.lock().unwrap();
        future_state.remove(&self.future_id);
    }
}

impl<Key> Future for Session<Key>
where
    Key: Clone + Debug,
{
    type Output = Result<Self>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let value = { self.future_state.lock().unwrap().value().cloned() };
        match value {
            Some(true) => Poll::Ready(Ok(self.to_owned())),
            Some(false) => Poll::Ready(Err(SessionError::Disconnected.into())),
            _ => {
                let mut future_state = self.future_state.lock().unwrap();
                future_state.insert(self.future_id, cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[derive(Debug)]
pub enum SessionState<Key> {
    New(Key),
    Established(Key),
    Terminated(Key),
    Poisoned,
}

impl<Key> SessionState<Key> {
    fn key(&self) -> &Key {
        match &self {
            SessionState::New(key)
            | SessionState::Established(key)
            | SessionState::Terminated(key) => &key,
            SessionState::Poisoned => panic!("Programming error: poisoned session state"),
        }
    }
}
