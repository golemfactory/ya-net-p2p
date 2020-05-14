use crate::common::FutureState;
use crate::error::{NetworkError, SessionError};
use crate::packet::WirePacket;
use crate::transport::connection::{Connection, ConnectionFut};
use crate::transport::Address;
use crate::Result;
use futures::prelude::*;
use futures::task::{Context, Poll};
use hashbrown::HashMap;
use std::fmt::Debug;
use std::ops::Not;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct Session<Key>
where
    Key: Clone + Debug,
{
    state: Arc<Mutex<SessionState<Key>>>,
    recent_conn: Arc<Mutex<Option<Connection<Key>>>>,
    connections: Arc<Mutex<HashMap<Address, Connection<Key>>>>,
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
            recent_conn: Arc::new(Mutex::new(None)),
            connections: Arc::new(Mutex::new(HashMap::new())),
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

    #[inline]
    pub fn addresses(&self) -> Vec<Address> {
        let connections = self.connections.lock().unwrap();
        connections.keys().cloned().collect()
    }
}

impl<Key> Session<Key>
where
    Key: Clone + Debug + Eq,
{
    pub fn add_connection(&mut self, conn: Connection<Key>) -> bool {
        let mut state = self.state.lock().unwrap();
        let mut connections = self.connections.lock().unwrap();
        let mut added = false;

        *state = match std::mem::replace(&mut *state, SessionState::Poisoned) {
            SessionState::New(key) => {
                if Self::connected(&mut *connections, &key, conn.clone()) {
                    log::info!("Session established ({:?}): {:?}", conn.address, key);
                    self.recent_conn.lock().unwrap().replace(conn);
                    self.future_state.lock().unwrap().ready(true);
                    added = true;
                    SessionState::Established(key)
                } else {
                    SessionState::New(key)
                }
            }
            SessionState::Established(key) => {
                if Self::connected(&mut *connections, &key, conn.clone()) {
                    self.recent_conn.lock().unwrap().replace(conn);
                    added = true;
                }
                SessionState::Established(key)
            }
            SessionState::Terminated(key) => {
                log::debug!("New connection for a terminated session {:?}", conn.address);
                SessionState::Terminated(key)
            }
            SessionState::Poisoned => panic!("Programming error: poisoned session state"),
        };

        added
    }

    pub async fn add_future_connection<F, Fut>(
        &mut self,
        mut futs: Vec<ConnectionFut<Key>>,
        start_session: F,
    ) -> Result<()>
    where
        F: Fn(Connection<Key>) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        while futs.is_empty().not() {
            let (conn, remaining) = futures::future::select_ok(futs).await?;
            futs = remaining;

            if let Some(_) = conn.ctx() {
                if self.add_connection(conn) {
                    break;
                }
            } else {
                start_session(conn).await?;
            }
        }
        Ok(())
    }

    pub fn remove_connection(&mut self, conn: &Connection<Key>) {
        let established = self.is_established();
        let now_empty = {
            let mut connections = self.connections.lock().unwrap();
            connections.remove(&conn.address);
            connections.is_empty()
        };

        if established && now_empty {
            self.terminate();
        }
    }

    pub fn terminate(&mut self) {
        let key = { self.key() };
        let mut state = self.state.lock().unwrap();

        match std::mem::replace(&mut (*state), SessionState::Terminated(key.clone())) {
            SessionState::Terminated(_) => (),
            _ => {
                log::debug!("Terminating session {:?}", key);
                (*self.connections.lock().unwrap()).clear();
                (*self.future_state.lock().unwrap()).ready(false);
            }
        };
    }

    #[inline]
    fn connected(
        connections: &mut HashMap<Address, Connection<Key>>,
        key: &Key,
        mut conn: Connection<Key>,
    ) -> bool {
        match conn.ctx().map(|k| (&k == key, k)) {
            None => conn.set_ctx(key.clone()),
            Some((false, conn_key)) => {
                log::error!("Session key mismatch: {:?} vs {:?} (conn)", key, conn_key);
                return false;
            }
            _ => (),
        }

        connections.insert(conn.address, conn);
        true
    }
}

impl<Key> Session<Key>
where
    Key: Clone + Debug + 'static,
{
    #[inline]
    pub fn send<P: Into<WirePacket> + 'static>(
        &self,
        packet: P,
    ) -> impl Future<Output = Result<()>> + 'static {
        match self.recent_conn.lock().unwrap().as_mut() {
            Some(conn) => conn.send(packet).left_future(),
            None => {
                log::warn!("No recent connection in session");
                futures::future::err(NetworkError::NoConnection.into()).right_future()
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
            recent_conn: self.recent_conn.clone(),
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
