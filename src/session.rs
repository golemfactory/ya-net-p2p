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

pub struct Session<Key: Clone> {
    state: Arc<Mutex<SessionState<Key>>>,
    recent_conn: Arc<Mutex<Option<Connection>>>,
    connections: Arc<Mutex<HashMap<Address, Connection>>>,
    future_state: Arc<Mutex<FutureState<bool>>>,
    future_id: usize,
}

impl<Key: Clone> Session<Key> {
    pub fn new(local: Key, remote: Key) -> Self {
        Session {
            state: Arc::new(Mutex::new(SessionState::New(local, remote))),
            recent_conn: Arc::new(Mutex::new(None)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            future_state: Arc::new(Mutex::new(FutureState::default())),
            future_id: usize::max_value(),
        }
    }

    #[inline]
    pub fn is_alive(&self) -> bool {
        match &(*self.state.lock().unwrap()) {
            SessionState::Terminated(_, _) | SessionState::Poisoned => false,
            _ => true,
        }
    }

    #[inline]
    pub fn is_established(&self) -> bool {
        match &(*self.state.lock().unwrap()) {
            SessionState::Established(_, _) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn addresses(&self) -> Vec<Address> {
        let connections = self.connections.lock().unwrap();
        connections.keys().cloned().collect()
    }

    #[inline]
    pub fn keys(&self) -> (Key, Key) {
        self.state.lock().unwrap().keys()
    }
}

impl<Key> Session<Key>
where
    Key: Clone + AsRef<[u8]>,
{
    pub fn add_connection(&mut self, conn: Connection) -> bool {
        let mut state = self.state.lock().unwrap();
        let mut connections = self.connections.lock().unwrap();
        let mut added = false;

        *state = match std::mem::replace(&mut *state, SessionState::Poisoned) {
            SessionState::New(local, remote) => {
                if Self::connected(&mut *connections, &local, &remote, conn.clone()) {
                    log::info!(
                        "Session established ({:?}): {}",
                        conn.address,
                        hex::encode(remote.as_ref())
                    );
                    self.recent_conn.lock().unwrap().replace(conn);
                    self.future_state.lock().unwrap().ready(true);
                    added = true;
                    SessionState::Established(local, remote)
                } else {
                    SessionState::New(local, remote)
                }
            }
            SessionState::Established(local, remote) => {
                if Self::connected(&mut *connections, &local, &remote, conn.clone()) {
                    self.recent_conn.lock().unwrap().replace(conn);
                    added = true;
                }
                SessionState::Established(local, remote)
            }
            SessionState::Terminated(local, remote) => {
                log::debug!("New connection for a terminated session {:?}", conn.address);
                SessionState::Terminated(local, remote)
            }
            SessionState::Poisoned => panic!("Programming error: poisoned session state"),
        };

        added
    }

    pub async fn add_future_connection<F, Fut>(
        &mut self,
        mut futs: Vec<ConnectionFut>,
        start_session: F,
    ) -> Result<()>
    where
        F: Fn(Connection) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        while futs.is_empty().not() {
            let (conn, remaining) = futures::future::select_ok(futs).await?;
            futs = remaining;
            start_session(conn).await?;
        }
        Ok(())
    }

    pub fn remove_connection(&mut self, conn: &Connection) {
        let established = self.is_established();
        let now_empty = {
            let mut connections = self.connections.lock().unwrap();
            connections.remove(&conn.address);
            connections.is_empty()
        };

        if established && now_empty {
            self.terminate();
        } else {
            let mut recent_conn_id = {
                self.recent_conn
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|conn| conn.id)
            };
            if recent_conn_id.map(|id| id == conn.id).unwrap_or(false) {
                self.update_recent()
            }
        }
    }

    pub fn terminate(&mut self) {
        let keys = { self.keys() };
        let mut state = self.state.lock().unwrap();

        match std::mem::replace(
            &mut (*state),
            SessionState::Terminated(keys.0, keys.1.clone()),
        ) {
            SessionState::Terminated(_, _) => (),
            _ => {
                log::debug!("Terminating session {}", hex::encode(keys.1.as_ref()));
                (self.recent_conn.lock().unwrap().take());
                (*self.connections.lock().unwrap()).clear();
                (*self.future_state.lock().unwrap()).ready(false);
            }
        };
    }

    fn update_recent(&mut self) {
        let connections = self.connections.lock().unwrap();
        if let Some(conn) = connections.values().next().cloned() {
            self.recent_conn.lock().unwrap().replace(conn);
        }
    }

    #[inline(always)]
    fn connected(
        connections: &mut HashMap<Address, Connection>,
        local: &Key,
        remote: &Key,
        mut conn: Connection,
    ) -> bool {
        conn.slot(local, remote);
        connections.insert(conn.address, conn).is_none()
    }
}

impl<Key> Session<Key>
where
    Key: Clone + 'static,
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

impl<Key: Clone> Clone for Session<Key> {
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

impl<Key: Clone> Drop for Session<Key> {
    fn drop(&mut self) {
        let mut future_state = self.future_state.lock().unwrap();
        future_state.remove(&self.future_id);
    }
}

impl<Key: Clone> Future for Session<Key> {
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

pub enum SessionState<Key: Clone> {
    New(Key, Key),
    Established(Key, Key),
    Terminated(Key, Key),
    Poisoned,
}

impl<Key: Clone> SessionState<Key> {
    fn keys(&self) -> (Key, Key) {
        match &self {
            SessionState::New(local, remote)
            | SessionState::Established(local, remote)
            | SessionState::Terminated(local, remote) => (local.clone(), remote.clone()),
            SessionState::Poisoned => panic!("Programming error: poisoned session state"),
        }
    }
}
