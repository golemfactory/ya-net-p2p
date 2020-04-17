use crate::event::{EvtSend, KadMessage};
use crate::message;
use crate::{Kad, Key, KeyLen, Node, ALPHA};
use actix::prelude::*;
use chrono::Utc;
use futures::task::{Poll, Waker};
use generic_array::ArrayLength;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use rand::RngCore;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;

pub(crate) struct Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    pub key: QueryKey,
    kad: Addr<Kad<N>>,
    node_limit: usize,
    req_ttl: i64,
    uid: usize,
    state: Rc<RefCell<QueryState<N>>>,
    future_state: Rc<RefCell<QueryFutureState>>,
}

impl<N> Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    pub fn new(
        key: QueryKey,
        nodes: Vec<Node<N>>,
        kad: Addr<Kad<N>>,
        node_limit: usize,
        req_ttl: i64,
    ) -> Self {
        let mut query = Query {
            key,
            kad,
            node_limit,
            req_ttl,
            uid: usize::max_value(),
            state: Rc::new(RefCell::new(QueryState::default())),
            future_state: Rc::new(RefCell::new(QueryFutureState::default())),
        };

        query.feed(nodes, None);
        query
    }

    #[inline(always)]
    pub fn in_progress(&self) -> bool {
        if let QueryState::InProgress { .. } = &*self.state.borrow() {
            return true;
        }
        false
    }

    pub fn feed(&mut self, nodes: Vec<Node<N>>, from: Option<&Key<N>>) {
        let mut iterate = false;

        if let QueryState::InProgress {
            started_at: _,
            pending,
            candidates,
            sent,
        } = &mut *self.state.borrow_mut()
        {
            if let Some(from) = from {
                pending.remove(from);
            }

            *candidates = std::mem::replace(candidates, Vec::new())
                .into_iter()
                .chain(nodes.into_iter())
                .filter(|n| !sent.contains(&n.key))
                .unique()
                .sorted_by_key(|n| n.distance(&self.key))
                .take(self.node_limit)
                .collect();

            iterate = pending.is_empty();
        }

        if iterate {
            self.iterate();
        }
    }

    pub fn iterate(&mut self) {
        let req_ttl = self.req_ttl;
        let mut send_out_nodes = None;

        if let QueryState::InProgress {
            started_at,
            pending,
            candidates,
            sent,
        } = &mut *self.state.borrow_mut()
        {
            if Utc::now().timestamp() - *started_at > req_ttl {
                pending.clear();
            }

            if pending.is_empty() {
                let mut nodes = std::mem::replace(candidates, Vec::new());
                *candidates = nodes.split_off(std::cmp::min(nodes.len(), ALPHA));
                *pending = nodes.iter().map(|n| n.key.clone()).collect();
                *started_at = Utc::now().timestamp();

                sent.extend(pending.clone());
                send_out_nodes = Some(nodes)
            }
        }

        if let Some(nodes) = send_out_nodes {
            match nodes.is_empty() {
                true => self.finish(QueryValue::None),
                false => self.send_out(nodes),
            }
        }
    }

    pub fn finish(&mut self, result: QueryValue<N>) {
        if self.in_progress() {
            self.state.replace(QueryState::Finished { result });
            self.future_state
                .borrow_mut()
                .waker_map
                .values()
                .for_each(Waker::wake_by_ref);
        }
    }

    fn send_out(&mut self, nodes: Vec<Node<N>>) {
        let address = self.kad.clone();
        let key = self.key.clone();

        log::debug!(
            "Querying {} node(s) (key: {})",
            nodes.len(),
            Key::<N>::fmt_key(&key)
        );

        actix_rt::spawn(async move {
            let mut rand = rand::thread_rng();

            for to in nodes.into_iter() {
                log::trace!("Send out to: {} (distance: {})", to.key, to.distance(&key));

                let rand_val = rand.next_u32();
                let message = match &key {
                    QueryKey::Node(key) => KadMessage::from(message::FindNode {
                        rand_val,
                        key: key.clone(),
                    }),
                    QueryKey::Value(key) => KadMessage::from(message::FindValue {
                        rand_val,
                        key: key.clone(),
                    }),
                };

                if let Err(e) = address.send(EvtSend { to, message }).await {
                    log::error!("Unable to send query message: {:?}", e);
                }
            }
        });
    }
}

impl<N> Clone for Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    fn clone(&self) -> Self {
        let state = self.future_state.borrow_mut();
        let uid = state.seq.fetch_add(1, SeqCst);

        Query {
            uid,
            key: self.key.clone(),
            kad: self.kad.clone(),
            node_limit: self.node_limit,
            req_ttl: self.req_ttl,
            state: self.state.clone(),
            future_state: self.future_state.clone(),
        }
    }
}

impl<N> Drop for Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    fn drop(&mut self) {
        let mut fut_state = self.future_state.borrow_mut();
        fut_state.waker_map.remove(&self.uid);
    }
}

impl<N> Future for Query<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Output = QueryValue<N>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut futures::task::Context<'_>) -> Poll<Self::Output> {
        if let QueryState::Finished { result } = &*self.state.borrow() {
            return Poll::Ready(result.clone());
        }

        let mut fut_state = self.future_state.borrow_mut();
        fut_state.waker_map.insert(self.uid, cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Debug)]
pub(crate) enum QueryState<N: KeyLen> {
    InProgress {
        started_at: i64,
        pending: HashSet<Key<N>>,
        candidates: Vec<Node<N>>,
        sent: HashSet<Key<N>>,
    },
    Finished {
        result: QueryValue<N>,
    },
}

impl<N: KeyLen> Default for QueryState<N> {
    fn default() -> Self {
        QueryState::InProgress {
            started_at: Utc::now().timestamp(),
            pending: HashSet::new(),
            candidates: Vec::new(),
            sent: HashSet::new(),
        }
    }
}

#[derive(Debug)]
struct QueryFutureState {
    seq: AtomicUsize,
    waker_map: HashMap<usize, Waker>,
}

impl Default for QueryFutureState {
    fn default() -> Self {
        QueryFutureState {
            seq: AtomicUsize::new(1),
            waker_map: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum QueryKey {
    Node(Vec<u8>),
    Value(Vec<u8>),
}

impl QueryKey {
    #[inline(always)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner().clone()
    }

    #[inline(always)]
    fn inner(&self) -> &Vec<u8> {
        match &self {
            QueryKey::Node(v) | QueryKey::Value(v) => &v,
        }
    }
}

impl AsRef<[u8]> for QueryKey {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.inner()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum QueryValue<N: KeyLen> {
    Node(Node<N>),
    Value(Vec<u8>),
    None,
}
