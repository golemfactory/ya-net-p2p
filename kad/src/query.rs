use crate::event::{KadMessage, KadRequestMessage};
use crate::message;
use crate::{Kad, Key, KeyLen, Node, NodeData, ALPHA};
use actix::prelude::*;
use chrono::Utc;
use futures::task::{Poll, Waker};
use generic_array::ArrayLength;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;

#[derive(Clone, Debug)]
pub(crate) struct QueryConfig {
    pub max_iterations: Option<u8>,
    pub node_limit: usize,
    pub req_ttl: i64,
}

pub(crate) struct Query<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    pub key: QueryKey,
    conf: QueryConfig,
    kad: Addr<Kad<N, D>>,
    state: Rc<RefCell<QueryState<N, D>>>,
    future_id: usize,
    future_state: Rc<RefCell<QueryFutureState>>,
}

impl<N, D> Query<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    pub fn new(
        key: QueryKey,
        conf: QueryConfig,
        nodes: Vec<Node<N, D>>,
        kad: Addr<Kad<N, D>>,
    ) -> Self {
        let mut query = Query {
            key,
            conf,
            kad,
            state: Rc::new(RefCell::new(QueryState::default())),
            future_id: usize::max_value(),
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

    pub fn feed(&mut self, nodes: Vec<Node<N, D>>, from: Option<&Key<N>>) {
        let mut iterate = false;

        if let QueryState::InProgress {
            started_at: _,
            iterations: _,
            pending,
            candidates,
            closest,
            sent,
        } = &mut *self.state.borrow_mut()
        {
            if let Some(from) = from {
                pending.remove(from);
            }

            *closest = std::mem::replace(closest, Vec::new())
                .into_iter()
                .chain(nodes.iter().cloned())
                .unique()
                .sorted_by_key(|n| n.distance(&self.key))
                .take(self.conf.node_limit)
                .collect();

            *candidates = std::mem::replace(candidates, Vec::new())
                .into_iter()
                .chain(nodes.into_iter())
                .filter(|n| !sent.contains(&n.key))
                .unique()
                .sorted_by_key(|n| n.distance(&self.key))
                .take(self.conf.node_limit)
                .collect();

            iterate = pending.is_empty();
        }

        if iterate {
            self.iterate();
        }
    }

    pub fn iterate(&mut self) {
        let mut closest_nodes = None;
        let mut send_out_nodes = None;

        if let QueryState::InProgress {
            started_at,
            iterations,
            pending,
            candidates,
            closest,
            sent,
        } = &mut *self.state.borrow_mut()
        {
            *iterations += 1;

            if Utc::now().timestamp() - *started_at > self.conf.req_ttl {
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

            if let Some(max_iter) = &self.conf.max_iterations {
                let at_max_iterations = *iterations == *max_iter as usize;
                let at_empty_send_out = match &send_out_nodes {
                    Some(nodes) => nodes.is_empty(),
                    _ => false,
                };

                if at_max_iterations || at_empty_send_out {
                    closest_nodes = Some(std::mem::replace(closest, Vec::new()));
                }
            }
        }

        if let Some(nodes) = closest_nodes {
            self.finish(QueryValue::Neighbors(nodes));
        } else if let Some(nodes) = send_out_nodes {
            match nodes.is_empty() {
                true => self.finish(QueryValue::None),
                false => self.send_out(nodes),
            }
        }
    }

    pub fn finish(&mut self, result: QueryValue<N, D>) {
        if self.in_progress() {
            self.state.replace(QueryState::Finished { result });
            self.future_state
                .borrow_mut()
                .waker_map
                .values()
                .for_each(Waker::wake_by_ref);
        }
    }

    fn send_out(&mut self, nodes: Vec<Node<N, D>>) {
        let address = self.kad.clone();
        let key = self.key.clone();

        log::debug!(
            "Querying {} node(s) (key: {})",
            nodes.len(),
            Key::<N>::fmt_key(&key)
        );

        for n in nodes.iter() {
            log::debug!("Send out to {}", n);
        }

        actix_rt::spawn(async move {
            for to in nodes.into_iter() {
                log::trace!("Send out to: {} (distance: {})", to.key, to.distance(&key));

                let message = match &key {
                    QueryKey::Node(key) => KadMessage::from(message::FindNode {
                        rand_val: 0,
                        key: key.clone(),
                    }),
                    QueryKey::Value(key) => KadMessage::from(message::FindValue {
                        rand_val: 0,
                        key: key.clone(),
                    }),
                };

                if let Err(e) = address.send(KadRequestMessage { to, message }).await {
                    log::error!("Unable to send query message: {:?}", e);
                }
            }
        });
    }
}

impl<N, D> Clone for Query<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    fn clone(&self) -> Self {
        let state = self.future_state.borrow_mut();
        let future_id = state.seq.fetch_add(1, SeqCst);

        Query {
            key: self.key.clone(),
            conf: self.conf.clone(),
            kad: self.kad.clone(),
            state: self.state.clone(),
            future_id,
            future_state: self.future_state.clone(),
        }
    }
}

impl<N, D> Drop for Query<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    fn drop(&mut self) {
        let mut fut_state = self.future_state.borrow_mut();
        fut_state.waker_map.remove(&self.future_id);
    }
}

impl<N, D> Future for Query<N, D>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
    D: NodeData + 'static,
{
    type Output = QueryValue<N, D>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut futures::task::Context<'_>) -> Poll<Self::Output> {
        if let QueryState::Finished { result } = &*self.state.borrow() {
            return Poll::Ready(result.clone());
        }

        let mut fut_state = self.future_state.borrow_mut();
        fut_state
            .waker_map
            .insert(self.future_id, cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Debug)]
pub(crate) enum QueryState<N: KeyLen, D: NodeData> {
    InProgress {
        started_at: i64,
        iterations: usize,
        pending: HashSet<Key<N>>,
        candidates: Vec<Node<N, D>>,
        closest: Vec<Node<N, D>>,
        sent: HashSet<Key<N>>,
    },
    Finished {
        result: QueryValue<N, D>,
    },
}

impl<N: KeyLen, D: NodeData> Default for QueryState<N, D> {
    fn default() -> Self {
        QueryState::InProgress {
            started_at: Utc::now().timestamp(),
            iterations: 0,
            pending: HashSet::new(),
            candidates: Vec::new(),
            closest: Vec::new(),
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
pub(crate) enum QueryValue<N: KeyLen, D: NodeData> {
    Node(Node<N, D>),
    Neighbors(Vec<Node<N, D>>),
    Value(Vec<u8>),
    None,
}
