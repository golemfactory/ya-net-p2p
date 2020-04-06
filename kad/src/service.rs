use crate::event::*;
use crate::query::*;
use crate::*;
use actix::prelude::*;
use chrono::Utc;
use futures::channel::mpsc;
use futures::{Future, FutureExt, SinkExt};
use generic_array::ArrayLength;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct KadConfig {
    pub name: String,
    pub max_key_sz: usize,
    pub max_val_sz: usize,
    pub val_ttl: u32,
    pub req_ttl: i64,
    pub qry_ttl: i64,
    pub req_upkeep_freq: Duration,
    pub sto_upkeep_freq: Duration,
    pub qry_upkeep_freq: Duration,
    pub tab_upkeep_freq: Duration,
}

impl KadConfig {
    pub fn with_name(name: impl ToString) -> Self {
        let mut conf = Self::default();
        conf.name = name.to_string();
        conf
    }
}

impl Default for KadConfig {
    fn default() -> Self {
        KadConfig {
            name: "Kad".to_owned(),
            max_key_sz: 33,
            max_val_sz: 65535,
            val_ttl: 604800,
            req_ttl: 5,
            qry_ttl: 30,
            req_upkeep_freq: Duration::from_secs(2),
            sto_upkeep_freq: Duration::from_secs(60),
            qry_upkeep_freq: Duration::from_secs(3),
            tab_upkeep_freq: Duration::from_secs(60),
        }
    }
}

pub struct Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    conf: KadConfig,
    me: Node<N>,
    table: Table<N>,
    storage: HashMap<Vec<u8>, (message::Value, i64)>,
    queries: HashMap<Vec<u8>, (Query<N>, i64)>,
    requests: HashMap<u32, (KadMessage, Key<N>, i64)>,
    tx: mpsc::Sender<KadEvtSend<N>>,
}

impl<N> Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    pub fn new(me: Node<N>, tx: mpsc::Sender<KadEvtSend<N>>) -> Self {
        Self::with_conf(KadConfig::default(), me, tx)
    }

    pub fn with_conf(conf: KadConfig, me: Node<N>, tx: mpsc::Sender<KadEvtSend<N>>) -> Self {
        let key = me.key.clone();
        Self {
            conf,
            me,
            table: Table::new(key, N::to_usize()),
            storage: HashMap::new(),
            queries: HashMap::new(),
            requests: HashMap::new(),
            tx,
        }
    }

    #[inline]
    fn storage_upkeep(&mut self, _: &mut Context<Self>) {
        let now = Utc::now().timestamp();
        self.storage
            .retain(|_, (value, created_at)| value.ttl as i64 + *created_at > now);
    }

    #[inline]
    fn request_upkeep(&mut self, _: &mut Context<Self>) {
        let mut to_remove = HashSet::new();
        let ttl = self.conf.req_ttl;
        let now = Utc::now().timestamp();

        self.requests.retain(|_, (_, key, created_at)| {
            if now - *created_at < ttl {
                true
            } else {
                to_remove.insert(key.clone());
                false
            }
        });

        to_remove.iter().for_each(|k| self.table.remove(k));
    }

    #[inline]
    fn query_upkeep(&mut self, _: &mut Context<Self>) {
        let ttl = self.conf.qry_ttl;
        let now = Utc::now().timestamp();

        self.queries.retain(|_, (query, created_at)| {
            if now - *created_at >= ttl {
                query.finish(QueryValue::None);
            } else {
                query.iterate();
            }
            query.in_progress()
        });
    }

    #[inline]
    fn table_upkeep(&mut self, ctx: &mut Context<Self>) {
        let address = ctx.address();
        self.table.stale_buckets().into_iter().for_each(|i| {
            let key = Key::<N>::random(i);
            let neighbors = self.table.neighbors(&key, Some(&key), Some(ALPHA));

            log::debug!(
                "{} table refresh: querying {} ({} nodes)",
                self.conf.name,
                key,
                neighbors.len()
            );
            self.initiate_query(QueryKey::Node(key.to_vec()), neighbors, address.clone());
        });
    }
}

impl<N> Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    fn find_node(&self, key: &Key<N>, excluded: Option<&Key<N>>) -> Vec<Node<N>> {
        let mut nodes = self.table.neighbors(&key, excluded, None);
        if key == &self.me.key {
            if nodes.len() == self.table.bucket_size {
                nodes.remove(nodes.len() - 1);
            }
            nodes.insert(0, self.me.clone());
        }
        nodes
    }

    fn find_value(&mut self, key: &Vec<u8>) -> Option<message::Value> {
        if let Some((value, created_at)) = self.storage.get(key) {
            let lifetime = value.ttl as i64 - (Utc::now().timestamp() - created_at);
            if lifetime > 0 {
                return Some(message::Value {
                    value: value.value.clone(),
                    ttl: lifetime as u32,
                });
            }
        }
        None
    }

    fn find_query(&mut self, rand_val: u32) -> Result<Query<N>> {
        let key_opt = self
            .requests
            .remove(&rand_val)
            .map(|(m, _, _)| m.queried_key())
            .flatten();

        let key = match key_opt {
            Some(key) => key,
            None => return Err(Error::request(rand_val)),
        };

        match self.queries.get(&key) {
            Some((query, _)) => Ok(query.clone()),
            None => Err(Error::query(&key)),
        }
    }

    fn initiate_query(
        &mut self,
        query_key: QueryKey,
        nodes: Vec<Node<N>>,
        address: Addr<Self>,
    ) -> Query<N> {
        if let Some((query, _)) = self.queries.get(query_key.as_ref()) {
            return query.clone();
        }

        let mut query = self
            .queries
            .entry(query_key.to_vec())
            .or_insert((
                Query::new(
                    query_key,
                    &nodes,
                    address,
                    self.table.bucket_size,
                    self.conf.req_ttl,
                ),
                Utc::now().timestamp(),
            ))
            .0
            .clone();

        query.iterate();
        query
    }
}

impl<N> Actor for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.sto_upkeep_freq, Self::storage_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.qry_upkeep_freq, Self::query_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.req_upkeep_freq, Self::request_upkeep)
            .finish()
            .spawn(ctx);
        IntervalFunc::new(self.conf.tab_upkeep_freq, Self::table_upkeep)
            .finish()
            .spawn(ctx);

        log::info!("{} ({}) service started", self.conf.name, self.me.key);
    }
}

impl<N> Handler<KadEvtBootstrap<N>> for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: KadEvtBootstrap<N>, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("{} bootstrapping", self.conf.name);

        self.table.extend(msg.nodes.iter());

        let fut = if msg.dormant {
            async move {
                // do nothing
                Ok(())
            }
            .left_future()
        } else {
            let query = self.initiate_query(
                QueryKey::Node(self.me.key.to_vec()),
                msg.nodes.clone(),
                ctx.address(),
            );

            async move {
                query.await;
                Ok(())
            }
            .right_future()
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<KadEvtReceive<N>> for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: KadEvtReceive<N>, ctx: &mut Context<Self>) -> Self::Result {
        log::trace!("{} rx {} from {}", self.conf.name, evt.message, evt.from);

        let address = ctx.address();
        let (from, _new, msg) = (evt.from, evt.new, evt.message);

        let evt_opt = if !self.table.add(&from) {
            // match self.table.bucket_oldest(&from.key) {
            //     Some(node) => {
            //         if from.key != node.key {
            //             Some(EvtSend::new(
            //                 node,
            //                 KadMessage::from(message::Ping {
            //                     rand_val: rand::thread_rng().next_u32(),
            //                 }),
            //             ))
            //         } else {
            //             None
            //         }
            //     }
            //     _ => None,
            // }
            Option::<EvtSend<N>>::None
        // TODO: } else if new { transfer_values(..)
        } else {
            None
        };

        let handler_fut = match msg {
            KadMessage::FindNode(m) => self.handle_find_node(m, &from.key).boxed_local(),
            KadMessage::FindNodeResult(m) => self.handle_node_result(m, &from.key).boxed_local(),
            KadMessage::FindValue(m) => self.handle_find_value(m, &from.key).boxed_local(),
            KadMessage::FindValueResult(m) => self.handle_value_result(m, &from.key).boxed_local(),
            KadMessage::Store(m) => self.handle_store(m).boxed_local(),
            KadMessage::Ping(m) => self.handle_ping(m).boxed_local(),
            KadMessage::Pong(m) => self.handle_pong(m).boxed_local(),
        };

        let fut = async move {
            if let Some(evt) = evt_opt {
                address.send(evt).await??;
            }
            if let Some(msg) = handler_fut.await? {
                address.send(EvtSend::new(from, msg)).await??;
            }
            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

type HandleMsgResult = Result<Option<KadMessage>>;

impl<N> Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    #[inline]
    fn handle_ping(&mut self, msg: message::Ping) -> impl Future<Output = HandleMsgResult> {
        async move {
            Ok(Some(KadMessage::from(message::Pong {
                rand_val: msg.rand_val,
            })))
        }
    }

    #[inline]
    fn handle_pong(&mut self, msg: message::Pong) -> impl Future<Output = HandleMsgResult> {
        self.requests.remove(&msg.rand_val);
        async move { Ok(None) }
    }

    #[inline]
    fn handle_store(&mut self, msg: message::Store) -> impl Future<Output = HandleMsgResult> {
        fn validate(msg: &message::Store, conf: &KadConfig) -> Result<()> {
            let value = match msg.value {
                Some(ref value) => value,
                None => return Err(Error::property("Store", "value")),
            };
            if msg.key.len() > conf.max_key_sz {
                return Err(Error::property("Store", "key"));
            }
            if value.value.len() > conf.max_val_sz {
                return Err(Error::property("Store", "value"));
            }
            if value.ttl > conf.val_ttl {
                return Err(Error::property("Store", "ttl"));
            }
            Ok(())
        }

        let value = match validate(&msg, &self.conf) {
            Ok(_) => msg.value.unwrap(),
            Err(error) => return error.fut().left_future(),
        };
        let now = Utc::now().timestamp();
        self.storage.insert(msg.key, (value, now));

        async move { Ok(None) }.right_future()
    }

    #[inline]
    fn handle_find_node(
        &mut self,
        msg: message::FindNode,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let rand_val = msg.rand_val;
        let nodes = match Key::<N>::try_from(msg.key) {
            Ok(key) => self.find_node(&key, Some(from)),
            Err(error) => return error.fut().left_future(),
        };

        async move {
            Ok(Some(KadMessage::from(message::FindNodeResult {
                rand_val,
                nodes: nodes.into_iter().map(Node::into).collect(),
            })))
        }
        .right_future()
    }

    #[inline]
    fn handle_node_result(
        &mut self,
        msg: message::FindNodeResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let mut nodes = Node::from_vec(msg.nodes);
        let fut = async move { Ok(None) }.right_future();

        match self.find_query(msg.rand_val) {
            Ok(mut query) => {
                if !query.in_progress() {
                    return fut;
                }

                log::debug!(
                    "{} rx nodes ({}) from {} for node query: {}",
                    self.conf.name,
                    nodes.len(),
                    from,
                    Key::<N>::fmt_key(&query.key),
                );

                self.table.extend(nodes.iter());

                if query.key.as_ref() == self.me.key.as_ref() {
                    nodes.extend(self.table.distant_nodes(&self.me.key).into_iter());
                    query.feed(nodes, Some(from));
                } else {
                    let node_idx = nodes
                        .iter()
                        .position(|n| n.key.as_ref() == query.key.as_ref());

                    if let Some(idx) = node_idx {
                        query.finish(QueryValue::Node(nodes[idx].clone()));
                    } else {
                        query.feed(nodes, Some(from));
                    }
                }
            }
            Err(error) => match error {
                Error::InvalidQuery(_) => {
                    log::debug!("{} rx nodes ({})", self.conf.name, nodes.len());
                    self.table.extend(nodes.iter());
                }
                _ => {
                    log::error!("{}", error);
                    return error.fut().left_future();
                }
            },
        };

        fut
    }

    #[inline]
    fn handle_find_value(
        &mut self,
        msg: message::FindValue,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        use message::find_value_result::Result as Response;

        let reply = match self.find_value(&msg.key) {
            Some(value) => message::FindValueResult {
                rand_val: msg.rand_val,
                result: Some(Response::Value(value)),
            },
            None => match Key::<N>::try_from(msg.key) {
                Ok(key) => message::FindValueResult {
                    rand_val: msg.rand_val,
                    result: Some(Response::Nodes(message::Nodes {
                        nodes: self
                            .find_node(&key, Some(from))
                            .into_iter()
                            .map(Node::into)
                            .collect(),
                    })),
                },
                Err(e) => return e.fut().left_future(),
            },
        };

        async move { Ok(Some(KadMessage::from(reply))) }.right_future()
    }

    #[inline]
    fn handle_value_result(
        &mut self,
        msg: message::FindValueResult,
        from: &Key<N>,
    ) -> impl Future<Output = HandleMsgResult> {
        let mut query = match self.find_query(msg.rand_val) {
            Ok(query) => query,
            Err(error) => return error.fut().left_future(),
        };

        let fut = async move { Ok(None) }.right_future();
        if !query.in_progress() {
            return fut;
        }

        let result = match msg.result {
            Some(result) => result,
            None => return Error::property("result", "missing").fut().left_future(),
        };

        match result {
            message::find_value_result::Result::Nodes(res) => {
                log::debug!(
                    "{} rx nodes for value query: {:?}",
                    self.conf.name,
                    query.key
                );
                let nodes = Node::from_vec(res.nodes);
                self.table.extend(nodes.iter());

                query.feed(nodes, Some(from));
            }
            message::find_value_result::Result::Value(res) => {
                log::debug!(
                    "{} rx value for value query: {:?}",
                    self.conf.name,
                    query.key
                );

                query.finish(QueryValue::Value(res.value));
            }
        }

        fut
    }
}

impl<N> Handler<KadEvtFindNode<N>> for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, Option<Node<N>>, Error>;

    fn handle(&mut self, msg: KadEvtFindNode<N>, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("{} find node request: {}", self.conf.name, msg.key);

        if self.me.key == msg.key {
            return ActorResponse::reply(Ok(Some(self.me.clone())));
        }
        if let Some(node) = self.table.get(&msg.key) {
            return ActorResponse::reply(Ok(Some(node.clone())));
        }

        let key = QueryKey::Node(msg.key.to_vec());
        let nodes = self.find_node(&msg.key, None);
        let query = self.initiate_query(key, nodes, ctx.address());

        let fut = async move {
            match query.await {
                QueryValue::Node(val) => Ok(Some(val)),
                _ => Ok(None),
            }
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<KadEvtFindValue> for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, Option<(Vec<u8>, Vec<u8>)>, Error>;

    fn handle(&mut self, msg: KadEvtFindValue, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!(
            "{} find value request: {}",
            self.conf.name,
            Key::<N>::fmt_key(&msg.key)
        );

        if let Some(msg_value) = self.find_value(&msg.key) {
            return ActorResponse::reply(Ok(Some((msg.key, msg_value.value.clone()))));
        }
        let node_key = match Key::<N>::try_from(msg.key.clone()) {
            Ok(key) => key,
            Err(error) => return ActorResponse::reply(Err(error)),
        };

        let key = QueryKey::Value(msg.key.clone());
        let nodes = self.find_node(&node_key, None);
        let query = self.initiate_query(key, nodes, ctx.address());
        let fut = async move {
            match query.await {
                QueryValue::Value(val) => Ok(Some((msg.key, val))),
                _ => Ok(None),
            }
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<EvtSend<N>> for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: EvtSend<N>, _: &mut Context<Self>) -> Self::Result {
        // Transform port for non-UDP & fixed-port operating mode?
        log::trace!("{} tx {} to {}", self.conf.name, evt.message, evt.to);

        if evt.message.is_request() {
            self.requests.insert(
                evt.message.rand_val(),
                (
                    evt.message.clone(),
                    evt.to.key.clone(),
                    Utc::now().timestamp(),
                ),
            );
        }

        let me = self.me.clone();
        let mut tx = self.tx.clone();

        let fut = async move {
            tx.send(KadEvtSend {
                from: me,
                to: evt.to,
                message: evt.message,
            })
            .await
            .map_err(Error::from)
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<EvtAddressChanged> for Kad<N>
where
    N: KeyLen + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = <EvtAddressChanged as Message>::Result;

    fn handle(&mut self, evt: EvtAddressChanged, _: &mut Context<Self>) -> Self::Result {
        log::debug!(
            "{} address changed from {:?} to {:?}",
            self.conf.name,
            self.me.address,
            evt.address
        );

        std::mem::replace(&mut self.me.address, evt.address);
        Ok(())
    }
}
