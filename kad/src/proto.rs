use crate::table::Table;
use crate::{message, Error, LocalAdd, LocalStore};
use crate::{KadMessage, KadMessageIn, Key, KeyLen, Node, Result};
use actix::prelude::*;
use chrono::Utc;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt};
use generic_array::ArrayLength;
use rand::RngCore;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;

const BUCKET_SIZE: usize = 20;
const MAX_KEY_SZ: usize = 33;
const MAX_VALUE_SZ: usize = 65536;
const MAX_VALUES_TO_SEND: usize = 100;
const MAX_TTL: u32 = 604800;
const MAX_REQ_TTL: i64 = 300;

pub struct Kad<N: KeyLen> {
    table: Table<N>,
    storage: HashMap<Vec<u8>, (message::Value, i64)>,
    tx: mpsc::Sender<KadMessage>,
}

impl<N: KeyLen> Kad<N> {
    pub fn new(me: Arc<Node<N>>, tx: mpsc::Sender<KadMessage>) -> Self {
        Self {
            table: Table::new(me, BUCKET_SIZE),
            storage: HashMap::new(),
            tx,
        }
    }

    pub fn keys_to_refresh(&self) -> Vec<Key<N>> {
        self.table
            .stale_buckets()
            .into_iter()
            .map(|b| Key::<N>::random(&b.range))
            .collect()
    }

    fn values_to_transfer(&self, _: &Node<N>) -> Vec<message::Value> {
        Vec::new()
    }
}

impl<N: KeyLen> Kad<N> {
    fn find_node(&self, key: &Key<N>, excluded: Option<&Key<N>>) -> Vec<Node<N>> {
        let mut nodes = self.table.neighbors(&key, excluded);
        if key == &self.table.me.key {
            nodes.push((*self.table.me).clone());
        }
        nodes
    }

    fn find_value(&mut self, key: &Vec<u8>) -> Option<message::Value> {
        let now = Utc::now().timestamp();
        self.storage
            .retain(|_, (value, created_at)| value.ttl as i64 + *created_at > now);

        match self.storage.get(key) {
            Some((value, created_at)) => Some(message::Value {
                value: value.value.clone(),
                ttl: value.ttl - (now - created_at) as u32,
            }),
            None => None,
        }
    }
}

//     def transferKeyValues(self, node):
//         """
//         Given a new node, send it all the keys/values it should be storing.
//         @param node: A new node that just joined (or that we just found out
//         about).
//         Process:
//         For each key in storage, get k closest nodes.  If newnode is closer
//         than the furtherst in that list, and the node for this server
//         is closer than the closest in that list, then store the key/value
//         on the new node (per section 2.5 of the paper)
//         """
//         def send_values(inv_list):
//             values = []
//             if inv_list[0]:
//                 for requested_inv in inv_list[1]:
//                     try:
//                         i = objects.Inv()
//                         i.ParseFromString(requested_inv)
//                         value = self.storage.getSpecific(i.keyword, i.valueKey)
//                         if value is not None:
//                             v = objects.Value()
//                             v.keyword = i.keyword
//                             v.valueKey = i.valueKey
//                             v.serializedData = value
//                             v.ttl = int(round(self.storage.get_ttl(i.keyword, i.valueKey)))
//                             values.append(v.SerializeToString())
//                     except Exception:
//                         pass
//                 if len(values) > 0:
//                     self.callValues(node, values)
//
//         inv = []
//         for keyword in self.storage.iterkeys():
//             keyword = keyword[0].decode("hex")
//             keynode = Node(keyword)
//             neighbors = self.router.findNeighbors(keynode, exclude=node)
//             if len(neighbors) > 0:
//                 newNodeClose = node.distanceTo(keynode) < neighbors[-1].distanceTo(keynode)
//                 thisNodeClosest = self.sourceNode.distanceTo(keynode) < neighbors[0].distanceTo(keynode)
//             if len(neighbors) == 0 \
//                     or (newNodeClose and thisNodeClosest) \
//                     or (thisNodeClosest and len(neighbors) < self.ksize):
//                 # pylint: disable=W0612
//                 for k, v in self.storage.iteritems(keyword):
//                     i = objects.Inv()
//                     i.keyword = keyword
//                     i.valueKey = k
//                     inv.append(i.SerializeToString())
//         if len(inv) > 100:
//             random.shuffle(inv)
//         if len(inv) > 0:
//             self.callInv(node, inv[:100]).addCallback(send_values)

impl<N: KeyLen> Actor for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Context = Context<Self>;
}

impl<N: KeyLen> Handler<KadMessageIn<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: KadMessageIn<N>, ctx: &mut Context<Self>) -> Self::Result {
        let address = ctx.address();
        let mut tx = self.tx.clone();

        let fut = match msg.inner.clone() {
            KadMessage::FindNode(m) => self.handle_find_node(m, &msg.sender.key).boxed_local(),
            KadMessage::FindNodeResult(m) => self.handle_find_node_result().boxed_local(),
            KadMessage::FindValue(m) => self.handle_find_value(m, &msg.sender.key).boxed_local(),
            KadMessage::FindValueResult(m) => self.handle_find_value_result().boxed_local(),
            KadMessage::Store(m) => self.handle_store(m, address.clone()).boxed_local(),
            KadMessage::Ping(m) => self.handle_ping(m).boxed_local(),
            _ => async move { Ok(None) }.boxed_local(),
        };

        let fut = async move {
            address.send(LocalAdd(msg.sender, msg.new_conn)).await??;
            if let Some(reply) = fut.await? {
                tx.send(reply).await?;
            }
            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

type HandlerResult = Result<Option<KadMessage>>;

impl<N> Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    #[inline]
    fn handle_ping(&mut self, msg: message::Ping) -> impl Future<Output = HandlerResult> {
        async move {
            Ok(Some(KadMessage::Pong(message::Pong {
                rand_val: msg.rand_val,
            })))
        }
    }

    #[inline]
    fn handle_store(
        &mut self,
        msg: message::Store,
        address: Addr<Self>,
    ) -> impl Future<Output = HandlerResult> {
        async move {
            let value = msg.value.ok_or(Error::message("Store: missing 'value'"))?;
            address.send(LocalStore(msg.key, value)).await??;
            Ok(None)
        }
    }

    #[inline]
    fn handle_find_node(
        &mut self,
        msg: message::FindNode,
        exclude: &Key<N>,
    ) -> impl Future<Output = HandlerResult> {
        let rand_val = msg.rand_val;
        let nodes = match Key::<N>::try_from(msg.key) {
            Ok(key) => Ok(self.find_node(&key, Some(exclude))),
            Err(e) => Err(e),
        };

        async move {
            Ok(Some(KadMessage::FindNodeResult(message::FindNodeResult {
                rand_val,
                nodes: nodes?.into_iter().map(Node::into).collect(),
            })))
        }
    }

    #[inline]
    fn handle_find_node_result(&mut self) -> impl Future<Output = HandlerResult> {
        async move { HandlerResult::Ok(None) }
    }

    #[inline]
    fn handle_find_value(
        &mut self,
        msg: message::FindValue,
        exclude: &Key<N>,
    ) -> impl Future<Output = HandlerResult> {
        use message::find_value_result::Result as Response;

        let reply = if let Some(value) = self.find_value(&msg.key) {
            Ok(message::FindValueResult {
                rand_val: msg.rand_val,
                result: Some(Response::Value(value)),
            })
        } else {
            match Key::<N>::try_from(msg.key) {
                Ok(key) => {
                    let nodes = self.find_node(&key, Some(exclude));
                    Ok(message::FindValueResult {
                        rand_val: msg.rand_val,
                        result: Some(Response::Nodes(message::Nodes {
                            nodes: nodes.into_iter().map(Node::into).collect(),
                        })),
                    })
                }
                Err(e) => Err(e),
            }
        };

        async move { Ok(Some(KadMessage::FindValueResult(reply?))) }
    }

    #[inline]
    fn handle_find_value_result(&mut self) -> impl Future<Output = HandlerResult> {
        async move { Ok(None) }
    }
}

impl<N> Handler<LocalAdd<N>> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: LocalAdd<N>, _: &mut Context<Self>) -> Self::Result {
        let node = msg.0;
        let new_conn = msg.1;
        let mut tx = self.tx.clone();

        let action = if !self.table.add(&node) {
            Some(KadMessage::Ping(message::Ping {
                rand_val: rand::thread_rng().next_u32(),
            }))
        } else if new_conn {
            let values = self.values_to_transfer(&node);
            // match values.len() {
            //     0 => None,
            //     _ => Some(KadMessage::Store(node.clone(), values)),
            // }
            None
        } else {
            None
        };

        let fut = async move {
            if let Some(a) = action {
                tx.send(a).await?;
            }
            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
}

impl<N> Handler<LocalStore> for Kad<N>
where
    N: KeyLen + Unpin + 'static,
    <N as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = <LocalStore as Message>::Result;

    fn handle(&mut self, msg: LocalStore, _: &mut Context<Self>) -> Self::Result {
        if msg.0.len() > MAX_KEY_SZ {
            return Err(Error::property(
                "Store",
                format!("key size > {}", MAX_KEY_SZ),
            ));
        }
        if msg.1.value.len() > MAX_VALUE_SZ {
            return Err(Error::property(
                "Store",
                format!("value size > {}", MAX_VALUE_SZ),
            ));
        }
        if msg.1.ttl > MAX_TTL {
            return Err(Error::property("Store", format!("ttl > {}", MAX_TTL)));
        }

        self.storage.insert(msg.0, (msg.1, Utc::now().timestamp()));
        Ok(())
    }
}
