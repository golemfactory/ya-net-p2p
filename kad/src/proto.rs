use crate::message;
use crate::model::*;
use crate::table::Table;
use crate::Error;
use crate::{KadAction, Key, KeyGen, KeyOps, Node};
use actix::prelude::*;
use chrono::Utc;
use futures::channel::mpsc;
use futures::SinkExt;
use generic_array::ArrayLength;
use std::collections::HashMap;
use std::sync::Arc;

const MAX_KEY_SZ: usize = 33;
const MAX_VALUE_SZ: usize = 65536;
const MAX_VALUES_TO_SEND: usize = 100;
const MAX_TTL: u32 = 604800;

pub struct Kad<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    table: Table<KeySz>,
    storage: HashMap<Vec<u8>, Vec<(message::Storage, i64)>>,
    tx: mpsc::Sender<KadAction<KeySz>>,
}

impl<KeySz> Kad<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    pub fn create(me: Arc<Node<KeySz>>, size: usize) -> (Self, mpsc::Receiver<KadAction<KeySz>>) {
        let (tx, rx) = mpsc::channel(64);
        (
            Self {
                table: Table::new(me, size),
                storage: HashMap::new(),
                tx,
            },
            rx,
        )
    }

    pub fn keys_to_refresh(&self) -> Vec<Key<KeySz>> {
        self.table
            .stale_buckets()
            .into_iter()
            .map(|b| Key::<KeySz>::random_within(&b.range))
            .collect()
    }

    fn values_to_transfer(&self, _: &Node<KeySz>) -> Result<Vec<message::Storage>, Error> {
        Ok(Vec::new())
    }

    fn find_nodes(&self, key: &Key<KeySz>, excluded: Option<&Key<KeySz>>) -> Vec<Node<KeySz>> {
        let mut nodes = self.table.neighbors(&key, excluded);
        if key == &self.table.me.key {
            nodes.push((*self.table.me).clone());
        }
        nodes
    }

    fn collect_values(&mut self, keyword: &Vec<u8>, max: Option<usize>) -> Vec<message::Storage> {
        match self.storage.get_mut(keyword) {
            Some(vec) => {
                let now = Utc::now().timestamp();
                vec.retain(|(storage, created_at)| storage.ttl as i64 + *created_at > now);

                let iter = vec.iter().map(|(s, _)| s.clone());
                match max {
                    Some(max) => iter.take(max).collect(),
                    None => iter.collect(),
                }
            }
            None => Vec::new(),
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

macro_rules! actor_response {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => return actix::ActorResponse::reply(Err(error)),
        }
    };
}

impl<KeySz> Actor for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Context = Context<Self>;
}

impl<KeySz> Handler<Ping<KeySz>> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, message::Pong, Error>;

    fn handle(&mut self, msg: Ping<KeySz>, ctx: &mut Context<Self>) -> Self::Result {
        let address = ctx.address();

        ActorResponse::r#async(
            async move {
                address.send(LocalAdd(msg.sender, msg.new_conn)).await??;

                Ok(message::Pong {
                    rand_val: msg.inner.rand_val,
                })
            }
            .into_actor(self),
        )
    }
}

impl<KeySz> Handler<Pong<KeySz>> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: Pong<KeySz>, ctx: &mut Context<Self>) -> Self::Result {
        let address = ctx.address();

        ActorResponse::r#async(
            async move {
                address.send(LocalAdd(msg.sender, msg.new_conn)).await??;

                Ok(())
            }
            .into_actor(self),
        )
    }
}

impl<KeySz> Handler<Store<KeySz>> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: Store<KeySz>, ctx: &mut Context<Self>) -> Self::Result {
        let address = ctx.address();

        ActorResponse::r#async(
            async move {
                address.send(LocalAdd(msg.sender, msg.new_conn)).await??;

                let msg = msg.inner;
                let storage = msg
                    .storage
                    .ok_or(Error::InvalidMessage("storage missing".to_owned()))?;

                if msg.keyword.len() > KeySz::to_usize() {
                    return Err(Error::InvalidProperty("keyword".to_owned()));
                }

                if storage.key.len() > MAX_KEY_SZ
                    || storage.value.len() > MAX_VALUE_SZ
                    || storage.ttl > MAX_TTL
                {
                    return Err(Error::InvalidProperty("storage".to_owned()));
                }

                address.send(LocalStore(msg.keyword, storage)).await??;
                Ok(())
            }
            .into_actor(self),
        )
    }
}

impl<KeySz> Handler<FindNode<KeySz>> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, message::FindNodeResult, Error>;

    fn handle(&mut self, msg: FindNode<KeySz>, ctx: &mut Context<Self>) -> Self::Result {
        let (sender, new_conn, msg) = (msg.sender, msg.new_conn, msg.inner);
        let rand_val = msg.rand_val;
        let address = ctx.address();

        if msg.key.len() > KeySz::to_usize() {
            return ActorResponse::reply(Err(Error::InvalidKeyLength(msg.key.len())));
        }

        let key = actor_response!(Key::<KeySz>::try_from_vec(msg.key));
        let nodes = self.find_nodes(&key, Some(&sender.key));

        ActorResponse::r#async(
            async move {
                address.send(LocalAdd(sender, new_conn)).await??;

                Ok(message::FindNodeResult {
                    rand_val,
                    nodes: nodes.into_iter().map(Node::into).collect(),
                })
            }
            .into_actor(self),
        )
    }
}

impl<KeySz> Handler<FindValue<KeySz>> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, message::FindValueResult, Error>;

    fn handle(&mut self, msg: FindValue<KeySz>, ctx: &mut Context<Self>) -> Self::Result {
        let (sender, new_conn, msg) = (msg.sender, msg.new_conn, msg.inner);
        let address = ctx.address();

        let result = match self.storage.contains_key(&msg.keyword) {
            true => {
                let values = self.collect_values(&msg.keyword, None);

                message::FindValueResult {
                    rand_val: msg.rand_val,
                    result: Some(message::find_value_result::Result::Values(
                        message::Values { values },
                    )),
                }
            }
            false => {
                let key = actor_response!(Key::<KeySz>::try_from_vec(msg.keyword));
                let nodes = self.find_nodes(&key, Some(&sender.key));

                message::FindValueResult {
                    rand_val: msg.rand_val,
                    result: Some(message::find_value_result::Result::Nodes(message::Nodes {
                        nodes: nodes.into_iter().map(Node::into).collect(),
                    })),
                }
            }
        };

        ActorResponse::r#async(
            async move {
                address.send(LocalAdd(sender, new_conn)).await??;
                Ok(result)
            }
            .into_actor(self),
        )
    }
}

impl<KeySz> Handler<LocalAdd<KeySz>> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: LocalAdd<KeySz>, _: &mut Context<Self>) -> Self::Result {
        let node = msg.0;
        let new_conn = msg.1;
        let mut tx = self.tx.clone();

        let action = if !self.table.add(&node) {
            Some(KadAction::Ping(node.clone()))
        } else if new_conn {
            let values = actor_response!(self.values_to_transfer(&node));
            match values.len() {
                0 => None,
                _ => Some(KadAction::TransferValues(node.clone(), values)),
            }
        } else {
            None
        };

        ActorResponse::r#async(
            async move {
                if let Some(a) = action {
                    if let Err(e) = tx.send(a).await {
                        log::warn!("Unable to add {:?}: {:?}", node, e);
                    }
                }
                Ok(())
            }
            .into_actor(self),
        )
    }
}

impl<KeySz> Handler<LocalStore> for Kad<KeySz>
where
    KeySz: ArrayLength<u8> + Unpin + 'static,
    <KeySz as ArrayLength<u8>>::ArrayType: Unpin,
{
    type Result = <LocalStore as Message>::Result;

    fn handle(&mut self, msg: LocalStore, _: &mut Context<Self>) -> Self::Result {
        let vec = self.storage.entry(msg.0).or_insert(Vec::new());
        vec.push((msg.1, Utc::now().timestamp()));
        Ok(())
    }
}
