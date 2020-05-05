use crate::{message, Error, Key, KeyLen, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

pub trait NodeData: Send + Unpin + Serialize + Clone + Debug {}
impl<D> NodeData for D where D: Send + Unpin + Serialize + Clone + Debug {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Node<N: KeyLen, D: NodeData> {
    pub key: Key<N>,
    pub data: D,
}

impl<N: KeyLen, D: NodeData> Node<N, D> {
    #[inline(always)]
    pub fn distance<O: AsRef<[u8]>>(&self, other: &O) -> Key<N> {
        self.key.distance(other)
    }
}

impl<N: KeyLen, D: NodeData + DeserializeOwned> Node<N, D> {
    pub fn from_vec(vec: Vec<message::Node>) -> Vec<Self> {
        vec.into_iter()
            .map(Node::<N, D>::try_from)
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
    }
}

impl<N: KeyLen, D: NodeData + DeserializeOwned> TryFrom<message::Node> for Node<N, D> {
    type Error = Error;

    fn try_from(node: message::Node) -> Result<Self> {
        if node.key.len() > N::to_usize() {
            return Err(Error::InvalidKeyLength(node.key.len()));
        }

        Ok(Node {
            key: Key::<N>::try_from(node.key)?,
            data: rmp_serde::from_read(node.data.as_slice()).map_err(|_| Error::InvalidNodeData)?,
        })
    }
}

impl<N: KeyLen, D: NodeData> From<Node<N, D>> for message::Node {
    fn from(node: Node<N, D>) -> Self {
        message::Node {
            key: node.key.to_vec(),
            data: rmp_serde::to_vec(&node.data).unwrap(),
        }
    }
}

impl<N: KeyLen, D: NodeData> Eq for Node<N, D> {}
impl<N: KeyLen, D: NodeData> PartialEq for Node<N, D> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<N: KeyLen, D: NodeData> Hash for Node<N, D> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl<N: KeyLen, D: NodeData> AsRef<[u8]> for Node<N, D> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl<N: KeyLen, D: NodeData> std::fmt::Display for Node<N, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Node {{ key: {}, data: {:?} }}",
            self.key, self.data
        ))
    }
}
