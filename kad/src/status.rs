use super::Result;
use crate::{KeyLen, Node, NodeData};
use actix::Message;
use serde::{Deserialize, Serialize};

#[derive(Message)]
#[rtype(result = "Result<KadStatus>")]
pub struct QueryKadStatus {
    query_dht: bool,
}

impl Default for QueryKadStatus {
    fn default() -> Self {
        QueryKadStatus { query_dht: false }
    }
}

impl QueryKadStatus {
    pub fn with_dht(self) -> Self {
        QueryKadStatus {
            query_dht: true,
            ..self
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KadStatus {
    pub host_node: KadStatusNodeInfo,
    pub nodes: Vec<KadStatusNodeInfo>,
    pub local_storage: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KadStatusNodeInfo {
    pub data: serde_json::Value,
    pub key: String,
}

impl KadStatusNodeInfo {
    pub(crate) fn from_node<N: KeyLen, D: NodeData>(node: &Node<N, D>) -> Self {
        let key = hex::encode(&node.key);
        let data = serde_json::to_value(&node.data).unwrap();
        KadStatusNodeInfo { data, key }
    }
}
