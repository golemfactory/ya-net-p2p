use crate::{message, Error, Key, KeyLen, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Node<N: KeyLen> {
    pub key: Key<N>,
    pub address: SocketAddr,
}

impl<N: KeyLen> Node<N> {
    #[inline(always)]
    pub fn distance<O: AsRef<[u8]>>(&self, other: &O) -> Key<N> {
        self.key.distance(other)
    }

    pub fn from_vec(vec: Vec<message::Node>) -> Vec<Self> {
        vec.into_iter()
            .map(Node::<N>::try_from)
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
    }
}

impl<N: KeyLen> TryFrom<message::Node> for Node<N> {
    type Error = Error;

    fn try_from(node: message::Node) -> Result<Self> {
        if node.key.len() > N::to_usize() {
            return Err(Error::InvalidKeyLength(node.key.len()));
        }

        Ok(Node {
            key: Key::<N>::try_from(node.key)?,
            address: match node.ip {
                Some(node_ip) => match node_ip {
                    message::node::Ip::V4(ip) => {
                        SocketAddr::from((Ipv4Addr::from(ip), node.port as u16))
                    }
                    message::node::Ip::V6(v6) => {
                        let mut ip = (v6.hi as u128) << 64;
                        ip |= v6.lo as u128;
                        SocketAddr::from((Ipv6Addr::from(ip), node.port as u16))
                    }
                },
                None => return Err(Error::property("Node", "Missing ip")),
            },
        })
    }
}

impl<N: KeyLen> From<Node<N>> for message::Node {
    fn from(node: Node<N>) -> Self {
        message::Node {
            ip: match node.address.ip() {
                IpAddr::V4(v4) => {
                    let ip: u32 = v4.into();
                    Some(message::node::Ip::V4(ip))
                }
                IpAddr::V6(v6) => {
                    let ip: u128 = v6.into();
                    let hi = (ip >> 64) as u64;
                    let lo = ip as u64;
                    Some(message::node::Ip::V6(message::IpV6 { hi, lo }))
                }
            },
            port: node.address.port() as u32,
            key: node.key.to_vec(),
        }
    }
}

impl<N: KeyLen> AsRef<[u8]> for Node<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl<N: KeyLen> std::fmt::Display for Node<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Node {{ key: {}, address: {:?} }}",
            self.key, self.address
        ))
    }
}
