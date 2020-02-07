use crate::{message, Error, Key, KeyOps};
use generic_array::ArrayLength;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Hash, Eq, Deserialize, Serialize)]
pub struct Node<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    pub key: Key<KeySz>,
    pub address: SocketAddr,
}

impl<KeySz> Node<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    #[inline(always)]
    pub fn distance(&self, other: &Self) -> Key<KeySz> {
        self.key.distance(&other.key)
    }
}

impl<KeySz> Clone for Node<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Node {
            key: self.key.clone(),
            address: self.address.clone(),
        }
    }
}

impl<KeySz> std::fmt::Debug for Node<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Node {{ key: {}, address: {:?} }}",
            hex::encode(&self.key),
            self.address
        ))
    }
}

impl<KeySz> PartialEq for Node<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.address == other.address
    }
}

impl<KeySz> TryFrom<message::Node> for Node<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(node: message::Node) -> Result<Self, Self::Error> {
        if node.key.len() > KeySz::to_usize() {
            return Err(Error::InvalidKeyLength(node.key.len()));
        }

        Ok(Node {
            key: Key::<KeySz>::try_from_vec(node.key)?,
            address: match node.ip {
                Some(node_ip) => match node_ip {
                    message::node::Ip::V4(ip) => {
                        SocketAddr::from(SocketAddrV4::new(ip.into(), node.port as u16))
                    }
                    message::node::Ip::V6(v6) => {
                        let mut ip = (v6.hi << 64) as u128;
                        ip |= v6.lo as u128;

                        SocketAddr::from(SocketAddrV6::new(ip.into(), node.port as u16, 0, 0))
                    }
                },
                None => return Err(Error::InvalidProperty("ip missing".to_owned())),
            },
        })
    }
}

impl<KeySz> From<Node<KeySz>> for message::Node
where
    KeySz: ArrayLength<u8>,
{
    fn from(node: Node<KeySz>) -> Self {
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
