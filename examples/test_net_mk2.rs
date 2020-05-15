use actix::prelude::*;
use ethsign::{PublicKey, SecretKey};
use futures::future::LocalBoxFuture;
use futures::FutureExt;
use hashbrown::HashMap;
use itertools::Itertools;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use ya_core_model::ethaddr::NodeId;
use ya_net::crypto::{Signature, SignatureECDSA};
use ya_net::error::{CryptoError, MessageError};
use ya_net::event::ServiceCmd;
use ya_net::packet::CryptoProcessor;
use ya_net::protocol::kad::{KadBootstrapCmd, KadProtocol, NodeDataExt};
use ya_net::protocol::rpc::{NetRpc, NetRpcError, NetRpcProtocol};
use ya_net::protocol::session::SessionProtocol;
use ya_net::transport::laminar::LaminarTransport;
use ya_net::Result;
use ya_net::*;
use ya_net_kad::key_lengths::U64;
use ya_service_bus::{RpcEnvelope, RpcMessage};

type KeySize = U64;
type Key = ya_net_kad::Key<KeySize>;
type Node = ya_net_kad::Node<KeySize, NodeDataExample>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct NodeDataExample {
    addresses: Vec<Address>,
}

impl NodeDataExt for NodeDataExample {
    #[inline]
    fn from_address(address: Address) -> Self {
        NodeDataExample {
            addresses: vec![address],
        }
    }

    #[inline]
    fn primary_address(&self) -> Option<Address> {
        self.addresses.first().cloned()
    }

    #[inline]
    fn addresses(&self) -> Vec<Address> {
        self.addresses.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RpcMessageExample {
    request: String,
}

impl RpcMessage for RpcMessageExample {
    const ID: &'static str = "RpcMessageExample";
    type Item = String;
    type Error = String;
}

#[derive(Clone, Debug)]
struct CryptoExample {
    identities: HashMap<NodeId, (SecretKey, PublicKey)>,
}

impl CryptoExample {
    fn new_identity(&mut self) -> (NodeId, PublicKey) {
        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        let secret = SecretKey::from_raw(&bytes).unwrap();
        let public = secret.public();

        let identity = NodeId::from(public.address().as_ref());
        self.identities
            .insert(identity.clone(), (secret, public.clone()));

        (identity, public)
    }
}

impl Default for CryptoExample {
    fn default() -> Self {
        CryptoExample {
            identities: HashMap::new(),
        }
    }
}

impl Crypto<Key> for CryptoExample {
    const SIGNATURE_SIZE: usize = 32;

    fn encrypt<'a, P: AsRef<[u8]>>(
        &self,
        _key: Key,
        payload: P,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let payload = payload.as_ref().to_vec();
        // FIXME: encrypt
        async move { Ok(payload) }.boxed_local()
    }

    fn decrypt<'a, P: AsRef<[u8]>>(
        &self,
        _key: Key,
        payload: P,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let payload = payload.as_ref().to_vec();
        // FIXME: decrypt
        async move { Ok(payload) }.boxed_local()
    }

    fn sign<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Signature>> {
        let public_key = match PublicKey::from_slice(key.as_ref()) {
            Ok(public_key) => public_key,
            _ => {
                log::error!("Cannot convert key.");
                return async move { Err(Error::key()) }.boxed_local();
            }
        };

        let node_id = NodeId::from(public_key.address().as_ref());
        let secret = match self.identities.get(&node_id) {
            Some(entry) => &entry.0,
            None => {
                log::error!("No key for identity {}", node_id);
                log::error!(
                    "Identities: {:?}",
                    self.identities.keys().collect::<Vec<_>>()
                );
                return futures::future::err(CryptoError::InvalidKey.into()).boxed_local();
            }
        };

        let key = Some(key.as_ref().to_vec());
        let signed = secret
            .sign(payload.as_slice())
            .map(|sig| {
                let mut data = Vec::with_capacity(33);
                data.push(sig.v);
                data.extend_from_slice(&sig.r[..]);
                data.extend_from_slice(&sig.s[..]);
                Signature::ECDSA(SignatureECDSA::P256K1 { data, key })
            })
            .map_err(|e| Error::from(MessageError::Signature(e.to_string())));

        async move { Ok(signed?) }.boxed_local()
    }

    #[inline]
    #[inline]
    fn verify<H: AsRef<[u8]>>(
        &self,
        key: Option<Key>,
        signature: &mut Signature,
        hash: H,
    ) -> Result<bool> {
        crypto::verify_secp256k1(key, signature, hash)
    }
}

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
struct ProtocolMessage<To> {
    to: To,
    message: String,
}

async fn spawn_node<C: Crypto<Key> + 'static>(
    node: Node,
    crypto: C,
) -> anyhow::Result<(
    Addr<Net<Key>>,
    Addr<KadProtocol<KeySize, NodeDataExample>>,
    Addr<NetRpcProtocol<Key>>,
)> {
    let socket_addrs = node
        .data
        .addresses()
        .into_iter()
        .map(|a| a.socket_addr)
        .collect::<Vec<_>>();
    let net = Net::new(socket_addrs).start();

    let auth = CryptoProcessor::new(node.key.clone(), crypto).start();
    let kad = KadProtocol::new(node.clone(), net.clone().recipient()).start();
    let ses = SessionProtocol::new(net.clone().recipient(), net.clone().recipient()).start();
    let rpc = NetRpcProtocol::new(net.clone().recipient()).start();
    let lam = LaminarTransport::<Key>::new(net.clone().recipient()).start();

    log::debug!("Adding manglers... [{}]", node.key);
    net.send(ServiceCmd::AddProcessor(auth.clone().recipient()))
        .await??;
    log::debug!("Setting DHT protocol... [{}]", node.key);
    net.send(ServiceCmd::SetDhtProtocol(kad.clone().recipient()))
        .await??;
    log::debug!("Adding session protocol... [{}]", node.key);
    net.send(ServiceCmd::SetSessionProtocol(ses.clone().recipient()))
        .await??;

    log::debug!("Adding protocols... [{}]", node.key);
    net.send(ServiceCmd::AddProtocol(
        KadProtocol::<KeySize, NodeDataExample>::PROTOCOL_ID,
        kad.clone().recipient(),
    ))
    .await??;
    net.send(ServiceCmd::AddProtocol(
        SessionProtocol::<Key>::PROTOCOL_ID,
        ses.clone().recipient(),
    ))
    .await??;
    net.send(ServiceCmd::AddProtocol(
        NetRpcProtocol::<Key>::PROTOCOL_ID,
        rpc.clone().recipient(),
    ))
    .await??;

    log::debug!("Adding transport... [{}]", node.key);
    net.send(ServiceCmd::AddTransport(
        Address::LAMINAR,
        lam.clone().recipient(),
    ))
    .await??;

    log::debug!("{} spawned", node);
    Ok((net, kad, rpc))
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    env::set_var(
        "RUST_LOG",
        env::var("RUST_LOG").unwrap_or("debug".to_string()),
    );
    env_logger::init();

    let node_count = 3 as usize;
    let mut crypto = CryptoExample::default();

    log::info!("Spawning {} nodes", node_count);

    let nodes = (0..node_count)
        .map(|idx| {
            let socket_addr: SocketAddr = format!("127.0.0.1:{}", 2000 + idx).parse().unwrap();
            Node {
                key: Key::try_from(crypto.new_identity().1.bytes().to_vec()).unwrap(),
                data: NodeDataExample::from_address(Address::new(Address::LAMINAR, socket_addr)),
            }
        })
        .collect::<Vec<_>>();

    let entries = futures::future::join_all(
        nodes
            .iter()
            .cloned()
            .map(|node| spawn_node(node, crypto.clone())),
    )
    .await
    .into_iter()
    .map(|r| r.unwrap())
    .collect::<Vec<_>>();

    log::info!("Nodes spawned");

    let first_node = nodes.first().cloned().unwrap();

    log::info!("Bootstrapping nodes");
    futures::future::join_all(entries.iter().skip(1).map(|(_, kad, _)| {
        kad.send(KadBootstrapCmd {
            nodes: vec![first_node.clone()],
        })
    }))
    .await;

    tokio::time::delay_for(Duration::from_secs(1)).await;

    let other_nodes = nodes.iter().skip(1).cloned().collect::<Vec<_>>();
    let other_entries = entries.iter().skip(1).cloned().collect::<Vec<_>>();
    let mut permutations = other_nodes
        .into_iter()
        .zip(other_entries.into_iter())
        .permutations(2)
        .collect::<Vec<_>>();

    log::info!(
        "Sending protocol commands for {} node permutations",
        permutations.len()
    );

    let protocol_actions = permutations.iter_mut().map(|vec| {
        let from = vec[0].0.key.to_string();
        let to = vec[1].0.key.clone();
        let address = to.to_string();
        let rpc2 = (vec[1]).1.clone().2;
        let (node1, (_, _, rpc1)) = &mut vec[0];

        async move {
            rpc2.bind_fn(&address, |msg: RpcEnvelope<RpcMessageExample>| {
                async move { Ok(format!("Response to: {}", msg.into_inner().request)) }
                    .boxed_local()
            });

            let response = rpc1
                .rpc(
                    &address,
                    from,
                    to,
                    RpcMessageExample {
                        request: format!("Hello from {}", node1.key),
                    },
                    5.0,
                )
                .await?;

            log::info!("SUCCESS: {:?}", response);
            Ok::<_, NetRpcError>(())
        }
    });

    futures::future::join_all(protocol_actions).await;
    actix_rt::signal::ctrl_c().await?;

    log::info!("Shutting down...");
    futures::future::join_all(
        entries
            .iter()
            .map(|(net, _, _)| net.send(ServiceCmd::Shutdown)),
    )
    .await;

    log::info!("done.");
    Ok(())
}
