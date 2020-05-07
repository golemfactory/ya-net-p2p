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
use ya_net::error::{CryptoError, MessageError};
use ya_net::event::{ProtocolCmd, SendCmd, ServiceCmd};
use ya_net::mangler::auth::AuthMangler;
use ya_net::packet::{Guarantees, Payload};
use ya_net::protocol::kad::{KadBootstrapCmd, KadProtocol, NodeDataExt};
use ya_net::protocol::session::SessionProtocol;
use ya_net::transport::laminar::LaminarTransport;
use ya_net::Result;
use ya_net::*;
use ya_net_kad::key_lengths::U64;

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

struct ProtocolExample {
    net: Recipient<SendCmd<Key>>,
}

impl ProtocolExample {
    const PROTOCOL_ID: ProtocolId = 123;

    fn new(net: Recipient<SendCmd<Key>>) -> Self {
        ProtocolExample { net }
    }
}

impl Actor for ProtocolExample {
    type Context = Context<Self>;

    fn started(&mut self, _: &mut Self::Context) {
        log::info!("ExampleProtocol started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("ExampleProtocol stopped");
    }
}

impl Handler<ProtocolCmd<Key>> for ProtocolExample {
    type Result = Result<()>;

    fn handle(&mut self, msg: ProtocolCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::RoamingPacket(address, packet) => {
                log::error!(
                    "Received an unexpected roaming packet from {:?}: {:?}",
                    address,
                    packet
                );
            }
            ProtocolCmd::SessionPacket(address, packet, key) => {
                match packet.payload.try_payload::<String>() {
                    Ok(message) => log::info!(
                        "SUCCESS: received a message from {:?} ({}): {}",
                        address,
                        key,
                        message
                    ),
                    _ => log::error!("Invalid packet from {:?} ({}): {:?}", address, key, packet),
                }
            }
            ProtocolCmd::Shutdown => ctx.stop(),
        }
        Ok(())
    }
}

impl Handler<ProtocolMessage<Key>> for ProtocolExample {
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolMessage<Key>, _: &mut Context<Self>) -> Self::Result {
        let net = self.net.clone();
        let fut = async move {
            net.send(SendCmd::Session {
                from: None,
                to: msg.to,
                packet: Packet {
                    guarantees: Guarantees::unordered(),
                    payload: Payload::builder(Self::PROTOCOL_ID)
                        .try_payload(&msg.message)?
                        .with_auth()
                        .with_signature()
                        .build(),
                },
            })
            .await??;

            Ok(())
        };

        ActorResponse::r#async(fut.into_actor(self))
    }
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
    const SIGNATURE_SIZE: usize = 0;

    fn encrypt<'a>(&self, _key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        async move { Ok(payload) }.boxed_local()
    }

    fn decrypt<'a>(&self, _key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        async move { Ok(payload) }.boxed_local()
    }

    fn sign<'a>(&self, key: Key, payload: Vec<u8>) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
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

        let signed = secret
            .sign(payload.as_slice())
            .map(|sig| {
                let mut vec = Vec::with_capacity(33);
                vec.push(sig.v);
                vec.extend_from_slice(&sig.r[..]);
                vec.extend_from_slice(&sig.s[..]);
                vec
            })
            .map_err(|e| Error::from(MessageError::Signature(e.to_string())));

        async move { Ok(signed?) }.boxed_local()
    }

    #[inline]
    fn verify(&self, key: Key, payload: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
        crypto::verify_secp256k1(key, payload, signature)
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
    Addr<ProtocolExample>,
)> {
    let socket_addrs = node
        .data
        .addresses()
        .into_iter()
        .map(|a| a.socket_addr)
        .collect::<Vec<_>>();
    let net = Net::new(socket_addrs).start();

    let auth = AuthMangler::new(node.key.clone(), crypto).start();
    let kad = KadProtocol::new(node.clone(), net.clone().recipient()).start();
    let ses = SessionProtocol::new(net.clone().recipient(), net.clone().recipient()).start();
    let exa = ProtocolExample::new(net.clone().recipient()).start();
    let lam = LaminarTransport::<Key>::new(net.clone().recipient()).start();

    log::debug!("Adding manglers... [{}]", node.key);
    net.send(ServiceCmd::AddMangler(auth.clone().recipient()))
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
        ProtocolExample::PROTOCOL_ID,
        exa.clone().recipient(),
    ))
    .await??;

    log::debug!("Adding transport... [{}]", node.key);
    net.send(ServiceCmd::AddTransport(
        Address::LAMINAR,
        lam.clone().recipient(),
    ))
    .await??;

    log::debug!("{} spawned", node);
    Ok((net, kad, exa))
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
        let key = vec[1].0.key.clone();
        let (node1, (_, _, exa1)) = &mut vec[0];

        exa1.send(ProtocolMessage {
            to: key,
            message: format!("Hello from {}", node1.key),
        })
    });

    let results = futures::future::join_all(protocol_actions).await;
    log::info!("Protocol send out results: {:?}", results);

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
