use actix::prelude::*;
use ethsign::{PublicKey, SecretKey};
use futures::future::LocalBoxFuture;
use futures::FutureExt;
use hashbrown::HashMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;
use url::Url;
use ya_client_model::NodeId;
use ya_net::crypto::{Signature, SignatureECDSA};
use ya_net::error::{CryptoError, MessageError};
use ya_net::event::{DhtCmd, ServiceCmd};
use ya_net::packet::CryptoProcessor;
use ya_net::protocol::kad::{KadProtocol, NodeDataExt};
use ya_net::protocol::service_bus::ServiceBusProtocol;
use ya_net::protocol::session::SessionProtocol;
use ya_net::transport::laminar::LaminarTransport;
use ya_net::*;
use ya_net::{NetAddrExt, Result};
use ya_net_kad::key_lengths::U64;
use ya_service_bus::{actix_rpc, RpcEndpoint, RpcEnvelope, RpcMessage};

type KeySize = U64;
type Key = ya_net_kad::Key<KeySize>;
type Node = ya_net_kad::Node<KeySize, NodeDataExample>;

const SERVICE_ADDR: &'static str = "/public/example";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageExample {
    message: String,
}

impl RpcMessage for MessageExample {
    const ID: &'static str = "MessageExample";
    type Item = MessageResponseExample;
    type Error = String;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageResponseExample {
    reply: String,
}

struct ServiceExample;

impl Actor for ServiceExample {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let addr = ctx.address();
        actix_rpc::bind::<MessageExample>(SERVICE_ADDR, addr.recipient());
    }
}

impl Handler<RpcEnvelope<MessageExample>> for ServiceExample {
    type Result = ActorResponse<Self, MessageResponseExample, String>;

    fn handle(&mut self, msg: RpcEnvelope<MessageExample>, _: &mut Context<Self>) -> Self::Result {
        log::info!("Received an RPC message: {}", msg.message);
        ActorResponse::reply(Ok(MessageResponseExample {
            reply: format!("Reply to: {}", msg.message),
        }))
    }
}

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

#[derive(Clone, Debug)]
struct CryptoExample {
    identities: HashMap<NodeId, (SecretKey, PublicKey)>,
}

impl CryptoExample {
    fn new_identity(&mut self) -> Vec<u8> {
        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        let secret = SecretKey::from_raw(&bytes).unwrap();
        let public = secret.public();

        let identity = NodeId::from(public.address().as_ref());
        self.identities
            .insert(identity.clone(), (secret, public.clone()));

        public.bytes().to_vec()
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

fn key_to_identity(key: &Key) -> anyhow::Result<NodeId> {
    let public = match PublicKey::from_slice(key.as_ref()) {
        Ok(public) => public,
        Err(_) => return Err(anyhow::anyhow!("Invalid key")),
    };
    Ok(NodeId::from(public.address().as_ref()))
}

#[derive(StructOpt)]
struct Args {
    /// Format: 127.0.0.1:11111
    #[structopt(short, long)]
    net_addr: String,
    /// Format: tcp://127.0.0.1:22222
    #[structopt(short, long)]
    gsb_addr: Url,
    /// Format: <key_hex>@127.0.0.1:33333
    #[structopt(short, long)]
    bootstrap: Option<String>,
    /// Format: <node_id>
    #[structopt(short, long)]
    send_to: Option<String>,
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();

    env::set_var(
        "RUST_LOG",
        env::var("RUST_LOG").unwrap_or("debug".to_string()),
    );
    env::set_var("GSB_URL", args.gsb_addr.to_string());
    env_logger::init();

    let mut crypto = CryptoExample::default();

    log::info!("Starting router");
    ya_sb_router::bind_gsb_router(Some(args.gsb_addr)).await?;

    log::info!("Starting example service");
    ServiceExample {}.start();

    log::info!("Spawning node");
    let socket_addr: SocketAddr = args.net_addr.parse()?;
    let socket_addrs = vec![socket_addr];
    let node = Node {
        key: Key::try_from(crypto.new_identity())?,
        data: NodeDataExample::from_address(Address::new(Address::LAMINAR, socket_addr)),
    };
    let identity = key_to_identity(&node.key)?;

    let net = Net::new(socket_addrs).start();
    let dht = net.set_dht(KadProtocol::new(node.clone(), &net));
    net.set_session(SessionProtocol::new(&net, &net));
    net.add_processor(CryptoProcessor::new(node.key.clone(), crypto));
    net.add_protocol(ServiceBusProtocol::new(&net, &dht));
    net.add_transport(LaminarTransport::<Key>::new(&net));

    log::info!("Node key: {}", hex::encode(&node.key));
    log::info!("Node identity: {}", identity);
    log::info!("Node addresses: {:?}", node.data.addresses());

    tokio::time::delay_for(Duration::from_secs(1)).await;

    if let Some(bootstrap) = args.bootstrap {
        let split = bootstrap.split('@').collect::<Vec<_>>();
        let key = hex::decode(&split[0])?;
        let socket_addr: SocketAddr = split[1].parse()?;
        let address = Address::new(Address::LAMINAR, socket_addr);

        log::info!("Bootstrapping node {} @ {:?}", split[0], address);
        dht.send(DhtCmd::Bootstrap(vec![(key, address)])).await??;
    }

    tokio::time::delay_for(Duration::from_secs(1)).await;

    log::info!("Publishing identity information");
    let _ = dht
        .send(DhtCmd::PublishValue(
            identity.as_ref().to_vec(),
            node.key.to_vec(),
        ))
        .await?;

    tokio::time::delay_for(Duration::from_secs(1)).await;

    if let Some(send_to) = args.send_to {
        log::info!("Sending a message via GSB");

        let response = NodeId::from_str(send_to.as_str())?
            .try_service(SERVICE_ADDR)?
            .send(MessageExample {
                message: format!("request from {}", identity),
            })
            .await?;

        log::info!("Received response: {:?}", response);
    }

    actix_rt::signal::ctrl_c().await?;

    log::info!("Shutting down...");
    net.send(ServiceCmd::Shutdown).await??;
    Ok(())
}
