use actix::prelude::*;
use ethsign::SecretKey;
use futures::future::LocalBoxFuture;
use futures::FutureExt;
use hashbrown::HashMap;
use rand::Rng;
use secp256k1::ecdh::SharedSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use structopt::StructOpt;
use url::Url;
use ya_client_model::NodeId;
use ya_net_kad::key_lengths::U64;
use ya_net_p2p::crypto::{aes, Crypto, Signature, SignatureECDSA};
use ya_net_p2p::error::MessageError;
use ya_net_p2p::event::{DhtCmd, DhtValue, ServiceCmd};
use ya_net_p2p::identity::IdentityManager;
use ya_net_p2p::packet::CryptoProcessor;
use ya_net_p2p::protocol::kad::{KadProtocol, NodeDataExt};
use ya_net_p2p::protocol::service_bus::ServiceBusProtocol;
use ya_net_p2p::protocol::session::SessionProtocol;
use ya_net_p2p::transport::laminar::LaminarTransport;
use ya_net_p2p::transport::Address;
use ya_net_p2p::*;
use ya_net_p2p::{NetAddrExt, Result};
use ya_service_bus::typed as bus;
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
    identities: HashMap<Identity, Vec<u8>>,
    key_pairs: HashMap<Vec<u8>, Vec<u8>>,
}

impl CryptoExample {
    fn new_identity(&mut self) -> Identity {
        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        let secret = SecretKey::from_raw(&bytes).unwrap();
        let public = secret.public();
        let public_raw = public.bytes().to_vec();

        let node_id = NodeId::from(public.address().as_ref());
        let identity = Identity::new(node_id.as_ref());

        self.identities.insert(identity.clone(), public_raw.clone());
        self.key_pairs.insert(public_raw.clone(), bytes.to_vec());
        identity
    }
}

impl Default for CryptoExample {
    fn default() -> Self {
        CryptoExample {
            identities: HashMap::new(),
            key_pairs: HashMap::new(),
        }
    }
}

impl Crypto for CryptoExample {
    fn derive_keys<'a>(
        &mut self,
        identity: &Identity,
    ) -> LocalBoxFuture<'a, Result<(Vec<u8>, Vec<u8>)>> {
        let public = self.identities.get(&identity).cloned();
        let secret = public
            .as_ref()
            .map(|k| self.key_pairs.get(k))
            .flatten()
            .cloned();

        async move {
            // Here we return the original keys instead of derived keys
            let public = public.ok_or_else(|| Error::key("missing public key"))?;
            let secret = secret.ok_or_else(|| Error::key("missing secret key"))?;
            Ok((public, secret))
        }
        .boxed_local()
    }

    fn derive_shared_secret<'a>(
        &mut self,
        remote_key: &[u8],
        local_secret_key: &[u8],
    ) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let mut remote_prefixed = [0; 65];
        remote_prefixed[0] = 0x04;
        remote_prefixed[1..].copy_from_slice(remote_key);

        let public = secp256k1::PublicKey::from_slice(&remote_prefixed);
        let secret = secp256k1::SecretKey::from_slice(&local_secret_key[32..]);

        async move {
            let public = public.map_err(|e| Error::key(format!("invalid public key: {:?}", e)))?;
            let secret = secret.map_err(|e| Error::key(format!("invalid secret key: {:?}", e)))?;
            let derived = SharedSecret::new(&public, &secret);
            Ok(derived[..][..aes::KEY_SIZE].to_vec())
        }
        .boxed_local()
    }

    #[inline]
    fn encrypt(&self, key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        Ok(aes::encrypt(key, payload.as_ref())?)
    }

    #[inline]
    fn decrypt(&self, key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        Ok(aes::decrypt(key, payload.as_ref())?)
    }

    fn sign<'a>(&self, secret_key: &[u8], payload: &[u8]) -> LocalBoxFuture<'a, Result<Signature>> {
        let secret = SecretKey::from_raw(&secret_key[32..]).unwrap();
        let hash = Sha256::digest(payload.as_ref());

        async move {
            secret
                .sign(hash.as_ref())
                .map(|sig| {
                    let mut data = Vec::with_capacity(33);
                    data.push(sig.v);
                    data.extend_from_slice(&sig.r[..]);
                    data.extend_from_slice(&sig.s[..]);
                    Signature::ECDSA(SignatureECDSA::P256K1 { data, key: None })
                })
                .map_err(|e| Error::from(MessageError::Signature(e.to_string())))
        }
        .boxed_local()
    }

    #[inline]
    fn verify(
        &self,
        key: Option<&[u8]>,
        signature: &mut Signature,
        payload: &[u8],
    ) -> Result<bool> {
        let hash = Sha256::digest(payload.as_ref());
        let sig = signature.data();

        if sig.len() == std::mem::size_of::<ethsign::Signature>() {
            let v = sig[0];
            let mut r = [0; 32];
            let mut s = [0; 32];

            r.copy_from_slice(&sig[1..33]);
            s.copy_from_slice(&sig[33..65]);

            let result = ethsign::Signature { v, r, s }
                .recover(hash.as_ref())
                .map_err(|e| Error::from(ethsign::Error::Secp256k1(e)))
                .map(|public_key| {
                    signature.set_key(public_key.bytes().to_vec());
                    public_key
                });

            match key {
                Some(key) => result.map(|rec| key == rec.bytes().as_ref()),
                _ => result.map(|_| true),
            }
        } else {
            Err(Error::sig("invalid signature size"))
        }
    }
}

trait TryRemoteEndpoint {
    fn try_service(&self, bus_addr: &str) -> anyhow::Result<bus::Endpoint>;
}

impl TryRemoteEndpoint for NodeId {
    fn try_service(&self, bus_addr: &str) -> anyhow::Result<bus::Endpoint> {
        if !bus_addr.starts_with("/public") {
            return Err(anyhow::anyhow!("Public prefix needed"));
        }
        let exported_part = &bus_addr["/public".len()..];
        let net_bus_addr = format!("/net/{:?}{}", self, exported_part);
        Ok(bus::service(&net_bus_addr))
    }
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

    log::info!("Starting crypto");
    let mut crypto = CryptoExample::default();
    let identity = crypto.new_identity();
    let derived_keys = crypto.derive_keys(&identity).await?;
    let identity_manager = IdentityManager::<Key>::from_raw(
        identity.clone(),
        derived_keys.0.clone(),
        derived_keys.0,
        derived_keys.1,
    )?;

    log::info!("Starting router");
    ya_sb_router::bind_gsb_router(Some(args.gsb_addr)).await?;

    log::info!("Starting example service");
    ServiceExample {}.start();

    log::info!("Spawning node");
    let socket_addr: SocketAddr = args.net_addr.parse()?;
    let socket_addrs = vec![socket_addr];
    let node = Node {
        key: identity_manager.get_default_key().clone(),
        data: NodeDataExample::from_address(Address::new(Address::LAMINAR, socket_addr)),
    };

    let net = Net::new(socket_addrs, identity_manager.clone()).start();
    let dht = net.set_dht(KadProtocol::new(node.clone(), &net));
    net.set_session(SessionProtocol::new(&identity_manager, &net, &net));
    net.add_processor(CryptoProcessor::new(&identity_manager, crypto));
    net.add_protocol(ServiceBusProtocol::new(&net));
    net.add_transport(LaminarTransport::<Key>::new(&net));

    log::info!("Key: {}", hex::encode(&node.key));
    log::info!("Identity: 0x{}", hex::encode(&identity));
    log::info!("Addresses: {:?}", node.data.addresses());

    if let Some(bootstrap) = args.bootstrap {
        let split = bootstrap.split('@').collect::<Vec<_>>();
        let key = hex::decode(&split[0])?;
        let socket_addr: SocketAddr = split[1].parse()?;
        let address = Address::new(Address::LAMINAR, socket_addr);

        log::info!("Bootstrapping node {} @ {:?}", split[0], address);
        dht.send(DhtCmd::Bootstrap(vec![(key, address)])).await??;
    }

    log::info!("Publishing identity information");
    let identity_key = identity_manager.default_key.as_ref().clone();
    let node_key = identity_manager.get_node_key(&identity).unwrap();
    let _ = dht
        .send(DhtCmd::PublishValue(
            identity.as_ref().to_vec(),
            DhtValue {
                identity_key,
                node_key,
            },
        ))
        .await?;

    if let Some(send_to) = args.send_to {
        log::info!("Sending a message via GSB");

        let response = NodeId::from_str(send_to.as_str())?
            .try_service(SERVICE_ADDR)?
            .send_as(
                format!("0x{}", hex::encode(&identity)),
                MessageExample {
                    message: format!("request from {}", hex::encode(&identity)),
                },
            )
            .await?;

        match response {
            Ok(value) => log::info!("Response: {:?}", value),
            Err(error) => log::error!("Response error: {}", error),
        }
    } else {
        log::info!("Awaiting connections");
    }

    actix_rt::signal::ctrl_c().await?;

    log::info!("Initiating shutdown");
    net.send(ServiceCmd::Shutdown).await??;
    Ok(())
}
