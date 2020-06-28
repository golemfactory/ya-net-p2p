use actix::prelude::*;
use actix_files::NamedFile;
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError};
use actix_web::{get, web, App, HttpRequest, HttpServer, Responder};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;
use ya_net_kad::key_lengths::U20;
use ya_net_kad::{Node, QueryKadStatus};
use ya_net_p2p::crypto::no_crypto;
use ya_net_p2p::event::{DhtCmd, ServiceCmd};
use ya_net_p2p::identity::IdentityManager;
use ya_net_p2p::packet::CryptoProcessor;
use ya_net_p2p::protocol::kad::{KadProtocol, NodeDataExt};
use ya_net_p2p::protocol::session::SessionProtocol;
use ya_net_p2p::transport::laminar::LaminarTransport;
use ya_net_p2p::{transport::Address, GetStatus, Identity, Net, NetAddrExt};

type KeySize = U20;
type Key = ya_net_kad::Key<KeySize>;

#[derive(StructOpt)]
struct Args {
    net_addr: SocketAddr,
    /// Format: <key_hex>@127.0.0.1:33333
    #[structopt(short, long)]
    bootstrap: Option<String>,
    /// force node key
    #[structopt(long)]
    id: Option<String>,
}

impl Args {
    fn http_addr(&self) -> SocketAddr {
        let mut http_addr = self.net_addr.clone();
        http_addr.set_port(http_addr.port() + 1);
        http_addr
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

type NetAddr = Addr<Net<Key>>;
type DhtService = Recipient<DhtCmd<Key>>;
type DhtStatus = Recipient<QueryKadStatus>;

#[get("/resolve/{key}")]
async fn resolve((key, dht): (web::Path<String>, web::Data<DhtService>)) -> impl Responder {
    let key_bytes = hex::decode(key.into_inner()).map_err(ErrorBadRequest)?;
    let result = dht
        .send(DhtCmd::ResolveNode(
            key_bytes.try_into().map_err(ErrorBadRequest)?,
        ))
        .await
        .map_err(ErrorInternalServerError)?
        .map_err(ErrorInternalServerError)?;
    Ok::<_, actix_web::Error>(web::Json(result))
}

#[get("/status")]
async fn status(net: web::Data<NetAddr>) -> impl Responder {
    Ok::<_, actix_web::Error>(web::Json(
        net.send(GetStatus::default())
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?
            .map_err(actix_web::error::ErrorInternalServerError)?,
    ))
}

#[get("/dht-status")]
async fn dht_status(dht: web::Data<DhtStatus>) -> impl Responder {
    Ok::<_, actix_web::Error>(web::Json(
        dht.send(QueryKadStatus::default())
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?
            .map_err(actix_web::error::ErrorInternalServerError)?,
    ))
}

#[get("/")]
async fn index(_req: HttpRequest) -> std::io::Result<NamedFile> {
    actix_files::NamedFile::open("examples/simple_node.html")
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();
    env::set_var(
        "RUST_LOG",
        env::var("RUST_LOG").unwrap_or("debug".to_string()),
    );
    env_logger::init();
    log::info!("Spawning node");
    let socket_addr = args.net_addr;
    let socket_addrs = vec![socket_addr];
    let mut id_bytes = rand::thread_rng().gen::<[u8; 20]>().to_vec();
    if let Some(key) = &args.id {
        id_bytes = hex::decode(key)?;
    };

    let identity = Identity::new(&id_bytes);
    let identity_manager = IdentityManager::<Key>::from_raw(
        identity.clone(),
        id_bytes.clone(),
        id_bytes.clone(),
        id_bytes.clone(),
    )?;
    let node_key = identity_manager.get_node_key(&identity).unwrap();
    let node = Node {
        key: node_key.clone(),
        data: NodeDataExample::from_address(Address::new(Address::LAMINAR, socket_addr)),
    };

    let net = Net::new(socket_addrs, identity_manager.clone()).start();
    let dht: Addr<KadProtocol<KeySize, NodeDataExample>> =
        net.set_dht(KadProtocol::new(node.clone(), &net));
    let _ = dht.send(QueryKadStatus::default());
    net.set_session(SessionProtocol::new(&identity_manager, &net, &net));
    net.add_processor(CryptoProcessor::new(&identity_manager, no_crypto()));
    net.add_transport(LaminarTransport::<Key>::new(&net));
    log::info!("Node key: {}", hex::encode(&node.key));
    log::info!("Node addresses: {:?}", node.data.addresses());
    tokio::time::delay_for(Duration::from_secs(1)).await;
    let http_addr = args.http_addr();

    if let Some(bootstrap) = args.bootstrap {
        let split = bootstrap.split('@').collect::<Vec<_>>();
        let key = hex::decode(&split[0])?;
        let socket_addr: SocketAddr = split[1].parse()?;
        let address = Address::new(Address::LAMINAR, socket_addr);

        log::info!("Bootstrapping node {} @ {:?}", split[0], address);
        dht.send(DhtCmd::Bootstrap(vec![(key, address)])).await??;
    }

    {
        let net = net.clone();
        let status_recipient = dht.clone().recipient::<QueryKadStatus>();
        let dht: DhtService = dht.clone().recipient();
        HttpServer::new(move || {
            App::new()
                .data(net.clone())
                .data(dht.clone())
                .data(status_recipient.clone())
                .service(index)
                .service(resolve)
                .service(status)
                .service(dht_status)
        })
        .bind(http_addr)?
        .run()
        .await?;
    }

    log::info!("Shutting down...");
    net.send(ServiceCmd::Shutdown).await??;
    Ok(())
}
