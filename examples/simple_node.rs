use actix::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;
use ya_net_kad::key_lengths::U20;
use ya_net_kad::Node;
use ya_net_p2p::event::{DhtCmd, ServiceCmd};
use ya_net_p2p::protocol::kad::{KadProtocol, NodeDataExt};
use ya_net_p2p::protocol::session::SessionProtocol;
use ya_net_p2p::{Address, Net, NetAddrExt};
type KeySize = U20;
type Key = ya_net_kad::Key<KeySize>;

#[derive(StructOpt)]
struct Args {
    net_addr: SocketAddr,
    /// Format: <key_hex>@127.0.0.1:33333
    #[structopt(short, long)]
    bootstrap: Option<String>,
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
    let id = rand::thread_rng().gen::<[u8; 20]>();
    let node = Node {
        key: Key::new(id),
        data: NodeDataExample::from_address(Address::new(Address::LAMINAR, socket_addr)),
    };
    let net = Net::new(socket_addrs).start();
    let dht = net.set_dht(KadProtocol::new(node.clone(), &net));
    net.set_session(SessionProtocol::new(&net, &net));
    log::info!("Node key: {}", hex::encode(&node.key));
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
    actix_rt::signal::ctrl_c().await?;

    log::info!("Shutting down...");
    net.send(ServiceCmd::Shutdown).await??;
    Ok(())
}
