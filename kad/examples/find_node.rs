use actix::prelude::*;
use futures::channel::mpsc;
use futures::StreamExt;
use generic_array::typenum::U512;
use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;
use tokio::time::delay_for;
use ya_net_kad::{Error, KadEvtBootstrap, KadEvtFindNode, KadEvtReceive, KadEvtSend};

type Size = U512;

type Key = ya_net_kad::Key<Size>;
type Node = ya_net_kad::Node<Size>;
type Kad = ya_net_kad::Kad<Size>;

const MULTIPLIER: usize = 16;

fn gen_key() -> Key {
    let mut rng = rand::thread_rng();
    Key::generate(|_| rng.gen_range(0, 256) as u8)
}

fn gen_address() -> SocketAddr {
    let mut rng = rand::thread_rng();
    format!(
        "{}.{}.{}.{}:{}",
        rng.gen_range(0, 256) as u8,
        rng.gen_range(0, 256) as u8,
        rng.gen_range(0, 256) as u8,
        rng.gen_range(0, 256) as u8,
        rng.gen_range(1000, 65536) as u16
    )
    .parse()
    .unwrap()
}

fn gen_keys(count: usize) -> HashSet<Key> {
    let mut set = HashSet::with_capacity(count);
    while set.len() < count {
        set.insert(gen_key());
    }
    set
}

fn gen_addresses(count: usize) -> HashSet<SocketAddr> {
    let mut set = HashSet::with_capacity(count);
    while set.len() < count {
        set.insert(gen_address());
    }
    set
}

fn gen_nodes(count: usize) -> HashSet<Node> {
    let keys = gen_keys(count);
    let addresses = gen_addresses(count);

    keys.into_iter()
        .zip(addresses.into_iter())
        .map(|(key, address)| Node { key, address })
        .collect()
}

fn spawn_nodes(
    size: usize,
) -> (
    HashMap<Node, Addr<Kad>>,
    HashMap<Node, Addr<Kad>>,
    mpsc::Receiver<KadEvtSend<Size>>,
) {
    let (tx, rx) = mpsc::channel(size * MULTIPLIER);
    let mut nodes = gen_nodes(size + (size + 99) / 100)
        .into_iter()
        .collect::<Vec<_>>();

    let boot = nodes
        .split_off(size)
        .into_iter()
        .map(|n| {
            (
                n.clone(),
                Kad::with_name(
                    format!("B:{}", hex::encode(&n.key.as_ref()[..8])),
                    n,
                    tx.clone(),
                )
                .start(),
            )
        })
        .collect::<HashMap<_, _>>();

    log::info!("Total nodes: {}", nodes.len());
    log::info!("Bootstrap nodes: {}", boot.len());

    let nodes = nodes
        .into_iter()
        .map(|n| {
            (
                n.clone(),
                Kad::with_name(
                    format!("N:{}", hex::encode(&n.key.as_ref()[..8])),
                    n,
                    tx.clone(),
                )
                .start(),
            )
        })
        .chain(boot.clone().into_iter())
        .collect();

    (boot, nodes, rx)
}

async fn bootstrap(
    boot: &HashMap<Node, Addr<Kad>>,
    nodes: &HashMap<Node, Addr<Kad>>,
) -> Result<(), Error> {
    let delay = Duration::from_millis(5);
    let init_vec = boot.iter().map(|(n, _)| n).cloned().collect::<Vec<_>>();

    for (node, addr) in nodes.iter() {
        log::info!("Bootstrapping {}", node);

        addr.send(KadEvtBootstrap {
            nodes: init_vec.clone(),
            dormant: false,
        })
        .await??;

        delay_for(delay).await;
    }

    Ok(())
}

async fn find_node(nodes: &HashMap<Node, Addr<Kad>>) -> Result<Option<Node>, Error> {
    let mut first;
    let mut second;
    let mut rng = rand::thread_rng();

    loop {
        let dist = Uniform::new(0, nodes.len());
        let first_idx = dist.sample(&mut rng);
        let second_idx = dist.sample(&mut rng);

        first = nodes.iter().skip(first_idx).next().unwrap();
        second = nodes.iter().skip(second_idx).next().unwrap();

        if first != second {
            break;
        }
    }

    log::info!("Initiating node {} lookup by {}", second.0, first.0);

    first
        .1
        .send(KadEvtFindNode {
            key: second.0.key.clone(),
            timeout: 0f64,
        })
        .await?
}

async fn route(
    concurrency_limit: usize,
    nodes: HashMap<Node, Addr<Kad>>,
    rx: mpsc::Receiver<KadEvtSend<Size>>,
) {
    let nodes_ref = &nodes;
    rx.for_each_concurrent(concurrency_limit, |m| async move {
        let (from, to, message) = (m.from, m.to, m.message);
        match nodes_ref.get(&to) {
            Some(addr) => {
                let sent = addr
                    .send(KadEvtReceive {
                        from: from.clone(),
                        new: false,
                        message,
                    })
                    .await;

                if let Err(e) = sent {
                    log::warn!("Unable to send a message from {} to {}: {:?}", from, to, e);
                }
            }
            None => log::error!("Address not found for node {}", to),
        }
    })
    .await;
}

#[derive(StructOpt)]
struct Args {
    node_count: usize,
}

#[actix_rt::main]
pub async fn main() -> anyhow::Result<()> {
    let var = "RUST_LOG";
    env::set_var(var, env::var(var).unwrap_or("debug".to_owned()));
    env_logger::init();

    let count = Args::from_args().node_count;
    let (boot, nodes, rx) = spawn_nodes(count);

    actix_rt::spawn(route(count * MULTIPLIER, nodes.clone(), rx));
    bootstrap(&boot, &nodes).await?;

    log::warn!("Interrupt with ctrl + c");

    loop {
        match find_node(&nodes).await {
            Ok(opt) => match opt {
                Some(node) => log::info!("Node found: {}", node),
                None => panic!("Node not found"),
            },
            Err(e) => panic!(format!("Node lookup error: {:?}", e)),
        }
    }
}
