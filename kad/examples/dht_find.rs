use actix::prelude::*;
use futures::channel::mpsc;
use futures::StreamExt;
use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;
use tokio::time::delay_for;
use ya_net_kad::{event::*, Error, KadConfig};

type Size = ya_net_kad::key_lengths::U32;
type Key = ya_net_kad::Key<Size>;
type Data = SocketAddr;
type Node = ya_net_kad::Node<Size, Data>;
type Kad = ya_net_kad::Kad<Size, Data>;

const MULTIPLIER: usize = 16;

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
        set.insert(Key::random(0));
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
        .map(|(key, address)| Node { key, data: address })
        .collect()
}

fn spawn_nodes(
    size: usize,
) -> (
    HashMap<Node, Addr<Kad>>,
    HashMap<Node, Addr<Kad>>,
    mpsc::Receiver<KadEvtSend<Size, Data>>,
) {
    let (tx, rx) = mpsc::channel(size * MULTIPLIER * 2);
    let mut nodes = gen_nodes(size + (size + 99) / 100 + 1)
        .into_iter()
        .collect::<Vec<_>>();

    let boot = nodes
        .split_off(size)
        .into_iter()
        .map(|n| {
            (
                n.clone(),
                Kad::with_conf(
                    KadConfig::with_name(format!("B:{}", hex::encode(&n.key.as_ref()[..8]))),
                    n,
                    tx.clone(),
                )
                .start(),
            )
        })
        .collect::<HashMap<_, _>>();

    log::info!("Nodes: {}", nodes.len());
    log::info!("Bootstrap nodes: {}", boot.len());

    let nodes = nodes
        .into_iter()
        .map(|n| {
            (
                n.clone(),
                Kad::with_conf(
                    KadConfig::with_name(format!("N:{}", hex::encode(&n.key.as_ref()[..8]))),
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
    let init_vec = boot.iter().map(|(n, _)| n).cloned().collect::<Vec<_>>();

    for (node, addr) in boot.iter() {
        log::info!("Bootstrapping {}", node);

        addr.send(KadBootstrap {
            nodes: init_vec.clone(),
            dormant: true,
        })
        .await??;
    }

    let mut futs = Vec::new();

    for (_, addr) in nodes.iter() {
        futs.push(addr.send(KadBootstrap {
            nodes: init_vec.clone(),
            dormant: false,
        }));

        delay_for(Duration::from_millis(2)).await;
    }

    futures::future::join_all(futs).await;
    Ok(())
}

async fn route(
    concurrency_limit: usize,
    nodes: HashMap<Node, Addr<Kad>>,
    rx: mpsc::Receiver<KadEvtSend<Size, Data>>,
) {
    let nodes_ref = &nodes;
    rx.for_each_concurrent(concurrency_limit, |m| async move {
        let (from, to, message) = (m.from, m.to, m.message);
        match nodes_ref.get(&to) {
            Some(addr) => {
                let sent = addr
                    .send(KadReceive {
                        from: from.clone(),
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

async fn find_node(nodes: &HashMap<Node, Addr<Kad>>) -> Result<Option<Node>, Error> {
    let mut rng = rand::thread_rng();
    let mut querying_node;
    let mut node_to_find;

    loop {
        let dist = Uniform::new(0, nodes.len());
        let first_idx = dist.sample(&mut rng);
        let second_idx = dist.sample(&mut rng);

        querying_node = nodes.iter().skip(first_idx).next().unwrap();
        node_to_find = nodes.iter().skip(second_idx).next().unwrap();

        if querying_node != node_to_find {
            break;
        }
    }

    let pause = Duration::from_secs(2);
    log::info!("Pausing for {}s", pause.as_secs());
    delay_for(pause).await;

    log::info!(
        "Initiating node query [{} by {}]",
        node_to_find.0.key,
        querying_node.0
    );

    let kad = querying_node.1;
    let queried_key = node_to_find.0.key.clone();
    kad.send(KadFindNode::new(queried_key)).await?
}

async fn find_value(nodes: &HashMap<Node, Addr<Kad>>) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
    let mut querying_node;
    let mut publishing_node;
    let mut rng = rand::thread_rng();

    loop {
        let dist = Uniform::new(0, nodes.len());
        let first_idx = dist.sample(&mut rng);
        let second_idx = dist.sample(&mut rng);

        querying_node = nodes.iter().skip(first_idx).next().unwrap();
        publishing_node = nodes.iter().skip(second_idx).next().unwrap();

        if querying_node != publishing_node {
            break;
        }
    }

    let store_data = format!("Data published by {}", publishing_node.0)
        .as_bytes()
        .to_vec();
    let store_key = sha2::Sha256::digest(store_data.as_slice()).to_vec();

    log::info!(
        "Publishing value [{} by {}]",
        hex::encode(&store_key),
        publishing_node.0
    );

    let kad = publishing_node.1;
    kad.send(KadStore {
        key: store_key.clone(),
        value: store_data,
        persistent: false,
    })
    .await??;

    let pause = Duration::from_secs(2);
    log::info!("Pausing for {}s", pause.as_secs());
    delay_for(pause).await;

    let kad = querying_node.1;
    kad.send(KadFindValue { key: store_key }).await?
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
enum Action {
    FindNode,
    FindValue,
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct Args {
    node_count: usize,
    action_count: usize,
    #[structopt(subcommand)]
    action: Action,
}

#[actix_rt::main]
pub async fn main() -> anyhow::Result<()> {
    let var = "RUST_LOG";
    env::set_var(var, env::var(var).unwrap_or("debug".to_owned()));
    env_logger::init();

    let args = Args::from_args();
    let node_count = std::cmp::max(3, args.node_count);
    let (boot, nodes, rx) = spawn_nodes(node_count);

    actix_rt::spawn(route(node_count * MULTIPLIER, nodes.clone(), rx));
    bootstrap(&boot, &nodes).await?;

    log::warn!("Interrupt with ctrl + c");

    let mut i: usize = 0;
    while i < args.action_count {
        match &args.action {
            Action::FindNode => match find_node(&nodes).await {
                Ok(opt) => match opt {
                    Some(node) => log::info!("Node found: {}", node),
                    None => panic!("Node not found"),
                },
                Err(e) => panic!(format!("Node lookup error: {:?}", e)),
            },
            Action::FindValue => match find_value(&nodes).await {
                Ok(opt) => match opt {
                    Some(entry) => {
                        let key = hex::encode(&entry.0);
                        let value = String::from_utf8(entry.1).unwrap();
                        log::info!("Value found: {} = {}", key, value);
                    }
                    None => panic!("Value not found"),
                },
                Err(e) => panic!(format!("Value lookup error: {:?}", e)),
            },
        }
        i += 1;
    }

    Ok(())
}
