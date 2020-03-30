use generic_array::typenum::U64;
use itertools::Itertools;
use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use std::collections::HashSet;
use std::net::SocketAddr;
use structopt::StructOpt;
use ya_net_kad::table::K;

type Size = U64;
type Key = ya_net_kad::Key<Size>;
type Node = ya_net_kad::Node<Size>;
type Table = ya_net_kad::Table<Size>;

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
        .map(|(key, address)| Node { key, address })
        .collect()
}

fn find_neighbors(key: &Key, nodes: &HashSet<Node>, rn: &Node) -> Vec<Node> {
    let mut table = Table::new(key.clone(), K);
    table.extend(nodes.iter());
    table.neighbors(&rn.key, None, Some(K))
}

fn dbg_nodes(me: &Key, rn: &Node, sorted: &Vec<Node>, neighbors: &Vec<Node>, limit: Option<usize>) {
    sorted
        .iter()
        .sorted_by_key(|p| rn.distance(&p))
        .zip(neighbors.iter().sorted_by_key(|p| rn.distance(&p)))
        .enumerate()
        .take(limit.unwrap_or(5))
        .for_each(|(i, (n1, n2))| {
            println!(
                "[{:>5}] srt: {} (distance {} | me: {})\n[{:>5}] kad: {} (distance {} | me: {})\n",
                i,
                n1.key,
                rn.distance(&n1),
                me.distance(&n1),
                i,
                n2.key,
                rn.distance(&n2),
                me.distance(&n2),
            )
        });
}

#[derive(StructOpt)]
struct Args {
    node_count: usize,
}

fn main() {
    let nodes = gen_nodes(Args::from_args().node_count);

    let mut rng = rand::thread_rng();
    let dist = Uniform::new(0, nodes.len());
    let idx = dist.sample(&mut rng);

    let rand_node = nodes.iter().skip(idx).next().unwrap();
    let sorted = nodes
        .iter()
        .sorted_by_key(|p| rand_node.distance(&p))
        .cloned()
        .take(K)
        .collect::<Vec<_>>();

    println!("Searched key: {}", rand_node.key);

    for (i, next) in sorted.iter().skip(1).enumerate() {
        println!();
        println!("{}. neighbor: {}", i, next.key);
        println!();

        let neighbors = find_neighbors(&next.key, &nodes, &rand_node);
        dbg_nodes(&next.key, &rand_node, &sorted, &neighbors, None);
    }

    println!("Random identity: {}", rand_node.key);

    let key = Key::random(0);
    let neighbors = find_neighbors(&key, &nodes, &rand_node);
    dbg_nodes(&key, &rand_node, &sorted, &neighbors, None);
}
