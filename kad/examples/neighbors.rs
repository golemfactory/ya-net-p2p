use generic_array::typenum::U64;
use itertools::Itertools;
use rand::Rng;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::rc::Rc;
use structopt::StructOpt;
use ya_net_kad::K;

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

fn dbg_nodes(me: &Node, sorted: &Vec<Node>, neighbors: &Vec<Node>) {
    sorted
        .iter()
        .sorted_by_key(|p| me.distance(&p))
        .zip(neighbors.iter().sorted_by_key(|p| me.distance(&p)))
        .enumerate()
        .for_each(|(i, (n1, n2))| {
            println!(
                "[{:>5}] srt: {} (distance {})\n[{:>5}] kad: {} (distance {})\n",
                i,
                n1.key,
                me.distance(&n1),
                i,
                n2.key,
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
    let me = Rc::new(Node {
        key: Key::random(0),
        address: gen_address(),
    });

    let mut table = Table::new(me.key.clone(), K);
    nodes.iter().for_each(|node| {
        table.add(node);
    });

    let neighbours = table.neighbors(&me.key, Some(&me.key), Some(nodes.len()));
    let sorted = nodes
        .iter()
        .filter(|p| p.key != me.key)
        .sorted_by_key(|p| me.distance(&p))
        .cloned()
        .collect::<Vec<_>>();

    println!("My key: {}", me.key);
    dbg_nodes(&me, &sorted, &neighbours);
}
