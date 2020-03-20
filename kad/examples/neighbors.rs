use generic_array::typenum::U512;
use itertools::Itertools;
use num_bigint::BigUint;
use rand::Rng;
use std::cmp::min;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

type Size = U512;

type Key = ya_net_kad::Key<Size>;
type Node = ya_net_kad::Node<Size>;
type Table = ya_net_kad::Table<Size>;

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

fn dbg_nodes(me: &Node, first: &Vec<Node>, second: &Vec<Node>) {
    first
        .iter()
        .sorted_by_key(|p| me.distance(&p))
        .zip(second.iter().sorted_by_key(|p| me.distance(&p)))
        .for_each(|(n1, n2)| {
            let d1 = BigUint::from_bytes_be(&me.distance(&n1).as_ref()).to_string();
            let d2 = BigUint::from_bytes_be(&me.distance(&n2).as_ref()).to_string();
            println!(
                "exp: {:?}\nkad: {:?}\n\nDistance\nexp: {}..{} (len {})\nkad: {}..{} (len {})\n\n\n",
                n1,
                n2,
                d1[..8].to_string(),
                d1[d1.len() - 8..].to_string(),
                d1.len(),
                d2[..8].to_string(),
                d2[d2.len() - 8..].to_string(),
                d2.len(),
            )
        });
}

fn main() {
    let node_count = 128;
    let neigh_count = 32;

    let me = Arc::new(Node {
        key: gen_key(),
        address: gen_address(),
    });

    let nodes = gen_nodes(node_count);

    let mut table = Table::new(me.clone(), 16);
    nodes.iter().for_each(|n| {
        table.add(n);
    });

    let neighbours = table.neighbors(&me.key, Some(&me.key));
    let len = min(neigh_count, neighbours.len());

    let expected = nodes
        .iter()
        .filter(|p| p.key != me.key)
        .sorted_by_key(|p| me.distance(&p))
        .take(len)
        .cloned()
        .collect::<Vec<_>>();

    dbg_nodes(&me, &expected, &neighbours);
}
