use crate::{Key, KeyLen, Node};
use chrono::{DateTime, Duration, Utc};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

pub const K: usize = 20;
const BUCKET_REFRESH_INTERVAL: i64 = 3600;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Table<N: KeyLen> {
    pub key: Key<N>,
    buckets: Vec<Bucket<N>>,
    pub bucket_size: usize,
}

impl<N: KeyLen> Table<N> {
    pub fn new(key: Key<N>, bucket_size: usize) -> Self {
        let buckets = vec![Bucket::new(bucket_size)];
        Table {
            key,
            buckets,
            bucket_size,
        }
    }

    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.nodes.len()).sum()
    }

    pub fn add(&mut self, node: &Node<N>) -> bool {
        let idx = self.bucket_index(&node.key);
        let bucket = &mut self.buckets[idx];

        if bucket.add(node.clone()) {
            true
        } else if idx != self.buckets.len() - 1 || self.buckets.len() == N::to_usize() * 8 {
            false
        } else {
            self.split(idx);
            self.add(node)
        }
    }

    #[inline]
    pub fn remove(&mut self, key: &Key<N>) {
        let idx = self.bucket_index(&key);
        self.buckets[idx].remove(key)
    }

    #[inline]
    pub fn contains(&self, node: &Node<N>) -> bool {
        self.buckets[self.bucket_index(&node.key)].contains(node)
    }

    #[inline]
    pub fn get(&self, key: &Key<N>) -> Option<&Node<N>> {
        self.buckets[self.bucket_index(&key)].get(key)
    }

    #[inline]
    pub fn stale_buckets(&self) -> Vec<&Bucket<N>> {
        self.buckets.iter().filter(|b| b.stale()).collect()
    }

    pub fn neighbors(
        &self,
        key: &Key<N>,
        excluded: Option<&Key<N>>,
        max: Option<usize>,
    ) -> Vec<Node<N>> {
        TableIter::new(&self.buckets, self.bucket_index(key))
            .filter(|n| excluded.map(|e| &n.key != e).unwrap_or(true))
            .cloned()
            .take(max.unwrap_or(self.bucket_size))
            .sorted_by_key(|e| key.distance(&e.key))
            .collect()
    }

    #[inline]
    pub fn bucket_oldest(&self, key: &Key<N>) -> Option<Node<N>> {
        let idx = self.bucket_index(key);
        self.buckets[idx].oldest().cloned()
    }

    #[inline]
    fn bucket_index(&self, key: &Key<N>) -> usize {
        let distance = self.key.distance(&key).leading_zeros();
        std::cmp::min(distance, self.buckets.len() - 1)
    }

    fn split(&mut self, idx: usize) {
        let queue = std::mem::replace(&mut self.buckets[idx].queue, Vec::new());
        let bucket = self.buckets[idx].split(&self.key, idx);

        self.buckets.insert(idx + 1, bucket);
        queue.iter().for_each(|node| {
            self.add(node);
        });
    }
}

struct TableIter<'b, N: KeyLen> {
    buckets_l: &'b [Bucket<N>],
    buckets_r: &'b [Bucket<N>],
    bucket: &'b [Node<N>],
    left: bool,
}

impl<'b, N: KeyLen> TableIter<'b, N> {
    fn new(buckets: &'b [Bucket<N>], idx: usize) -> Self {
        TableIter {
            buckets_l: &buckets[..idx],
            buckets_r: &buckets[idx + 1..],
            bucket: &buckets[idx].nodes,
            left: true,
        }
    }
}

impl<'b, N: KeyLen> Iterator for TableIter<'b, N> {
    type Item = &'b Node<N>;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_len = self.bucket.len();
        if cur_len == 0 {
            if self.left {
                let len = self.buckets_l.len();
                if len > 0 {
                    self.bucket = &self.buckets_l[len - 1].nodes;
                    self.buckets_l = &self.buckets_l[..len - 1];
                    return self.next();
                }
            } else {
                let len = self.buckets_r.len();
                if len > 0 {
                    self.bucket = &self.buckets_r[len - 1].nodes;
                    self.buckets_r = &self.buckets_r[..len - 1];
                    return self.next();
                }
            }
        } else {
            let elem = &self.bucket[cur_len - 1];
            self.bucket = &self.bucket[..cur_len - 1];
            return Some(elem);
        }

        None
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bucket<N: KeyLen> {
    updated: DateTime<Utc>,
    nodes: Vec<Node<N>>,
    queue: Vec<Node<N>>,
    size: usize,
}

impl<N: KeyLen> Bucket<N> {
    fn new(size: usize) -> Self {
        Self::with_nodes(Vec::with_capacity(size), size)
    }

    fn with_nodes(nodes: Vec<Node<N>>, size: usize) -> Self {
        Bucket {
            updated: Utc::now(),
            nodes,
            queue: Vec::new(),
            size,
        }
    }

    #[inline(always)]
    pub fn oldest(&self) -> Option<&Node<N>> {
        self.nodes.get(0)
    }

    #[inline(always)]
    pub fn stale(&self) -> bool {
        Utc::now() - self.updated > Duration::seconds(BUCKET_REFRESH_INTERVAL)
    }

    #[inline(always)]
    fn contains(&self, node: &Node<N>) -> bool {
        self.nodes.contains(node)
    }

    fn get(&self, key: &Key<N>) -> Option<&Node<N>> {
        match self.nodes.iter().position(|node| &node.key == key) {
            Some(idx) => Some(&self.nodes[idx]),
            None => None,
        }
    }

    fn add(&mut self, node: Node<N>) -> bool {
        self.updated = Utc::now();

        self.remove(&node.key);
        let push = self.nodes.len() < self.size;
        if push {
            self.nodes.push(node);
        // If the bucket is full, keep track of node in a replacement list,
        // per section 4.1 of the paper.
        } else {
            self.queue.push(node);
        }
        push
    }

    fn remove(&mut self, key: &Key<N>) {
        if let Some(idx) = self.nodes.iter().position(|node| &node.key == key) {
            self.nodes.remove(idx);
            if let Some(queued) = self.queue.pop() {
                self.add(queued);
            }
        }
    }

    fn split(&mut self, key: &Key<N>, idx: usize) -> Bucket<N> {
        let nodes = std::mem::replace(&mut self.nodes, Vec::new());
        let (retain, split) = nodes
            .into_iter()
            .partition(|node| node.key.distance(key).leading_zeros() == idx);
        std::mem::replace(&mut self.nodes, retain);
        Bucket::with_nodes(split, self.size)
    }
}
