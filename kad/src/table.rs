use crate::key::RangeOps;
use crate::{Key, KeyLen, Node};
use chrono::{DateTime, Duration, Utc};
use itertools::Itertools;
use num_bigint::{BigUint, ToBigUint};
use serde::{Deserialize, Serialize};
use std::ops::Range;

const BUCKET_REFRESH_INTERVAL: i64 = 3600;
pub const K: usize = 20;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Table<N: KeyLen> {
    pub key: Key<N>,
    buckets: Vec<Bucket<N>>,
    pub k: usize,
}

impl<N: KeyLen> Table<N> {
    pub fn new(key: Key<N>, k: usize) -> Self {
        Table {
            key,
            buckets: vec![Bucket::new(Key::<N>::range(), k)],
            k,
        }
    }

    #[inline]
    pub fn get(&self, key: &Key<N>) -> Option<&Node<N>> {
        let idx = self.bucket_index(&key);
        self.buckets[idx].get(key)
    }

    pub fn add(&mut self, node: &Node<N>) -> bool {
        self.dedup(&node);

        let idx = self.bucket_index(&node.key);
        let bucket = &mut self.buckets[idx];

        if bucket.add(node.clone()) {
            true
        // Per section 4.2 of paper, split if the bucket has the node in its range
        // or if the depth is not congruent to 0 mod 5
        } else if bucket.in_range(&self.key) || bucket.depth() % 5 != 0 {
            self.split(idx);
            self.add(node)
        } else {
            false
        }
    }

    #[inline]
    pub fn remove(&mut self, node: &Node<N>) -> Option<Node<N>> {
        let idx = self.bucket_index(&node.key);
        self.buckets[idx].remove(node)
    }

    #[inline]
    pub fn contains(&self, node: &Node<N>) -> bool {
        self.buckets[self.bucket_index(&node.key)].contains(node)
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
        let max = max.unwrap_or(self.k);
        TableIter::new(&self.buckets, self.bucket_index(key))
            .filter(|n| excluded.map(|e| &n.key != e).unwrap_or(true))
            .cloned()
            .take(max)
            .sorted_by_key(|e| self.key.distance(&e.key))
            .collect()
    }

    fn bucket_index(&self, key: &Key<N>) -> usize {
        let key = key.to_biguint().unwrap();

        self.buckets
            .iter()
            .enumerate()
            .find(|(_, b)| key < b.range.end)
            .map(|(i, _)| i)
            .expect("bucket_index must yield a value")
    }

    fn dedup(&mut self, node: &Node<N>) {
        let key = &node.key;
        let address = node.address;

        self.buckets
            .iter_mut()
            .for_each(|b| b.inner.retain(|e| e.address != address || &e.key == key));
    }

    fn split(&mut self, idx: usize) {
        let (first, second) = self.buckets[idx].split();
        self.buckets[idx] = first;
        self.buckets.insert(idx + 1, second);
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
            bucket: &buckets[idx].inner,
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
                    self.bucket = &self.buckets_l[len - 1].inner;
                    self.buckets_l = &self.buckets_l[..len - 1];
                    return self.next();
                }
            } else {
                let len = self.buckets_r.len();
                if len > 0 {
                    self.bucket = &self.buckets_r[len - 1].inner;
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
    inner: Vec<Node<N>>,
    queue: Vec<Node<N>>,
    updated: DateTime<Utc>,
    pub range: Range<BigUint>,
    pub k: usize,
}

impl<N: KeyLen> Bucket<N> {
    fn new(range: Range<BigUint>, k: usize) -> Self {
        Self::with_inner(Vec::with_capacity(k), range, k)
    }

    fn with_inner(inner: Vec<Node<N>>, range: Range<BigUint>, k: usize) -> Self {
        Bucket {
            inner,
            queue: Vec::new(),
            updated: Utc::now(),
            range,
            k,
        }
    }

    fn get(&self, key: &Key<N>) -> Option<&Node<N>> {
        match self.inner.iter().position(|x| &x.key == key) {
            Some(i) => Some(&self.inner[i]),
            None => None,
        }
    }

    fn add(&mut self, node: Node<N>) -> bool {
        self.updated = Utc::now();

        if self.contains(&node) {
            self.remove(&node);
        }

        let push = self.inner.len() < self.k;
        if push {
            self.inner.push(node);
        // If the bucket is full, keep track of node in a replacement list,
        // per section 4.1 of the paper.
        } else {
            self.queue.push(node);
        }
        push
    }

    fn remove(&mut self, node: &Node<N>) -> Option<Node<N>> {
        match self.inner.iter().position(|x| x == node) {
            // Set a replacement for the deleted node
            Some(i) => {
                let result = Some(self.inner.remove(i));
                if let Some(queued) = self.queue.pop() {
                    self.add(queued);
                }
                result
            }
            None => None,
        }
    }

    fn split(&self) -> (Bucket<N>, Bucket<N>) {
        let (rf, rs) = self.range.split();
        let start_bytes = rs.start.to_bytes_be();
        let (f, s) = self
            .inner
            .clone()
            .into_iter()
            .partition(|n| n.key.as_ref() < start_bytes.as_slice());

        (
            Bucket::with_inner(f, rf, self.k),
            Bucket::with_inner(s, rs, self.k),
        )
    }

    #[inline(always)]
    fn in_range(&self, key: &Key<N>) -> bool {
        let big_uint = key.to_biguint().unwrap();
        self.range.contains(&big_uint)
    }

    #[inline(always)]
    fn contains(&self, node: &Node<N>) -> bool {
        self.inner.contains(node)
    }

    fn depth(&self) -> usize {
        let first = match self.inner.get(0) {
            Some(e) => e.key.as_ref(),
            None => return 0,
        };

        self.inner[1..].iter().fold(first.len(), move |len, n| {
            let key = n.key.as_ref();
            std::cmp::min(
                len,
                key.iter().zip(first).take_while(|(e, o)| e.eq(o)).count(),
            )
        })
    }

    #[inline(always)]
    fn stale(&self) -> bool {
        Utc::now() - self.updated > Duration::seconds(BUCKET_REFRESH_INTERVAL)
    }
}
