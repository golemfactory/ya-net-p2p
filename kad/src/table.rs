use crate::key::RangeOps;
use crate::{message, Error, Key, KeyGen, KeyOps, Node};
use chrono::{DateTime, Duration, Utc};
use generic_array::ArrayLength;
use itertools::Itertools;
use num_bigint::BigUint;
use serde::export::Formatter;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::Range;
use std::sync::Arc;

const BUCKET_REFRESH_INTERVAL: i64 = 3600;

pub struct Table<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    buckets: Vec<Bucket<KeySz>>,
    pub me: Arc<Node<KeySz>>,
    size: usize,
}

impl<KeySz> Table<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    pub fn new(me: Arc<Node<KeySz>>, size: usize) -> Self {
        Table {
            buckets: vec![Bucket::new(Key::<KeySz>::range(), size)],
            me,
            size,
        }
    }

    pub fn add(&mut self, node: &Node<KeySz>) -> bool {
        self.dedup(&node);

        let idx = self.bucket_index(&node.key);
        let bucket = &mut self.buckets[idx];

        if bucket.add(node.clone()) {
            true
        // Per section 4.2 of paper, split if the bucket has the node in its range
        // or if the depth is not congruent to 0 mod 5
        } else if bucket.in_range(&self.me) || bucket.depth() % 5 != 0 {
            self.split(idx);
            self.add(node)
        } else {
            false
        }
    }

    pub fn remove(&mut self, node: &Node<KeySz>) -> Option<Node<KeySz>> {
        let idx = self.bucket_index(&node.key);
        self.buckets[idx].remove(node)
    }

    pub fn contains(&self, node: &Node<KeySz>) -> bool {
        self.buckets[self.bucket_index(&node.key)].contains(node)
    }

    pub fn neighbors(&self, key: &Key<KeySz>, excluded: Option<&Key<KeySz>>) -> Vec<Node<KeySz>> {
        TableIter::new(&self.buckets, self.bucket_index(key))
            .filter(|n| match excluded {
                Some(e) => &n.key != e,
                None => true,
            })
            .map(|e| e.clone())
            .take(self.size)
            .sorted_by_key(|e| self.me.distance(&e))
            .collect()
    }

    pub fn stale_buckets(&self) -> Vec<&Bucket<KeySz>> {
        self.buckets.iter().filter(|b| b.stale()).collect()
    }

    fn bucket_index(&self, key: &Key<KeySz>) -> usize {
        let key = key.to_big_uint();

        self.buckets
            .iter()
            .enumerate()
            .find(|(_, b)| key < b.range.end)
            .map(|(i, _)| i)
            .expect("bucket_index must yield a value")
    }

    fn dedup(&mut self, node: &Node<KeySz>) {
        let key = &node.key;
        let address = node.address;

        for b in self.buckets.iter_mut() {
            b.inner.retain(|e| e.address != address || &e.key == key);
        }
    }

    fn split(&mut self, idx: usize) {
        let (first, second) = self.buckets[idx].split();
        self.buckets[idx] = first;
        self.buckets.insert(idx + 1, second);
    }
}

struct TableIter<'b, KeySz>
where
    KeySz: ArrayLength<u8>,
{
    buckets_l: &'b [Bucket<KeySz>],
    buckets_r: &'b [Bucket<KeySz>],
    bucket: &'b [Node<KeySz>],
    left: bool,
}

impl<'b, KeySz> TableIter<'b, KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn new(buckets: &'b [Bucket<KeySz>], idx: usize) -> Self {
        TableIter {
            buckets_l: &buckets[..idx],
            buckets_r: &buckets[idx + 1..],
            bucket: &buckets[idx].inner,
            left: true,
        }
    }
}

impl<'b, KeySz> Iterator for TableIter<'b, KeySz>
where
    KeySz: ArrayLength<u8>,
{
    type Item = &'b Node<KeySz>;

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

#[derive(Clone, Debug)]
pub struct Bucket<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    inner: Vec<Node<KeySz>>,
    queue: Vec<Node<KeySz>>,
    updated: DateTime<Utc>,
    pub(crate) range: Range<BigUint>,
    pub(crate) size: usize,
}

impl<KeySz> Bucket<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn new(range: Range<BigUint>, size: usize) -> Self {
        Self::with_inner(Vec::with_capacity(size), range, size)
    }

    fn with_inner(inner: Vec<Node<KeySz>>, range: Range<BigUint>, size: usize) -> Self {
        Bucket {
            inner,
            queue: Vec::new(),
            updated: Utc::now(),
            range,
            size,
        }
    }

    fn add(&mut self, node: Node<KeySz>) -> bool {
        self.updated = Utc::now();

        if self.contains(&node) {
            self.remove(&node);
        }

        let push = self.inner.len() < self.size;
        if push {
            self.inner.push(node);
        // If the bucket is full, keep track of node in a replacement list,
        // per section 4.1 of the paper.
        } else {
            self.queue.push(node);
        }
        push
    }

    fn remove(&mut self, node: &Node<KeySz>) -> Option<Node<KeySz>> {
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

    #[inline(always)]
    fn in_range(&self, node: &Node<KeySz>) -> bool {
        let big_uint = node.key.to_big_uint();
        self.range.contains(&big_uint)
    }

    #[inline(always)]
    fn contains(&self, node: &Node<KeySz>) -> bool {
        self.inner.contains(node)
    }

    #[inline(always)]
    fn head(&self) -> Option<&Node<KeySz>> {
        self.inner.last()
    }

    fn split(&self) -> (Bucket<KeySz>, Bucket<KeySz>) {
        let (rf, rs) = self.range.split();
        let start_bytes = rs.start.to_bytes_be();
        let (f, s) = self
            .inner
            .clone()
            .into_iter()
            .partition(|n| n.key.as_ref() < start_bytes.as_slice());

        (
            Bucket::with_inner(f, rf, self.size),
            Bucket::with_inner(s, rs, self.size),
        )
    }

    #[inline(always)]
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
