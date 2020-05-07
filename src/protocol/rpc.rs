use crate::ProtocolId;
use hashbrown::{HashMap, HashSet};
use std::hash::Hash;
use std::time::{Duration, Instant};

pub type RequestId = usize;

pub struct RpcProtocol {}

impl RpcProtocol {
    pub const PROTOCOL_ID: ProtocolId = 10000;
}

#[derive(Debug)]
struct Ledger<Key, Id, IdSeq>
where
    Key: Clone + Hash + Eq,
    Id: Copy + Hash + Eq,
    IdSeq: Default,
{
    calls: HashMap<Id, Key>,
    calls_rev: HashMap<Key, HashSet<Id>>,
    active: HashMap<Id, Instant>,
    call_seq: IdSeq,
}

impl<Key, Id, IdSeq> Default for Ledger<Key, Id, IdSeq>
where
    Key: Clone + Hash + Eq,
    Id: Copy + Hash + Eq,
    IdSeq: Default,
{
    fn default() -> Self {
        Ledger {
            calls: HashMap::new(),
            calls_rev: HashMap::new(),
            active: HashMap::new(),
            call_seq: IdSeq::default(),
        }
    }
}

#[allow(dead_code)]
impl<Key, Id, IdSeq> Ledger<Key, Id, IdSeq>
where
    Key: Clone + Hash + Eq,
    Id: Copy + Hash + Eq,
    IdSeq: Default,
{
    fn insert(&mut self, id: Id, key: Key) {
        self.calls.insert(id, key.clone());
        self.calls_rev
            .entry(key)
            .or_insert_with(HashSet::new)
            .insert(id);
        self.active.insert(id, Instant::now());
    }

    fn remove(&mut self, id: &Id) {
        if let Some(key) = self.calls.remove(id) {
            if let Some(ids) = self.calls_rev.get_mut(&key) {
                ids.remove(id);
                if ids.is_empty() {
                    self.calls_rev.remove(&key);
                }
            }
            self.active.remove(id);
        }
    }

    fn remove_by_key(&mut self, key: &Key) {
        self.calls_rev.remove(key).map(|ids| {
            ids.into_iter().for_each(|id| {
                self.calls.remove(&id);
                self.active.remove(&id);
            })
        });
    }

    fn remove_older_than(&mut self, duration: &Duration, now: &Instant) {
        let mut active = std::mem::replace(&mut self.active, HashMap::new());
        active
            .drain_filter(|_, time| *duration < *now - *time)
            .for_each(|(id, _)| self.remove(&id));
        std::mem::replace(&mut self.active, active);
    }
}
