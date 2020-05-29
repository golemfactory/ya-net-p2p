use crate::error::Error;
use crate::Result;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;
use std::str::FromStr;

pub type Slot = u32;

#[inline(always)]
pub fn to_slot<T: AsRef<[u8]>>(t: T) -> Slot {
    crc::crc32::checksum_ieee(t.as_ref())
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Identity {
    inner: Vec<u8>,
}

impl Identity {
    pub fn new(data: &[u8]) -> Self {
        Identity {
            inner: data.to_vec(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.clone()
    }
}

impl FromStr for Identity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let string = match s[..2].to_lowercase() == "0x" {
            true => &s[2..],
            false => &s,
        };
        let inner = hex::decode(string).map_err(|_| identity_error(s))?;
        Ok(Identity { inner })
    }
}

impl std::fmt::Display for Identity {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("0x{}", hex::encode(&self.inner)))
    }
}

impl AsRef<[u8]> for Identity {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

#[derive(Clone)]
pub struct IdentityManager<Key>
where
    Key: Eq + Hash + Clone,
{
    pub default_key: Rc<Key>,
    identities: Rc<RefCell<HashMap<Key, Identity>>>,
    keys: Rc<RefCell<HashMap<Identity, Key>>>,
    node_keys: Rc<RefCell<HashMap<Identity, Key>>>,
    local_key_pairs: Rc<RefCell<HashMap<Key, Key>>>,
}

impl<Key> IdentityManager<Key>
where
    Key: Eq + Hash + Clone,
{
    pub fn new(default_key: Key) -> Self {
        IdentityManager {
            default_key: Rc::new(default_key),
            identities: Rc::new(RefCell::new(HashMap::new())),
            keys: Rc::new(RefCell::new(HashMap::new())),
            node_keys: Rc::new(RefCell::new(HashMap::new())),
            local_key_pairs: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    pub fn from_raw<E>(
        identity: Identity,
        default_key: Vec<u8>,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Self>
    where
        Key: TryFrom<Vec<u8>, Error = E>,
        E: Into<Error>,
    {
        let default_key =
            Key::try_from(default_key).map_err(|_| Error::key("invalid public key"))?;
        let public_key = Key::try_from(public_key).map_err(|_| Error::key("invalid public key"))?;
        let secret_key = Key::try_from(secret_key).map_err(|_| Error::key("invalid secret key"))?;

        let mut manager = Self::new(public_key.clone());
        manager.insert_key(identity.clone(), public_key.clone());
        manager.insert_node_key(identity, default_key);
        manager.insert_key_pair(public_key, secret_key);
        Ok(manager)
    }

    pub fn insert_key(&mut self, identity: Identity, public_key: Key) {
        self.identities
            .borrow_mut()
            .insert(public_key.clone(), identity.clone());
        self.keys.borrow_mut().insert(identity, public_key);
    }

    #[inline]
    pub fn insert_node_key(&mut self, identity: Identity, node_key: Key) {
        self.node_keys.borrow_mut().insert(identity, node_key);
    }

    #[inline]
    pub fn insert_key_pair(&mut self, public_key: Key, secret_key: Key) {
        self.local_key_pairs
            .borrow_mut()
            .insert(public_key, secret_key);
    }

    #[inline]
    pub fn get_identity(&self, key: &Key) -> Option<Identity> {
        self.identities.borrow().get(key).cloned()
    }

    #[inline]
    pub fn get_key(&self, identity: &Identity) -> Option<Key> {
        self.keys.borrow().get(identity).cloned()
    }

    #[inline]
    pub fn get_node_key(&self, identity: &Identity) -> Option<Key> {
        self.node_keys.borrow().get(identity).cloned()
    }

    #[inline]
    pub fn get_secret_key(&self, public_key: &Key) -> Option<Key> {
        self.local_key_pairs.borrow().get(&public_key).cloned()
    }

    #[inline]
    pub fn get_default_key(&self) -> &Key {
        self.default_key.as_ref()
    }
}

#[inline]
fn identity_error(identity: &str) -> Error {
    Error::protocol(format!("invalid identity: {}", identity))
}
