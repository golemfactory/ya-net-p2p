use crate::Error;
use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;

pub mod lengths {
    pub use generic_array::typenum::{Unsigned, consts::*};
}

pub trait KeyLen: ArrayLength<u8> + Debug + Unpin + Clone + Ord + Hash {}
impl<N> KeyLen for N where N: ArrayLength<u8> + Debug + Unpin + Clone + Ord + Hash {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub struct Key<N: KeyLen> {
    inner: GenericArray<u8, N>,
}

impl<N: KeyLen> Key<N> {
    pub fn distance<O: AsRef<[u8]>>(&self, other: &O) -> Self {
        let other = other.as_ref();
        let l = other.len();
        let n = N::to_usize();

        let inner = if l > n {
            GenericArray::<u8, N>::generate(|_| 0xff)
        } else {
            GenericArray::<u8, N>::from_iter(
                self.inner
                    .iter()
                    .zip(std::iter::repeat(&0xff).take(n - l).chain(other.iter()))
                    .map(|(f, s)| f ^ s),
            )
        };

        Self { inner }
    }

    pub fn leading_zeros(&self) -> usize {
        let result = self.inner.iter().try_fold(0 as usize, |acc, b| {
            let zeros = b.leading_zeros() as usize;
            let next = acc + zeros;

            if zeros < 8 {
                Err(next)
            } else {
                Ok(next)
            }
        });

        match result {
            Ok(v) | Err(v) => v,
        }
    }
}

impl<N: KeyLen> Key<N> {
    pub fn add_prefix<'l, M: KeyLen, I: Iterator<Item = &'l u8>>(
        &self,
        iter: I,
    ) -> Result<Key<M>, Error> {
        let prefix = iter.cloned().collect::<Vec<_>>();
        let len = N::to_usize() + prefix.len();
        if len != M::to_usize() {
            return Err(Error::InvalidKeyLength(len));
        }

        Ok(Key {
            inner: GenericArray::<u8, M>::from_iter(
                prefix.into_iter().chain(self.as_ref().iter().cloned()),
            ),
        })
    }

    pub fn remove_prefix<M: KeyLen>(&self, size: usize) -> Result<Key<M>, Error> {
        let len = N::to_usize() - size;
        if len != M::to_usize() {
            return Err(Error::InvalidKeyLength(len));
        }

        Ok(Key {
            inner: GenericArray::<u8, M>::from_iter(self.as_ref().iter().skip(size).cloned()),
        })
    }

    #[inline(always)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl<N: KeyLen> Key<N> {
    pub fn random(leading_zeros: usize) -> Self {
        let mut rng = rand::thread_rng();

        let n = N::to_usize();
        let z = leading_zeros / 8;

        let inner = if z >= n {
            GenericArray::<u8, N>::from_iter(std::iter::repeat(0u8).take(n))
        } else {
            let x = (rng.gen::<u8>() >> (leading_zeros % 8) as u8)
                | (1u8 << (8 - 1 - (leading_zeros % 8)) as u8);

            GenericArray::<u8, N>::from_iter(
                std::iter::repeat(0u8)
                    .take(z)
                    .chain(std::iter::once(x))
                    .chain((0..(n - z - 1)).map(|_| rng.gen::<u8>())),
            )
        };

        Self { inner }
    }

    #[inline]
    pub fn fmt_key<K: AsRef<[u8]>>(key: K) -> String {
        let r = key.as_ref();
        let n = min(8, r.len() / 2);
        format!(
            "{}..{}",
            hex::encode(&r[..n]),
            hex::encode(&r[r.len() - n..]),
        )
    }
}

impl<N: KeyLen> TryFrom<Vec<u8>> for Key<N> {
    type Error = Error;

    fn try_from(other: Vec<u8>) -> Result<Self, Self::Error> {
        let l = other.len();
        let n = N::to_usize();

        if l > n {
            Err(Error::InvalidKeyLength(l))
        } else {
            Ok(Key {
                inner: GenericArray::<u8, N>::from_iter(
                    std::iter::repeat(0u8).take(n - l).chain(other.into_iter()),
                ),
            })
        }
    }
}

impl<N: KeyLen> AsRef<[u8]> for Key<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<N: KeyLen> std::hash::Hash for Key<N> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.inner.as_slice())
    }
}

impl<N: KeyLen> std::fmt::Display for Key<N> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&Self::fmt_key(self))
    }
}

#[cfg(test)]
mod test {
    use super::{lengths, lengths::Unsigned, Key};

    #[test]
    fn rand_key_leading_zeros() {
        for i in 0..(lengths::U128::to_usize() * 8) {
            let key = Key::<lengths::U128>::random(i);
            assert_eq!(key.leading_zeros(), i);
        }
    }

    #[test]
    fn add_remove_prefix() {
        let key = Key::<lengths::U32>::random(0);

        assert!(key.add_prefix::<lengths::U32, _>([1u8].iter()).is_err());
        assert!(key.add_prefix::<lengths::U33, _>([1u8, 2].iter()).is_err());
        assert!(key.add_prefix::<lengths::U36, _>([1u8, 2].iter()).is_err());

        assert!(key.add_prefix::<lengths::U32, _>([0u8; 0].iter()).is_ok());
        let key_ext = key
            .add_prefix::<lengths::U36, _>([1u8, 2, 3, 4].iter())
            .unwrap();

        assert!(key_ext.remove_prefix::<lengths::U32>(3).is_err());
        assert!(key_ext.remove_prefix::<lengths::U32>(5).is_err());

        assert!(key_ext.remove_prefix::<lengths::U32>(4).is_ok());
        assert!(key_ext.remove_prefix::<lengths::U33>(3).is_ok());
        assert!(key_ext.remove_prefix::<lengths::U36>(0).is_ok());
    }
}
