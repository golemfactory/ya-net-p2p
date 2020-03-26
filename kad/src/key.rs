use crate::Error;
use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::convert::TryFrom;
use std::hash::Hash;
use std::iter::FromIterator;

pub trait KeyLen: ArrayLength<u8> + Unpin + Clone + Ord + Hash {}
impl<L> KeyLen for L where L: ArrayLength<u8> + Unpin + Clone + Ord + Hash {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct Key<N: KeyLen> {
    inner: GenericArray<u8, N>,
}

impl<N: KeyLen> Key<N> {
    pub fn random(leading_zeros: usize) -> Self {
        let mut rng = rand::thread_rng();

        let n = N::to_usize();
        let z = leading_zeros / 8;
        let x = (rng.gen::<u8>() >> (leading_zeros % 8) as u8)
            | 1u8 << (8 - 1 - (leading_zeros % 8)) as u8;

        let inner = if z >= n {
            GenericArray::<u8, N>::from_iter(std::iter::repeat(0u8).take(n))
        } else {
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
    pub fn generate<F: FnMut(usize) -> u8>(f: F) -> Self {
        Self {
            inner: GenericArray::<u8, N>::generate(f),
        }
    }

    pub fn distance<O: AsRef<[u8]>>(&self, other: &O) -> Self {
        let other = other.as_ref();
        let l = other.len();
        let n = N::to_usize();
        let d = if l > n {
            return Self {
                inner: GenericArray::<u8, N>::generate(|_| 0xff),
            };
        } else {
            n - l
        };

        Self {
            inner: GenericArray::<u8, N>::from_iter(
                self.inner
                    .iter()
                    .zip(std::iter::repeat(&0u8).take(d).chain(other.iter()))
                    .map(|(f, s)| f ^ s),
            ),
        }
    }

    pub fn leading_zeros(&self) -> usize {
        let result = self.inner.iter().try_fold(0 as usize, |acc, b| {
            if acc % 8 == 0 {
                Ok(acc + b.leading_zeros() as usize)
            } else {
                Err(acc)
            }
        });

        match result {
            Ok(v) => v,
            Err(v) => v,
        }
    }
}

impl<N: KeyLen> Key<N> {
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

impl<N: KeyLen> AsRef<[u8]> for Key<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<N: KeyLen> std::fmt::Display for Key<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&Self::fmt_key(self))
    }
}

impl<N: KeyLen> TryFrom<Vec<u8>> for Key<N> {
    type Error = Error;

    fn try_from(other: Vec<u8>) -> Result<Self, Self::Error> {
        let l = other.len();
        let n = N::to_usize();
        let d = if l > n {
            return Err(Error::InvalidKeyLength(l));
        } else {
            n - l
        };

        Ok(Key {
            inner: GenericArray::<u8, N>::from_iter(
                std::iter::repeat(0u8).take(d).chain(other.into_iter()),
            ),
        })
    }
}
