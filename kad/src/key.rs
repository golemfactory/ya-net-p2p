use crate::Error;
use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::convert::TryFrom;
use std::hash::Hash;
use std::iter::FromIterator;

pub trait KeyLen: ArrayLength<u8> + std::fmt::Debug + Unpin + Clone + Ord + Hash {}
impl<L> KeyLen for L where L: ArrayLength<u8> + std::fmt::Debug + Unpin + Clone + Ord + Hash {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
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
                    .zip(std::iter::repeat(&0u8).take(n - l).chain(other.iter()))
                    .map(|(f, s)| f ^ s),
            )
        };

        Self { inner }
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
            Ok(v) | Err(v) => v,
        }
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
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
    use super::*;
    use generic_array::typenum::{Unsigned, U128};
    use generic_array::ArrayLength;

    type Size = U128;

    fn leading_zeros() {
        for i in 0..(Size::to_usize() * 8) {
            let key = Key::<Size>::random(i);
            assert_eq!(key.leading_zeros(), i);
        }
    }
}
