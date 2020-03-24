use crate::Error;
use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use std::convert::TryFrom;
use std::hash::Hash;
use std::iter::FromIterator;
use std::ops::Range;

lazy_static::lazy_static! {
    static ref BIG_UINT_ONE: BigUint = 1_u32.to_biguint().unwrap();
    static ref BIG_UINT_TWO: BigUint = 2_u32.to_biguint().unwrap();
}

pub trait KeyLen: ArrayLength<u8> + Unpin + Clone + Ord + Hash {}
impl<L> KeyLen for L where L: ArrayLength<u8> + Unpin + Clone + Ord + Hash {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct Key<N: KeyLen> {
    inner: GenericArray<u8, N>,
}

impl<N: KeyLen> Key<N> {
    pub fn range() -> Range<BigUint> {
        let max_bytes = (0..N::to_usize()).map(|_| 0xff).collect::<Vec<u8>>();
        let max = BigUint::from_bytes_be(&max_bytes);

        Range {
            start: BigUint::from(0u64),
            end: max + &*BIG_UINT_ONE,
        }
    }

    pub fn random(range: &Range<BigUint>) -> Self {
        let self_range = Self::range();
        let big = rand::thread_rng().gen_biguint_range(
            max(&self_range.start, &range.start),
            min(&self_range.end, &range.end),
        );

        Self::try_from(big.to_bytes_be()).unwrap()
    }

    #[inline]
    pub fn generate<F: FnMut(usize) -> u8>(f: F) -> Self {
        Self {
            inner: GenericArray::<u8, N>::generate(f),
        }
    }

    pub fn distance<O: AsRef<[u8]>>(&self, other: &O) -> Self {
        let other = other.as_ref();
        let other_len = other.len();
        let len = N::to_usize();
        let diff = if other_len > len {
            return Self {
                inner: GenericArray::<u8, N>::generate(|_| 0xff),
            };
        } else {
            len - other_len
        };

        Self {
            inner: GenericArray::<u8, N>::from_iter(
                self.inner
                    .iter()
                    .zip(std::iter::repeat(&0u8).take(diff).chain(other.iter()))
                    .map(|(f, s)| f ^ s),
            ),
        }
    }
}

impl<N: KeyLen> AsRef<[u8]> for Key<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<N: KeyLen> TryFrom<Vec<u8>> for Key<N> {
    type Error = Error;

    fn try_from(other: Vec<u8>) -> Result<Self, Self::Error> {
        let other_len = other.len();
        let len = N::to_usize();
        let diff = if other_len > len {
            return Err(Error::InvalidKeyLength(other_len));
        } else {
            len - other_len
        };

        Ok(Key {
            inner: GenericArray::<u8, N>::from_iter(
                std::iter::repeat(0u8).take(diff).chain(other.into_iter()),
            ),
        })
    }
}

impl<N: KeyLen> ToBigUint for Key<N> {
    fn to_biguint(&self) -> Option<BigUint> {
        Some(BigUint::from_bytes_be(&self.inner))
    }
}

pub(crate) trait RangeOps<T> {
    fn split(&self) -> (Range<T>, Range<T>);
}

impl RangeOps<BigUint> for Range<BigUint> {
    fn split(&self) -> (Range<BigUint>, Range<BigUint>) {
        let start = &self.start;
        let end = &self.end;
        let mid = end - ((end - start) / &*BIG_UINT_TWO);

        (
            Range {
                start: start.clone(),
                end: mid.clone(),
            },
            Range {
                start: mid.clone(),
                end: end.clone() + &*BIG_UINT_ONE,
            },
        )
    }
}
