use crate::Error;
use generic_array::{ArrayLength, GenericArray};
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use std::cmp::{max, min};
use std::iter::FromIterator;
use std::ops::Range;

lazy_static::lazy_static! {
    static ref BIG_UINT_ONE: BigUint = 1_u32.to_biguint().unwrap();
    static ref BIG_UINT_TWO: BigUint = 2_u32.to_biguint().unwrap();
}

pub type Key<KeySz> = GenericArray<u8, KeySz>;

pub trait KeyOps: Sized {
    fn distance(&self, other: &Self) -> Self;
    fn try_from_vec(vec: Vec<u8>) -> Result<Self, Error>;
    fn to_big_uint(&self) -> BigUint;
}

pub trait KeyGen: KeyOps {
    fn range() -> Range<BigUint>;
    fn random_within(range: &Range<BigUint>) -> Self;
}

impl<KeySz> KeyOps for Key<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn distance(&self, other: &Self) -> Self {
        Self::from_iter(self.iter().zip(other.iter()).map(|(f, s)| f ^ s))
    }

    fn try_from_vec(vec: Vec<u8>) -> Result<Self, Error> {
        let size = vec.len();
        let expected = KeySz::to_usize();
        let ds = if size > expected {
            return Err(Error::InvalidKeyLength(size));
        } else {
            expected - size
        };

        Ok(Self::from_iter(
            ConstIter(0u8).take(ds).chain(vec.into_iter()),
        ))
    }

    fn to_big_uint(&self) -> BigUint {
        BigUint::from_bytes_be(self)
    }
}

impl<KeySz> KeyGen for Key<KeySz>
where
    KeySz: ArrayLength<u8>,
{
    fn range() -> Range<BigUint> {
        let size = KeySz::to_usize();
        let max_bytes = (0..size).map(|_| 0xff).collect::<Vec<u8>>();
        let max = BigUint::from_bytes_be(&max_bytes);

        Range {
            start: BigUint::from(0u64),
            end: max + &*BIG_UINT_ONE,
        }
    }

    fn random_within(range: &Range<BigUint>) -> Self {
        let self_range = Self::range();
        let big = rand::thread_rng().gen_biguint_range(
            max(&self_range.start, &range.start),
            min(&self_range.end, &range.end),
        );
        Self::try_from_vec(big.to_bytes_be()).unwrap()
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

struct ConstIter<T: Copy>(T);

impl<T: Copy> Iterator for ConstIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0)
    }
}
