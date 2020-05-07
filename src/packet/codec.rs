use crate::Result;
use tokio_bytes::{Bytes, BytesMut};

pub trait Codec: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(value: Vec<u8>) -> Result<Self>;
}

pub trait BytesCodec: Sized {
    fn encode(&self, bytes: &mut BytesMut);
    fn decode(bytes: &mut Bytes) -> Result<Self>;
}
