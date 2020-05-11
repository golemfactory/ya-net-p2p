use crate::Result;
use tokio_bytes::{Bytes, BytesMut};

pub trait Codec: Sized {
    fn encode(&mut self, bytes: &mut BytesMut);
    fn decode(bytes: &mut Bytes) -> Result<Self>;

    #[inline]
    fn encode_vec(&mut self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        self.encode(&mut bytes);
        bytes.to_vec()
    }

    #[inline]
    fn decode_vec(value: Vec<u8>) -> Result<Self> {
        let mut bytes: Bytes = Bytes::from(value);
        Self::decode(&mut bytes)
    }
}
