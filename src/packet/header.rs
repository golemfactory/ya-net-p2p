use crate::error::{Error, MessageError};
use crate::packet::codec::BytesCodec;
use crate::protocol::ProtocolId;
use crate::Result;
use std::mem::size_of;
use tokio_bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PilotHeader {
    pub protocol_id: ProtocolId,
    pub header_flags: u8,
    pub payload_offset: u16,
}

impl PilotHeader {
    pub const FLAG_RELAY: u8 = 0b_1000_0000;
    pub const FLAG_AUTH: u8 = 0b_0000_0001;
    pub const FLAG_SIGNATURE: u8 = 0b_0000_0010;
    pub const FLAG_ENCRYPTION: u8 = 0b_0000_0100;

    #[inline]
    pub fn relay(&self) -> bool {
        self.header_flags & Self::FLAG_RELAY == Self::FLAG_RELAY
    }

    #[inline]
    pub fn auth(&self) -> bool {
        self.header_flags & Self::FLAG_AUTH == Self::FLAG_AUTH
    }

    #[inline]
    pub fn signature(&self) -> bool {
        self.header_flags & Self::FLAG_SIGNATURE == Self::FLAG_SIGNATURE
    }

    #[inline]
    pub fn encryption(&self) -> bool {
        self.header_flags & Self::FLAG_ENCRYPTION == Self::FLAG_ENCRYPTION
    }
}

impl BytesCodec for PilotHeader {
    fn encode(&self, bytes: &mut BytesMut) {
        bytes.put_uint(self.protocol_id as u64, size_of::<ProtocolId>());
        bytes.put_u8(self.header_flags);
        bytes.put_u16(self.payload_offset);
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < size_of::<PilotHeader>() {
            return Err(insufficient_bytes("PilotHeader"));
        }

        let protocol_id = bytes.get_uint(size_of::<ProtocolId>());
        let header_flags = bytes.get_u8();
        let payload_offset = bytes.get_u16();

        Ok(PilotHeader {
            protocol_id: protocol_id as ProtocolId,
            header_flags,
            payload_offset,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytesHeader {
    vec: Vec<u8>,
}

impl BytesHeader {
    #[inline]
    pub fn ser_overhead() -> usize {
        size_of::<u16>()
    }

    #[inline]
    pub fn ser_size(&self) -> usize {
        Self::ser_overhead() + self.vec.len()
    }

    #[inline]
    pub fn vec(&self) -> &Vec<u8> {
        &self.vec
    }
}

impl From<Vec<u8>> for BytesHeader {
    fn from(mut vec: Vec<u8>) -> Self {
        let len = vec.len() as u16;
        vec.truncate(len as usize);
        BytesHeader { vec }
    }
}

impl BytesCodec for BytesHeader {
    fn encode(&self, bytes: &mut BytesMut) {
        bytes.put_u16(self.vec.len() as u16);
        bytes.put(self.vec.as_ref());
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < size_of::<u16>() {
            return Err(insufficient_bytes("BytesHeader::len"));
        }

        let size = bytes.get_u16() as usize;
        match bytes.remaining() < size {
            true => Err(insufficient_bytes("BytesHeader::to")),
            false => {
                let vec = bytes.split_to(size).to_vec();
                Ok(BytesHeader { vec })
            }
        }
    }
}

#[inline]
pub fn insufficient_bytes(target: &str) -> Error {
    MessageError::Codec(format!("Insufficient bytes for {}", target)).into()
}
