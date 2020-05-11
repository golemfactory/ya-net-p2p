use crate::error::{Error, MessageError};
use crate::packet::codec::Codec;
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
    pub const FLAG_SIGNATURE: u8 = 0b_0000_0001;
    pub const FLAG_ENCRYPTION: u8 = 0b_0000_0010;

    #[inline]
    pub fn is_relayed(&self) -> bool {
        self.header_flags & Self::FLAG_RELAY == Self::FLAG_RELAY
    }

    #[inline]
    pub fn is_signed(&self) -> bool {
        self.header_flags & Self::FLAG_SIGNATURE == Self::FLAG_SIGNATURE
    }

    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.header_flags & Self::FLAG_ENCRYPTION == Self::FLAG_ENCRYPTION
    }
}

impl Codec for PilotHeader {
    fn encode(&mut self, bytes: &mut BytesMut) {
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

impl From<ProtocolId> for PilotHeader {
    fn from(protocol_id: u16) -> Self {
        PilotHeader {
            protocol_id,
            payload_offset: 0,
            header_flags: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytesPayload {
    vec: Vec<u8>,
}

impl BytesPayload {
    #[inline]
    pub fn size(&self) -> usize {
        size_of::<u16>() + self.vec.len()
    }

    #[inline]
    pub fn vec(&self) -> &Vec<u8> {
        &self.vec
    }
}

impl BytesPayload {
    #[inline]
    pub fn encode_with_vec(vec: &Vec<u8>, bytes: &mut BytesMut) {
        bytes.put_u16(vec.len() as u16);
        bytes.put(vec.as_ref());
    }

    #[inline]
    pub fn decode_to_vec(bytes: &mut Bytes) -> Result<Vec<u8>> {
        Self::decode(bytes).map(|b| b.vec)
    }
}

impl From<Vec<u8>> for BytesPayload {
    fn from(mut vec: Vec<u8>) -> Self {
        let len = vec.len() as u16;
        vec.truncate(len as usize);
        BytesPayload { vec }
    }
}

impl Codec for BytesPayload {
    fn encode(&mut self, bytes: &mut BytesMut) {
        Self::encode_with_vec(&self.vec, bytes)
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
                Ok(BytesPayload { vec })
            }
        }
    }
}

impl Default for BytesPayload {
    fn default() -> Self {
        BytesPayload::from(Vec::new())
    }
}

#[inline]
pub fn insufficient_bytes(target: &str) -> Error {
    MessageError::Codec(format!("Insufficient bytes for {}", target)).into()
}
