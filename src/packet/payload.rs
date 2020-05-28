use crate::crypto::{Signature, SignatureECDSA};
use crate::error::MessageError;
use crate::identity::{Identity, Slot};
use crate::packet::codec::Codec;
use crate::protocol::{ProtocolId, ProtocolVersion};
use crate::{Error, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::mem;
use std::mem::size_of;
use tokio_bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug)]
pub struct Payload {
    pub protocol_id: ProtocolId,
    pub protocol_ver: ProtocolVersion,
    flags: u8,
    pub sender: Option<Slot>,
    pub recipient: Option<Slot>,
    pub signature: Option<Signature>,
    pub body: Body,
}

impl Payload {
    pub const FLAG_SIGNATURE: u8 = 0b_0000_0001;
    pub const FLAG_ENCRYPTION: u8 = 0b_0000_0010;

    pub fn new(protocol_id: ProtocolId, protocol_ver: ProtocolVersion, payload: Vec<u8>) -> Self {
        Payload {
            protocol_id,
            protocol_ver,
            flags: 0,
            sender: None,
            recipient: None,
            signature: None,
            body: Body::from(payload),
        }
    }

    pub fn try_with<P: Serialize>(
        protocol_id: ProtocolId,
        protocol_ver: ProtocolVersion,
        payload: &P,
    ) -> Result<Self> {
        Ok(Self::new(
            protocol_id,
            protocol_ver,
            crate::serialize::to_vec(payload)?,
        ))
    }

    pub fn decode_body<D: DeserializeOwned>(&self) -> Result<D> {
        let deserialized = crate::serialize::from_read(self.body.as_ref())?;
        Ok(deserialized)
    }
}

impl Payload {
    #[inline]
    pub fn is_signed(&self) -> bool {
        self.flags & Self::FLAG_SIGNATURE == Self::FLAG_SIGNATURE
    }

    pub fn sign(mut self) -> Self {
        self.flags |= Self::FLAG_SIGNATURE;
        self
    }

    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.flags & Self::FLAG_ENCRYPTION == Self::FLAG_ENCRYPTION
    }

    #[inline]
    pub fn encrypt(mut self) -> Self {
        self.flags |= Self::FLAG_ENCRYPTION;
        self
    }

    #[inline]
    pub fn encode_for_signing(&self) -> Vec<u8> {
        let mut cloned = self.clone();
        cloned.signature = None;
        cloned.encode_vec()
    }
}

impl Codec for Payload {
    fn encode(&mut self, bytes: &mut BytesMut) {
        bytes.put_uint(self.protocol_id as u64, size_of::<ProtocolId>());
        bytes.put_uint(self.protocol_ver as u64, size_of::<ProtocolVersion>());
        bytes.put_u8(self.flags);

        if self.flags & Self::FLAG_ENCRYPTION == Self::FLAG_ENCRYPTION {
            bytes.put_uint(self.sender.unwrap() as u64, size_of::<Slot>());
            bytes.put_uint(self.recipient.unwrap() as u64, size_of::<Slot>());
        }
        if self.flags & Self::FLAG_SIGNATURE == Self::FLAG_SIGNATURE {
            if let Some(signature) = &mut self.signature {
                signature.encode(bytes);
            }
        }

        self.body.encode(bytes);
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let protocol_id = bytes.get_uint(size_of::<ProtocolId>()) as ProtocolId;
        let protocol_ver = bytes.get_uint(size_of::<ProtocolVersion>()) as ProtocolVersion;
        let flags = bytes.get_u8();

        let (sender, recipient) = if flags & Self::FLAG_ENCRYPTION == Self::FLAG_ENCRYPTION {
            let sender = bytes.get_uint(size_of::<Slot>()) as Slot;
            let recipient = bytes.get_uint(size_of::<Slot>()) as Slot;
            (Some(sender), Some(recipient))
        } else {
            (None, None)
        };
        let signature = if flags & Self::FLAG_SIGNATURE == Self::FLAG_SIGNATURE {
            Some(Signature::decode(bytes)?)
        } else {
            None
        };

        let body = Body::decode(bytes)?;

        Ok(Payload {
            protocol_id,
            protocol_ver,
            flags,
            sender,
            recipient,
            signature,
            body,
        })
    }
}

impl Codec for Signature {
    fn encode(&mut self, bytes: &mut BytesMut) {
        match self {
            Signature::ECDSA(ecdsa) => {
                bytes.put_u8(0u8);
                ecdsa.encode(bytes);
            }
        }
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let marker = bytes.get_u8();
        match marker {
            0u8 => Ok(Signature::ECDSA(SignatureECDSA::decode(bytes)?)),
            _ => Err(MessageError::UnsupportedSignature.into()),
        }
    }
}

impl Codec for SignatureECDSA {
    fn encode(&mut self, bytes: &mut BytesMut) {
        match self {
            SignatureECDSA::P256K1 { data, key: _ } => {
                bytes.put_u8(0u8);
                Body::encode_with_vec(data, bytes)
            }
        }
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let marker = bytes.get_u8();

        match marker {
            0u8 => Ok(SignatureECDSA::P256K1 {
                data: Body::decode_to_vec(bytes)?,
                key: None,
            }),
            _ => Err(MessageError::UnsupportedSignature.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Body {
    vec: Vec<u8>,
}

impl Body {
    #[inline]
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.vec, Vec::new())
    }

    #[inline]
    pub fn encode_with_vec(vec: &Vec<u8>, bytes: &mut BytesMut) {
        bytes.put_u32(vec.len() as u32);
        bytes.put(vec.as_slice());
    }

    #[inline]
    pub fn decode_to_vec(bytes: &mut Bytes) -> Result<Vec<u8>> {
        Self::decode(bytes).map(|b| b.vec)
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::from(Vec::new())
    }
}

impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        self.vec.as_ref()
    }
}

impl From<Vec<u8>> for Body {
    #[inline]
    fn from(mut vec: Vec<u8>) -> Self {
        let len = vec.len() as u32;
        vec.truncate(len as usize);
        Body { vec }
    }
}

impl Codec for Body {
    #[inline]
    fn encode(&mut self, bytes: &mut BytesMut) {
        Self::encode_with_vec(&self.vec, bytes)
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < size_of::<u32>() {
            return Err(insufficient_bytes());
        }

        let len = bytes.get_u32() as usize;
        match bytes.remaining() < len {
            true => Err(insufficient_bytes()),
            false => {
                let vec = bytes.split_to(len).to_vec();
                Ok(Body { vec })
            }
        }
    }
}

#[inline]
pub fn insufficient_bytes() -> Error {
    MessageError::Codec("insufficient bytes".to_string()).into()
}

#[cfg(test)]
mod test {
    use super::Payload;
    use crate::crypto::{Signature, SignatureECDSA};
    use crate::packet::codec::Codec;
    use crate::protocol::{ProtocolId, ProtocolVersion};

    #[test]
    fn deserialize() {
        let protocol_id = 12345 as ProtocolId;
        let protocol_ver = 0 as ProtocolVersion;
        let mut payload = Payload::new(protocol_id, protocol_ver, [1u8; 29].to_vec());

        payload.flags |= Payload::FLAG_SIGNATURE;
        payload.signature = Some(Signature::ECDSA(SignatureECDSA::P256K1 {
            data: [3u8; 32].to_vec(),
            key: None,
        }));

        let mut decoded = Payload::decode_vec(payload.encode_vec()).unwrap();
        assert_eq!(payload.encode_vec(), decoded.encode_vec());
    }
}
