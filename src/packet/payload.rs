use crate::crypto::{Signature, SignatureECDSA};
use crate::error::MessageError;
use crate::packet::codec::Codec;
use crate::packet::header::*;
use crate::protocol::ProtocolId;
use crate::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::mem;
use tokio_bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug)]
pub struct Payload {
    pilot_header: PilotHeader,
    relay_header: Option<BytesPayload>,
    payload: BytesPayload,
    pub signature: Option<Signature>,
}

impl Payload {
    #[inline]
    pub fn new(protocol_id: ProtocolId) -> Self {
        Payload {
            pilot_header: PilotHeader::from(protocol_id),
            relay_header: None,
            payload: BytesPayload::default(),
            signature: None,
        }
    }

    fn update_payload_offset(&mut self) {
        let mut payload_offset = mem::size_of::<PilotHeader>();
        if let Some(header) = &self.relay_header {
            payload_offset += header.size();
        }
        self.pilot_header.payload_offset = payload_offset as u16;
    }
}

impl Payload {
    #[inline]
    pub fn is_relayed(&self) -> bool {
        self.pilot_header.is_relayed()
    }

    #[inline]
    pub fn is_signed(&self) -> bool {
        self.pilot_header.is_signed()
    }

    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.pilot_header.is_encrypted()
    }
}

impl Payload {
    #[inline]
    pub fn protocol_id(&self) -> ProtocolId {
        self.pilot_header.protocol_id
    }

    #[inline]
    pub fn relay(&self) -> Option<&Vec<u8>> {
        self.relay_header.as_ref().map(|h| h.vec())
    }

    #[inline]
    pub fn signature(&mut self) -> Option<&mut Signature> {
        self.signature.as_mut()
    }

    #[inline]
    pub fn payload(&self) -> &BytesPayload {
        &self.payload
    }

    pub fn decode_payload<D: DeserializeOwned>(&self) -> Result<D> {
        let deserialized = crate::serialize::from_read(self.payload.vec().as_slice())?;
        Ok(deserialized)
    }

    pub fn signature_data(&self) -> Vec<u8> {
        let mut cloned = self.clone();
        cloned.signature = None;
        cloned.encode_vec()
    }
}

impl Payload {
    #[inline]
    pub fn with_relaying(mut self, to: Vec<u8>) -> Self {
        self.pilot_header.header_flags |= PilotHeader::FLAG_RELAY;
        self.relay_header = Some(BytesPayload::from(to));
        self
    }

    #[inline]
    pub fn with_signature(mut self) -> Self {
        self.pilot_header.header_flags |= PilotHeader::FLAG_SIGNATURE;
        self
    }

    #[inline]
    pub fn with_encryption(mut self) -> Self {
        self.pilot_header.header_flags |= PilotHeader::FLAG_ENCRYPTION;
        self
    }

    #[inline]
    pub fn with_payload(mut self, vec: Vec<u8>) -> Self {
        self.payload = BytesPayload::from(vec);
        self
    }

    pub fn encode_payload<P: Serialize>(mut self, payload: &P) -> Result<Self> {
        self.payload = BytesPayload::from(crate::serialize::to_vec(payload)?);
        Ok(self)
    }
}

impl Codec for Payload {
    fn encode(&mut self, bytes: &mut BytesMut) {
        self.update_payload_offset();

        self.pilot_header.encode(bytes);
        if let Some(header) = &mut self.relay_header {
            header.encode(bytes);
        }
        self.payload.encode(bytes);
        if let Some(signature) = &mut self.signature {
            signature.encode(bytes);
        }
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let pilot_header = PilotHeader::decode(bytes)?;
        let relay_header = match pilot_header.is_relayed() {
            true => Some(BytesPayload::decode(bytes)?),
            false => None,
        };
        let payload = BytesPayload::decode(bytes)?;
        let signature = match pilot_header.is_signed() {
            true => Some(Signature::decode(bytes)?),
            false => None,
        };

        Ok(Payload {
            pilot_header,
            relay_header,
            payload,
            signature,
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
            Signature::Plain(key) => {
                bytes.put_u8(1u8);
                BytesPayload::encode_with_vec(&key, bytes);
            }
        }
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let marker = bytes.get_u8();
        match marker {
            0u8 => Ok(Signature::ECDSA(SignatureECDSA::decode(bytes)?)),
            1u8 => Ok(Signature::Plain(BytesPayload::decode_to_vec(bytes)?)),
            _ => Err(MessageError::UnsupportedSignature.into()),
        }
    }
}

impl Codec for SignatureECDSA {
    fn encode(&mut self, bytes: &mut BytesMut) {
        match self {
            SignatureECDSA::P256K1 { data, key: _ } => {
                bytes.put_u8(0u8);
                BytesPayload::encode_with_vec(data, bytes)
            }
        }
    }

    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let marker = bytes.get_u8();

        match marker {
            0u8 => Ok(SignatureECDSA::P256K1 {
                data: BytesPayload::decode_to_vec(bytes)?,
                key: None,
            }),
            _ => Err(MessageError::UnsupportedSignature.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Payload;
    use crate::crypto::{Signature, SignatureECDSA};
    use crate::packet::codec::Codec;
    use crate::packet::header::PilotHeader;
    use crate::protocol::ProtocolId;

    #[test]
    fn deserialize() {
        let protocol_id = 12345 as ProtocolId;
        let mut payload = Payload::new(protocol_id)
            .with_relaying([1u8; 32].to_vec())
            .with_payload([2u8; 29].to_vec());

        payload.pilot_header.header_flags |= PilotHeader::FLAG_SIGNATURE;
        payload.signature = Some(Signature::ECDSA(SignatureECDSA::P256K1 {
            data: [3u8; 32].to_vec(),
            key: None,
        }));

        let mut decoded = Payload::decode_vec(payload.encode_vec()).unwrap();
        assert_eq!(payload.encode_vec(), decoded.encode_vec());
    }

    #[test]
    fn plain_sig() {
        let protocol_id = 12345 as ProtocolId;
        let mut payload = Payload::new(protocol_id)
            .with_relaying([1u8; 32].to_vec())
            .with_payload([2u8; 29].to_vec())
            .with_signature();
        payload.signature = Some(Signature::Plain(vec![3u8; 20]));
        let mut decoded = Payload::decode_vec(payload.encode_vec()).unwrap();
        assert_eq!(payload.encode_vec(), decoded.encode_vec());
    }
}
