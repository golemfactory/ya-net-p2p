use crate::packet::codec::{BytesCodec, Codec};
use crate::packet::header::*;
use crate::protocol::ProtocolId;
use crate::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::mem;
use tokio_bytes::{BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payload {
    pilot_header: PilotHeader,
    relay_header: Option<BytesHeader>,
    auth_header: Option<BytesHeader>,
    sig_header: Option<BytesHeader>,
    payload: Vec<u8>,
}

impl Payload {
    #[inline]
    pub fn builder(protocol_id: ProtocolId) -> PayloadBuilder {
        PayloadBuilder::new(protocol_id)
    }

    #[inline]
    pub fn mangle(&mut self) -> PayloadMangler {
        PayloadMangler { inner: self }
    }

    fn update_payload_offset(&mut self) {
        let mut payload_offset = mem::size_of::<PilotHeader>();

        if let Some(header) = &self.relay_header {
            payload_offset += header.ser_size();
        }
        if let Some(header) = &self.auth_header {
            payload_offset += header.ser_size();
        }
        if let Some(header) = &self.sig_header {
            payload_offset += header.ser_size();
        }

        self.pilot_header.payload_offset = payload_offset as u16;
    }
}

impl Payload {
    #[inline]
    pub fn protocol_id(&self) -> ProtocolId {
        self.pilot_header.protocol_id
    }

    #[inline]
    pub fn relay(&self) -> Option<&Vec<u8>> {
        match &self.relay_header {
            Some(header) => Some(header.vec()),
            _ => None,
        }
    }

    #[inline]
    pub fn auth(&self) -> Option<&Vec<u8>> {
        match &self.auth_header {
            Some(header) => Some(header.vec()),
            _ => None,
        }
    }

    #[inline]
    pub fn sig(&self) -> Option<&Vec<u8>> {
        match &self.sig_header {
            Some(header) => Some(header.vec()),
            _ => None,
        }
    }

    #[inline]
    pub fn payload(&self) -> &Vec<u8> {
        &self.payload
    }

    pub fn try_payload<D: DeserializeOwned>(&self) -> Result<D> {
        let deserialized = crate::serialize::from_read(self.payload.as_slice())?;
        Ok(deserialized)
    }
}

impl Payload {
    #[inline]
    pub fn with_auth(&self) -> bool {
        self.pilot_header.auth()
    }

    #[inline]
    pub fn with_signature(&self) -> bool {
        self.pilot_header.signature()
    }

    #[inline]
    pub fn with_encryption(&self) -> bool {
        self.pilot_header.encryption()
    }
}

impl Codec for Payload {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = BytesMut::with_capacity(mem::size_of::<PilotHeader>());
        self.pilot_header.encode(&mut bytes);

        if let Some(header) = &self.relay_header {
            header.encode(&mut bytes);
        }
        if let Some(header) = &self.auth_header {
            header.encode(&mut bytes);
        }
        if let Some(header) = &self.sig_header {
            header.encode(&mut bytes);
        }

        bytes.put(self.payload.as_ref());
        bytes.to_vec()
    }

    fn decode(value: Vec<u8>) -> Result<Self> {
        let mut bytes: Bytes = Bytes::from(value);
        let pilot_header = PilotHeader::decode(&mut bytes)?;

        let relay_header = match pilot_header.relay() {
            true => Some(BytesHeader::decode(&mut bytes)?),
            false => None,
        };
        let auth_header = match pilot_header.auth() {
            true => Some(BytesHeader::decode(&mut bytes)?),
            false => None,
        };
        let sig_header = match pilot_header.signature() {
            true => Some(BytesHeader::decode(&mut bytes)?),
            false => None,
        };
        let payload = bytes.as_ref().to_vec();

        Ok(Payload {
            pilot_header,
            relay_header,
            auth_header,
            sig_header,
            payload,
        })
    }
}

#[derive(Clone)]
pub struct PayloadBuilder {
    inner: Payload,
}

impl PayloadBuilder {
    pub fn new(protocol_id: ProtocolId) -> Self {
        PayloadBuilder {
            inner: Payload {
                pilot_header: PilotHeader {
                    protocol_id,
                    payload_offset: 0,
                    header_flags: 0,
                },
                relay_header: None,
                auth_header: None,
                sig_header: None,
                payload: Vec::new(),
            },
        }
    }

    #[inline]
    pub fn relay(mut self, to: Vec<u8>) -> Self {
        self.inner.pilot_header.header_flags |= PilotHeader::FLAG_RELAY;
        self.inner.relay_header = Some(BytesHeader::from(to));
        self
    }

    #[inline]
    pub fn payload(mut self, vec: Vec<u8>) -> Self {
        self.inner.payload = vec;
        self
    }

    pub fn try_payload<P: Serialize>(mut self, payload: &P) -> Result<Self> {
        self.inner.payload = crate::serialize::to_vec(payload)?;
        Ok(self)
    }

    #[inline]
    pub fn with_signature(mut self) -> Self {
        self.inner.pilot_header.header_flags |= PilotHeader::FLAG_SIGNATURE;
        self
    }

    #[inline]
    pub fn with_auth(mut self) -> Self {
        self.inner.pilot_header.header_flags |= PilotHeader::FLAG_AUTH;
        self
    }

    #[inline]
    pub fn with_encryption(mut self) -> Self {
        self.inner.pilot_header.header_flags |= PilotHeader::FLAG_ENCRYPTION;
        self
    }

    pub fn build(mut self) -> Payload {
        self.inner.update_payload_offset();
        self.inner
    }
}

impl From<Payload> for PayloadBuilder {
    fn from(payload: Payload) -> Self {
        PayloadBuilder { inner: payload }
    }
}

pub struct PayloadMangler<'p> {
    inner: &'p mut Payload,
}

impl<'p> PayloadMangler<'p> {
    pub fn signature_data(&mut self) -> Vec<u8> {
        self.inner.sig_header = None;
        self.inner.update_payload_offset();
        self.inner.encode()
    }

    #[inline]
    pub fn sig(&mut self, sig: Vec<u8>) -> &mut Self {
        self.inner.pilot_header.header_flags |= PilotHeader::FLAG_SIGNATURE;
        self.inner.sig_header = Some(BytesHeader::from(sig));
        self.inner.update_payload_offset();
        self
    }

    #[inline]
    pub fn auth(&mut self, key: Vec<u8>) -> &mut Self {
        self.inner.pilot_header.header_flags |= PilotHeader::FLAG_AUTH;
        self.inner.auth_header = Some(BytesHeader::from(key));
        self.inner.update_payload_offset();
        self
    }

    #[inline]
    pub fn payload(&mut self, vec: Vec<u8>) -> &mut Self {
        self.inner.payload = vec;
        self
    }
}

#[cfg(test)]
mod test {
    use super::Payload;
    use crate::packet::codec::Codec;
    use crate::protocol::ProtocolId;

    #[test]
    fn deserialize() {
        let protocol_id = 12345 as ProtocolId;
        let payload = Payload::builder(protocol_id)
            .auth([1u8; 32].to_vec())
            .relay([2u8; 32].to_vec())
            .payload([3u8; 29].to_vec())
            .build();
        let decoded = Payload::decode(payload.encode()).unwrap();
        assert_eq!(payload, decoded);
    }
}
