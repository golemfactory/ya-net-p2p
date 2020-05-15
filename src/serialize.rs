mod cbor {
    use crate::error::{Error, MessageError};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_cbor;
    use std::io::Read;

    #[inline]
    pub fn from_read<R, T>(rd: R) -> Result<T, Error>
    where
        R: Read,
        T: DeserializeOwned,
    {
        serde_cbor::from_reader(rd).map_err(Error::from)
    }

    #[inline]
    pub fn to_vec<T>(val: &T) -> Result<Vec<u8>, Error>
    where
        T: Serialize,
    {
        serde_cbor::to_vec(val).map_err(Error::from)
    }

    impl From<serde_cbor::Error> for Error {
        fn from(error: serde_cbor::Error) -> Self {
            MessageError::Codec(format!("cbor error: {:?}", error)).into()
        }
    }
}

pub use cbor::*;
