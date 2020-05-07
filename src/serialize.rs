mod message_pack {
    use crate::error::{Error, MessageError};
    use rmp_serde::{decode, encode};
    pub use rmp_serde::{from_read, to_vec};

    impl From<encode::Error> for Error {
        fn from(error: encode::Error) -> Self {
            MessageError::Codec(format!("rmp encode error: {:?}", error)).into()
        }
    }

    impl From<decode::Error> for Error {
        fn from(error: decode::Error) -> Self {
            MessageError::Codec(format!("rmp decode error: {:?}", error)).into()
        }
    }
}

pub use message_pack::*;
