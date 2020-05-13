mod serialize_rmp {
    use crate::Error;
    use rmp_serde::{decode, encode};
    pub use rmp_serde::{from_read, to_vec};

    impl From<encode::Error> for Error {
        fn from(error: encode::Error) -> Self {
            Error::SerializationError(format!("rmp encode error: {:?}", error)).into()
        }
    }

    impl From<decode::Error> for Error {
        fn from(error: decode::Error) -> Self {
            Error::SerializationError(format!("rmp decode error: {:?}", error)).into()
        }
    }
}

pub use serialize_rmp::*;
