use crate::message;
use crate::Error;
use crate::Node;
use generic_array::ArrayLength;

macro_rules! wrap_message {
    ($ident:ident, $rtype:expr) => {
        #[derive(Clone, Debug, actix::Message)]
        #[rtype(result = $rtype)]
        pub struct $ident<KeySz: ArrayLength<u8>> {
            pub sender: Node<KeySz>,
            pub new_conn: bool,
            pub inner: message::$ident,
        }
    };
}

wrap_message!(Ping, "Result<message::Pong, Error>");
wrap_message!(Pong, "Result<(), Error>");
wrap_message!(Store, "Result<(), Error>");
wrap_message!(FindNode, "Result<message::FindNodeResult, Error>");
wrap_message!(FindValue, "Result<message::FindValueResult, Error>");

#[derive(Clone, Debug, actix::Message)]
#[rtype(result = "Result<(), Error>")]
pub struct LocalAdd<KeySz: ArrayLength<u8>>(pub Node<KeySz>, pub bool);

#[derive(Clone, Debug, actix::Message)]
#[rtype(result = "Result<(), Error>")]
pub struct LocalStore(pub Vec<u8>, pub message::Storage);
