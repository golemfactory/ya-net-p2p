use crate::error::Error;
use crate::event::{ProtocolCmd, SendCmd, SessionCmd, SessionEvt};
use crate::packet::payload::Payload;
use crate::packet::{Guarantees, Packet};
use crate::ProtocolId;
use actix::prelude::*;
use futures::FutureExt;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::time::Duration;

pub struct ProtocolConfig {
    upkeep_interval: Duration,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            upkeep_interval: Duration::from_secs(60),
        }
    }
}

pub struct SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + 'static,
{
    conf: ProtocolConfig,
    packets: Recipient<SendCmd<Key>>,
    events: Recipient<SessionEvt<Key>>,
}

impl<Key> SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + 'static,
{
    pub const PROTOCOL_ID: ProtocolId = 0;

    pub fn new(packets: Recipient<SendCmd<Key>>, events: Recipient<SessionEvt<Key>>) -> Self {
        Self::with_config(ProtocolConfig::default(), packets, events)
    }

    pub fn with_config(
        conf: ProtocolConfig,
        packets: Recipient<SendCmd<Key>>,
        events: Recipient<SessionEvt<Key>>,
    ) -> Self {
        Self {
            conf,
            packets,
            events,
        }
    }

    fn upkeep(&mut self, _: &mut Context<Self>) {}
}

impl<Key> Actor for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(self.conf.upkeep_interval, Self::upkeep)
            .finish()
            .spawn(ctx);

        log::info!("Session service started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::info!("Session service stopped");
    }
}

impl<Key, E> Handler<SessionCmd<Key>> for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error>,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: SessionCmd<Key>, _: &mut Context<Self>) -> Self::Result {
        match msg {
            SessionCmd::Initiate(address) => {
                let packet = Packet {
                    payload: Payload::new(Self::PROTOCOL_ID).with_signature(),
                    guarantees: Guarantees::ordered_default(),
                };

                let fut = self
                    .packets
                    .send(SendCmd::Roaming {
                        from: None,
                        to: address,
                        packet,
                    })
                    .map(|_| Ok(()));

                ActorResponse::r#async(fut.into_actor(self))
            }
            SessionCmd::Disconnect(_key, _reason) => ActorResponse::reply(Ok(())),
        }
    }
}

impl<Key, E> Handler<ProtocolCmd<Key>> for SessionProtocol<Key>
where
    Key: Send + Debug + Clone + Unpin + AsRef<[u8]> + TryFrom<Vec<u8>, Error = E> + 'static,
    E: Into<Error>,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: ProtocolCmd<Key>, ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            ProtocolCmd::RoamingPacket(address, mut packet)
            | ProtocolCmd::SessionPacket(address, mut packet, _) => {
                let sender = self.events.clone();

                let key_vec = match packet.payload.signature().map(|sig| sig.key()).flatten() {
                    Some(key_vec) => key_vec,
                    _ => {
                        log::warn!("Missing key / signature in packet");
                        return ActorResponse::reply(Ok(()));
                    }
                };

                let key = match Key::try_from(key_vec) {
                    Ok(key) => key,
                    Err(e) => return ActorResponse::reply(Err(e.into())),
                };

                let fut = sender
                    .send(SessionEvt::Established(address, key))
                    .map(|_| Ok(()));

                return ActorResponse::r#async(fut.into_actor(self));
            }
            ProtocolCmd::Shutdown => ctx.stop(),
        }

        ActorResponse::reply(Ok(()))
    }
}
