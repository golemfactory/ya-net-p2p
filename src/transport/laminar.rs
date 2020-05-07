use crate::common::FlattenResult;
use crate::error::*;
use crate::event::*;
use crate::packet::{AddressedPacket, DeliveryType, EncodedPacket, Guarantees, OrderingType};
use crate::transport::Address;
use crate::Result;
use actix::prelude::*;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::{FutureExt, SinkExt, TryFutureExt};
use laminar::{DeliveryGuarantee, OrderingGuarantee, Socket, SocketEvent};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct TransportConfig {
    poll_interval: Duration,
    channel_buffer_size: usize,
    laminar_config: laminar::Config,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            poll_interval: Duration::from_millis(1),
            channel_buffer_size: 128,
            laminar_config: Self::default_laminar_config(),
        }
    }
}

impl TransportConfig {
    pub fn default_laminar_config() -> laminar::Config {
        let mut config = laminar::Config::default();
        config.max_fragments = 64;
        config.max_packet_size = 65535;
        config.fragment_reassembly_buffer_size = 256;
        config
    }
}

struct ThreadControl {
    tx: oneshot::Sender<()>,
    arbiter: Arbiter,
}

impl ThreadControl {
    fn spawn() -> (Self, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        let control = ThreadControl {
            tx,
            arbiter: Arbiter::new(),
        };
        (control, rx)
    }

    #[inline]
    fn send<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.arbiter.send(f.boxed())
    }

    fn stop(self) {
        let _ = self.tx.send(());
    }
}

pub struct LaminarTransport<Ctx>
where
    Ctx: Send + Clone + Debug,
{
    conf: TransportConfig,
    recipient: Recipient<TransportEvt>,
    thread_control: Option<ThreadControl>,
    message_sender: Option<mpsc::Sender<AddressedPacket>>,
    phantom: PhantomData<Ctx>,
}

impl<Ctx> LaminarTransport<Ctx>
where
    Ctx: Send + Clone + Debug,
{
    pub fn new(recipient: Recipient<TransportEvt>) -> Self {
        Self::with_config(recipient, TransportConfig::default())
    }

    pub fn with_config(recipient: Recipient<TransportEvt>, conf: TransportConfig) -> Self {
        LaminarTransport {
            conf,
            recipient,
            thread_control: None,
            message_sender: None,
            phantom: PhantomData,
        }
    }

    fn send_packet(
        &self,
        socket_addr: SocketAddr,
        packet: EncodedPacket,
    ) -> impl Future<Output = Result<()>> {
        let mut sender = match &self.message_sender {
            Some(sender) => sender.clone(),
            None => return futures::future::err(ChannelError::Closed.into()).left_future(),
        };

        return async move {
            sender
                .send(packet.addressed_with(Address::LAMINAR, socket_addr))
                .await?;
            Ok(())
        }
        .right_future();
    }
}

impl<Ctx> Actor for LaminarTransport<Ctx>
where
    Ctx: Unpin + Send + Clone + Debug + 'static,
{
    type Context = Context<Self>;

    fn started(&mut self, _: &mut Self::Context) {
        log::debug!("Laminar transport service started");
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        log::debug!("Laminar transport service stopped");
    }
}

impl<Ctx> Handler<TransportCmd> for LaminarTransport<Ctx>
where
    Ctx: Unpin + Send + Clone + Debug + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, msg: TransportCmd, ctx: &mut Context<Self>) -> Self::Result {
        log::debug!("Transport command: {:?}", msg);

        match msg {
            TransportCmd::Bind(addresses) => {
                let actor = ctx.address();
                let fut = async move {
                    actor.send(InternalRequest::Unbind).await??;
                    actor.send(InternalRequest::Bind(addresses)).await??;
                    Ok(())
                };
                return ActorResponse::r#async(fut.into_actor(self));
            }
            TransportCmd::Shutdown => {
                let actor = ctx.address();
                let fut = async move {
                    actor.send(InternalRequest::Unbind).await??;
                    Ok(())
                };
                return ActorResponse::r#async(fut.into_actor(self));
            }
            TransportCmd::Connect(socket_addr) => {
                // There is no 'connect' option, so send an empty message (with ack).
                // This will trigger a new connection event if successful.
                let fut = self
                    .send_packet(
                        socket_addr,
                        EncodedPacket {
                            guarantees: Guarantees::unordered(),
                            message: vec![],
                        },
                    )
                    .map_err(|e| log::error!("Unable to connect: {}", e))
                    .map(|_| ());

                ctx.spawn(fut.into_actor(self));
            }
            TransportCmd::Disconnect(address) => {
                let actor = ctx.address();
                let fut = async move {
                    if let Err(e) = actor
                        .send(LaminarEvent(SocketEvent::Timeout(address)))
                        .await
                        .flatten_result()
                    {
                        log::error!("Unable to Disconnect: {}", e);
                    }
                };

                ctx.spawn(fut.into_actor(self));
            }
            TransportCmd::Packet(socket_addr, packet) => {
                return ActorResponse::r#async(
                    self.send_packet(socket_addr, packet).into_actor(self),
                );
            }
        }

        ActorResponse::reply(Ok(()))
    }
}

impl<Ctx> Handler<LaminarEvent> for LaminarTransport<Ctx>
where
    Ctx: Unpin + Send + Clone + Debug + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, evt: LaminarEvent, _: &mut Context<Self>) -> Self::Result {
        match evt.0 {
            SocketEvent::Connect(socket_addr) | SocketEvent::ConnectTo(socket_addr) => {
                log::trace!("Laminar: connected to {:?}", socket_addr);

                let channel = match &self.message_sender {
                    Some(sender) => sender.clone(),
                    None => return ActorResponse::reply(Err(ChannelError::Closed.into())),
                };
                let event =
                    TransportEvt::Connected(Address::new(Address::LAMINAR, socket_addr), channel);

                ActorResponse::r#async(
                    self.recipient
                        .send(event)
                        .map_err(Error::from)
                        .into_actor(self),
                )
            }
            SocketEvent::Timeout(socket_addr) => {
                log::trace!("Laminar: timeout {:?}", socket_addr);

                let event = TransportEvt::Disconnected(
                    Address::new(Address::LAMINAR, socket_addr.clone()),
                    DisconnectReason::Timeout,
                );

                ActorResponse::r#async(
                    self.recipient
                        .send(event)
                        .map_err(Error::from)
                        .into_actor(self),
                )
            }
            SocketEvent::Packet(packet) => {
                let packet = AddressedPacket::from(packet);
                log::trace!("Laminar: packet from {:?}", packet.address);

                ActorResponse::r#async(
                    self.recipient
                        .clone()
                        .send(TransportEvt::Packet(packet.address, packet.encoded))
                        .map_err(Error::from)
                        .into_actor(self),
                )
            }
        }
    }
}

impl<Ctx> Handler<InternalRequest> for LaminarTransport<Ctx>
where
    Ctx: Unpin + Send + Clone + Debug + 'static,
{
    type Result = ActorResponse<Self, (), Error>;

    fn handle(&mut self, req: InternalRequest, ctx: &mut Context<Self>) -> Self::Result {
        match req {
            InternalRequest::Bind(addresses) => {
                let mut socket = match Socket::bind_with_config::<&[SocketAddr]>(
                    addresses.as_ref(),
                    self.conf.laminar_config.clone(),
                ) {
                    Ok(socket) => socket,
                    Err(e) => {
                        return ActorResponse::reply(Err(
                            NetworkError::Transport(e.to_string()).into()
                        ))
                    }
                };

                let actor = ctx.address();
                let (evt_tx, mut evt_rx) =
                    mpsc::channel::<AddressedPacket>(self.conf.channel_buffer_size);
                let (control, mut thread_rx) = ThreadControl::spawn();

                let poll_interval = self.conf.poll_interval;
                control.send(async move {
                    let socket_sender = socket.get_packet_sender();
                    let socket_receiver = socket.get_event_receiver();

                    loop {
                        match thread_rx.try_recv() {
                            Ok(Some(_)) | Err(_) => break,
                            _ => (),
                        }

                        socket.manual_poll(Instant::now());

                        while let Ok(Some(evt)) = evt_rx.try_next() {
                            if let Err(e) = socket_sender.send(evt.into()).map_err(Error::from) {
                                log::error!("Error sending packet: {}", e);
                            }
                        }

                        while let Ok(socket_evt) = socket_receiver.try_recv() {
                            match actor
                                .clone()
                                .send(LaminarEvent(socket_evt))
                                .map_err(Error::from)
                                .await
                            {
                                Ok(result) => {
                                    if let Err(e) = result {
                                        log::error!("Error handling SocketEvent: {}", e);
                                    }
                                }
                                Err(e) => log::warn!("Unable to send SocketEvent: {}", e),
                            }
                        }

                        tokio::time::delay_for(poll_interval).await;
                    }
                });

                self.thread_control.replace(control);
                self.message_sender.replace(evt_tx);
            }
            InternalRequest::Unbind => {
                self.message_sender.take();
                if let Some(control) = self.thread_control.take() {
                    log::info!("Unbinding listeners");
                    control.stop();
                }
            }
        }

        ActorResponse::reply(Ok(()))
    }
}

#[derive(Debug, Message)]
#[rtype(result = "Result<()>")]
struct LaminarEvent(SocketEvent);

#[derive(Clone, Debug, Message)]
#[rtype(result = "Result<()>")]
enum InternalRequest {
    Unbind,
    Bind(Vec<SocketAddr>),
}

impl From<laminar::Packet> for AddressedPacket {
    fn from(packet: laminar::Packet) -> Self {
        AddressedPacket {
            address: Address::new(Address::LAMINAR, packet.addr()),
            encoded: EncodedPacket {
                message: packet.payload().into(),
                guarantees: Guarantees {
                    ordering: packet.order_guarantee().into(),
                    delivery: packet.delivery_guarantee().into(),
                },
            },
        }
    }
}

impl From<AddressedPacket> for laminar::Packet {
    fn from(evt: AddressedPacket) -> Self {
        let address = evt.address.socket_addr;
        let message = evt.encoded.message;
        let guarantees = evt.encoded.guarantees;

        match &guarantees.delivery {
            DeliveryType::Acknowledged => match guarantees.ordering {
                OrderingType::Unordered {} => laminar::Packet::reliable_unordered(address, message),
                OrderingType::Ordered { stream_id } => {
                    laminar::Packet::reliable_ordered(address, message, stream_id)
                }
                OrderingType::Sequenced { stream_id } => {
                    laminar::Packet::reliable_sequenced(address, message, stream_id)
                }
            },
            DeliveryType::Unacknowledged => match guarantees.ordering {
                OrderingType::Unordered {} => laminar::Packet::unreliable(address, message),
                OrderingType::Ordered { .. } => {
                    laminar::Packet::unreliable_sequenced(address, message, None)
                }
                OrderingType::Sequenced { stream_id } => {
                    laminar::Packet::unreliable_sequenced(address, message, stream_id)
                }
            },
        }
    }
}

impl From<OrderingGuarantee> for OrderingType {
    fn from(ordering: OrderingGuarantee) -> Self {
        match ordering {
            OrderingGuarantee::Sequenced(stream_id) => OrderingType::Sequenced { stream_id },
            OrderingGuarantee::Ordered(stream_id) => OrderingType::Ordered { stream_id },
            OrderingGuarantee::None => OrderingType::Unordered {},
        }
    }
}

impl From<DeliveryGuarantee> for DeliveryType {
    fn from(ordering: DeliveryGuarantee) -> Self {
        match ordering {
            DeliveryGuarantee::Reliable => DeliveryType::Acknowledged,
            DeliveryGuarantee::Unreliable => DeliveryType::Unacknowledged,
        }
    }
}
