(function() {var implementors = {};
implementors["ya_net_p2p"] = [{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/struct.NetConfig.html\" title=\"struct ya_net_p2p::NetConfig\">NetConfig</a>","synthetic":true,"types":["ya_net_p2p::service::NetConfig"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"struct\" href=\"ya_net_p2p/struct.Net.html\" title=\"struct ya_net_p2p::Net\">Net</a>&lt;Key&gt;","synthetic":true,"types":["ya_net_p2p::service::Net"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/crypto/enum.Signature.html\" title=\"enum ya_net_p2p::crypto::Signature\">Signature</a>","synthetic":true,"types":["ya_net_p2p::crypto::Signature"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/crypto/enum.SignatureECDSA.html\" title=\"enum ya_net_p2p::crypto::SignatureECDSA\">SignatureECDSA</a>","synthetic":true,"types":["ya_net_p2p::crypto::SignatureECDSA"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.NetworkError.html\" title=\"enum ya_net_p2p::error::NetworkError\">NetworkError</a>","synthetic":true,"types":["ya_net_p2p::error::NetworkError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.SessionError.html\" title=\"enum ya_net_p2p::error::SessionError\">SessionError</a>","synthetic":true,"types":["ya_net_p2p::error::SessionError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.DiscoveryError.html\" title=\"enum ya_net_p2p::error::DiscoveryError\">DiscoveryError</a>","synthetic":true,"types":["ya_net_p2p::error::DiscoveryError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.ProtocolError.html\" title=\"enum ya_net_p2p::error::ProtocolError\">ProtocolError</a>","synthetic":true,"types":["ya_net_p2p::error::ProtocolError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.MessageError.html\" title=\"enum ya_net_p2p::error::MessageError\">MessageError</a>","synthetic":true,"types":["ya_net_p2p::error::MessageError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.ChannelError.html\" title=\"enum ya_net_p2p::error::ChannelError\">ChannelError</a>","synthetic":true,"types":["ya_net_p2p::error::ChannelError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.CryptoError.html\" title=\"enum ya_net_p2p::error::CryptoError\">CryptoError</a>","synthetic":true,"types":["ya_net_p2p::error::CryptoError"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/error/enum.Error.html\" title=\"enum ya_net_p2p::error::Error\">Error</a>","synthetic":true,"types":["ya_net_p2p::error::Error"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.ServiceCmd.html\" title=\"enum ya_net_p2p::event::ServiceCmd\">ServiceCmd</a>&lt;Key&gt;","synthetic":true,"types":["ya_net_p2p::event::ServiceCmd"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.SendCmd.html\" title=\"enum ya_net_p2p::event::SendCmd\">SendCmd</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::event::SendCmd"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.TransportCmd.html\" title=\"enum ya_net_p2p::event::TransportCmd\">TransportCmd</a>","synthetic":true,"types":["ya_net_p2p::event::TransportCmd"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.ProtocolCmd.html\" title=\"enum ya_net_p2p::event::ProtocolCmd\">ProtocolCmd</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::event::ProtocolCmd"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.SessionCmd.html\" title=\"enum ya_net_p2p::event::SessionCmd\">SessionCmd</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::event::SessionCmd"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.DhtCmd.html\" title=\"enum ya_net_p2p::event::DhtCmd\">DhtCmd</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::event::DhtCmd"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.DhtResponse.html\" title=\"enum ya_net_p2p::event::DhtResponse\">DhtResponse</a>","synthetic":true,"types":["ya_net_p2p::event::DhtResponse"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.ProcessCmd.html\" title=\"enum ya_net_p2p::event::ProcessCmd\">ProcessCmd</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::event::ProcessCmd"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.TransportEvt.html\" title=\"enum ya_net_p2p::event::TransportEvt\">TransportEvt</a>","synthetic":true,"types":["ya_net_p2p::event::TransportEvt"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.SessionEvt.html\" title=\"enum ya_net_p2p::event::SessionEvt\">SessionEvt</a>&lt;Key&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::event::SessionEvt"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/event/enum.DisconnectReason.html\" title=\"enum ya_net_p2p::event::DisconnectReason\">DisconnectReason</a>","synthetic":true,"types":["ya_net_p2p::event::DisconnectReason"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/packet/struct.Payload.html\" title=\"struct ya_net_p2p::packet::Payload\">Payload</a>","synthetic":true,"types":["ya_net_p2p::packet::payload::Payload"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/packet/struct.Packet.html\" title=\"struct ya_net_p2p::packet::Packet\">Packet</a>","synthetic":true,"types":["ya_net_p2p::packet::Packet"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/packet/struct.WirePacket.html\" title=\"struct ya_net_p2p::packet::WirePacket\">WirePacket</a>","synthetic":true,"types":["ya_net_p2p::packet::WirePacket"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/packet/struct.AddressedPacket.html\" title=\"struct ya_net_p2p::packet::AddressedPacket\">AddressedPacket</a>","synthetic":true,"types":["ya_net_p2p::packet::AddressedPacket"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/packet/struct.Guarantees.html\" title=\"struct ya_net_p2p::packet::Guarantees\">Guarantees</a>","synthetic":true,"types":["ya_net_p2p::packet::Guarantees"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/packet/enum.DeliveryType.html\" title=\"enum ya_net_p2p::packet::DeliveryType\">DeliveryType</a>","synthetic":true,"types":["ya_net_p2p::packet::DeliveryType"]},{"text":"impl Freeze for <a class=\"enum\" href=\"ya_net_p2p/packet/enum.OrderingType.html\" title=\"enum ya_net_p2p::packet::OrderingType\">OrderingType</a>","synthetic":true,"types":["ya_net_p2p::packet::OrderingType"]},{"text":"impl&lt;Key, Crypto&gt; Freeze for <a class=\"struct\" href=\"ya_net_p2p/packet/processor/crypto/struct.CryptoProcessor.html\" title=\"struct ya_net_p2p::packet::processor::crypto::CryptoProcessor\">CryptoProcessor</a>&lt;Key, Crypto&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Crypto: Freeze,<br>&nbsp;&nbsp;&nbsp;&nbsp;Key: Freeze,&nbsp;</span>","synthetic":true,"types":["ya_net_p2p::packet::processor::crypto::CryptoProcessor"]},{"text":"impl&lt;N, D&gt; !Freeze for <a class=\"struct\" href=\"ya_net_p2p/protocol/kad/struct.KadProtocol.html\" title=\"struct ya_net_p2p::protocol::kad::KadProtocol\">KadProtocol</a>&lt;N, D&gt;","synthetic":true,"types":["ya_net_p2p::protocol::kad::KadProtocol"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/protocol/session/struct.ProtocolConfig.html\" title=\"struct ya_net_p2p::protocol::session::ProtocolConfig\">ProtocolConfig</a>","synthetic":true,"types":["ya_net_p2p::protocol::session::ProtocolConfig"]},{"text":"impl&lt;Key&gt; Freeze for <a class=\"struct\" href=\"ya_net_p2p/protocol/session/struct.SessionProtocol.html\" title=\"struct ya_net_p2p::protocol::session::SessionProtocol\">SessionProtocol</a>&lt;Key&gt;","synthetic":true,"types":["ya_net_p2p::protocol::session::SessionProtocol"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/transport/struct.Address.html\" title=\"struct ya_net_p2p::transport::Address\">Address</a>","synthetic":true,"types":["ya_net_p2p::transport::Address"]},{"text":"impl&lt;Ctx&gt; Freeze for <a class=\"struct\" href=\"ya_net_p2p/transport/connection/struct.Connection.html\" title=\"struct ya_net_p2p::transport::connection::Connection\">Connection</a>&lt;Ctx&gt;","synthetic":true,"types":["ya_net_p2p::transport::connection::Connection"]},{"text":"impl&lt;Ctx&gt; Freeze for <a class=\"struct\" href=\"ya_net_p2p/transport/connection/struct.ConnectionManager.html\" title=\"struct ya_net_p2p::transport::connection::ConnectionManager\">ConnectionManager</a>&lt;Ctx&gt;","synthetic":true,"types":["ya_net_p2p::transport::connection::ConnectionManager"]},{"text":"impl&lt;Ctx&gt; Freeze for <a class=\"enum\" href=\"ya_net_p2p/transport/connection/enum.PendingConnection.html\" title=\"enum ya_net_p2p::transport::connection::PendingConnection\">PendingConnection</a>&lt;Ctx&gt;","synthetic":true,"types":["ya_net_p2p::transport::connection::PendingConnection"]},{"text":"impl Freeze for <a class=\"struct\" href=\"ya_net_p2p/transport/laminar/struct.TransportConfig.html\" title=\"struct ya_net_p2p::transport::laminar::TransportConfig\">TransportConfig</a>","synthetic":true,"types":["ya_net_p2p::transport::laminar::TransportConfig"]},{"text":"impl&lt;Ctx&gt; Freeze for <a class=\"struct\" href=\"ya_net_p2p/transport/laminar/struct.LaminarTransport.html\" title=\"struct ya_net_p2p::transport::laminar::LaminarTransport\">LaminarTransport</a>&lt;Ctx&gt;","synthetic":true,"types":["ya_net_p2p::transport::laminar::LaminarTransport"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()