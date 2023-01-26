extern crate pnet;
use crossbeam_channel::{Receiver, Sender};
use std::{fmt, net::IpAddr};

use pnet::{
    datalink::NetworkInterface,
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
        Packet,
    },
};

#[derive(Debug)]
pub struct PacketData {
    pub source: IpAddr,
    pub dst: IpAddr,
    pub protocol: String,
}

pub struct PacketFilter {
    pub source: IpAddr,
    pub dst: IpAddr,
}

pub struct CapturerError {
    pub cause: String,
}

impl fmt::Display for CapturerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error in packet capture: {}", self.cause)
    }
}

pub struct Capturer {
    rx: Box<dyn pnet::datalink::DataLinkReceiver>,
    interface: NetworkInterface,
    packet_channel: Sender<PacketData>,
}

impl Capturer {
    pub fn open(
        interface_name: &str,
        packet_channel: Sender<PacketData>,
    ) -> Result<Capturer, CapturerError> {
        // closure for filter
        let match_filter = |iface: &pnet::datalink::NetworkInterface| iface.name == interface_name;

        let capture_interface = pnet::datalink::interfaces()
            .into_iter()
            .filter(match_filter)
            .next()
            .ok_or_else(|| CapturerError {
                cause: format!("No such network interface: {}", interface_name),
            });

        // TODO: fix me
        let interface = match capture_interface {
            Ok(interface) => interface,
            Err(e) => {
                return Err(CapturerError {
                    cause: e.to_string(),
                })
            }
        };

        println!("listening on interface: {}", interface_name);
        //
        // https://github.com/libpnet/libpnet/blob/master/pnet_datalink/src/lib.rs#L157
        let config = pnet::datalink::Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: pnet::datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: true,
        };

        let (_, rx) = match pnet::datalink::channel(&interface, config) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(CapturerError {
                    cause: "unhandled channel type".to_string(),
                })
            }
            Err(e) => {
                return Err(CapturerError {
                    cause: e.to_string(),
                })
            }
        };

        Ok(Self {
            rx: rx,
            interface: interface,
            packet_channel: packet_channel,
        })
    }

    pub fn capture(self: &mut Self, exit_channel: Receiver<bool>) {
        loop {
            let mut buf: [u8; 1600] = [0u8; 1600];
            let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

            match self.rx.next() {
                Ok(packet) => {
                    let payload_offset = 14;
                    let version = pnet::packet::ipv4::Ipv4Packet::new(&packet[payload_offset..])
                        .unwrap()
                        .get_version();

                    if version == 4 {
                        fake_ethernet_frame.set_destination(pnet::util::MacAddr(0, 0, 0, 0, 0, 0));
                        fake_ethernet_frame.set_source(pnet::util::MacAddr(0, 0, 0, 0, 0, 0));
                        fake_ethernet_frame.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
                        fake_ethernet_frame.set_payload(&packet[payload_offset..]);

                        self.handle_ethernet_frame(&fake_ethernet_frame);
                        continue;
                    }
                }

                Err(e) => panic!("capture error: {}", e),
            }

            match exit_channel.try_recv() {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    fn handle_ethernet_frame(self: &mut Self, ethernet: &MutableEthernetPacket) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => self.handle_ipv4_packet(ethernet),
            _ => println!(
                "{}: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                self.interface.name,
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            ),
        }
    }

    fn handle_ipv4_packet(self: &mut Self, ethernet: &MutableEthernetPacket) {
        let header = Ipv4Packet::new(ethernet.payload());

        if let Some(header) = header {
            self.handle_transport_protocol(
                IpAddr::V4(header.get_source()),
                IpAddr::V4(header.get_destination()),
                header.get_next_level_protocol(),
                header.payload(),
            )
        } else {
            println!("{}: Malformed IPv4 packet", self.interface.name)
        }
    }

    fn handle_transport_protocol(
        self: &mut Self,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
    ) {
        match protocol {
            IpNextHeaderProtocols::Tcp => self.handle_tcp_packet(source, destination, packet),

            _ => {}
        }
    }

    fn handle_tcp_packet(self: &mut Self, source: IpAddr, destination: IpAddr, packet: &[u8]) {
        let tcp = TcpPacket::new(packet);
        if let Some(tcp) = tcp {
            //println!(
            //    "{}: TCP packet: {}:{} > {}:{}; length: {}",
            //    self.interface.name,
            //    source,
            //    tcp.get_source(),
            //    destination,
            //    tcp.get_destination(),
            //    packet.len()
            //);

            let d = PacketData {
                source: source,
                dst: destination,
                protocol: "TCP".to_string(),
            };

            match self.packet_channel.send(d) {
                Ok(_) => {}
                Err(e) => {
                    println!("packet send failed: {}", e);
                }
            }
        } else {
            println!("{}: malformed TCP packet", self.interface.name)
        }
    }
}
