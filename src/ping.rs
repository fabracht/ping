#[allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use log::{debug, error, info, warn};
use pnet::{
    packet::{
        icmp::echo_request::{MutableEchoRequestPacket}, ipv4::MutableIpv4Packet, MutablePacket,
        PacketSize,
    },
    transport::TransportChannelType::Layer3,
};
use pnet::{
    packet::{
        icmp::{
            echo_reply::{self},
            echo_request, IcmpPacket, IcmpTypes,
        },
        ip::{IpNextHeaderProtocols},
        Packet,
    },
    transport::{ipv4_packet_iter, TransportReceiver, TransportSender},
};

static IPV4_HEADER_LEN: usize = 21;
static IPV4_BUFFER: usize = 1024;
static ICMP_HEADER_LEN: usize = 8;
static ICMP_PAYLOAD_LEN: usize = 640;

#[derive(Clone)]
pub struct PingMachina {
    transport_sender: Arc<Mutex<TransportSender>>,
    transport_receiver: Arc<Mutex<TransportReceiver>>,
    destination_address: IpAddr,
    duration: Duration,
}

impl PingMachina {
    pub fn new() -> Self {
        let (tx, rx) = pnet::transport::transport_channel(2 << 15, Layer3(IpNextHeaderProtocols::Icmp))
            .map_err(|e| e.to_string())
            .expect("Failed creating transport channel. Try to `sudo setcap cap_net_raw+ep /path/to/exec`.\
             Or run program with sudo.");
        Self {
            transport_sender: Arc::new(Mutex::new(tx)),
            transport_receiver: Arc::new(Mutex::new(rx)),
            destination_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 66)),
            duration: Duration::from_secs(10),
        }
    }

    fn handle_icmp_packet(
        &self,
        source: IpAddr,
        packet: &[u8],
        ttl: u8,
        dt: f64,
        ip_packet_size: usize,
    ) {
        let icmp_packet = IcmpPacket::new(packet);

        if let Some(icmp_packet) = icmp_packet {
            match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => {
                    let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                    info!(
                        "{} icmp - {} ip packet bytes from {:?}: icmp_seq={} ttl={} time={:.3} ms",
                        icmp_packet.packet().len(),
                        ip_packet_size,
                        source,
                        echo_reply_packet.get_sequence_number(),
                        ttl,
                        dt
                    );
                    error!(
                        "ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        source,
                        self.destination_address,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    );
                }
                IcmpTypes::EchoRequest => {
                    let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                    error!(
                        "ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        source,
                        self.destination_address,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    );
                }
                _ => error!(
                    "ICMP packet {} -> {} (type={:?})",
                    source,
                    self.destination_address,
                    icmp_packet.get_icmp_type()
                ),
            }
        } else {
            error!("Malformed ICMP Packet");
        }
    }

    ///creating new icmp echo_request_packet
    fn create_icmp_packet<'a>(
        &self,
        buffer_ip: &'a mut [u8],
        buffer_icmp: &'a mut [u8],
        dest: Ipv4Addr,
        ttl: u8,
        sequence_number: u16,
    ) -> MutableIpv4Packet<'a> {

        let mut ipv4_packet =
            MutableIpv4Packet::new(buffer_ip).expect("Error creating ipv4 packet");
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
        let total_length = (IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16;
        ipv4_packet.set_total_length(total_length);
        ipv4_packet.set_ttl(ttl);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_destination(dest);
        ipv4_packet.set_source(Ipv4Addr::new(192, 168, 1, 68));
        let mut icmp_packet =
            MutableEchoRequestPacket::new(buffer_icmp).expect("Error creating icmp packet");
        icmp_packet.set_sequence_number(sequence_number);
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        
        let checksum = pnet::util::checksum(&icmp_packet.packet_mut(), 1);
        icmp_packet.set_checksum(checksum);
        ipv4_packet.set_payload(icmp_packet.packet_mut());
        ipv4_packet
    }

    pub fn run(&self) {
        let mut rx = self.transport_receiver.lock().unwrap();

        let mut buffer_ip = vec![0u8; IPV4_HEADER_LEN + IPV4_BUFFER];
        let mut buffer_icmp = vec![0u8; ICMP_PAYLOAD_LEN + ICMP_HEADER_LEN]; // 8 header bytes, then payload
        // let dest = Ipv4Addr::new(142, 250, 69, 206);
        // let dest = Ipv4Addr::new(172, 217, 24, 238);
        let dest = Ipv4Addr::new(192, 168, 1, 68);
        let ttl = 64;
        info!("Running");
        let start = Instant::now();
        loop {
            let send_packet =
                self.create_icmp_packet(&mut buffer_ip, &mut buffer_icmp, dest, ttl, 1);
            let now = Instant::now();

            match self
                .transport_sender
                .lock()
                .unwrap()
                .send_to(send_packet, IpAddr::V4(dest))
            {
                Ok(_) => debug!("Sent icmp packet to {} with icmp_seq {}", dest, 0),
                Err(e) => warn!(
                    "Failed sending packet to {}  with icmp_seq {} : {}",
                    dest, 1, e
                ),
            }

            let mut iter = ipv4_packet_iter(&mut rx);
            while let Ok(Some((packet, _addr))) =
                &mut iter.next_with_timeout(Duration::from_millis(ttl as u64))
            {
                let source = packet.get_source();
                let packet_size = packet.packet_size();
                let delta_t = Instant::now().duration_since(now);
                let delta_t_micros = delta_t.as_secs_f64() * 1000.0;
                self.handle_icmp_packet(
                    IpAddr::V4(source),
                    packet.payload(),
                    packet.get_ttl(),
                    delta_t_micros,
                    packet_size,
                );
            }
            if Instant::now().duration_since(start) > self.duration {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

impl Default for PingMachina {
    fn default() -> Self {
        Self::new()
    }
}
