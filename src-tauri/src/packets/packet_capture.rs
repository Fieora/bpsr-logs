use crate::packets::opcodes::Pkt;
use crate::packets::packet_process::PacketProcessor;
use byteorder::{BigEndian, ReadBytesExt};
use etherparse::TransportSlice::Tcp;
use etherparse::{
    Ethernet2Header, IpHeader, NetHeaders, NetSlice, SlicedPacket, TcpSlice, TransportHeader,
    VlanHeader,
};
use log::{error, info};
use std::cell::RefCell;
use std::io::Cursor;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use windivert::error::WinDivertError;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::WinDivertFlags;
use windivert::WinDivert;
use crate::packets::tcp_reassembler::TCPReassembler;

pub fn start_capture() -> Result<Receiver<(Pkt, Vec<u8>, String)>, WinDivertError> {
    let (packet_sender, packet_receiver) = channel();
    let port = 8006;
    // let filter =
    //     format!("!loopback and ip and tcp and (tcp.SrcPort == {port} || tcp.DstPort == {port}) and tcp.PayloadLength > 20"); // loopback is for linux - windows makes its own loopback adapter
    // let wd: Option<WinDivert<NetworkLayer>> = match WinDivert::<NetworkLayer>::network( // todo: the way were doing this breaks if we try filter by tcp port for some reason
    //     filter,
    //     999,
    //     WinDivertFlags::new().set_sniff().set_recv_only(),
    // ) {
    //     Ok(handle) => {
    //         info!("WinDivert handle re-opened with new filter.");
    //         Some(handle)
    //     }
    //     Err(e) => {
    //         error!("Failed to initialize WinDivert: {}", e);
    //         None
    //     }
    // };
    info!("hmm");
    let filter =
        format!("!loopback && ip && tcp",);
    let handle = WinDivert::network(filter, 999, WinDivertFlags::new().set_sniff())?;
    info!("hmm");

    let reassembler = TCPReassembler::new(); // todo: can i move this into sniff_packet?
    // info!("sniff_packet 1");  // TODO: comment
    tokio::spawn(async move {

        sniff_packet(Option::from(handle), packet_sender, reassembler).await
    });
    // info!("sniff_packet 2");  // TODO: comment

    Ok(packet_receiver)
}

async fn sniff_packet(
    wd: Option<WinDivert<NetworkLayer>>,
    packet_sender: std::sync::mpsc::Sender<(Pkt, Vec<u8>, String)>,
    mut reassembler: TCPReassembler,
) {
    // info!("sniff_packet");  // TODO: comment
    let mut current_server = String::new();

    let mut buffer: Vec<u8> = vec![0u8; 10 * 1024 * 1024];
    while let Some(ref wd_handle) = wd {
        match wd_handle.recv(Some(&mut buffer)) {
            Ok(packet) => {
                let sliced_packet = SlicedPacket::from_ip(packet.data.as_ref());
                match sliced_packet {
                    Ok(value) => {
                        // info!("let ipv4_packet = match value.net");  // TODO: comment
                        // Extract IP packet information
                        let ipv4_packet = match value.net {
                            Some(NetSlice::Ipv4(ipv4)) => ipv4,
                            _ => return, // exit function if not IPv4
                        };
                        // info!(
                        //     "  Ipv4 {:?} => {:?}",
                        //     ipv4_packet.header().source_addr(),
                        //     ipv4_packet.header().destination_addr()
                        // );

                        // Extract TCP packet information
                        let tcp_packet = match value.transport {
                            Some(Tcp(tcp)) => tcp,
                            _ => continue,
                        };
                        let hex_str = hex::encode(tcp_packet.payload());
                        // info!("hex_str 1: {:?}", hex_str);

                        // info!(
                        //     "  TCP {:?} -> {:?}",
                        //     tcp_packet.source_port(),
                        //     tcp_packet.destination_port()
                        // );

                        let srcaddr = ipv4_packet.header().source_addr();
                        let srcport = tcp_packet.source_port();
                        let dstaddr = ipv4_packet.header().destination_addr();
                        let dstport = tcp_packet.destination_port();
                        let src_server =
                            format!("{}:{} -> {}:{}", srcaddr, srcport, dstaddr, dstport);

                        // try to identify game server via small packets TODO: this logic is horrible and idk how to write rust
                        // info!("current_server != src_server");  // TODO: comment
                        if current_server != src_server {
                            let tcp_payload = tcp_packet.payload().to_vec();
                            // First check:
                            if tcp_payload.get(4).copied() == Some(0) {
                                let data = tcp_payload.get(10..).unwrap_or(&[]);
                                let mut offset = 0;

                                // info!("BEFORE while offset + 4 <= data.len()");  // TODO: comment
                                while offset + 4 <= data.len() {
                                    // info!("while offset + 4 <= data.len()");  // TODO: comment
                                    // read 4-byte big-endian length
                                    let len_buf = match data.get(offset..offset + 4) {
                                        Some(slice) => slice,
                                        None => continue, // not enough data
                                    };
                                    let msg_len =
                                        u32::from_be_bytes(len_buf.try_into().unwrap()) as usize;
                                    offset += 4;

                                    if offset + msg_len - 4 > data.len() {
                                        // error!("offset + msg_len - 4 > data.len()");
                                        continue; // not enough data
                                    }

                                    let data1 =
                                        data.get(offset..offset + msg_len - 4).unwrap_or(&[]);

                                    if msg_len >= 4 {
                                        offset += msg_len - 4;
                                    }

                                    let signature: [u8; 6] = [0x00, 0x63, 0x33, 0x53, 0x42, 0x00];
                                    if data1.len() < 5 + signature.len() {
                                        // error!("data1.len() < 5 + signature.len()");
                                        continue;
                                    }

                                    if data1.get(5..5 + signature.len()) != Some(&signature[..]) {
                                        // error!("data1.get(5..5 + signature.len()) != Some(&signature[..])");
                                        continue; // signature mismatch
                                    }

                                    if current_server != src_server {
                                        current_server = src_server.to_string();
                                        // clear_data_on_server_change(); TODO: implement this
                                        // info!("Got Scene Server Address: {}", src_server);
                                        // TODO: comment
                                    }
                                }
                            }
                            // Second check: login return packet
                            // info!("BEFORE if buf.len() == 0x62"); // TODO: comment
                            if tcp_payload.len() == 0x62 {
                                // info!("if buf.len() == 0x62");  // TODO: comment
                                let signature: [u8; 24] = [
                                    0x00, 0x00, 0x00, 0x62, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
                                    0x00, 0x11, 0x45, 0x14, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x4e,
                                    0x08, 0x01, 0x22, 0x24,
                                ];

                                if tcp_payload.len() >= 20
                                    && tcp_payload.get(0..10) == Some(&signature[0..10])
                                    && tcp_payload.get(14..20) == Some(&signature[14..20])
                                {
                                    if current_server != src_server {
                                        reassembler.clear_cache(tcp_packet.sequence_number() + tcp_payload.len() as u32);
                                        current_server = src_server.to_string();
                                        info!(
                                            "Got Scene Server Address by Login Return Packet: {}",
                                            src_server
                                        );
                                    }
                                }
                            }
                        }

                        // let hex_str = hex::encode(tcp_packet.payload());
                        // info!("hex_str 2: {:?}", hex_str); // todo: comment

                        // todo: tcp packet reconstruction
                        if let Some((seq_num, data)) = reassembler.push_segment(tcp_packet.clone()) {
                            let hex_str = hex::encode(data.to_vec());
                            info!("seq num: {:?} - reassembled data: {:?}", seq_num, hex_str); // todo: comment
                            let mut processor = PacketProcessor::new();
                            processor.process_packet_init(data, packet_sender.clone(), src_server);
                        }
                    }
                    Err(value) => error!("Err {:?}", value),
                }
            }
            Err(e) => {
                error!("Failed to receive packet: {}", e);
            }
        }
    }
}

