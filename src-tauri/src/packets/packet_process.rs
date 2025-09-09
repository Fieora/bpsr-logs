use crate::packets::opcodes::Pkt;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, Cursor, Read};
use std::sync::mpsc::{channel, Sender};
use log::{debug, error};

// Message type constants
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    None = 0,
    Call = 1,
    Notify = 2,
    Return = 3,
    Echo = 4,
    FrameUp = 5,
    FrameDown = 6,
}

impl From<u16> for MessageType {
    fn from(value: u16) -> Self {
        match value {
            0 => MessageType::None,
            1 => MessageType::Call,
            2 => MessageType::Notify,
            3 => MessageType::Return,
            4 => MessageType::Echo,
            5 => MessageType::FrameUp,
            6 => MessageType::FrameDown,
            _ => MessageType::None,
        }
    }
}

// Binary reader implementation
pub struct BinaryReader {
    cursor: Cursor<Vec<u8>>,
}

impl BinaryReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    pub fn peek_u32(&mut self) -> io::Result<u32> {
        let pos = self.cursor.position();
        let value = self.cursor.read_u32::<BigEndian>()?;
        self.cursor.set_position(pos);
        Ok(value)
    }

    pub fn read_u32(&mut self) -> io::Result<u32> {
        self.cursor.read_u32::<BigEndian>()
    }

    pub fn read_u16(&mut self) -> io::Result<u16> {
        self.cursor.read_u16::<BigEndian>()
    }

    pub fn read_u64(&mut self) -> io::Result<u64> {
        self.cursor.read_u64::<BigEndian>()
    }

    pub fn remaining(&self) -> usize {
        let total_len = self.cursor.get_ref().len() as u64;
        let current_pos = self.cursor.position();
        (total_len.saturating_sub(current_pos)) as usize
    }

    pub fn read_bytes(&mut self, count: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; count];
        self.cursor.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_remaining(&mut self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let _ = self.cursor.read_to_end(&mut buffer);
        buffer
    }

    pub fn peek_remaining(&mut self) -> Vec<u8> {
        let pos = self.cursor.position();
        let mut buffer = Vec::new();
        let _ = self.cursor.read_to_end(&mut buffer);
        self.cursor.set_position(pos);
        buffer
    }
}

// PacketProcessor implementation
pub struct PacketProcessor {
    current_user_uuid: u64,
    internal_buffer: Vec<u8>,
    packet_sender: Sender<(Pkt, Vec<u8>, String)>,
}

impl PacketProcessor {
    pub fn new() -> Self {
        let (tx, _rx): (Sender<(Pkt, Vec<u8>, String)>, _) = channel();
        Self {
            current_user_uuid: 0,
            internal_buffer: Vec::new(),
            packet_sender: tx,
        }
    }

    pub fn set_current_user_uuid(&mut self, uuid: u64) {
        self.current_user_uuid = uuid;
    }

    fn decompress_payload(&self, buffer: &[u8]) -> Option<Vec<u8>> {
        // Implementation would use zstd crate
        // Example: zstd::decode_all(buffer).ok()
        // warn!("zstd decompression not implemented yet");
        zstd::decode_all(buffer).ok()
    }

    fn process_notify_msg(
        &mut self,
        reader: &mut BinaryReader,
        is_zstd_compressed: bool,
        src_server: String,
    ) -> io::Result<()> {
        let service_uuid = reader.read_u64();
        // info!("service_uuid {:?}", service_uuid); // todo: comment
        reader.read_u32();
        // if (service_uuid !== 0x0000000063335342n) {
        //     logger.debug(`Skipping NotifyMsg with serviceId ${ service_uuid }`);
        //     return;
        // }
        // info!(
        //     "peek_remaining 3 {:?}",
        //     hex::encode(reader.peek_remaining())
        // ); // todo: comment
        let method_id = reader.read_u32()?;
        // info!("method_id {:?}", method_id); // todo: comment

        let notify_method = match Pkt::try_from(method_id) {
            Ok(notify_method) => notify_method,
            Err(_) => return Ok(()), // return early from the function
        };
        let mut msg_payload = reader.read_remaining();
        // info!("before decompress msg_payload {:?}", msg_payload); // todo: comment
        if is_zstd_compressed {
            if let Some(decompressed) = self.decompress_payload(&msg_payload) {
                msg_payload = decompressed;
            }
        }
        // info!("after decompress msg_payload {:?}", msg_payload); // todo: comment

        match notify_method {
            Pkt::SyncNearEntities => self
                .packet_sender
                .send((notify_method, msg_payload, src_server))
                .expect("TODO: panic message"),
            Pkt::DataNotifySyncContainerData => self
                .packet_sender
                .send((notify_method, msg_payload, src_server))
                .expect("TODO: panic message"),
            Pkt::SyncContainerDirtyData => self
                .packet_sender
                .send((notify_method, msg_payload, src_server))
                .expect("TODO: panic message"),
            Pkt::SyncServerTime => self
                .packet_sender
                .send((notify_method, msg_payload, src_server))
                .expect("TODO: panic message"),
            Pkt::SyncToMeDeltaInfo => self
                .packet_sender
                .send((notify_method, msg_payload, src_server))
                .expect("TODO: panic message"),
            Pkt::SyncNearDeltaInfo => self
                .packet_sender
                .send((notify_method, msg_payload, src_server))
                .expect("TODO: panic message"),
        }

        Ok(())
    }

    fn process_return_msg(
        &mut self,
        _reader: &mut BinaryReader,
        _is_zstd_compressed: bool,
    ) -> io::Result<()> {
        // debug!("Unimplemented processing return"); // todo: idk why it hits this alot
        Ok(())
    }

    pub fn process_packet_init(
        &mut self,
        tcp_payload: Vec<u8>,
        packet_sender: Sender<(Pkt, Vec<u8>, String)>,
        src_server: String,
    ) {
        // info!("testtesttest {}", line!()); // todo: comment
        self.packet_sender = packet_sender;
        self.safe_process_packet(tcp_payload, src_server);
    }

    pub fn process_packet(
        &mut self,
        tcp_payload: Vec<u8>,
        src_server: String
    ) -> Result<(), Box<dyn std::error::Error>> {
        // info!("testtesttest {}", line!()); // todo: comment
        let mut packets_reader = BinaryReader::new(tcp_payload);
        const MIN_PACKET_SIZE: usize = 6;
        const MAX_PACKET_SIZE: usize = 1024 * 1024;

        while packets_reader.remaining() >= MIN_PACKET_SIZE {
            // info!("testtesttest {}", line!()); // todo: comment
            let packet_size = packets_reader.peek_u32()? as usize;
            // info!("packet_size {:?}", packet_size); // todo: comment
            if !(MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&packet_size) {
                // warn!(
                //     "Invalid packet length detected: {}. Discarding corrupt buffer.",
                //     packet_size
                // );
                return Ok(());
            }

            if packets_reader.remaining() < packet_size {
                return Ok(());
            }

            let packet_data = packets_reader.read_bytes(packet_size)?;
            let mut packet_reader = BinaryReader::new(packet_data);
            // info!(
            //     "peek_remaining 1 {:?}",
            //     hex::encode(packet_reader.peek_remaining())
            // ); // todo: comment

            // Skip packet size
            // info!("hihihi");
            packet_reader.read_u32()?;
            // info!("hihihi");
            // info!(
            //     "peek_remaining 2 {:?}",
            //     hex::encode(packet_reader.peek_remaining())
            // ); // todo: comment

            let packet_type = packet_reader.read_u16()?;
            // info!("packet_type {:?}", packet_type); // todo: comment
            let is_zstd_compressed = (packet_type & 0x8000) != 0; // lowest bit of the upper 16 (i.e. 17th bit)
            let msg_type_id = packet_type & 0x7fff; // lower 16 bits
            // info!("msg_type_id {:?}", msg_type_id); // todo: comment
            let message_type = MessageType::from(msg_type_id);
            // info!("testtesttest {}", line!());  // todo: comment

            match message_type {
                MessageType::Notify => {
                    // info!("process_notify_msg {}", line!());  // todo: comment
                    self.process_notify_msg(&mut packet_reader, is_zstd_compressed, src_server.to_string())?;
                }
                MessageType::Return => {
                    self.process_return_msg(&mut packet_reader, is_zstd_compressed)?;
                }
                MessageType::FrameDown => {
                    // Skip serverSequenceId
                    packet_reader.read_u32()?;

                    if packet_reader.remaining() == 0 {
                        continue;
                    }

                    let mut nested_packet = packet_reader.read_remaining();

                    if is_zstd_compressed {
                        if let Some(decompressed) = self.decompress_payload(&nested_packet) {
                            nested_packet = decompressed;
                        } else {
                            continue;
                        }
                    }

                    // Recursive call to process nested packet
                    self.safe_process_packet(nested_packet, src_server.to_string());
                }
                _ => {
                    // Silently ignore unknown packet types
                }
            }
        }

        Ok(())
    }

    pub fn process_data_chunk(&mut self, data_chunk: Vec<u8>) {
        if data_chunk.is_empty() {
            return;
        }

        self.internal_buffer.extend_from_slice(&data_chunk);
        self.parse_buffer();
    }

    fn parse_buffer(&mut self) {
        const MIN_PACKET_SIZE: usize = 6;
        const MAX_PACKET_SIZE: usize = 1024 * 1024;

        while self.internal_buffer.len() >= 4 {
            let temp_reader = BinaryReader::new(self.internal_buffer.clone());
            let has_header = self.does_stream_have_identifier(&temp_reader);

            if !has_header {
                // Handle case where stream doesn't have identifier
                break;
            }

            // Continue with packet parsing logic
            // This would contain the full buffer parsing implementation
            break; // Placeholder to prevent infinite loop
        }
    }

    fn does_stream_have_identifier(&self, _reader: &BinaryReader) -> bool {
        // Implementation would check for stream identifier
        // Placeholder implementation
        true
    }

    // Safe wrapper function that handles errors like the JavaScript try-catch
    pub fn safe_process_packet(&mut self, tcp_payload: Vec<u8>, src_server: String) {
        // info!("testtesttest {}", line!()); // todo: comment
        if let Err(e) = self.process_packet(tcp_payload, src_server) {
            error!(
                "Fatal error while parsing packet data for player {}.\nErr: {:?}",
                self.current_user_uuid >> 16,
                e
            );
        }
    }
}

impl Default for PacketProcessor {
    fn default() -> Self {
        Self::new()
    }
}
