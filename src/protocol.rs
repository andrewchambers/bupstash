use super::address::*;
use super::crypto;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const MAX_PACKET_SIZE: usize = 1024 * 1024 * 16;

#[derive(Serialize, Deserialize, Debug)]
struct ServerInfo {
    protocol_version: String,
}

struct Chunk<'a> {
    address: Address,
    data: &'a [u8],
}

#[derive(Serialize, Deserialize, Debug)]
struct AckSend {
    gc_generation: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommitSend {
    header: crypto::EncryptionHeader,
    root: Address,
}

enum PacketKind {
    ServerInfo,
    BeginSend,
    AckSend,
    Chunk,
    CommitSend,
}

const PACKET_KIND_SERVER_INFO: u16 = 0;
const PACKET_KIND_BEGIN_SEND: u16 = 1;
const PACKET_KIND_ACK_SEND: u16 = 2;
const PACKET_KIND_CHUNK: u16 = 3;
const PACKET_KIND_COMMIT_SEND: u16 = 4;

impl PacketKind {
    fn header_kind_byte(&self) -> u8 {
        match self {
            PacketKind::ServerInfo => 0,
            PacketKind::BeginSend => 1,
            PacketKind::AckSend => 2,
            PacketKind::Chunk => 3,
            PacketKind::CommitSend => 4,
        }
    }
}

fn read_packet(r: &mut dyn std::io::Read) -> Result<(PacketKind, Vec<u8>), failure::Error> {
    let mut hdr: [u8; 6] = [0; 6];
    r.read_exact(&mut hdr[..])?;
    let sz = (hdr[0] as usize) << 24
        | (hdr[1] as usize) << 16
        | (hdr[2] as usize) << 8
        | (hdr[3] as usize);

    if sz > MAX_PACKET_SIZE {
        return Err(failure::format_err!("packet too large"));
    }

    let kind = (hdr[4] as u16) << 8 | (hdr[5] as u16);

    let mut buf: Vec<u8> = Vec::with_capacity(sz);
    // We just created buf with capacity sz and u8 is a primitive type.
    // This means we don't need to write the buffer memory twice.
    unsafe {
        buf.set_len(sz);
    };
    r.read_exact(&mut buf)?;
    let kind = match kind {
        0 => PacketKind::ServerInfo,
        _ => return Err(failure::format_err!("protocol error, unknown packet kind")),
    };
    Ok((kind, buf))
}

fn send_hdr(w: &mut dyn std::io::Write, kind: u16, sz: u32) -> Result<(), failure::Error> {
    let mut hdr: [u8; 6] = [0; 6];
    hdr[0] = ((sz & 0xff00_0000) >> 24) as u8;
    hdr[1] = ((sz & 0x00ff_0000) >> 16) as u8;
    hdr[2] = ((sz & 0x0000_ff00) >> 8) as u8;
    hdr[3] = (sz & 0x0000_00ff) as u8;
    hdr[4] = ((kind & 0xff00) >> 8) as u8;
    hdr[5] = (kind & 0xff) as u8;
    w.write_all(&hdr[..])?;
    Ok(())
}

fn send_packet(w: &mut dyn std::io::Write, kind: u16, data: &[u8]) -> Result<(), failure::Error> {
    let sz: u32 = data.len().try_into()?;
    send_hdr(w, kind, sz)?;
    w.write_all(data)?;
    Ok(())
}

fn send_server_info(w: &mut dyn std::io::Write, info: &ServerInfo) -> Result<(), failure::Error> {
    let j = serde_json::to_string(&info)?;
    send_packet(w, PACKET_KIND_SERVER_INFO, j.as_bytes())
}

fn send_begin_send(w: &mut dyn std::io::Write) -> Result<(), failure::Error> {
    send_packet(w, PACKET_KIND_BEGIN_SEND, &[])
}

fn send_ack_send(w: &mut dyn std::io::Write, ack: &AckSend) -> Result<(), failure::Error> {
    let j = serde_json::to_string(&ack)?;
    send_packet(w, PACKET_KIND_ACK_SEND, j.as_bytes())
}

fn send_chunk(w: &mut dyn std::io::Write, chunk: &Chunk) -> Result<(), failure::Error> {
    send_hdr(
        w,
        PACKET_KIND_CHUNK,
        (ADDRESS_SZ + chunk.data.len()).try_into()?,
    )?;
    w.write_all(&chunk.address.bytes[..])?;
    w.write_all(&chunk.data)?;
    Ok(())
}

fn send_commit(w: &mut dyn std::io::Write, e: &CommitSend) -> Result<(), failure::Error> {
    let j = serde_json::to_string(&e)?;
    send_packet(w, PACKET_KIND_COMMIT_SEND, j.as_bytes())
}

fn decode_server_info(buf: &[u8]) -> Result<ServerInfo, failure::Error> {
    let info: ServerInfo = serde_json::from_slice(buf)?;
    Ok(info)
}

fn decode_ack_send(buf: &[u8]) -> Result<AckSend, failure::Error> {
    let ack: AckSend = serde_json::from_slice(buf)?;
    Ok(ack)
}

fn decode_chunk(buf: &[u8]) -> Result<Chunk, failure::Error> {
    if buf.len() < ADDRESS_SZ {
        return Err(failure::format_err!(
            "protocol error, chunk smaller than address"
        ));
    }

    let mut address = Address { bytes: [0; 32] };

    address.bytes[..].clone_from_slice(&buf[..ADDRESS_SZ]);

    Ok(Chunk {
        address,
        data: &buf[ADDRESS_SZ..],
    })
}
