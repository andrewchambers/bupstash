use super::address::*;
use super::crypto;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const MAX_PACKET_SIZE: usize = 1024 * 1024 * 16;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ServerInfo {
    pub protocol: String,
}

#[derive(Debug, PartialEq)]
pub struct Chunk {
    pub address: Address,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BeginSend {}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AckSend {
    pub gc_generation: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CommitSend {
    pub header: crypto::VersionedEncryptionHeader,
    pub root: Address,
}

#[derive(Debug, PartialEq)]
pub enum Packet {
    ServerInfo(ServerInfo),
    BeginSend(BeginSend),
    AckSend(AckSend),
    Chunk(Chunk),
    CommitSend(CommitSend),
}

const PACKET_KIND_SERVER_INFO: u8 = 0;
const PACKET_KIND_BEGIN_SEND: u8 = 1;
const PACKET_KIND_ACK_SEND: u8 = 2;
const PACKET_KIND_CHUNK: u8 = 3;
const PACKET_KIND_COMMIT_SEND: u8 = 4;

pub fn read_packet(r: &mut dyn std::io::Read) -> Result<Packet, failure::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    r.read_exact(&mut hdr[..])?;
    let sz = (hdr[0] as usize) << 24
        | (hdr[1] as usize) << 16
        | (hdr[2] as usize) << 8
        | (hdr[3] as usize);

    if sz > MAX_PACKET_SIZE {
        return Err(failure::format_err!("packet too large"));
    }

    let kind = hdr[4];

    let mut buf: Vec<u8> = Vec::with_capacity(sz);
    // We just created buf with capacity sz and u8 is a primitive type.
    // This means we don't need to write the buffer memory twice.
    unsafe {
        buf.set_len(sz);
    };
    r.read_exact(&mut buf)?;
    let packet = match kind {
        PACKET_KIND_SERVER_INFO => Packet::ServerInfo(serde_json::from_slice(&buf)?),
        PACKET_KIND_BEGIN_SEND => Packet::BeginSend(serde_json::from_slice(&buf)?),
        PACKET_KIND_ACK_SEND => Packet::AckSend(serde_json::from_slice(&buf)?),
        PACKET_KIND_CHUNK => {
            if buf.len() < ADDRESS_SZ {
                return Err(failure::format_err!(
                    "protocol error, chunk smaller than address"
                ));
            }

            let mut address = Address { bytes: [0; 32] };

            address.bytes[..].clone_from_slice(&buf[buf.len() - ADDRESS_SZ..]);
            buf.truncate(buf.len() - ADDRESS_SZ);
            Packet::Chunk(Chunk { address, data: buf })
        }
        PACKET_KIND_COMMIT_SEND => Packet::CommitSend(serde_json::from_slice(&buf)?),
        _ => return Err(failure::format_err!("protocol error, unknown packet kind")),
    };
    Ok(packet)
}

fn send_hdr(w: &mut dyn std::io::Write, kind: u8, sz: u32) -> Result<(), failure::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    hdr[0] = ((sz & 0xff00_0000) >> 24) as u8;
    hdr[1] = ((sz & 0x00ff_0000) >> 16) as u8;
    hdr[2] = ((sz & 0x0000_ff00) >> 8) as u8;
    hdr[3] = (sz & 0x0000_00ff) as u8;
    hdr[4] = kind;
    w.write_all(&hdr[..])?;
    Ok(())
}

pub fn write_packet(w: &mut dyn std::io::Write, p: &Packet) -> Result<(), failure::Error> {
    match p {
        Packet::ServerInfo(ref v) => {
            let j = serde_json::to_string(&v)?;
            let b = j.as_bytes();
            send_hdr(w, PACKET_KIND_SERVER_INFO, b.len().try_into()?)?;
            w.write(b)?;
        }
        Packet::BeginSend(ref v) => {
            let j = serde_json::to_string(&v)?;
            let b = j.as_bytes();
            send_hdr(w, PACKET_KIND_BEGIN_SEND, b.len().try_into()?)?;
            w.write(b)?;
        }
        Packet::AckSend(ref v) => {
            let j = serde_json::to_string(&v)?;
            let b = j.as_bytes();
            send_hdr(w, PACKET_KIND_ACK_SEND, b.len().try_into()?)?;
            w.write(b)?;
        }
        Packet::Chunk(ref v) => {
            send_hdr(
                w,
                PACKET_KIND_CHUNK,
                (v.data.len() + ADDRESS_SZ).try_into()?,
            )?;
            w.write(&v.data)?;
            w.write(&v.address.bytes)?;
        }
        Packet::CommitSend(ref v) => {
            let j = serde_json::to_string(&v)?;
            let b = j.as_bytes();
            send_hdr(w, PACKET_KIND_COMMIT_SEND, b.len().try_into()?)?;
            w.write(b)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::crypto;
    use super::super::keys;
    use super::*;

    #[test]
    fn send_recv() {
        let packets = vec![
            Packet::ServerInfo(ServerInfo {
                protocol: "foobar".to_owned(),
            }),
            Packet::BeginSend(BeginSend {}),
            Packet::AckSend(AckSend {
                gc_generation: "blah".to_owned(),
            }),
            Packet::CommitSend(CommitSend {
                root: Address::default(),
                header: {
                    let master_key = keys::MasterKey::gen();
                    let ectx = crypto::EncryptContext::new(&keys::Key::MasterKeyV1(master_key));
                    ectx.encryption_header()
                },
            }),
            Packet::Chunk(Chunk {
                address: Address::default(),
                data: vec![1, 2, 3],
            }),
        ];

        for p1 in packets.iter() {
            let mut c1 = std::io::Cursor::new(Vec::new());
            write_packet(&mut c1, p1).unwrap();
            let b = c1.into_inner();
            let mut c2 = std::io::Cursor::new(b);
            let p2 = read_packet(&mut c2).unwrap();
            assert!(p1 == &p2);
        }
    }
}
