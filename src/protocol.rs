use super::address::*;
use super::itemset;
use super::repository;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const MAX_PACKET_SIZE: usize = 1024 * 1024 * 16;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ServerInfo {
    pub protocol: String,
    pub repo_id: String,
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
pub struct RequestData {
    pub id: i64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AckRequestData {
    pub metadata: Option<itemset::VersionedItemMetadata>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StartGC {}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct GCComplete {
    pub stats: repository::GCStats,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestItemSync {
    pub after: i64,
    pub gc_generation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AckItemSync {
    pub gc_generation: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StorageConnect {
    pub protocol: String,
    pub path: String,
}

#[derive(Debug, PartialEq)]
pub enum Packet {
    ServerInfo(ServerInfo),
    BeginSend(BeginSend),
    AckSend(AckSend),
    Chunk(Chunk),
    LogOp(itemset::LogOp),
    AckLogOp(i64),
    RequestData(RequestData),
    AckRequestData(AckRequestData),
    StartGC(StartGC),
    GCComplete(GCComplete),
    RequestItemSync(RequestItemSync),
    AckItemSync(AckItemSync),
    SyncLogOps(Vec<(i64, itemset::LogOp)>),
    RequestChunk(Address),
    AckRequestChunk(Vec<u8>),
    WriteBarrier,
    AckWriteBarrier,
    StorageConnect(StorageConnect),
    EndOfTransmission,
}

const PACKET_KIND_SERVER_INFO: u8 = 0;
const PACKET_KIND_BEGIN_SEND: u8 = 1;
const PACKET_KIND_ACK_SEND: u8 = 2;
const PACKET_KIND_CHUNK: u8 = 3;
const PACKET_KIND_LOG_OP: u8 = 4;
const PACKET_KIND_ACK_LOG_OP: u8 = 5;
const PACKET_KIND_REQUEST_DATA: u8 = 6;
const PACKET_KIND_ACK_REQUEST_DATA: u8 = 7;
const PACKET_KIND_START_GC: u8 = 8;
const PACKET_KIND_GC_COMPLETE: u8 = 9;
const PACKET_KIND_REQUEST_ITEM_SYNC: u8 = 10;
const PACKET_KIND_ACK_ITEM_SYNC: u8 = 11;
const PACKET_KIND_SYNC_LOG_OPS: u8 = 12;
const PACKET_KIND_REQUEST_CHUNK: u8 = 13;
const PACKET_KIND_ACK_REQUEST_CHUNK: u8 = 14;
const PACKET_KIND_WRITE_BARRIER: u8 = 15;
const PACKET_KIND_ACK_WRITE_BARRIER: u8 = 16;
const PACKET_KIND_STORAGE_CONNECT: u8 = 17;
const PACKET_KIND_END_OF_TRANSMISSION: u8 = 255;

lazy_static::lazy_static! {
    static ref BINCODE_CFG: bincode::Config = bincode::config().big_endian().clone();
}

fn read_from_remote(r: &mut dyn std::io::Read, buf: &mut [u8]) -> Result<(), failure::Error> {
    if let Err(_) = r.read_exact(buf) {
        failure::bail!("remote disconnected");
    };
    Ok(())
}

pub fn read_packet(r: &mut dyn std::io::Read) -> Result<Packet, failure::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    read_from_remote(r, &mut hdr[..])?;
    let sz = (hdr[0] as usize) << 24
        | (hdr[1] as usize) << 16
        | (hdr[2] as usize) << 8
        | (hdr[3] as usize);

    if sz > MAX_PACKET_SIZE {
        failure::bail!("packet too large");
    }

    let kind = hdr[4];

    /* special case chunks, bypass serde */
    if kind == PACKET_KIND_CHUNK {
        if sz < ADDRESS_SZ {
            failure::bail!("protocol error, chunk smaller than address");
        }

        let mut address = Address { bytes: [0; 32] };
        read_from_remote(r, &mut address.bytes[..])?;
        let sz = sz - ADDRESS_SZ;
        let mut data: Vec<u8> = Vec::with_capacity(sz);
        unsafe {
            data.set_len(sz);
        };

        read_from_remote(r, &mut data)?;
        return Ok(Packet::Chunk(Chunk { address, data }));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(sz);
    unsafe {
        buf.set_len(sz);
    };

    read_from_remote(r, &mut buf)?;
    let packet = match kind {
        PACKET_KIND_SERVER_INFO => Packet::ServerInfo(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_BEGIN_SEND => Packet::BeginSend(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_ACK_SEND => Packet::AckSend(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_LOG_OP => Packet::LogOp(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_ACK_LOG_OP => Packet::AckLogOp(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_REQUEST_DATA => Packet::RequestData(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_ACK_REQUEST_DATA => Packet::AckRequestData(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_START_GC => Packet::StartGC(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_GC_COMPLETE => Packet::GCComplete(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_REQUEST_ITEM_SYNC => Packet::RequestItemSync(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_ACK_ITEM_SYNC => Packet::AckItemSync(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_SYNC_LOG_OPS => Packet::SyncLogOps(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_REQUEST_CHUNK => Packet::RequestChunk(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_ACK_REQUEST_CHUNK => Packet::AckRequestChunk(buf),
        PACKET_KIND_STORAGE_CONNECT => Packet::StorageConnect(BINCODE_CFG.deserialize(&buf)?),
        PACKET_KIND_WRITE_BARRIER => Packet::WriteBarrier,
        PACKET_KIND_ACK_WRITE_BARRIER => Packet::AckWriteBarrier,
        PACKET_KIND_END_OF_TRANSMISSION => Packet::EndOfTransmission,
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

pub fn write_packet(w: &mut dyn std::io::Write, pkt: &Packet) -> Result<(), failure::Error> {
    match pkt {
        Packet::Chunk(ref v) => {
            send_hdr(
                w,
                PACKET_KIND_CHUNK,
                (v.data.len() + ADDRESS_SZ).try_into()?,
            )?;
            w.write_all(&v.address.bytes)?;
            w.write_all(&v.data)?;
        }
        Packet::ServerInfo(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_SERVER_INFO, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::BeginSend(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_BEGIN_SEND, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::AckSend(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_ACK_SEND, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::LogOp(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_LOG_OP, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::AckLogOp(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_ACK_LOG_OP, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RequestData(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_REQUEST_DATA, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::AckRequestData(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_ACK_REQUEST_DATA, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::StartGC(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_START_GC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::GCComplete(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_GC_COMPLETE, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RequestItemSync(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::AckItemSync(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_ACK_ITEM_SYNC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::SyncLogOps(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_SYNC_LOG_OPS, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RequestChunk(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_REQUEST_CHUNK, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::AckRequestChunk(ref v) => {
            send_hdr(w, PACKET_KIND_ACK_REQUEST_CHUNK, v.len().try_into()?)?;
            w.write_all(&v)?;
        }
        Packet::StorageConnect(ref v) => {
            let b = BINCODE_CFG.serialize(&v)?;
            send_hdr(w, PACKET_KIND_STORAGE_CONNECT, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::WriteBarrier => {
            send_hdr(w, PACKET_KIND_WRITE_BARRIER, 0)?;
        }
        Packet::AckWriteBarrier => {
            send_hdr(w, PACKET_KIND_ACK_WRITE_BARRIER, 0)?;
        }
        Packet::EndOfTransmission => {
            send_hdr(w, PACKET_KIND_END_OF_TRANSMISSION, 0)?;
        }
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::super::keys;
    use super::*;

    #[test]
    fn send_recv() {
        let packets = vec![
            Packet::ServerInfo(ServerInfo {
                repo_id: "abc".to_string(),
                protocol: "foobar".to_owned(),
            }),
            Packet::BeginSend(BeginSend {}),
            Packet::AckSend(AckSend {
                gc_generation: "blah".to_owned(),
            }),
            {
                let master_key = keys::MasterKey::gen();
                Packet::LogOp(itemset::LogOp::AddItem(itemset::VersionedItemMetadata::V1(
                    itemset::ItemMetadata {
                        address: Address::default(),
                        tree_height: 3,
                        master_key_id: master_key.id,
                        hash_key_part_2a: master_key.hash_key_part_2a,
                        hash_key_part_2b: master_key.hash_key_part_2b,
                        encrypted_tags: vec![1, 2, 3],
                    },
                )))
            },
            Packet::Chunk(Chunk {
                address: Address::default(),
                data: vec![1, 2, 3],
            }),
            Packet::RequestData(RequestData { id: 153534 }),
            {
                let master_key = keys::MasterKey::gen();
                Packet::AckRequestData(AckRequestData {
                    metadata: Some(itemset::VersionedItemMetadata::V1(itemset::ItemMetadata {
                        address: Address::default(),
                        tree_height: 1234,
                        master_key_id: master_key.id,
                        hash_key_part_2a: master_key.hash_key_part_2a,
                        hash_key_part_2b: master_key.hash_key_part_2b,
                        encrypted_tags: vec![1, 2, 3],
                    })),
                })
            },
            Packet::StartGC(StartGC {}),
            Packet::GCComplete(GCComplete {
                stats: repository::GCStats {
                    chunks_remaining: 1,
                    chunks_freed: 123,
                    bytes_freed: 345,
                    bytes_remaining: 678,
                },
            }),
            Packet::RequestItemSync(RequestItemSync {
                after: 123,
                gc_generation: Some("123".to_owned()),
            }),
            Packet::AckItemSync(AckItemSync {
                gc_generation: "123".to_owned(),
            }),
            Packet::SyncLogOps(vec![(765756, itemset::LogOp::RemoveItems(vec![123]))]),
            Packet::RequestChunk(Address::default()),
            Packet::AckRequestChunk(vec![1, 2, 3]),
            Packet::StorageConnect(StorageConnect {
                protocol: "foobar".to_owned(),
                path: "abc".to_string(),
            }),
            Packet::WriteBarrier,
            Packet::AckWriteBarrier,
            Packet::EndOfTransmission,
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
