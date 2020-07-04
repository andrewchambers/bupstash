use super::address::*;
use super::itemset;
use super::repository;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

pub const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024 * 16;

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
pub struct TBeginSend {
    pub delta_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RBeginSend {
    pub has_delta_id: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TRequestData {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRequestData {
    pub metadata: Option<itemset::VersionedItemMetadata>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TGc {}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RGc {
    pub stats: repository::GCStats,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TRequestItemSync {
    pub after: i64,
    pub gc_generation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRequestItemSync {
    pub gc_generation: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StorageConnect {
    pub protocol: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StorageBeginGC {}

#[derive(Debug, PartialEq)]
pub enum Packet {
    ServerInfo(ServerInfo),
    TBeginSend(TBeginSend),
    RBeginSend(RBeginSend),
    Chunk(Chunk),
    TLogOp(itemset::LogOp),
    RLogOp(Option<String>),
    TRequestData(TRequestData),
    RRequestData(RRequestData),
    TGc(TGc),
    RGc(RGc),
    TRequestItemSync(TRequestItemSync),
    RRequestItemSync(RRequestItemSync),
    SyncLogOps(Vec<(i64, Option<String>, itemset::LogOp)>),
    TRequestChunk(Address),
    RRequestChunk(Vec<u8>),
    TStorageWriteBarrier,
    RStorageWriteBarrier,
    StorageConnect(StorageConnect),
    StorageBeginGC,
    StorageGCReachable(Vec<u8>), /* Actually vector of addresses, u8 to avoid copy */
    StorageGCHeartBeat,
    StorageGCComplete(repository::GCStats),
    EndOfTransmission,
}

const PACKET_KIND_SERVER_INFO: u8 = 0;
const PACKET_KIND_T_BEGIN_SEND: u8 = 1;
const PACKET_KIND_R_BEGIN_SEND: u8 = 2;
const PACKET_KIND_CHUNK: u8 = 3;
const PACKET_KIND_T_LOG_OP: u8 = 4;
const PACKET_KIND_R_LOG_OP: u8 = 5;
const PACKET_KIND_T_REQUEST_DATA: u8 = 6;
const PACKET_KIND_R_REQUEST_DATA: u8 = 7;
const PACKET_KIND_T_GC: u8 = 8;
const PACKET_KIND_R_GC: u8 = 9;
const PACKET_KIND_T_REQUEST_ITEM_SYNC: u8 = 10;
const PACKET_KIND_R_REQUEST_ITEM_SYNC: u8 = 11;
const PACKET_KIND_SYNC_LOG_OPS: u8 = 12;
const PACKET_KIND_T_REQUEST_CHUNK: u8 = 13;
const PACKET_KIND_R_REQUEST_CHUNK: u8 = 14;
const PACKET_KIND_T_STORAGE_WRITE_BARRIER: u8 = 15;
const PACKET_KIND_R_STRORAGE_WRITE_BARRIER: u8 = 16;
const PACKET_KIND_STORAGE_CONNECT: u8 = 17;
const PACKET_KIND_STORAGE_BEGIN_GC: u8 = 18;
const PACKET_KIND_STORAGE_GC_REACHABLE: u8 = 19;
const PACKET_KIND_STORAGE_GC_HEARTBEAT: u8 = 20;
const PACKET_KIND_STORAGE_GC_COMPLETE: u8 = 21;
const PACKET_KIND_END_OF_TRANSMISSION: u8 = 255;

fn read_from_remote(r: &mut dyn std::io::Read, buf: &mut [u8]) -> Result<(), failure::Error> {
    if r.read_exact(buf).is_err() {
        failure::bail!("remote disconnected");
    };
    Ok(())
}

pub fn read_packet(
    r: &mut dyn std::io::Read,
    max_packet_size: usize,
) -> Result<Packet, failure::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    read_from_remote(r, &mut hdr[..])?;
    let kind = hdr[4];

    let sz = (hdr[3] as usize) << 24
        | (hdr[2] as usize) << 16
        | (hdr[1] as usize) << 8
        | (hdr[0] as usize);

    if sz > max_packet_size {
        failure::bail!("packet too large");
    }

    /* special case chunks, bypass serde */
    if kind == PACKET_KIND_CHUNK {
        if sz < ADDRESS_SZ {
            failure::bail!("protocol error, packet smaller than address");
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
        PACKET_KIND_SERVER_INFO => Packet::ServerInfo(bincode::deserialize(&buf)?),
        PACKET_KIND_T_BEGIN_SEND => Packet::TBeginSend(bincode::deserialize(&buf)?),
        PACKET_KIND_R_BEGIN_SEND => Packet::RBeginSend(bincode::deserialize(&buf)?),
        PACKET_KIND_T_LOG_OP => Packet::TLogOp(bincode::deserialize(&buf)?),
        PACKET_KIND_R_LOG_OP => Packet::RLogOp(bincode::deserialize(&buf)?),
        PACKET_KIND_T_REQUEST_DATA => Packet::TRequestData(bincode::deserialize(&buf)?),
        PACKET_KIND_R_REQUEST_DATA => Packet::RRequestData(bincode::deserialize(&buf)?),
        PACKET_KIND_T_GC => Packet::TGc(bincode::deserialize(&buf)?),
        PACKET_KIND_R_GC => Packet::RGc(bincode::deserialize(&buf)?),
        PACKET_KIND_T_REQUEST_ITEM_SYNC => Packet::TRequestItemSync(bincode::deserialize(&buf)?),
        PACKET_KIND_R_REQUEST_ITEM_SYNC => Packet::RRequestItemSync(bincode::deserialize(&buf)?),
        PACKET_KIND_SYNC_LOG_OPS => Packet::SyncLogOps(bincode::deserialize(&buf)?),
        PACKET_KIND_T_REQUEST_CHUNK => Packet::TRequestChunk(bincode::deserialize(&buf)?),
        PACKET_KIND_R_REQUEST_CHUNK => Packet::RRequestChunk(buf),
        PACKET_KIND_STORAGE_CONNECT => Packet::StorageConnect(bincode::deserialize(&buf)?),
        PACKET_KIND_STORAGE_BEGIN_GC => Packet::StorageBeginGC,
        PACKET_KIND_STORAGE_GC_REACHABLE => Packet::StorageGCReachable(buf),
        PACKET_KIND_STORAGE_GC_HEARTBEAT => Packet::StorageGCHeartBeat,
        PACKET_KIND_STORAGE_GC_COMPLETE => Packet::StorageGCComplete(bincode::deserialize(&buf)?),
        PACKET_KIND_T_STORAGE_WRITE_BARRIER => Packet::TStorageWriteBarrier,
        PACKET_KIND_R_STRORAGE_WRITE_BARRIER => Packet::RStorageWriteBarrier,
        PACKET_KIND_END_OF_TRANSMISSION => Packet::EndOfTransmission,
        _ => return Err(failure::format_err!("protocol error, unknown packet kind")),
    };
    Ok(packet)
}

fn send_hdr(w: &mut dyn std::io::Write, kind: u8, sz: u32) -> Result<(), failure::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    hdr[4] = kind;
    hdr[3] = ((sz & 0xff00_0000) >> 24) as u8;
    hdr[2] = ((sz & 0x00ff_0000) >> 16) as u8;
    hdr[1] = ((sz & 0x0000_ff00) >> 8) as u8;
    hdr[0] = (sz & 0x0000_00ff) as u8;
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
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_SERVER_INFO, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TBeginSend(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_T_BEGIN_SEND, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RBeginSend(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_R_BEGIN_SEND, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TLogOp(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_T_LOG_OP, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RLogOp(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_R_LOG_OP, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRequestData(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_DATA, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestData(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_DATA, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TGc(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_T_GC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RGc(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_R_GC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRequestItemSync(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestItemSync(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::SyncLogOps(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_SYNC_LOG_OPS, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRequestChunk(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_CHUNK, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestChunk(ref v) => {
            send_hdr(w, PACKET_KIND_R_REQUEST_CHUNK, v.len().try_into()?)?;
            w.write_all(&v)?;
        }
        Packet::StorageConnect(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_STORAGE_CONNECT, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::StorageBeginGC => {
            send_hdr(w, PACKET_KIND_STORAGE_BEGIN_GC, 0)?;
        }
        Packet::StorageGCReachable(reachable) => {
            send_hdr(
                w,
                PACKET_KIND_STORAGE_GC_REACHABLE,
                reachable.len().try_into()?,
            )?;
            w.write_all(&reachable)?;
        }
        Packet::StorageGCHeartBeat => {
            send_hdr(w, PACKET_KIND_STORAGE_GC_HEARTBEAT, 0)?;
        }
        Packet::StorageGCComplete(ref v) => {
            let b = bincode::serialize(&v)?;
            send_hdr(w, PACKET_KIND_STORAGE_GC_COMPLETE, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TStorageWriteBarrier => {
            send_hdr(w, PACKET_KIND_T_STORAGE_WRITE_BARRIER, 0)?;
        }
        Packet::RStorageWriteBarrier => {
            send_hdr(w, PACKET_KIND_R_STRORAGE_WRITE_BARRIER, 0)?;
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
            Packet::TBeginSend(TBeginSend {
                delta_id: Some("abc".to_owned()),
            }),
            Packet::RBeginSend(RBeginSend { has_delta_id: true }),
            {
                let master_key = keys::MasterKey::gen();
                Packet::TLogOp(itemset::LogOp::AddItem(itemset::VersionedItemMetadata::V1(
                    itemset::ItemMetadata {
                        plain_text_metadata: itemset::PlainTextItemMetadata {
                            address: Address::default(),
                            tree_height: 3,
                            master_key_id: master_key.id,
                        },
                        encrypted_metadata: vec![1, 2, 3],
                    },
                )))
            },
            Packet::RLogOp(Some("123".to_owned())),
            Packet::Chunk(Chunk {
                address: Address::default(),
                data: vec![1, 2, 3],
            }),
            Packet::TRequestData(TRequestData {
                id: "1234".to_owned(),
            }),
            {
                let master_key = keys::MasterKey::gen();
                Packet::RRequestData(RRequestData {
                    metadata: Some(itemset::VersionedItemMetadata::V1(itemset::ItemMetadata {
                        plain_text_metadata: itemset::PlainTextItemMetadata {
                            address: Address::default(),
                            tree_height: 3,
                            master_key_id: master_key.id,
                        },
                        encrypted_metadata: vec![1, 2, 3],
                    })),
                })
            },
            Packet::TGc(TGc {}),
            Packet::RGc(RGc {
                stats: repository::GCStats {
                    chunks_remaining: 1,
                    chunks_freed: 123,
                    bytes_freed: 345,
                    bytes_remaining: 678,
                },
            }),
            Packet::TRequestItemSync(TRequestItemSync {
                after: 123,
                gc_generation: Some("123".to_owned()),
            }),
            Packet::RRequestItemSync(RRequestItemSync {
                gc_generation: "123".to_owned(),
            }),
            Packet::SyncLogOps(vec![(
                765756,
                Some("abdef".to_owned()),
                itemset::LogOp::RemoveItems(vec!["123".to_owned()]),
            )]),
            Packet::TRequestChunk(Address::default()),
            Packet::RRequestChunk(vec![1, 2, 3]),
            Packet::StorageConnect(StorageConnect {
                protocol: "foobar".to_owned(),
                path: "abc".to_owned(),
            }),
            {
                let mut reachable = Vec::new();
                reachable.extend_from_slice(&Address::default().bytes[..]);
                Packet::StorageGCReachable(reachable)
            },
            Packet::StorageBeginGC,
            Packet::StorageGCHeartBeat,
            Packet::StorageGCComplete(repository::GCStats {
                chunks_remaining: 1,
                chunks_freed: 123,
                bytes_freed: 345,
                bytes_remaining: 678,
            }),
            Packet::TStorageWriteBarrier,
            Packet::RStorageWriteBarrier,
            Packet::EndOfTransmission,
        ];

        for p1 in packets.iter() {
            let mut c1 = std::io::Cursor::new(Vec::new());
            write_packet(&mut c1, p1).unwrap();
            let b = c1.into_inner();
            let mut c2 = std::io::Cursor::new(b);
            let p2 = read_packet(&mut c2, DEFAULT_MAX_PACKET_SIZE).unwrap();
            assert!(p1 == &p2);
        }
    }
}
