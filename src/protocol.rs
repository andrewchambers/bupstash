use super::address::*;
use super::index;
use super::itemset;
use super::repository;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

pub const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024 * 16;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum LockHint {
    Read,
    Write,
    Gc,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TOpenRepository {
    pub lock_hint: LockHint,
    pub repository_protocol_version: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ROpenRepository {
    pub now: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, PartialEq)]
pub struct Chunk {
    pub address: Address,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TBeginSend {
    pub delta_id: Option<Xid>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RBeginSend {
    pub gc_generation: Xid,
    pub has_delta_id: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TRequestData {
    pub id: Xid,
    pub ranges: Option<Vec<index::HTreeDataRange>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRequestData {
    pub metadata: Option<itemset::VersionedItemMetadata>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TRequestIndex {
    pub id: Xid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRequestIndex {
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
    pub gc_generation: Option<Xid>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRequestItemSync {
    pub gc_generation: Xid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StorageConnect {
    pub protocol: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AddItem {
    pub gc_generation: Xid,
    pub item: itemset::VersionedItemMetadata,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Progress {
    Notice(String),
    SetMessage(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Abort {
    pub message: String,
    pub code: Option<serde_bare::Uint>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRestoreRemoved {
    pub n_restored: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct StorageBeginGC {
    pub reachability_db_path: std::path::PathBuf,
}

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum Packet {
    TOpenRepository(TOpenRepository),
    ROpenRepository(ROpenRepository),
    TInitRepository(Option<repository::StorageEngineSpec>),
    RInitRepository,
    TBeginSend(TBeginSend),
    RBeginSend(RBeginSend),
    Chunk(Chunk),
    TSendSync,
    RSendSync,
    TAddItem(AddItem),
    RAddItem(Xid),
    TRmItems(Vec<Xid>),
    RRmItems,
    TRequestData(TRequestData),
    RRequestData(RRequestData),
    TGc(TGc),
    RGc(RGc),
    TRequestItemSync(TRequestItemSync),
    RRequestItemSync(RRequestItemSync),
    SyncLogOps(Vec<(i64, Option<Xid>, itemset::LogOp)>),
    TRequestChunk(Address),
    RRequestChunk(Vec<u8>),
    Progress(Progress),
    Abort(Abort),
    TRestoreRemoved,
    RRestoreRemoved(RRestoreRemoved),
    TRequestIndex(TRequestIndex),
    RRequestIndex(RRequestIndex),
    TStorageWriteBarrier,
    RStorageWriteBarrier,
    StorageConnect(StorageConnect),
    StorageBeginGC(StorageBeginGC),
    StorageGCHeartBeat,
    StorageGCComplete(repository::GCStats),
    EndOfTransmission,
}

const PACKET_KIND_T_OPEN_REPOSITORY: u8 = 0;
const PACKET_KIND_R_OPEN_REPOSITORY: u8 = 1;
const PACKET_KIND_T_INIT_REPOSITORY: u8 = 2;
const PACKET_KIND_R_INIT_REPOSITORY: u8 = 3;
const PACKET_KIND_T_BEGIN_SEND: u8 = 4;
const PACKET_KIND_R_BEGIN_SEND: u8 = 5;
const PACKET_KIND_T_SEND_SYNC: u8 = 6;
const PACKET_KIND_R_SEND_SYNC: u8 = 7;
const PACKET_KIND_CHUNK: u8 = 8;
const PACKET_KIND_T_ADD_ITEM: u8 = 9;
const PACKET_KIND_R_ADD_ITEM: u8 = 10;
const PACKET_KIND_T_RM_ITEMS: u8 = 11;
const PACKET_KIND_R_RM_ITEMS: u8 = 12;
const PACKET_KIND_T_REQUEST_DATA: u8 = 13;
const PACKET_KIND_R_REQUEST_DATA: u8 = 14;
const PACKET_KIND_T_GC: u8 = 15;
const PACKET_KIND_R_GC: u8 = 16;
const PACKET_KIND_T_REQUEST_ITEM_SYNC: u8 = 17;
const PACKET_KIND_R_REQUEST_ITEM_SYNC: u8 = 18;
const PACKET_KIND_SYNC_LOG_OPS: u8 = 19;
const PACKET_KIND_T_REQUEST_CHUNK: u8 = 20;
const PACKET_KIND_R_REQUEST_CHUNK: u8 = 21;
const PACKET_KIND_PROGRESS: u8 = 22;
const PACKET_KIND_ABORT: u8 = 23;
const PACKET_KIND_T_RESTORE_REMOVED: u8 = 24;
const PACKET_KIND_R_RESTORE_REMOVED: u8 = 25;
const PACKET_KIND_T_REQUEST_INDEX: u8 = 26;
const PACKET_KIND_R_REQUEST_INDEX: u8 = 27;

// Backend storage protocol messages.
const PACKET_KIND_T_STORAGE_WRITE_BARRIER: u8 = 100;
const PACKET_KIND_R_STORAGE_WRITE_BARRIER: u8 = 101;
const PACKET_KIND_STORAGE_CONNECT: u8 = 102;
const PACKET_KIND_STORAGE_BEGIN_GC: u8 = 103;
const PACKET_KIND_STORAGE_GC_HEARTBEAT: u8 = 104;
const PACKET_KIND_STORAGE_GC_COMPLETE: u8 = 105;

const PACKET_KIND_END_OF_TRANSMISSION: u8 = 255;

fn read_from_remote(r: &mut dyn std::io::Read, buf: &mut [u8]) -> Result<(), anyhow::Error> {
    if r.read_exact(buf).is_err() {
        anyhow::bail!("remote disconnected");
    };
    Ok(())
}

pub fn read_packet(
    r: &mut dyn std::io::Read,
    max_packet_size: usize,
) -> Result<Packet, anyhow::Error> {
    let pkt = read_packet_raw(r, max_packet_size)?;
    if let Packet::Abort(Abort { message, .. }) = pkt {
        return Err(anyhow::format_err!("remote error: {}", message));
    }
    Ok(pkt)
}

pub fn read_packet_raw(
    r: &mut dyn std::io::Read,
    max_packet_size: usize,
) -> Result<Packet, anyhow::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    read_from_remote(r, &mut hdr[..])?;
    let kind = hdr[4];

    let sz = (hdr[3] as usize) << 24
        | (hdr[2] as usize) << 16
        | (hdr[1] as usize) << 8
        | (hdr[0] as usize);

    if sz > max_packet_size {
        anyhow::bail!("packet too large");
    }

    /* special case chunks, bypass serde */
    if kind == PACKET_KIND_CHUNK {
        if sz < ADDRESS_SZ {
            anyhow::bail!("protocol error, packet smaller than address");
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
        PACKET_KIND_T_OPEN_REPOSITORY => Packet::TOpenRepository(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_OPEN_REPOSITORY => Packet::ROpenRepository(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_INIT_REPOSITORY => Packet::TInitRepository(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_INIT_REPOSITORY => Packet::RInitRepository,
        PACKET_KIND_T_BEGIN_SEND => Packet::TBeginSend(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_BEGIN_SEND => Packet::RBeginSend(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_SEND_SYNC => Packet::TSendSync,
        PACKET_KIND_R_SEND_SYNC => Packet::RSendSync,
        PACKET_KIND_T_ADD_ITEM => Packet::TAddItem(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_ADD_ITEM => Packet::RAddItem(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_RM_ITEMS => Packet::TRmItems(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_RM_ITEMS => Packet::RRmItems,
        PACKET_KIND_T_REQUEST_DATA => Packet::TRequestData(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_DATA => Packet::RRequestData(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_INDEX => Packet::TRequestIndex(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_INDEX => Packet::RRequestIndex(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_GC => Packet::TGc(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_GC => Packet::RGc(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_ITEM_SYNC => Packet::TRequestItemSync(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_ITEM_SYNC => Packet::RRequestItemSync(serde_bare::from_slice(&buf)?),
        PACKET_KIND_SYNC_LOG_OPS => Packet::SyncLogOps(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_CHUNK => Packet::TRequestChunk(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_CHUNK => Packet::RRequestChunk(buf),
        PACKET_KIND_PROGRESS => Packet::Progress(serde_bare::from_slice(&buf)?),
        PACKET_KIND_ABORT => Packet::Abort(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_RESTORE_REMOVED => Packet::TRestoreRemoved,
        PACKET_KIND_R_RESTORE_REMOVED => Packet::RRestoreRemoved(serde_bare::from_slice(&buf)?),
        PACKET_KIND_STORAGE_CONNECT => Packet::StorageConnect(serde_bare::from_slice(&buf)?),
        PACKET_KIND_STORAGE_BEGIN_GC => Packet::StorageBeginGC(serde_bare::from_slice(&buf)?),
        PACKET_KIND_STORAGE_GC_HEARTBEAT => Packet::StorageGCHeartBeat,
        PACKET_KIND_STORAGE_GC_COMPLETE => Packet::StorageGCComplete(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_STORAGE_WRITE_BARRIER => Packet::TStorageWriteBarrier,
        PACKET_KIND_R_STORAGE_WRITE_BARRIER => Packet::RStorageWriteBarrier,
        PACKET_KIND_END_OF_TRANSMISSION => Packet::EndOfTransmission,
        _ => {
            return Err(anyhow::format_err!(
                "protocol error, unknown packet kind sent by remote"
            ))
        }
    };
    Ok(packet)
}

fn send_hdr(w: &mut dyn std::io::Write, kind: u8, sz: u32) -> Result<(), anyhow::Error> {
    let mut hdr: [u8; 5] = [0; 5];
    hdr[4] = kind;
    hdr[3] = ((sz & 0xff00_0000) >> 24) as u8;
    hdr[2] = ((sz & 0x00ff_0000) >> 16) as u8;
    hdr[1] = ((sz & 0x0000_ff00) >> 8) as u8;
    hdr[0] = (sz & 0x0000_00ff) as u8;
    w.write_all(&hdr[..])?;
    Ok(())
}

pub fn write_packet(w: &mut dyn std::io::Write, pkt: &Packet) -> Result<(), anyhow::Error> {
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
        Packet::TOpenRepository(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_OPEN_REPOSITORY, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::ROpenRepository(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_OPEN_REPOSITORY, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TInitRepository(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_INIT_REPOSITORY, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RInitRepository => {
            send_hdr(w, PACKET_KIND_R_INIT_REPOSITORY, 0)?;
        }
        Packet::TBeginSend(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_BEGIN_SEND, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RBeginSend(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_BEGIN_SEND, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TSendSync => {
            send_hdr(w, PACKET_KIND_T_SEND_SYNC, 0)?;
        }
        Packet::RSendSync => {
            send_hdr(w, PACKET_KIND_R_SEND_SYNC, 0)?;
        }
        Packet::TAddItem(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_ADD_ITEM, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RAddItem(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_ADD_ITEM, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRmItems(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_RM_ITEMS, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRmItems => {
            send_hdr(w, PACKET_KIND_R_RM_ITEMS, 0)?;
        }
        Packet::TRequestData(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_DATA, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestData(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_DATA, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRequestIndex(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_INDEX, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestIndex(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_INDEX, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TGc(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_GC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RGc(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_GC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRequestItemSync(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestItemSync(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::SyncLogOps(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_SYNC_LOG_OPS, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRequestChunk(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_CHUNK, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::RRequestChunk(ref v) => {
            send_hdr(w, PACKET_KIND_R_REQUEST_CHUNK, v.len().try_into()?)?;
            w.write_all(&v)?;
        }
        Packet::Progress(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_PROGRESS, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::Abort(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_ABORT, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TRestoreRemoved => {
            send_hdr(w, PACKET_KIND_T_RESTORE_REMOVED, 0)?;
        }
        Packet::RRestoreRemoved(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_R_RESTORE_REMOVED, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::StorageConnect(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_STORAGE_CONNECT, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::StorageBeginGC(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_STORAGE_BEGIN_GC, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::StorageGCHeartBeat => {
            send_hdr(w, PACKET_KIND_STORAGE_GC_HEARTBEAT, 0)?;
        }
        Packet::StorageGCComplete(ref v) => {
            let b = serde_bare::to_vec(&v)?;
            send_hdr(w, PACKET_KIND_STORAGE_GC_COMPLETE, b.len().try_into()?)?;
            w.write_all(&b)?;
        }
        Packet::TStorageWriteBarrier => {
            send_hdr(w, PACKET_KIND_T_STORAGE_WRITE_BARRIER, 0)?;
        }
        Packet::RStorageWriteBarrier => {
            send_hdr(w, PACKET_KIND_R_STORAGE_WRITE_BARRIER, 0)?;
        }
        Packet::EndOfTransmission => {
            send_hdr(w, PACKET_KIND_END_OF_TRANSMISSION, 0)?;
        }
    }
    w.flush()?;
    Ok(())
}
