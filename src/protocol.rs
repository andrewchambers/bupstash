use super::abloom;
use super::address::*;
use super::index;
use super::oplog;
use super::repository;
use super::xid::*;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::io::Read;
use thiserror::Error;

pub const CURRENT_REPOSITORY_PROTOCOL_VERSION: &str = "12";
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024 * 16;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum OpenMode {
    Read,
    ReadWrite,
    Gc,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TOpenRepository {
    // Open mode can be used by server implementations for load balancing purposes.
    // An example of why this is useful is that garbage collection can be extremely
    // memory intensive, while get/put operations have relatively constant memory
    // requirements.
    pub open_mode: OpenMode,
    pub protocol_version: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ROpenRepository {
    pub unix_now_millis: u64,
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
    pub item_id: Xid,
    pub gc_generation: Xid,
    pub has_delta_id: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TRequestMetadata {
    pub id: Xid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRequestMetadata {
    pub metadata: Option<oplog::VersionedItemMetadata>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestData {
    pub id: Xid,
    pub partial: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestIndex {
    pub id: Xid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TGc {}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RGc {
    pub stats: repository::GcStats,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TRequestItemSync {
    pub after: Option<serde_bare::Uint>,
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
    pub item: oplog::VersionedItemMetadata,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Progress {
    Notice(String),
    SetMessage(String),
}

pub const ABORT_CODE_SERVER_UNAVAILABLE: u64 = 0x9cf5c3ce325d27a6;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Abort {
    pub message: String,
    pub code: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RRecoverRemoved {
    pub n_recovered: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RStorageEstimateCount {
    pub count: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SyncStats {
    pub added_chunks: u64,
    pub added_bytes: u64,
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
    RSendSync(SyncStats),
    TAddItem(AddItem),
    RAddItem,
    TRmItems(Vec<Xid>),
    RRmItems(serde_bare::Uint),
    TRequestMetadata(TRequestMetadata),
    RRequestMetadata(RRequestMetadata),
    RequestData(RequestData),
    RequestDataRanges(Vec<index::HTreeDataRange>),
    TGc(TGc),
    RGc(RGc),
    TRequestItemSync(TRequestItemSync),
    RRequestItemSync(RRequestItemSync),
    SyncLogOps(Vec<oplog::LogOp>),
    TRequestChunkData(Address),
    RRequestChunkData(Vec<u8>),
    Progress(Progress),
    Abort(Abort),
    TRecoverRemoved,
    RRecoverRemoved(RRecoverRemoved),
    RequestIndex(RequestIndex),
    TStorageWriteBarrier,
    RStorageWriteBarrier(SyncStats),
    StorageConnect(StorageConnect),
    TStoragePrepareForSweep(Xid),
    RStoragePrepareForSweep,
    StorageBeginSweep(abloom::ABloom),
    StorageSweepComplete(repository::GcStats),
    TStorageQuerySweepCompleted(Xid),
    RStorageQuerySweepCompleted(bool),
    TStorageEstimateCount,
    RStorageEstimateCount(RStorageEstimateCount),
    StoragePipelineGetChunks(Vec<Address>),
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
const PACKET_KIND_REQUEST_DATA: u8 = 13;
const PACKET_KIND_REQUEST_DATA_RANGES: u8 = 14;
const PACKET_KIND_T_GC: u8 = 15;
const PACKET_KIND_R_GC: u8 = 16;
const PACKET_KIND_T_REQUEST_ITEM_SYNC: u8 = 17;
const PACKET_KIND_R_REQUEST_ITEM_SYNC: u8 = 18;
const PACKET_KIND_SYNC_LOG_OPS: u8 = 19;
const PACKET_KIND_T_REQUEST_CHUNK_DATA: u8 = 20;
const PACKET_KIND_R_REQUEST_CHUNK_DATA: u8 = 21;
const PACKET_KIND_PROGRESS: u8 = 22;
const PACKET_KIND_ABORT: u8 = 23;
const PACKET_KIND_T_RECOVER_REMOVED: u8 = 24;
const PACKET_KIND_R_RECOVER_REMOVED: u8 = 25;
const PACKET_KIND_REQUEST_INDEX: u8 = 26;
const PACKET_KIND_T_REQUEST_METADATA: u8 = 28;
const PACKET_KIND_R_REQUEST_METADATA: u8 = 29;

// Backend storage protocol messages, not really subject to the same
// compatibility requirements.
const PACKET_KIND_T_STORAGE_WRITE_BARRIER: u8 = 100;
const PACKET_KIND_R_STORAGE_WRITE_BARRIER: u8 = 101;
const PACKET_KIND_STORAGE_CONNECT: u8 = 102;
const PACKET_KIND_T_STORAGE_PREPARE_FOR_SWEEP: u8 = 103;
const PACKET_KIND_R_STORAGE_PREPARE_FOR_SWEEP: u8 = 104;
const PACKET_KIND_T_STORAGE_ESTIMATE_COUNT: u8 = 105;
const PACKET_KIND_R_STORAGE_ESTIMATE_COUNT: u8 = 106;
const PACKET_KIND_STORAGE_BEGIN_SWEEP: u8 = 107;
const PACKET_KIND_STORAGE_SWEEP_COMPLETE: u8 = 108;
const PACKET_KIND_T_STORAGE_QUERY_SWEEP_COMPLETED: u8 = 109;
const PACKET_KIND_R_STORAGE_QUERY_SWEEP_COMPLETED: u8 = 110;
const PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS: u8 = 111;

const PACKET_KIND_END_OF_TRANSMISSION: u8 = 255;

// Note that these functions intentionally do not return the underlying IO error.
// This is done for a few reasons:
//
// - We don't want to see any EPIPE at the top level caused by disconnects in the backend.
// - It seems like it is always clearer for the end user to see a disconnected message.

fn read_from_remote_into_vec(
    r: &mut dyn std::io::Read,
    buf: &mut Vec<u8>,
    n: usize,
) -> Result<(), anyhow::Error> {
    // The stdlib is smart enough to avoid zero initializing if we use read_to_end,
    // we can't do that ourselves easily without clippy complaining.
    match r.take(n as u64).read_to_end(buf) {
        Ok(n_read) if n_read == n => (),
        _ => anyhow::bail!("remote disconnected"),
    }
    Ok(())
}

fn read_from_remote(r: &mut dyn std::io::Read, buf: &mut [u8]) -> Result<(), anyhow::Error> {
    if r.read_exact(buf).is_err() {
        anyhow::bail!("remote disconnected")
    }
    Ok(())
}

fn write_to_remote(w: &mut dyn std::io::Write, buf: &[u8]) -> Result<(), anyhow::Error> {
    if w.write_all(buf).is_err() {
        anyhow::bail!("remote disconnected")
    }
    Ok(())
}

fn flush_remote(w: &mut dyn std::io::Write) -> Result<(), anyhow::Error> {
    if w.flush().is_err() {
        anyhow::bail!("remote disconnected")
    }
    Ok(())
}

#[derive(Error, Debug)]
pub enum AbortError {
    #[error("remote error: server unavailable ({message})")]
    ServerUnavailable { message: String },
    #[error("remote error: {message}")]
    Other { message: String },
}

pub fn read_packet(
    r: &mut dyn std::io::Read,
    max_packet_size: usize,
) -> Result<Packet, anyhow::Error> {
    let pkt = read_packet_raw(r, max_packet_size)?;
    if let Packet::Abort(Abort { message, code }) = pkt {
        match code {
            Some(code) if code == ABORT_CODE_SERVER_UNAVAILABLE => {
                return Err(AbortError::ServerUnavailable { message }.into())
            }
            _ => return Err(AbortError::Other { message }.into()),
        }
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
        read_from_remote_into_vec(r, &mut data, sz)?;
        return Ok(Packet::Chunk(Chunk { address, data }));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(sz);
    read_from_remote_into_vec(r, &mut buf, sz)?;

    let packet = match kind {
        PACKET_KIND_T_OPEN_REPOSITORY => Packet::TOpenRepository(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_OPEN_REPOSITORY => Packet::ROpenRepository(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_INIT_REPOSITORY => Packet::TInitRepository(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_INIT_REPOSITORY => Packet::RInitRepository,
        PACKET_KIND_T_BEGIN_SEND => Packet::TBeginSend(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_BEGIN_SEND => Packet::RBeginSend(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_SEND_SYNC => Packet::TSendSync,
        PACKET_KIND_R_SEND_SYNC => Packet::RSendSync(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_ADD_ITEM => Packet::TAddItem(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_ADD_ITEM => Packet::RAddItem,
        PACKET_KIND_T_RM_ITEMS => Packet::TRmItems(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_RM_ITEMS => Packet::RRmItems(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_METADATA => Packet::TRequestMetadata(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_METADATA => Packet::RRequestMetadata(serde_bare::from_slice(&buf)?),
        PACKET_KIND_REQUEST_DATA => Packet::RequestData(serde_bare::from_slice(&buf)?),
        PACKET_KIND_REQUEST_DATA_RANGES => Packet::RequestDataRanges(serde_bare::from_slice(&buf)?),
        PACKET_KIND_REQUEST_INDEX => Packet::RequestIndex(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_GC => Packet::TGc(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_GC => Packet::RGc(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_ITEM_SYNC => Packet::TRequestItemSync(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_ITEM_SYNC => Packet::RRequestItemSync(serde_bare::from_slice(&buf)?),
        PACKET_KIND_SYNC_LOG_OPS => Packet::SyncLogOps(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_CHUNK_DATA => {
            Packet::TRequestChunkData(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_R_REQUEST_CHUNK_DATA => Packet::RRequestChunkData(buf),
        PACKET_KIND_PROGRESS => Packet::Progress(serde_bare::from_slice(&buf)?),
        PACKET_KIND_ABORT => Packet::Abort(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_RECOVER_REMOVED => Packet::TRecoverRemoved,
        PACKET_KIND_R_RECOVER_REMOVED => Packet::RRecoverRemoved(serde_bare::from_slice(&buf)?),
        PACKET_KIND_STORAGE_CONNECT => Packet::StorageConnect(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_STORAGE_PREPARE_FOR_SWEEP => {
            Packet::TStoragePrepareForSweep(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_R_STORAGE_PREPARE_FOR_SWEEP => Packet::RStoragePrepareForSweep,
        PACKET_KIND_T_STORAGE_ESTIMATE_COUNT => Packet::TStorageEstimateCount,
        PACKET_KIND_R_STORAGE_ESTIMATE_COUNT => {
            Packet::RStorageEstimateCount(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_STORAGE_BEGIN_SWEEP => {
            Packet::StorageBeginSweep(abloom::ABloom::from_bytes(buf))
        }
        PACKET_KIND_STORAGE_SWEEP_COMPLETE => {
            Packet::StorageSweepComplete(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_T_STORAGE_QUERY_SWEEP_COMPLETED => {
            Packet::TStorageQuerySweepCompleted(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_R_STORAGE_QUERY_SWEEP_COMPLETED => {
            Packet::RStorageQuerySweepCompleted(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_T_STORAGE_WRITE_BARRIER => Packet::TStorageWriteBarrier,
        PACKET_KIND_R_STORAGE_WRITE_BARRIER => {
            Packet::RStorageWriteBarrier(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS => {
            if buf.len() % ADDRESS_SZ != 0 {
                anyhow::bail!("protocol error, pipeline get chunks size error");
            }
            let addrs = buf
                .chunks(ADDRESS_SZ)
                .map(|a| Address::from_slice(a).unwrap())
                .collect();
            Packet::StoragePipelineGetChunks(addrs)
        }
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
    write_to_remote(w, &hdr[..])?;
    Ok(())
}

// We write a lot of chunks and sometimes having to create a packet
// (which requires buffer ownership) is tedious, this shorthand helps.
pub fn write_chunk(
    w: &mut dyn std::io::Write,
    address: &Address,
    data: &[u8],
) -> Result<(), anyhow::Error> {
    send_hdr(w, PACKET_KIND_CHUNK, (data.len() + ADDRESS_SZ).try_into()?)?;
    write_to_remote(w, &address.bytes)?;
    write_to_remote(w, data)?;
    flush_remote(w)?;
    Ok(())
}

pub fn write_request_data_ranges(
    w: &mut dyn std::io::Write,
    ranges: &[index::HTreeDataRange],
) -> Result<(), anyhow::Error> {
    let b = serde_bare::to_vec(ranges)?;
    send_hdr(w, PACKET_KIND_REQUEST_DATA_RANGES, b.len().try_into()?)?;
    write_to_remote(w, &b)?;
    flush_remote(w)?;
    Ok(())
}

pub fn write_storage_pipelined_get_chunks(
    w: &mut dyn std::io::Write,
    addresses: &[Address],
) -> Result<(), anyhow::Error> {
    let b = addresses_to_bytes(addresses);
    send_hdr(
        w,
        PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS,
        b.len().try_into()?,
    )?;
    write_to_remote(w, b)?;
    flush_remote(w)?;
    Ok(())
}

pub fn write_begin_sweep(
    w: &mut dyn std::io::Write,
    bloom: &abloom::ABloom,
) -> Result<(), anyhow::Error> {
    let b = bloom.borrow_bytes();
    send_hdr(w, PACKET_KIND_STORAGE_BEGIN_SWEEP, b.len().try_into()?)?;
    write_to_remote(w, b)?;
    flush_remote(w)?;
    Ok(())
}

pub fn write_packet(w: &mut dyn std::io::Write, pkt: &Packet) -> Result<(), anyhow::Error> {
    match pkt {
        Packet::Chunk(ref v) => {
            return write_chunk(w, &v.address, &v.data);
        }
        Packet::TOpenRepository(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_OPEN_REPOSITORY, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::ROpenRepository(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_OPEN_REPOSITORY, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TInitRepository(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_INIT_REPOSITORY, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RInitRepository => {
            send_hdr(w, PACKET_KIND_R_INIT_REPOSITORY, 0)?;
        }
        Packet::TBeginSend(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_BEGIN_SEND, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RBeginSend(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_BEGIN_SEND, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TSendSync => {
            send_hdr(w, PACKET_KIND_T_SEND_SYNC, 0)?;
        }
        Packet::RSendSync(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_SEND_SYNC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TAddItem(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_ADD_ITEM, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RAddItem => {
            send_hdr(w, PACKET_KIND_R_ADD_ITEM, 0)?;
        }
        Packet::TRmItems(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_RM_ITEMS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RRmItems(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_RM_ITEMS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TRequestMetadata(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_METADATA, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RRequestMetadata(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_METADATA, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RequestData(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_REQUEST_DATA, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RequestDataRanges(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_REQUEST_DATA_RANGES, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RequestIndex(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_REQUEST_INDEX, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TGc(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_GC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RGc(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_GC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TRequestItemSync(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RRequestItemSync(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_ITEM_SYNC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::SyncLogOps(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_SYNC_LOG_OPS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TRequestChunkData(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_CHUNK_DATA, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RRequestChunkData(ref v) => {
            send_hdr(w, PACKET_KIND_R_REQUEST_CHUNK_DATA, v.len().try_into()?)?;
            write_to_remote(w, v)?;
        }
        Packet::Progress(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_PROGRESS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::Abort(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_ABORT, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TRecoverRemoved => {
            send_hdr(w, PACKET_KIND_T_RECOVER_REMOVED, 0)?;
        }
        Packet::RRecoverRemoved(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_RECOVER_REMOVED, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::StorageConnect(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_STORAGE_CONNECT, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TStoragePrepareForSweep(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_T_STORAGE_PREPARE_FOR_SWEEP,
                b.len().try_into()?,
            )?;
            write_to_remote(w, &b)?;
        }
        Packet::RStoragePrepareForSweep => {
            send_hdr(w, PACKET_KIND_R_STORAGE_PREPARE_FOR_SWEEP, 0)?;
        }
        Packet::TStorageEstimateCount => {
            send_hdr(w, PACKET_KIND_T_STORAGE_ESTIMATE_COUNT, 0)?;
        }
        Packet::RStorageEstimateCount(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_STORAGE_ESTIMATE_COUNT, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::StorageBeginSweep(ref v) => {
            return write_begin_sweep(w, v);
        }
        Packet::StorageSweepComplete(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_STORAGE_SWEEP_COMPLETE, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TStorageQuerySweepCompleted(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_T_STORAGE_QUERY_SWEEP_COMPLETED,
                b.len().try_into()?,
            )?;
            write_to_remote(w, &b)?;
        }
        Packet::RStorageQuerySweepCompleted(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_R_STORAGE_QUERY_SWEEP_COMPLETED,
                b.len().try_into()?,
            )?;
            write_to_remote(w, &b)?;
        }
        Packet::TStorageWriteBarrier => {
            send_hdr(w, PACKET_KIND_T_STORAGE_WRITE_BARRIER, 0)?;
        }
        Packet::RStorageWriteBarrier(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_STORAGE_WRITE_BARRIER, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::StoragePipelineGetChunks(ref a) => {
            return write_storage_pipelined_get_chunks(w, a);
        }
        Packet::EndOfTransmission => {
            send_hdr(w, PACKET_KIND_END_OF_TRANSMISSION, 0)?;
        }
    }
    flush_remote(w)?;
    Ok(())
}
