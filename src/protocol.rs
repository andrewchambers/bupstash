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

pub const CURRENT_REPOSITORY_PROTOCOL_VERSION: &str = "13";
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024 * 32;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
pub enum OpenMode {
    Read,
    ReadWrite,
    Gc,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TOpenRepository {
    // Open mode can be used by server implementations for load balancing purposes.
    // An example of why this is useful is that garbage collection can be extremely
    // memory intensive, while get/put operations have relatively constant memory
    // requirements.
    pub open_mode: OpenMode,
    pub protocol_version: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ROpenRepository {
    pub unix_now_millis: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Chunk {
    pub address: Address,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TBeginSend {
    pub delta_id: Option<Xid>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RBeginSend {
    pub item_id: Xid,
    pub gc_generation: Xid,
    pub has_delta_id: bool,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TRequestMetadata {
    pub id: Xid,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RRequestMetadata {
    pub metadata: Option<oplog::VersionedItemMetadata>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RequestData {
    pub id: Xid,
    pub partial: bool,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RequestIndex {
    pub id: Xid,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TGc {}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RGc {
    pub stats: repository::GcStats,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TRequestOpLogSync {
    pub after: Option<serde_bare::Uint>,
    pub gc_generation: Option<Xid>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RRequestOpLogSync {
    pub gc_generation: Xid,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct StorageConnect {
    pub protocol: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct AddItem {
    pub item: oplog::VersionedItemMetadata,
}

pub const ABORT_CODE_SERVER_UNAVAILABLE: u64 = 0x9cf5c3ce325d27a6;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Abort {
    pub message: String,
    pub code: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RRecoverRemoved {
    pub n_recovered: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RBeginItemSyncPush {
    pub gc_generation: Xid,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RStorageEstimateCount {
    pub count: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct FlushStats {
    pub added_chunks: u64,
    pub added_bytes: u64,
}

#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum Packet {
    TOpenRepository(TOpenRepository),
    ROpenRepository(ROpenRepository),
    TInitRepository(Option<repository::StorageEngineSpec>),
    RInitRepository,
    TBeginSend(TBeginSend),
    RBeginSend(RBeginSend),
    Chunk(Chunk),
    TFlush,
    RFlush(FlushStats),
    TAddItem(AddItem),
    RAddItem,
    TRmItems(Vec<Xid>),
    RRmItems(serde_bare::Uint),
    TRequestMetadata(TRequestMetadata),
    RRequestMetadata(RRequestMetadata),
    RequestData(RequestData),
    RequestDataRanges(Vec<index::HTreeDataRange>),
    TGc(TGc),
    GcProgress(String),
    RGc(RGc),
    TRequestOpLogSync(TRequestOpLogSync),
    RRequestOpLogSync(RRequestOpLogSync),
    SyncLogOps(Vec<oplog::LogOp>),

    Abort(Abort),
    TRecoverRemoved,
    RRecoverRemoved(RRecoverRemoved),
    RequestIndex(RequestIndex),
    TBeginItemSyncPush,
    RBeginItemSyncPush(RBeginItemSyncPush),
    ItemSyncFilterItems(Vec<Xid>),
    ItemSyncFilterItemsProgress(serde_bare::Uint),
    ItemSyncItems(Vec<Xid>),
    TBeginItemSyncPull,
    RBeginItemSyncPull,
    ItemSyncRequestAddresses(Vec<Xid>),
    ItemSyncFilterExisting(Vec<Address>),
    ItemSyncFilterExistingProgress(serde_bare::Uint),
    ItemSyncAddresses(Vec<Address>),
    ItemSyncRequestMetadata(Vec<Xid>),
    ItemSyncMetadata(Vec<oplog::VersionedItemMetadata>),
    ItemSyncAddItems(Vec<(Xid, oplog::VersionedItemMetadata)>),
    TEndItemSyncPull,
    REndItemSyncPull,
    TEndItemSyncPush,
    REndItemSyncPush,

    // Storage plugin protocol packets.
    TStorageRequestChunkData(Address),
    RStorageRequestChunkData(Vec<u8>),
    TStorageFlush,
    RStorageFlush(FlushStats),
    StorageConnect(StorageConnect),
    TStoragePrepareForSweep(Xid),
    RStoragePrepareForSweep,
    StorageBeginSweep(abloom::ABloom),
    StorageSweepProgress(String),
    StorageSweepComplete(repository::GcStats),
    TStorageQuerySweepCompleted(Xid),
    RStorageQuerySweepCompleted(bool),
    TStorageEstimateCount,
    RStorageEstimateCount(RStorageEstimateCount),
    StoragePipelineGetChunks(Vec<Address>),
    StorageFilterExisting(Vec<Address>),
    StorageFilterExistingProgress(serde_bare::Uint),
    StorageAddresses(Vec<Address>),

    // Shared protocol packets.
    EndOfTransmission,
}

const PACKET_KIND_T_OPEN_REPOSITORY: u8 = 0;
const PACKET_KIND_R_OPEN_REPOSITORY: u8 = 1;
const PACKET_KIND_T_INIT_REPOSITORY: u8 = 2;
const PACKET_KIND_R_INIT_REPOSITORY: u8 = 3;
const PACKET_KIND_T_BEGIN_SEND: u8 = 4;
const PACKET_KIND_R_BEGIN_SEND: u8 = 5;
const PACKET_KIND_T_FLUSH: u8 = 6;
const PACKET_KIND_R_FLUSH: u8 = 7;
const PACKET_KIND_CHUNK: u8 = 8;
const PACKET_KIND_T_ADD_ITEM: u8 = 9;
const PACKET_KIND_R_ADD_ITEM: u8 = 10;
const PACKET_KIND_T_RM_ITEMS: u8 = 11;
const PACKET_KIND_R_RM_ITEMS: u8 = 12;
const PACKET_KIND_REQUEST_DATA: u8 = 13;
const PACKET_KIND_REQUEST_DATA_RANGES: u8 = 14;
const PACKET_KIND_T_GC: u8 = 15;
const PACKET_KIND_GC_PROGRESS: u8 = 16;
const PACKET_KIND_R_GC: u8 = 17;
const PACKET_KIND_T_REQUEST_OPLOG_SYNC: u8 = 18;
const PACKET_KIND_R_REQUEST_OPLOG_SYNC: u8 = 19;
const PACKET_KIND_SYNC_LOG_OPS: u8 = 20;
const PACKET_KIND_ABORT: u8 = 21;
const PACKET_KIND_T_RECOVER_REMOVED: u8 = 22;
const PACKET_KIND_R_RECOVER_REMOVED: u8 = 23;
const PACKET_KIND_REQUEST_INDEX: u8 = 24;
const PACKET_KIND_T_REQUEST_METADATA: u8 = 25;
const PACKET_KIND_R_REQUEST_METADATA: u8 = 26;
const PACKET_KIND_T_BEGIN_ITEM_SYNC_PUSH: u8 = 27;
const PACKET_KIND_R_BEGIN_ITEM_SYNC_PUSH: u8 = 28;
const PACKET_KIND_ITEM_SYNC_FILTER_ITEMS: u8 = 29;
const PACKET_KIND_ITEM_SYNC_FILTER_ITEMS_PROGRESS: u8 = 30;
const PACKET_KIND_ITEM_SYNC_ITEMS: u8 = 31;
const PACKET_KIND_T_BEGIN_ITEM_SYNC_PULL: u8 = 32;
const PACKET_KIND_R_BEGIN_ITEM_SYNC_PULL: u8 = 33;
const PACKET_KIND_ITEM_SYNC_REQUEST_ADDRESSES: u8 = 34;
const PACKET_KIND_ITEM_SYNC_ADDRESSES: u8 = 35;
const PACKET_KIND_ITEM_SYNC_FILTER_EXISTING: u8 = 36;
const PACKET_KIND_ITEM_SYNC_FILTER_EXISTING_PROGRESS: u8 = 37;
const PACKET_KIND_ITEM_SYNC_REQUEST_METADATA: u8 = 38;
const PACKET_KIND_ITEM_SYNC_METADATA: u8 = 39;
const PACKET_KIND_ITEM_SYNC_ADD_ITEMS: u8 = 40;
const PACKET_KIND_T_END_ITEM_SYNC_PULL: u8 = 41;
const PACKET_KIND_R_END_ITEM_SYNC_PULL: u8 = 42;
const PACKET_KIND_T_END_ITEM_SYNC_PUSH: u8 = 43;
const PACKET_KIND_R_END_ITEM_SYNC_PUSH: u8 = 44;

// Backend storage protocol messages, not really subject to the same
// compatibility requirements.
const PACKET_KIND_STORAGE_CONNECT: u8 = 100;
const PACKET_KIND_T_STORAGE_FLUSH: u8 = 101;
const PACKET_KIND_R_STORAGE_FLUSH: u8 = 102;
const PACKET_KIND_T_STORAGE_PREPARE_FOR_SWEEP: u8 = 103;
const PACKET_KIND_R_STORAGE_PREPARE_FOR_SWEEP: u8 = 104;
const PACKET_KIND_T_STORAGE_ESTIMATE_COUNT: u8 = 105;
const PACKET_KIND_R_STORAGE_ESTIMATE_COUNT: u8 = 106;
const PACKET_KIND_STORAGE_BEGIN_SWEEP: u8 = 107;
const PACKET_KIND_STORAGE_SWEEP_PROGRESS: u8 = 108;
const PACKET_KIND_STORAGE_SWEEP_COMPLETE: u8 = 109;
const PACKET_KIND_T_STORAGE_QUERY_SWEEP_COMPLETED: u8 = 110;
const PACKET_KIND_R_STORAGE_QUERY_SWEEP_COMPLETED: u8 = 111;
const PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS: u8 = 112;
const PACKET_KIND_T_STORAGE_REQUEST_CHUNK_DATA: u8 = 113;
const PACKET_KIND_R_STORAGE_REQUEST_CHUNK_DATA: u8 = 114;
const PACKET_KIND_STORAGE_FILTER_EXISTING: u8 = 115;
const PACKET_KIND_STORAGE_FILTER_EXISTING_PROGRESS: u8 = 116;
const PACKET_KIND_STORAGE_ADDRESSES: u8 = 117;

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

    /* special case decoders that, bypass serde for performance */
    if kind == PACKET_KIND_CHUNK {
        if sz < ADDRESS_SZ {
            anyhow::bail!("protocol error, chunk packet smaller than address");
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
        PACKET_KIND_T_FLUSH => Packet::TFlush,
        PACKET_KIND_R_FLUSH => Packet::RFlush(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_ADD_ITEM => Packet::TAddItem(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_ADD_ITEM => Packet::RAddItem,
        PACKET_KIND_R_RM_ITEMS => Packet::RRmItems(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_METADATA => Packet::TRequestMetadata(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_REQUEST_METADATA => Packet::RRequestMetadata(serde_bare::from_slice(&buf)?),
        PACKET_KIND_REQUEST_DATA => Packet::RequestData(serde_bare::from_slice(&buf)?),
        PACKET_KIND_REQUEST_DATA_RANGES => Packet::RequestDataRanges(serde_bare::from_slice(&buf)?),
        PACKET_KIND_REQUEST_INDEX => Packet::RequestIndex(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_GC => Packet::TGc(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_GC => Packet::RGc(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_REQUEST_OPLOG_SYNC => {
            Packet::TRequestOpLogSync(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_R_REQUEST_OPLOG_SYNC => {
            Packet::RRequestOpLogSync(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_SYNC_LOG_OPS => Packet::SyncLogOps(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_STORAGE_REQUEST_CHUNK_DATA => {
            Packet::TStorageRequestChunkData(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_R_STORAGE_REQUEST_CHUNK_DATA => Packet::RStorageRequestChunkData(buf),
        PACKET_KIND_GC_PROGRESS => Packet::GcProgress(serde_bare::from_slice(&buf)?),
        PACKET_KIND_ABORT => Packet::Abort(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_RECOVER_REMOVED => Packet::TRecoverRemoved,
        PACKET_KIND_R_RECOVER_REMOVED => Packet::RRecoverRemoved(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_BEGIN_ITEM_SYNC_PUSH => Packet::TBeginItemSyncPush,
        PACKET_KIND_ITEM_SYNC_FILTER_EXISTING_PROGRESS => Packet::ItemSyncFilterExistingProgress(serde_bare::from_slice(&buf)?),
        PACKET_KIND_R_BEGIN_ITEM_SYNC_PUSH => {
            Packet::RBeginItemSyncPush(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_ITEM_SYNC_REQUEST_ADDRESSES
        | PACKET_KIND_ITEM_SYNC_REQUEST_METADATA
        | PACKET_KIND_ITEM_SYNC_FILTER_ITEMS
        | PACKET_KIND_ITEM_SYNC_ITEMS
        | PACKET_KIND_T_RM_ITEMS => {
            if sz % XID_SZ != 0 {
                anyhow::bail!("protocol error, packet must be a multiple of xid size");
            }
            let xids = buf
                .chunks(XID_SZ)
                .map(|b| Xid::from_slice(b).unwrap())
                .collect();
            match kind {
                PACKET_KIND_ITEM_SYNC_REQUEST_ADDRESSES => Packet::ItemSyncRequestAddresses(xids),
                PACKET_KIND_ITEM_SYNC_FILTER_ITEMS => Packet::ItemSyncFilterItems(xids),
                PACKET_KIND_ITEM_SYNC_ITEMS => Packet::ItemSyncItems(xids),
                PACKET_KIND_ITEM_SYNC_REQUEST_METADATA => Packet::ItemSyncRequestMetadata(xids),
                PACKET_KIND_T_RM_ITEMS => Packet::TRmItems(xids),
                _ => unreachable!(),
            }
        }
        PACKET_KIND_T_BEGIN_ITEM_SYNC_PULL => Packet::TBeginItemSyncPull,
        PACKET_KIND_R_BEGIN_ITEM_SYNC_PULL => Packet::RBeginItemSyncPull,
        PACKET_KIND_ITEM_SYNC_METADATA => Packet::ItemSyncMetadata(serde_bare::from_slice(&buf)?),
        PACKET_KIND_ITEM_SYNC_ADD_ITEMS => Packet::ItemSyncAddItems(serde_bare::from_slice(&buf)?),
        PACKET_KIND_T_END_ITEM_SYNC_PUSH => Packet::TEndItemSyncPush,
        PACKET_KIND_R_END_ITEM_SYNC_PUSH => Packet::REndItemSyncPush,
        PACKET_KIND_T_END_ITEM_SYNC_PULL => Packet::TEndItemSyncPull,
        PACKET_KIND_R_END_ITEM_SYNC_PULL => Packet::REndItemSyncPull,
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
        PACKET_KIND_STORAGE_SWEEP_PROGRESS => {
            Packet::StorageSweepProgress(serde_bare::from_slice(&buf)?)
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
        PACKET_KIND_T_STORAGE_FLUSH => Packet::TStorageFlush,
        PACKET_KIND_R_STORAGE_FLUSH => {
            Packet::RStorageFlush(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_ITEM_SYNC_ADDRESSES
        | PACKET_KIND_ITEM_SYNC_FILTER_EXISTING
        | PACKET_KIND_STORAGE_FILTER_EXISTING
        | PACKET_KIND_STORAGE_ADDRESSES
        | PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS => {
            if buf.len() % ADDRESS_SZ != 0 {
                anyhow::bail!("protocol error, packet must be a multiple of address size");
            }
            let addrs = buf
                .chunks(ADDRESS_SZ)
                .map(|a| Address::from_slice(a).unwrap())
                .collect();
            match kind {
                PACKET_KIND_ITEM_SYNC_ADDRESSES => Packet::ItemSyncAddresses(addrs),
                PACKET_KIND_ITEM_SYNC_FILTER_EXISTING => Packet::ItemSyncFilterExisting(addrs),
                PACKET_KIND_STORAGE_ADDRESSES => Packet::StorageAddresses(addrs),
                PACKET_KIND_STORAGE_FILTER_EXISTING => Packet::StorageFilterExisting(addrs),
                PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS => Packet::StoragePipelineGetChunks(addrs),
                _ => unreachable!(),
            }
        }
        PACKET_KIND_STORAGE_FILTER_EXISTING_PROGRESS => {
            Packet::StorageFilterExistingProgress(serde_bare::from_slice(&buf)?)
        }
        PACKET_KIND_END_OF_TRANSMISSION => Packet::EndOfTransmission,
        _ => {
            return Err(anyhow::format_err!(
                "protocol error, unknown packet kind ({}) sent by remote (possibly a bupstash version incompatibility)",
                kind
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

fn write_xid_vec_packet(
    w: &mut dyn std::io::Write,
    kind: u8,
    xids: &[Xid],
) -> Result<(), anyhow::Error> {
    let b = xids_to_bytes(xids);
    send_hdr(w, kind, b.len().try_into()?)?;
    write_to_remote(w, b)?;
    flush_remote(w)?;
    Ok(())
}

pub fn write_item_sync_request_addresses(
    w: &mut dyn std::io::Write,
    xids: &[Xid],
) -> Result<(), anyhow::Error> {
    write_xid_vec_packet(w, PACKET_KIND_ITEM_SYNC_REQUEST_ADDRESSES, xids)
}

pub fn write_item_sync_filter_items(
    w: &mut dyn std::io::Write,
    xids: &[Xid],
) -> Result<(), anyhow::Error> {
    write_xid_vec_packet(w, PACKET_KIND_ITEM_SYNC_FILTER_ITEMS, xids)
}

fn write_address_vec_packet(
    w: &mut dyn std::io::Write,
    kind: u8,
    addresses: &[Address],
) -> Result<(), anyhow::Error> {
    let b = addresses_to_bytes(addresses);
    send_hdr(w, kind, b.len().try_into()?)?;
    write_to_remote(w, b)?;
    flush_remote(w)?;
    Ok(())
}

pub fn write_storage_pipelined_get_chunks(
    w: &mut dyn std::io::Write,
    addresses: &[Address],
) -> Result<(), anyhow::Error> {
    write_address_vec_packet(w, PACKET_KIND_STORAGE_PIPELINE_GET_CHUNKS, addresses)
}

pub fn write_item_sync_addresses(
    w: &mut dyn std::io::Write,
    addresses: &[Address],
) -> Result<(), anyhow::Error> {
    write_address_vec_packet(w, PACKET_KIND_ITEM_SYNC_ADDRESSES, addresses)
}

pub fn write_item_sync_filter_existing(
    w: &mut dyn std::io::Write,
    addresses: &[Address],
) -> Result<(), anyhow::Error> {
    write_address_vec_packet(w, PACKET_KIND_ITEM_SYNC_FILTER_EXISTING, addresses)
}

pub fn write_storage_filter_existing(
    w: &mut dyn std::io::Write,
    addresses: &[Address],
) -> Result<(), anyhow::Error> {
    write_address_vec_packet(w, PACKET_KIND_STORAGE_FILTER_EXISTING, addresses)
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
        Packet::TFlush => {
            send_hdr(w, PACKET_KIND_T_FLUSH, 0)?;
        }
        Packet::RFlush(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_FLUSH, b.len().try_into()?)?;
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
            write_xid_vec_packet(w, PACKET_KIND_T_RM_ITEMS, v)?;
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
        Packet::TRequestOpLogSync(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_T_REQUEST_OPLOG_SYNC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::RRequestOpLogSync(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_REQUEST_OPLOG_SYNC, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::SyncLogOps(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_SYNC_LOG_OPS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TStorageRequestChunkData(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_T_STORAGE_REQUEST_CHUNK_DATA,
                b.len().try_into()?,
            )?;
            write_to_remote(w, &b)?;
        }
        Packet::RStorageRequestChunkData(ref v) => {
            send_hdr(
                w,
                PACKET_KIND_R_STORAGE_REQUEST_CHUNK_DATA,
                v.len().try_into()?,
            )?;
            write_to_remote(w, v)?;
        }
        Packet::GcProgress(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_GC_PROGRESS, b.len().try_into()?)?;
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
        Packet::TBeginItemSyncPush => {
            send_hdr(w, PACKET_KIND_T_BEGIN_ITEM_SYNC_PUSH, 0)?;
        }
        Packet::RBeginItemSyncPush(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_BEGIN_ITEM_SYNC_PUSH, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TBeginItemSyncPull => {
            send_hdr(w, PACKET_KIND_T_BEGIN_ITEM_SYNC_PULL, 0)?;
        }
        Packet::RBeginItemSyncPull => {
            send_hdr(w, PACKET_KIND_R_BEGIN_ITEM_SYNC_PULL, 0)?;
        }
        Packet::ItemSyncFilterItems(ref v) => {
            write_xid_vec_packet(w, PACKET_KIND_ITEM_SYNC_FILTER_ITEMS, v)?;
        }
        Packet::ItemSyncFilterItemsProgress(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_ITEM_SYNC_FILTER_ITEMS_PROGRESS,
                b.len().try_into()?,
            )?;
            write_to_remote(w, &b)?;
        }
        Packet::ItemSyncItems(ref v) => {
            write_xid_vec_packet(w, PACKET_KIND_ITEM_SYNC_ITEMS, v)?;
        }
        Packet::ItemSyncRequestAddresses(ref v) => {
            write_item_sync_request_addresses(w, v)?;
        }
        Packet::ItemSyncAddresses(ref v) => {
            write_item_sync_addresses(w, v)?;
        }
        Packet::ItemSyncFilterExisting(ref v) => {
            write_item_sync_filter_existing(w, v)?;
        }
        Packet::ItemSyncFilterExistingProgress(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_ITEM_SYNC_FILTER_EXISTING_PROGRESS,
                b.len().try_into()?,
            )?;
            write_to_remote(w, &b)?;
        }
        Packet::ItemSyncRequestMetadata(ref v) => {
            write_xid_vec_packet(w, PACKET_KIND_ITEM_SYNC_REQUEST_METADATA, v)?;
        }
        Packet::ItemSyncMetadata(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_ITEM_SYNC_METADATA, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::ItemSyncAddItems(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_ITEM_SYNC_ADD_ITEMS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::TEndItemSyncPush => {
            send_hdr(w, PACKET_KIND_T_END_ITEM_SYNC_PUSH, 0)?;
        }
        Packet::REndItemSyncPush => {
            send_hdr(w, PACKET_KIND_R_END_ITEM_SYNC_PUSH, 0)?;
        }
        Packet::TEndItemSyncPull => {
            send_hdr(w, PACKET_KIND_T_END_ITEM_SYNC_PULL, 0)?;
        }
        Packet::REndItemSyncPull => {
            send_hdr(w, PACKET_KIND_R_END_ITEM_SYNC_PULL, 0)?;
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
        Packet::StorageSweepProgress(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_STORAGE_SWEEP_PROGRESS, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::StorageSweepComplete(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_STORAGE_SWEEP_COMPLETE, b.len().try_into()?)?;
            write_to_remote(w, &b)?;
        }
        Packet::StorageAddresses(ref v) => {
            write_address_vec_packet(w, PACKET_KIND_STORAGE_ADDRESSES, v)?;
        }
        Packet::StorageFilterExisting(ref v) => {
            write_storage_filter_existing(w, v)?;
        }
        Packet::StorageFilterExistingProgress(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(
                w,
                PACKET_KIND_STORAGE_FILTER_EXISTING_PROGRESS,
                b.len().try_into()?,
            )?;
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
        Packet::TStorageFlush => {
            send_hdr(w, PACKET_KIND_T_STORAGE_FLUSH, 0)?;
        }
        Packet::RStorageFlush(ref v) => {
            let b = serde_bare::to_vec(v)?;
            send_hdr(w, PACKET_KIND_R_STORAGE_FLUSH, b.len().try_into()?)?;
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
