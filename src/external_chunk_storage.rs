use super::abloom;
use super::address::Address;
use super::chunk_storage::Engine;
use super::protocol::*;
use super::repository;
use super::xid;
use std::os::unix::net::UnixStream;

pub struct ExternalStorage {
    sock: UnixStream,
}

impl ExternalStorage {
    pub fn new(socket_path: &std::path::Path, path: &str) -> Result<Self, anyhow::Error> {
        let mut sock = UnixStream::connect(socket_path)?;
        write_packet(
            &mut sock,
            &Packet::StorageConnect(StorageConnect {
                protocol: "s-6".to_string(),
                path: path.to_string(),
            }),
        )?;

        Ok(ExternalStorage { sock })
    }
}

impl Engine for ExternalStorage {
    fn pipelined_get_chunks(
        &mut self,
        addresses: &[Address],
        on_chunk: &mut dyn FnMut(&Address, &[u8]) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        // In the future it would probably be good (though more complicated) to perform the writing of the addresses,
        // and reading of the results concurrently, though it complicates both the plugin and bupstash.
        write_storage_pipelined_get_chunks(&mut self.sock, addresses)?;

        for address in addresses {
            match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE)? {
                Packet::RStorageRequestChunkData(data) => on_chunk(address, &data)?,
                _ => anyhow::bail!("unexpected packet reponse, expected chunk"),
            }
        }

        Ok(())
    }

    fn filter_existing_chunks(
        &mut self,
        on_progress: &mut dyn FnMut(u64) -> Result<(), anyhow::Error>,
        addresses: Vec<Address>,
    ) -> Result<Vec<Address>, anyhow::Error> {
        write_storage_filter_existing(&mut self.sock, &addresses)?;
        std::mem::drop(addresses);
        loop {
            match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE)? {
                Packet::StorageFilterExistingProgress(n) => on_progress(n.0)?,
                Packet::StorageAddresses(missing) => return Ok(missing),
                _ => anyhow::bail!(
                    "expected StorageAddresses or StorageFilterAddresses progress packet"
                ),
            };
        }
    }

    fn get_chunk(&mut self, address: &Address) -> Result<Vec<u8>, anyhow::Error> {
        write_packet(&mut self.sock, &Packet::TStorageRequestChunkData(*address))?;
        match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RStorageRequestChunkData(data) => Ok(data),
            _ => anyhow::bail!("unexpected packet reponse, expected RRequestChunkData"),
        }
    }

    fn add_chunk(&mut self, address: &Address, data: Vec<u8>) -> Result<(), anyhow::Error> {
        write_chunk(&mut self.sock, address, &data)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<FlushStats, anyhow::Error> {
        write_packet(&mut self.sock, &Packet::TStorageFlush)?;
        match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RStorageFlush(stats) => Ok(stats),
            _ => anyhow::bail!("unexpected packet reponse, expected RStorageFlush"),
        }
    }

    fn prepare_for_sweep(&mut self, gc_id: xid::Xid) -> Result<(), anyhow::Error> {
        write_packet(&mut self.sock, &Packet::TStoragePrepareForSweep(gc_id))?;
        match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE) {
            Ok(Packet::RStoragePrepareForSweep) => (),
            Ok(_) => anyhow::bail!("unexpected packet response, expected RStoragePrepareForSweep"),
            Err(err) => return Err(err),
        }
        Ok(())
    }

    fn estimate_chunk_count(&mut self) -> Result<u64, anyhow::Error> {
        write_packet(&mut self.sock, &Packet::TStorageEstimateCount)?;
        match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE) {
            Ok(Packet::RStorageEstimateCount(v)) => Ok(v.count.0),
            Ok(_) => anyhow::bail!("unexpected packet response, expected RStorageEstimateCount"),
            Err(err) => Err(err),
        }
    }

    fn sweep(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
        reachable: abloom::ABloom,
    ) -> Result<repository::GcStats, anyhow::Error> {
        write_begin_sweep(&mut self.sock, &reachable)?;
        std::mem::drop(reachable);
        loop {
            match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE)? {
                Packet::StorageSweepProgress(msg) => {
                    update_progress_msg(msg)?;
                }
                Packet::StorageSweepComplete(stats) => {
                    let _ = write_packet(&mut self.sock, &Packet::EndOfTransmission);
                    return Ok(stats);
                }
                _ => anyhow::bail!("unexpected packet response, expected StorageSweepProgress or StorageSweepComplete"),
            }
        }
    }

    fn sweep_completed(&mut self, gc_id: xid::Xid) -> Result<bool, anyhow::Error> {
        write_packet(&mut self.sock, &Packet::TStorageQuerySweepCompleted(gc_id))?;
        match read_packet(&mut self.sock, DEFAULT_MAX_PACKET_SIZE)? {
            Packet::RStorageQuerySweepCompleted(completed) => Ok(completed),
            _ => anyhow::bail!("unexpected packet response, expected RStorageSweepCompleted"),
        }
    }
}
