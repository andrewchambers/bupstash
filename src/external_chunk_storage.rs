use super::abloom;
use super::address::Address;
use super::chunk_storage::Engine;
use super::protocol;
use super::repository;
use super::xid;
use std::os::unix::net::UnixStream;

pub struct ExternalStorage {
    sock: UnixStream,
}

impl ExternalStorage {
    pub fn new(socket_path: &std::path::Path, path: &str) -> Result<Self, anyhow::Error> {
        let mut sock = UnixStream::connect(socket_path)?;
        protocol::write_packet(
            &mut sock,
            &protocol::Packet::StorageConnect(protocol::StorageConnect {
                protocol: "s-5".to_string(),
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
        protocol::write_storage_pipelined_get_chunks(&mut self.sock, addresses)?;

        for address in addresses {
            match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE)? {
                protocol::Packet::RRequestChunkData(data) => on_chunk(address, &data)?,
                _ => anyhow::bail!("unexpected packet reponse, expected chunk"),
            }
        }

        Ok(())
    }

    fn get_chunk(&mut self, address: &Address) -> Result<Vec<u8>, anyhow::Error> {
        protocol::write_packet(
            &mut self.sock,
            &protocol::Packet::TRequestChunkData(*address),
        )?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE)? {
            protocol::Packet::RRequestChunkData(data) => Ok(data),
            _ => anyhow::bail!("unexpected packet reponse, expected RRequestChunkData"),
        }
    }

    fn add_chunk(&mut self, address: &Address, data: Vec<u8>) -> Result<(), anyhow::Error> {
        protocol::write_chunk(&mut self.sock, address, &data)?;
        Ok(())
    }

    fn sync(&mut self) -> Result<protocol::SyncStats, anyhow::Error> {
        protocol::write_packet(&mut self.sock, &protocol::Packet::TStorageWriteBarrier)?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE)? {
            protocol::Packet::RStorageWriteBarrier(stats) => Ok(stats),
            _ => anyhow::bail!("unexpected packet reponse, expected RStorageWriteBarrier"),
        }
    }

    fn prepare_for_sweep(&mut self, gc_id: xid::Xid) -> Result<(), anyhow::Error> {
        protocol::write_packet(
            &mut self.sock,
            &protocol::Packet::TStoragePrepareForSweep(gc_id),
        )?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
            Ok(protocol::Packet::RStoragePrepareForSweep) => (),
            Ok(_) => anyhow::bail!("unexpected packet response, expected RStoragePrepareForSweep"),
            Err(err) => return Err(err),
        }
        Ok(())
    }

    fn estimate_chunk_count(&mut self) -> Result<u64, anyhow::Error> {
        protocol::write_packet(&mut self.sock, &protocol::Packet::TStorageEstimateCount)?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
            Ok(protocol::Packet::RStorageEstimateCount(v)) => Ok(v.count.0),
            Ok(_) => anyhow::bail!("unexpected packet response, expected RStorageEstimateCount"),
            Err(err) => Err(err),
        }
    }

    fn sweep(
        &mut self,
        update_progress_msg: &mut dyn FnMut(String) -> Result<(), anyhow::Error>,
        reachable: abloom::ABloom,
    ) -> Result<repository::GcStats, anyhow::Error> {
        protocol::write_begin_sweep(&mut self.sock, &reachable)?;
        std::mem::drop(reachable);
        loop {
            match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
                Ok(protocol::Packet::Progress(protocol::Progress::SetMessage(msg))) => {
                    update_progress_msg(msg)?;
                }
                Ok(protocol::Packet::StorageSweepComplete(stats)) => {
                    let _ = protocol::write_packet(
                        &mut self.sock,
                        &protocol::Packet::EndOfTransmission,
                    );
                    return Ok(stats);
                }
                Ok(_) => anyhow::bail!("unexpected packet response, expected StorageSweepComplete"),
                Err(err) => return Err(err),
            }
        }
    }

    fn sweep_completed(&mut self, gc_id: xid::Xid) -> Result<bool, anyhow::Error> {
        protocol::write_packet(
            &mut self.sock,
            &protocol::Packet::TStorageQuerySweepCompleted(gc_id),
        )?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE)? {
            protocol::Packet::RStorageQuerySweepCompleted(completed) => Ok(completed),
            _ => anyhow::bail!("unexpected packet response, expected RStorageSweepCompleted"),
        }
    }
}
