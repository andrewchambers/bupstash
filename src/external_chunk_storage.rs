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
                protocol: "s-2".to_string(),
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

    fn sync(&mut self) -> Result<(), anyhow::Error> {
        protocol::write_packet(&mut self.sock, &protocol::Packet::TStorageWriteBarrier)?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE)? {
            protocol::Packet::RStorageWriteBarrier => Ok(()),
            _ => anyhow::bail!("unexpected packet reponse, expected RStorageWriteBarrier"),
        }
    }

    fn prepare_for_gc(&mut self, gc_id: xid::Xid) -> Result<(), anyhow::Error> {
        protocol::write_packet(
            &mut self.sock,
            &protocol::Packet::TStoragePrepareForGC(gc_id),
        )?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
            Ok(protocol::Packet::RStoragePrepareForGC) => (),
            Ok(_) => anyhow::bail!("unexpected packet response, expected RStoragePrepareForGC"),
            Err(err) => return Err(err),
        }
        Ok(())
    }

    fn gc(
        &mut self,
        reachability_db_path: &std::path::Path,
        _reachability_db: &mut rusqlite::Connection,
    ) -> Result<repository::GCStats, anyhow::Error> {
        protocol::write_packet(
            &mut self.sock,
            &protocol::Packet::StorageBeginGC(protocol::StorageBeginGC {
                reachability_db_path: reachability_db_path.to_owned(),
            }),
        )?;

        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE) {
            Ok(protocol::Packet::StorageGCComplete(stats)) => {
                let _ =
                    protocol::write_packet(&mut self.sock, &protocol::Packet::EndOfTransmission);
                Ok(stats)
            }
            Ok(_) => anyhow::bail!("unexpected packet response, expected StorageGCComplete"),
            Err(err) => Err(err),
        }
    }

    fn gc_completed(&mut self, gc_id: xid::Xid) -> Result<bool, anyhow::Error> {
        protocol::write_packet(
            &mut self.sock,
            &protocol::Packet::TStorageGCCompleted(gc_id),
        )?;
        match protocol::read_packet(&mut self.sock, protocol::DEFAULT_MAX_PACKET_SIZE)? {
            protocol::Packet::RStorageGCCompleted(completed) => Ok(completed),
            _ => anyhow::bail!("unexpected packet response, expected RStorageAwaitGCCompletion"),
        }
    }
}
