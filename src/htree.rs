use super::address::*;
use super::compression;
use super::crypto;
use std::convert::TryInto;

pub const MINIMUM_ADDR_CHUNK_SIZE: usize = 2 * (8 + ADDRESS_SZ);
pub const SENSIBLE_ADDR_MAX_CHUNK_SIZE: usize = 30000 * (8 + ADDRESS_SZ);

#[derive(Debug, thiserror::Error)]
pub enum HTreeError {
    #[error("corrupt or tampered data")]
    CorruptOrTamperedDataError,
    #[error("missing data")]
    DataMissing,
}

pub trait Sink {
    fn add_chunk(&mut self, addr: &Address, data: Vec<u8>) -> Result<(), anyhow::Error>;
}

pub trait Source {
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error>;
}

use std::collections::HashMap;

impl Sink for HashMap<Address, Vec<u8>> {
    fn add_chunk(&mut self, addr: &Address, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.insert(*addr, data);
        Ok(())
    }
}

impl Source for HashMap<Address, Vec<u8>> {
    fn get_chunk(&mut self, addr: &Address) -> Result<Vec<u8>, anyhow::Error> {
        if let Some(v) = self.get(addr) {
            Ok(v.clone())
        } else {
            Err(HTreeError::DataMissing.into())
        }
    }
}

pub struct TreeWriter {
    min_addr_chunk_size: usize,
    max_addr_chunk_size: usize,
    tree_blocks: Vec<Vec<u8>>,
    data_chunk_count: u64,
    stream_size: u64,
}

pub fn tree_block_address(data: &[u8]) -> Address {
    let mut hs = crypto::HashState::new(None);
    hs.update(data);
    Address { bytes: hs.finish() }
}

impl TreeWriter {
    pub fn new(min_addr_chunk_size: usize, max_addr_chunk_size: usize) -> TreeWriter {
        assert!(min_addr_chunk_size >= MINIMUM_ADDR_CHUNK_SIZE);
        assert!(max_addr_chunk_size >= MINIMUM_ADDR_CHUNK_SIZE);
        assert!(min_addr_chunk_size <= max_addr_chunk_size);
        TreeWriter {
            min_addr_chunk_size,
            max_addr_chunk_size,
            tree_blocks: Vec::new(),
            data_chunk_count: 0,
            stream_size: 0,
        }
    }

    fn clear_level(&mut self, sink: &mut dyn Sink, level: usize) -> Result<(), anyhow::Error> {
        // Writing empty blocks the parent level is pointless.
        if !self.tree_blocks[level].is_empty() {
            let mut block = Vec::with_capacity(self.min_addr_chunk_size);
            std::mem::swap(&mut block, &mut self.tree_blocks[level]);
            let block_address = tree_block_address(&block);
            let mut leaf_count: u64 = 0;
            for chunk in block.chunks(8 + ADDRESS_SZ) {
                leaf_count += u64::from_le_bytes(chunk[..8].try_into()?);
            }
            let block = compression::compress(compression::Scheme::None, block);
            sink.add_chunk(&block_address, block)?;
            self.add_addr(sink, level + 1, leaf_count, &block_address)?;
        }
        Ok(())
    }

    fn add_addr(
        &mut self,
        sink: &mut dyn Sink,
        level: usize,
        leaf_count: u64,
        addr: &Address,
    ) -> Result<(), anyhow::Error> {
        if self.tree_blocks.len() < level + 1 {
            self.tree_blocks.push(Vec::new());
        }

        self.tree_blocks[level].extend(&leaf_count.to_le_bytes());
        self.tree_blocks[level].extend(&addr.bytes);
        // if the 15 leading bits are set, we have a 1/(2**15) chance a given chunk is a split point,
        // each entry is 32 bytes + and 8 byte offset, that gives us ~1MB chunks.
        let is_split_point = addr.bytes[0] == 0xff && ((addr.bytes[1] & 0xfe) == 0xfe);

        if self.tree_blocks[level].len() >= self.min_addr_chunk_size {
            let next_would_overflow_max_size =
                self.tree_blocks[level].len() + 8 + ADDRESS_SZ > self.max_addr_chunk_size;

            if is_split_point || next_would_overflow_max_size {
                self.clear_level(sink, level)?;
            }
        }

        Ok(())
    }

    pub fn add_data_addr(
        &mut self,
        sink: &mut dyn Sink,
        addr: &Address,
    ) -> Result<(), anyhow::Error> {
        self.data_chunk_count += 1;
        self.add_addr(sink, 0, 1, addr)?;
        Ok(())
    }

    pub fn add(
        &mut self,
        sink: &mut dyn Sink,
        addr: &Address,
        real_sz: u64,
        data: Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        sink.add_chunk(addr, data)?;
        self.add_data_addr(sink, addr)?;
        self.add_stream_size(real_sz);
        Ok(())
    }

    pub fn add_stream_size(&mut self, sz: u64) {
        self.stream_size += sz;
    }

    pub fn data_chunk_count(&self) -> u64 {
        self.data_chunk_count
    }

    fn finish_level(
        &mut self,
        sink: &mut dyn Sink,
        level: usize,
    ) -> Result<(usize, Address), anyhow::Error> {
        if self.tree_blocks.len() - 1 == level && self.tree_blocks[level].len() == (8 + ADDRESS_SZ)
        {
            // We are the top level, and we only ever got a single address written to us.
            // This block is actually the root address.
            let mut result_addr = Address::default();
            result_addr
                .bytes
                .clone_from_slice(&self.tree_blocks[level][8..]);
            return Ok((level, result_addr));
        }
        // The tree blocks must contain whole addresses.
        assert!((self.tree_blocks[level].len() % (8 + ADDRESS_SZ)) == 0);
        self.clear_level(sink, level)?;
        Ok(self.finish_level(sink, level + 1)?)
    }

    pub fn finish(
        mut self,
        sink: &mut dyn Sink,
    ) -> Result<(usize, u64, u64, Address), anyhow::Error> {
        // Its a bug to call finish without adding a single chunk.
        // Either the number of tree_blocks grew larger than 1, or the root
        // block has at at least one address.
        assert!(
            self.tree_blocks.len() > 1
                || ((self.tree_blocks.len() == 1) && self.tree_blocks[0].len() >= (8 + ADDRESS_SZ))
        );
        let (height, address) = self.finish_level(sink, 0)?;
        Ok((height, self.data_chunk_count, self.stream_size, address))
    }
}

pub struct TreeReader {
    tree_blocks: Vec<Vec<u8>>,
    tree_heights: Vec<usize>,
    read_offsets: Vec<usize>,
}

impl TreeReader {
    pub fn new(level: usize, data_chunk_count: u64, addr: &Address) -> TreeReader {
        let mut tr = TreeReader {
            tree_blocks: Vec::new(),
            tree_heights: Vec::new(),
            read_offsets: Vec::new(),
        };
        let mut initial_block = Vec::new();
        initial_block.extend(&data_chunk_count.to_le_bytes()[..]);
        initial_block.extend(&addr.bytes);
        tr.tree_blocks.push(initial_block);
        tr.tree_heights.push(level);
        tr.read_offsets.push(0);
        tr
    }

    pub fn pop_level(&mut self) -> Option<Vec<u8>> {
        self.tree_heights.pop();
        self.read_offsets.pop();
        self.tree_blocks.pop()
    }

    pub fn push_level(&mut self, level: usize, data: Vec<u8>) -> Result<(), anyhow::Error> {
        if (data.len() % (8 + ADDRESS_SZ)) != 0 {
            return Err(HTreeError::CorruptOrTamperedDataError.into());
        }
        self.read_offsets.push(0);
        self.tree_heights.push(level);
        self.tree_blocks.push(data);
        Ok(())
    }

    fn prune_empty(&mut self) {
        loop {
            if self.tree_blocks.is_empty() {
                return;
            }
            let data = self.tree_blocks.last().unwrap();
            let read_offset = self.read_offsets.last().unwrap();
            let remaining = &data[*read_offset..];
            if !remaining.is_empty() {
                return;
            }
            self.pop_level();
        }
    }

    pub fn peek_addr(&mut self) -> Option<(usize, Address)> {
        self.prune_empty();

        if self.tree_blocks.is_empty() {
            return None;
        }

        let data = self.tree_blocks.last().unwrap();
        let height = *self.tree_heights.last().unwrap();
        let read_offset = self.read_offsets.last().unwrap();
        let remaining = &data[*read_offset..];
        assert!(!remaining.is_empty());
        let mut addr = Address::default();
        addr.bytes.clone_from_slice(&remaining[8..8 + ADDRESS_SZ]);
        Some((height, addr))
    }

    pub fn next_addr(&mut self) -> Option<(usize, Address)> {
        let addr = self.peek_addr();
        if addr.is_some() {
            let read_offset = self.read_offsets.last_mut().unwrap();
            *read_offset += 8 + ADDRESS_SZ;
        }
        addr
    }

    pub fn current_height(&mut self) -> Option<usize> {
        self.prune_empty();
        match self.tree_heights.last() {
            Some(h) => Some(*h),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_no_level() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);
        let addr = Address::from_bytes(&[1; ADDRESS_SZ]);
        tw.add(&mut chunks, &addr, 3, vec![1, 2, 3]).unwrap();
        let (_, n_data, data_sz, result) = tw.finish(&mut chunks).unwrap();
        // root = chunk1
        assert_eq!(n_data, 1);
        assert_eq!(data_sz, 3);
        assert_eq!(chunks.len(), 1);
        let addr_chunk = chunks.get_mut(&result).unwrap();
        assert_eq!(addr_chunk.len(), 3);
    }

    #[test]
    fn test_write_shape_single_level() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);

        tw.add(
            &mut chunks,
            &Address::from_bytes(&[1; ADDRESS_SZ]),
            0,
            vec![],
        )
        .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[2; ADDRESS_SZ]),
            1,
            vec![0],
        )
        .unwrap();

        let (_, n_data, data_sz, result) = tw.finish(&mut chunks).unwrap();

        // One chunk per added. One for addresses.
        // root = [chunk1 .. chunk2]
        // chunk1, chunk2
        assert_eq!(n_data, 2);
        assert_eq!(data_sz, 1);
        assert_eq!(chunks.len(), 3);
        let addr_chunk = chunks.get_mut(&result).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_two_levels() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);

        tw.add(
            &mut chunks,
            &Address::from_bytes(&[1; ADDRESS_SZ]),
            0,
            vec![],
        )
        .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[2; ADDRESS_SZ]),
            1,
            vec![0],
        )
        .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[3; ADDRESS_SZ]),
            3,
            vec![1, 2, 3],
        )
        .unwrap();

        let (_, n_data, data_sz, result) = tw.finish(&mut chunks).unwrap();

        // root = [address1 .. address2]
        // address1 = [chunk0 .. chunk1]
        // address2 = [chunk3]
        // chunk0, chunk1, chunk3
        assert_eq!(n_data, 3);
        assert_eq!(data_sz, 4);
        assert_eq!(chunks.len(), 6);
        let addr_chunk = chunks.get_mut(&result).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_single_level_content_split() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Allow large chunks.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, SENSIBLE_ADDR_MAX_CHUNK_SIZE);

        tw.add(
            &mut chunks,
            &Address::from_bytes(&[1; ADDRESS_SZ]),
            0,
            vec![],
        )
        .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[2; ADDRESS_SZ]),
            1,
            vec![0],
        )
        .unwrap();

        let (_, n_data, data_sz, result) = tw.finish(&mut chunks).unwrap();

        // One chunk per added. One for addresses.
        // root = [chunk1 .. chunk2 ]
        // chunk1, chunk2
        assert_eq!(n_data, 2);
        assert_eq!(data_sz, 1);
        assert_eq!(chunks.len(), 3);
        let addr_chunk = chunks.get_mut(&result).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_two_levels_content_split() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Allow large chunks.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, SENSIBLE_ADDR_MAX_CHUNK_SIZE);

        tw.add(
            &mut chunks,
            &Address::from_bytes(&[1; ADDRESS_SZ]),
            0,
            vec![],
        )
        .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[0xff; ADDRESS_SZ]),
            1,
            vec![0],
        )
        .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[2; ADDRESS_SZ]),
            3,
            vec![1, 2, 3],
        )
        .unwrap();

        let (_, n_data, data_sz, result) = tw.finish(&mut chunks).unwrap();

        // root = [address1 .. address2]
        // address1 = [chunk0, chunk1]
        // address2 = [chunk3]
        // chunk0, chunk1, chunk3
        assert_eq!(n_data, 3);
        assert_eq!(data_sz, 4);
        assert_eq!(chunks.len(), 6);
        let addr_chunk = chunks.get_mut(&result).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_tree_reader_walk() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        let height: usize;
        let n_data: u64;
        let addr: Address;

        {
            // Chunks that can only fit two addresses.
            let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);
            tw.add(
                &mut chunks,
                &Address::from_bytes(&[1; ADDRESS_SZ]),
                0,
                vec![],
            )
            .unwrap();
            tw.add(
                &mut chunks,
                &Address::from_bytes(&[2; ADDRESS_SZ]),
                1,
                vec![0],
            )
            .unwrap();
            tw.add(
                &mut chunks,
                &Address::from_bytes(&[3; ADDRESS_SZ]),
                3,
                vec![1, 2, 3],
            )
            .unwrap();

            let result = tw.finish(&mut chunks).unwrap();
            height = result.0;
            n_data = result.1;
            addr = result.3;
        }

        let mut tr = TreeReader::new(height, n_data, &addr);

        // First address is already counted
        let mut count = 0;
        let mut leaf_count = 0;

        loop {
            match tr.next_addr() {
                Some((height, addr)) => {
                    if height != 0 {
                        let data = chunks.get_chunk(&addr).unwrap();
                        let data = compression::unauthenticated_decompress(data).unwrap();
                        tr.push_level(height - 1, data).unwrap();
                    }

                    count += 1;
                    if height == 0 {
                        leaf_count += 1;
                    }
                }
                None => {
                    break;
                }
            }
        }

        // root = [address1 .. address2]
        // address1 = [chunk0 .. chunk1]
        // address2 = [chunk3]
        // chunk0, chunk1, chunk3
        assert_eq!(count, 6);
        assert_eq!(leaf_count, 3);
        assert_eq!(n_data, leaf_count);
    }
}
