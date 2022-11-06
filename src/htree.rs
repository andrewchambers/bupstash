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
}

pub trait Sink {
    fn add_htree_chunk(&mut self, addr: &Address, data: Vec<u8>) -> Result<(), anyhow::Error>;
}

pub struct TreeMeta {
    pub height: usize,
    pub address: Address,
    pub total_chunk_count: u64,
    pub data_chunk_count: u64,
}

pub struct TreeWriter {
    min_addr_chunk_size: usize,
    max_addr_chunk_size: usize,
    tree_blocks: Vec<Vec<u8>>,
    total_chunk_count: u64,
    data_chunk_count: u64,
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
            total_chunk_count: 0,
            data_chunk_count: 0,
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
            sink.add_htree_chunk(&block_address, block)?;
            self.total_chunk_count += 1;
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

        self.tree_blocks[level].extend(leaf_count.to_le_bytes());
        self.tree_blocks[level].extend(addr.bytes);
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
        self.total_chunk_count += 1;
        self.add_addr(sink, 0, 1, addr)?;
        Ok(())
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
        self.finish_level(sink, level + 1)
    }

    pub fn finish(mut self, sink: &mut dyn Sink) -> Result<TreeMeta, anyhow::Error> {
        // Its a bug to call finish without adding a single chunk.
        // Either the number of tree_blocks grew larger than 1, or the root
        // block has at at least one address.
        assert!(
            self.tree_blocks.len() > 1
                || ((self.tree_blocks.len() == 1) && self.tree_blocks[0].len() >= (8 + ADDRESS_SZ))
        );
        let (height, address) = self.finish_level(sink, 0)?;
        Ok(TreeMeta {
            height,
            address,
            total_chunk_count: self.total_chunk_count,
            data_chunk_count: self.data_chunk_count,
        })
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
        initial_block.extend(addr.bytes);
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
        if !data.is_empty() {
            self.read_offsets.push(0);
            self.tree_heights.push(level);
            self.tree_blocks.push(data);
        }
        Ok(())
    }

    pub fn peek_addr(&mut self) -> Option<(usize, Address)> {
        if self.tree_blocks.is_empty() {
            return None;
        }
        let data = self.tree_blocks.last().unwrap();
        let height = *self.tree_heights.last().unwrap();
        let read_offset = self.read_offsets.last().unwrap();
        let remaining = &data[*read_offset..];
        let mut addr = Address::default();
        addr.bytes.clone_from_slice(&remaining[8..8 + ADDRESS_SZ]);
        Some((height, addr))
    }

    pub fn next_addr(&mut self) -> Option<(usize, Address)> {
        if self.tree_blocks.is_empty() {
            return None;
        }
        let data = self.tree_blocks.last().unwrap();
        let height = *self.tree_heights.last().unwrap();
        let read_offset = self.read_offsets.last_mut().unwrap();
        let remaining = &data[*read_offset..];
        let mut addr = Address::default();
        addr.bytes.clone_from_slice(&remaining[8..8 + ADDRESS_SZ]);
        if remaining.len() == 8 + ADDRESS_SZ {
            self.pop_level();
        } else {
            *read_offset += 8 + ADDRESS_SZ;
        }
        Some((height, addr))
    }

    pub fn remaining_level_addrs(&self) -> Option<usize> {
        if let Some(data) = self.tree_blocks.last() {
            let read_offset = self.read_offsets.last().unwrap();
            let remaining = &data[*read_offset..];
            Some(remaining.len() / (8 + ADDRESS_SZ))
        } else {
            None
        }
    }

    pub fn current_height(&mut self) -> Option<usize> {
        self.tree_heights.last().copied()
    }

    pub fn fast_forward(&mut self, num_chunks_to_skip: u64) -> Result<u64, anyhow::Error> {
        let mut n_skipped = 0;
        loop {
            if n_skipped == num_chunks_to_skip {
                return Ok(n_skipped);
            }
            match self.tree_blocks.last() {
                Some(data) => {
                    let read_offset = self.read_offsets.last_mut().unwrap();
                    let remaining = &data[*read_offset..];
                    let num_chunks = u64::from_le_bytes(remaining[0..8].try_into().unwrap());
                    if n_skipped + num_chunks > num_chunks_to_skip {
                        return Ok(n_skipped);
                    }
                    n_skipped += num_chunks;
                    if remaining.len() == 8 + ADDRESS_SZ {
                        self.pop_level();
                    } else {
                        *read_offset += 8 + ADDRESS_SZ;
                    }
                }
                None => return Ok(n_skipped),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    impl Sink for HashMap<Address, Vec<u8>> {
        fn add_htree_chunk(&mut self, addr: &Address, data: Vec<u8>) -> Result<(), anyhow::Error> {
            self.insert(*addr, data);
            Ok(())
        }
    }

    #[test]
    fn test_write_no_level() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);
        let addr = Address::from_bytes(&[1; ADDRESS_SZ]);
        tw.add_data_addr(&mut chunks, &addr).unwrap();
        let meta = tw.finish(&mut chunks).unwrap();
        // root = chunk1
        assert_eq!(meta.data_chunk_count, 1);
        assert_eq!(meta.total_chunk_count, 1);
        assert_eq!(chunks.len(), 0);
        assert_eq!(addr, meta.address);
    }

    #[test]
    fn test_write_shape_single_level() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);

        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]))
            .unwrap();
        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]))
            .unwrap();

        let meta = tw.finish(&mut chunks).unwrap();

        // One chunk per added. One for addresses.
        // root = [chunk1 .. chunk2]
        // chunk1, chunk2
        assert_eq!(meta.data_chunk_count, 2);
        assert_eq!(meta.total_chunk_count, 3);
        assert_eq!(chunks.len(), 1);
        let addr_chunk = chunks.get_mut(&meta.address).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_two_levels() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);

        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]))
            .unwrap();
        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]))
            .unwrap();
        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[3; ADDRESS_SZ]))
            .unwrap();

        let meta = tw.finish(&mut chunks).unwrap();

        // root = [address1 .. address2]
        // address1 = [chunk0 .. chunk1]
        // address2 = [chunk3]
        // chunk0, chunk1, chunk3
        assert_eq!(meta.data_chunk_count, 3);
        assert_eq!(meta.total_chunk_count, 6);
        assert_eq!(chunks.len(), 3);
        let addr_chunk = chunks.get_mut(&meta.address).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_single_level_content_split() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Allow large chunks.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, SENSIBLE_ADDR_MAX_CHUNK_SIZE);

        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]))
            .unwrap();
        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]))
            .unwrap();

        let meta = tw.finish(&mut chunks).unwrap();

        // One chunk per added. One for addresses.
        // root = [chunk1 .. chunk2 ]
        // chunk1, chunk2
        assert_eq!(meta.data_chunk_count, 2);
        assert_eq!(meta.total_chunk_count, 3);
        assert_eq!(chunks.len(), 1);
        let addr_chunk = chunks.get_mut(&meta.address).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_two_levels_content_split() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Allow large chunks.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, SENSIBLE_ADDR_MAX_CHUNK_SIZE);

        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]))
            .unwrap();
        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[0xff; ADDRESS_SZ]))
            .unwrap();
        tw.add_data_addr(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]))
            .unwrap();

        let meta = tw.finish(&mut chunks).unwrap();

        // root = [address1 .. address2]
        // address1 = [chunk0, chunk1]
        // address2 = [chunk3]
        // chunk0, chunk1, chunk3
        assert_eq!(meta.data_chunk_count, 3);
        assert_eq!(meta.total_chunk_count, 6);
        assert_eq!(chunks.len(), 3);
        let addr_chunk = chunks.get_mut(&meta.address).unwrap().clone();
        let addr_chunk = compression::unauthenticated_decompress(addr_chunk).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_tree_reader_walk() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        let meta = {
            // Chunks that can only fit two addresses.
            let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, MINIMUM_ADDR_CHUNK_SIZE);
            tw.add_data_addr(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]))
                .unwrap();
            tw.add_data_addr(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]))
                .unwrap();
            tw.add_data_addr(&mut chunks, &Address::from_bytes(&[3; ADDRESS_SZ]))
                .unwrap();

            tw.finish(&mut chunks).unwrap()
        };

        let mut tr = TreeReader::new(meta.height, meta.data_chunk_count, &meta.address);

        // First address is already counted
        let mut count = 0;
        let mut leaf_count = 0;

        loop {
            match tr.next_addr() {
                Some((height, addr)) => {
                    if height != 0 {
                        let data = chunks.get(&addr).unwrap();
                        let data = compression::unauthenticated_decompress(data.clone()).unwrap();
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
        assert_eq!(meta.total_chunk_count, count);
        assert_eq!(meta.data_chunk_count, leaf_count);
    }
}
