use super::address::*;
use super::crypto;
use super::rollsum;
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
    max_addr_chunk_size: usize,
    tree_blocks: Vec<Vec<u8>>,
    chunk_mask: u32,
    rollsums: Vec<rollsum::Rollsum>,
    data_chunk_count: u64,
}

pub fn tree_block_address(data: &[u8]) -> Address {
    let mut hs = crypto::HashState::new(None);
    hs.update(data);
    Address { bytes: hs.finish() }
}

impl TreeWriter {
    pub fn new(max_addr_chunk_size: usize, chunk_mask: u32) -> TreeWriter {
        assert!(max_addr_chunk_size >= MINIMUM_ADDR_CHUNK_SIZE);
        TreeWriter {
            chunk_mask,
            max_addr_chunk_size,
            tree_blocks: Vec::new(),
            rollsums: Vec::new(),
            data_chunk_count: 0,
        }
    }

    fn clear_level(&mut self, sink: &mut dyn Sink, level: usize) -> Result<(), anyhow::Error> {
        // Writing empty blocks the parent level is pointless.
        if !self.tree_blocks[level].is_empty() {
            let mut block = Vec::with_capacity(MINIMUM_ADDR_CHUNK_SIZE);
            std::mem::swap(&mut block, &mut self.tree_blocks[level]);
            let block_address = tree_block_address(&block);
            let mut leaf_count: u64 = 0;
            for chunk in block.chunks(8 + ADDRESS_SZ) {
                leaf_count += u64::from_le_bytes(chunk[..8].try_into()?);
            }
            sink.add_chunk(&block_address, block)?;
            self.add_addr(sink, level + 1, leaf_count, &block_address)?;
        }
        self.rollsums[level].reset();
        Ok(())
    }

    pub fn add_addr(
        &mut self,
        sink: &mut dyn Sink,
        level: usize,
        leaf_count: u64,
        addr: &Address,
    ) -> Result<(), anyhow::Error> {
        if level == 0 {
            self.data_chunk_count += 1;
        }

        if self.tree_blocks.len() < level + 1 {
            self.tree_blocks.push(Vec::new());
            self.rollsums
                .push(rollsum::Rollsum::new_with_chunk_mask(self.chunk_mask));
        }

        self.tree_blocks[level].extend(&leaf_count.to_le_bytes());
        self.tree_blocks[level].extend(&addr.bytes);
        // An address is a hash of all the content, it is an open question
        // as to how effective using more or less bits of the hash in the
        // rollsum will really be.
        // Also note that since the leaf_count is encoded in the address hash,
        // we don't need to run the rollsum against those bytes.
        let mut is_split_point = false;
        for b in addr.bytes.iter() {
            is_split_point = self.rollsums[level].roll_byte(*b) || is_split_point;
        }

        if self.tree_blocks[level].len() >= 2 * (8 + ADDRESS_SZ) {
            let next_would_overflow_max_size =
                self.tree_blocks[level].len() + 8 + ADDRESS_SZ > self.max_addr_chunk_size;

            if is_split_point || next_would_overflow_max_size {
                self.clear_level(sink, level)?;
            }
        }

        Ok(())
    }

    pub fn add(
        &mut self,
        sink: &mut dyn Sink,
        addr: &Address,
        data: Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        sink.add_chunk(addr, data)?;
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
        Ok(self.finish_level(sink, level + 1)?)
    }

    pub fn finish(mut self, sink: &mut dyn Sink) -> Result<(usize, u64, Address), anyhow::Error> {
        // Its a bug to call finish without adding a single chunk.
        // Either the number of tree_blocks grew larger than 1, or the root
        // block has at at least one address.
        assert!(
            self.tree_blocks.len() > 1
                || ((self.tree_blocks.len() == 1) && self.tree_blocks[0].len() >= (8 + ADDRESS_SZ))
        );
        let (height, address) = self.finish_level(sink, 0)?;
        Ok((height, self.data_chunk_count, address))
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

    fn prune_empty(&mut self) -> () {
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
        // Split mask is almost never successful.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, 0xffffffff);
        let addr = Address::from_bytes(&[1; ADDRESS_SZ]);
        tw.add(&mut chunks, &addr, vec![1, 2, 3]).unwrap();
        let (_, n_data, result) = tw.finish(&mut chunks).unwrap();
        // root = chunk1
        assert_eq!(n_data, 1);
        assert_eq!(chunks.len(), 1);
        let addr_chunk = chunks.get_mut(&result).unwrap();
        assert_eq!(addr_chunk.len(), 3);
    }

    #[test]
    fn test_write_shape_single_level() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        // Split mask is almost never successful.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, 0xffffffff);

        tw.add(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]), vec![])
            .unwrap();
        tw.add(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]), vec![0])
            .unwrap();

        let (_, n_data, result) = tw.finish(&mut chunks).unwrap();

        // One chunk per added. One for addresses.
        // root = [chunk1 .. chunk2]
        // chunk1, chunk2
        assert_eq!(n_data, 2);
        assert_eq!(chunks.len(), 3);
        let addr_chunk = chunks.get_mut(&result).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_two_levels() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Chunks that can only fit two addresses.
        // Split mask always is almost never successful.
        let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, 0xffffffff);

        tw.add(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]), vec![])
            .unwrap();
        tw.add(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]), vec![0])
            .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[3; ADDRESS_SZ]),
            vec![1, 2, 3],
        )
        .unwrap();

        let (_, n_data, result) = tw.finish(&mut chunks).unwrap();

        // root = [address1 .. address2]
        // address1 = [chunk0 .. chunk1]
        // address2 = [chunk3]
        // chunk0, chunk1, chunk3
        assert_eq!(n_data, 3);
        assert_eq!(chunks.len(), 6);
        let addr_chunk = chunks.get_mut(&result).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_single_level_content_split() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Allow large chunks.
        // Split mask that is always successful.
        let mut tw = TreeWriter::new(SENSIBLE_ADDR_MAX_CHUNK_SIZE, 0);

        tw.add(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]), vec![])
            .unwrap();
        tw.add(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]), vec![0])
            .unwrap();

        let (_, n_data, result) = tw.finish(&mut chunks).unwrap();

        // One chunk per added. One for addresses.
        // root = [chunk1 .. chunk2 ]
        // chunk1, chunk2
        assert_eq!(n_data, 2);
        assert_eq!(chunks.len(), 3);
        let addr_chunk = chunks.get_mut(&result).unwrap();
        assert_eq!(addr_chunk.len(), 2 * (8 + ADDRESS_SZ));
    }

    #[test]
    fn test_write_shape_two_levels_content_split() {
        let mut chunks = HashMap::<Address, Vec<u8>>::new();
        // Allow large chunks.
        // Split mask that is always successful.
        let mut tw = TreeWriter::new(SENSIBLE_ADDR_MAX_CHUNK_SIZE, 0);

        tw.add(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]), vec![])
            .unwrap();
        tw.add(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]), vec![0])
            .unwrap();
        tw.add(
            &mut chunks,
            &Address::from_bytes(&[3; ADDRESS_SZ]),
            vec![1, 2, 3],
        )
        .unwrap();

        let (_, n_data, result) = tw.finish(&mut chunks).unwrap();

        // root = [address1 .. address2]
        // address1 = [chunk0 .. chunk1]
        // address2 = [chunk3 ]
        // chunk0, chunk1, chunk3
        assert_eq!(n_data, 3);
        assert_eq!(chunks.len(), 6);
        let addr_chunk = chunks.get_mut(&result).unwrap();
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
            // Split mask is never successful.
            let mut tw = TreeWriter::new(MINIMUM_ADDR_CHUNK_SIZE, 0xffffffff);
            tw.add(&mut chunks, &Address::from_bytes(&[1; ADDRESS_SZ]), vec![])
                .unwrap();
            tw.add(&mut chunks, &Address::from_bytes(&[2; ADDRESS_SZ]), vec![0])
                .unwrap();
            tw.add(
                &mut chunks,
                &Address::from_bytes(&[3; ADDRESS_SZ]),
                vec![1, 2, 3],
            )
            .unwrap();

            let result = tw.finish(&mut chunks).unwrap();
            height = result.0;
            n_data = result.1;
            addr = result.2;
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
