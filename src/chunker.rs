use super::rollsum::{FastGearHasher, GearTab, RollsumSplitter};

#[derive(Clone)]
pub struct RollsumChunker {
    rs: FastGearHasher,
    min_sz: usize,
    max_sz: usize,
    default_chunk_capacity: usize,
    cur_vec: Vec<u8>,
}

impl RollsumChunker {
    pub fn new(gear_tab: GearTab, mut min_sz: usize, mut max_sz: usize) -> RollsumChunker {
        if min_sz == 0 {
            min_sz = 1
        }
        if max_sz < min_sz {
            max_sz = min_sz
        }
        let default_chunk_capacity = max_sz / 2;
        RollsumChunker {
            rs: FastGearHasher::new(gear_tab),
            min_sz,
            max_sz,
            default_chunk_capacity,
            cur_vec: Vec::with_capacity(default_chunk_capacity),
        }
    }

    fn spare_capacity(&self) -> usize {
        self.cur_vec.capacity() - self.cur_vec.len()
    }

    fn swap_vec(&mut self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.default_chunk_capacity);
        std::mem::swap(&mut v, &mut self.cur_vec);
        v
    }

    pub fn add_bytes(&mut self, buf: &[u8]) -> (usize, Option<Vec<u8>>) {
        let mut n_bytes = buf.len();

        if (n_bytes + self.cur_vec.len()) > self.max_sz {
            let overshoot = (n_bytes + self.cur_vec.len()) - self.max_sz;
            n_bytes -= overshoot;
        }

        if self.spare_capacity() < n_bytes {
            let mut growth = (self.max_sz / 3).max(1);
            if self.cur_vec.capacity() + growth > self.max_sz {
                growth = self.max_sz - self.cur_vec.capacity();
            }
            self.cur_vec.reserve(growth);
            n_bytes = std::cmp::min(self.spare_capacity(), n_bytes);
        }

        // None of the bytes we are adding will count towards the
        // next chunk, simply add them all, the bytes don't matter
        // as we will cycle WINDOW_SIZE too.
        if let Some(window_size) = self.rs.window_size() {
            if self.min_sz >= window_size
                && (self.cur_vec.len() + n_bytes < (self.min_sz - window_size))
            {
                self.cur_vec.extend_from_slice(&buf[0..n_bytes]);
                return (n_bytes, None);
            }
        }

        match self.rs.roll_bytes(&buf[0..n_bytes]) {
            Some(split) => {
                self.cur_vec.extend_from_slice(&buf[0..split]);
                if self.cur_vec.len() < self.min_sz {
                    (split, None)
                } else {
                    (split, Some(self.swap_vec()))
                }
            }
            None => {
                self.cur_vec.extend_from_slice(&buf[0..n_bytes]);
                if self.cur_vec.len() == self.max_sz {
                    (n_bytes, Some(self.swap_vec()))
                } else {
                    (n_bytes, None)
                }
            }
        }
    }

    pub fn buffered_count(&mut self) -> usize {
        self.cur_vec.len()
    }

    pub fn force_split(&mut self) -> Option<Vec<u8>> {
        self.rs.reset();
        let v = self.swap_vec();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    pub fn take_buffered(&mut self) -> Vec<u8> {
        self.rs.reset();
        let mut v = Vec::new();
        std::mem::swap(&mut self.cur_vec, &mut v);
        v
    }

    pub fn finish(self) -> Vec<u8> {
        self.cur_vec
    }
}

#[cfg(test)]
mod tests {
    use super::super::rollsum::{GearTab, TEST_GEAR_TAB_DATA};
    use super::*;

    #[test]
    fn test_add_bytes() {
        let mut ch = RollsumChunker::new(GearTab::from_array(TEST_GEAR_TAB_DATA), 1, 2);

        match ch.add_bytes(b"a") {
            (1, None) => (),
            v => panic!("{:?}", v),
        }

        match ch.add_bytes(b"bc") {
            (1, Some(v)) => assert_eq!(v, b"ab"),
            v => panic!("{:?}", v),
        }

        match ch.add_bytes(b"c") {
            (1, None) => (),
            v => panic!("{:?}", v),
        }

        assert_eq!(ch.finish(), b"c");
    }

    #[test]
    fn test_force_split_bytes() {
        let mut ch = RollsumChunker::new(GearTab::from_array(TEST_GEAR_TAB_DATA), 10, 100);
        assert_eq!(ch.force_split(), None);
        ch.add_bytes(b"abc");

        match ch.force_split() {
            Some(v) => assert_eq!(v, b"abc"),
            None => panic!("fail!"),
        }
        assert_eq!(ch.force_split(), None);
        ch.add_bytes(b"def");
        assert_eq!(ch.finish(), b"def");
    }
}
