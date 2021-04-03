use super::rollsum::{GearTab, Rollsum, WINDOW_SIZE};

pub struct RollsumChunker {
    gear_tab: GearTab,
    rs: Rollsum,
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
            rs: Rollsum::new(),
            gear_tab,
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
        debug_assert!(self.cur_vec.len() < self.max_sz);

        let mut n_bytes = buf.len();

        if (n_bytes + self.cur_vec.len()) > self.max_sz {
            let overshoot = (n_bytes + self.cur_vec.len()) - self.max_sz;
            n_bytes -= overshoot;
            debug_assert!(self.cur_vec.len() + n_bytes <= self.max_sz);
        }

        if self.spare_capacity() < n_bytes {
            let mut growth = self.max_sz / 3;
            if growth == 0 {
                growth = 1;
            }
            if self.cur_vec.capacity() + growth > self.max_sz {
                growth = self.max_sz - self.cur_vec.capacity();
            }
            self.cur_vec.reserve(growth);
            debug_assert!(self.spare_capacity() >= n_bytes);
        }

        // None of the bytes we are adding will count towards the
        // next chunk, simply add them all, the bytes don't matter
        // as we will cycle WINDOW_SIZE too.
        if self.min_sz >= WINDOW_SIZE
            && (self.cur_vec.len() + n_bytes < (self.min_sz - WINDOW_SIZE))
        {
            self.cur_vec.extend_from_slice(&buf[0..n_bytes]);
            return (n_bytes, None);
        }

        n_bytes = std::cmp::min(self.spare_capacity(), n_bytes);

        match self.rs.roll_bytes(&self.gear_tab, &buf[0..n_bytes]) {
            Some(split) => {
                self.cur_vec.extend_from_slice(&buf[0..split]);
                (split, Some(self.swap_vec()))
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
    use super::super::rollsum::TEST_GEAR_TAB;
    use super::*;

    #[test]
    fn test_add_bytes() {
        let mut ch = RollsumChunker::new(TEST_GEAR_TAB, 1, 2);

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
        let mut ch = RollsumChunker::new(TEST_GEAR_TAB, 10, 100);
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
