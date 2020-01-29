use super::rollsum::Rollsum;

pub struct RollsumChunker {
    rs: Rollsum,
    min_sz: usize,
    max_sz: usize,
    default_chunk_capacity: usize,
    cur_vec: Vec<u8>,
}

impl RollsumChunker {
    pub fn new(mut rs: Rollsum, mut min_sz: usize, mut max_sz: usize) -> RollsumChunker {
        if min_sz == 0 {
            min_sz = 1
        }
        if max_sz < min_sz {
            max_sz = min_sz
        }
        let default_chunk_capacity = max_sz / 2;
        rs.reset();
        RollsumChunker {
            rs,
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
            if self.cur_vec.capacity() + growth > self.max_sz {
                growth = self.max_sz - self.cur_vec.capacity();
            }
            self.cur_vec.reserve(growth);
            debug_assert!(self.cur_vec.capacity() <= self.max_sz);
        }
        let mut n_added = 0;
        for b in buf[0..n_bytes].iter() {
            self.cur_vec.push(*b);
            n_added += 1;
            if (self.rs.roll_byte(*b) && self.cur_vec.len() > self.min_sz)
                || self.cur_vec.len() == self.max_sz
            {
                return (n_added, Some(self.swap_vec()));
            }
        }
        (n_added, None)
    }

    pub fn finish(self) -> Vec<u8> {
        self.cur_vec
    }
}

#[test]
fn test_add_bytes() {
    let rs = Rollsum::new();
    let mut ch = RollsumChunker::new(rs, 1, 2);

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
