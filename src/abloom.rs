use super::address;
use std::convert::TryInto;

// ABloom is a bloom filter specialized for addresses by taking advantage of the
// fact that addresses are already randomly distributed.
//
// See https://en.wikipedia.org/wiki/Bloom_filter

#[derive(Debug, PartialEq)]
pub struct ABloom {
    nbits: u64,
    bytes: Vec<u8>,
}

// k is the number of hash functions in the bloom filter.
const K: usize = 4;

fn count_set_bits(bytes: &[u8]) -> u64 {
    let mut n: u64 = 0;
    for b in bytes.iter() {
        n += b.count_ones() as u64;
    }
    n
}

pub fn approximate_mem_size_upper_bound(false_postive_rate: f64, num_addrs: u64) -> usize {
    // see wiki: Optimal number of hash functions...
    // > Goel and Gupta,[9] however, give a rigorous upper bound
    // > that makes no approximations and requires no assumptions.
    // false_positives = (1 - e ^ (-k*n/m))^k
    // If we rearrange we get:
    // m = -k*n/ln(1 - root(k, false_positives))
    let k = K as f64;
    let n = num_addrs as f64;
    let e = false_postive_rate;
    let m = (-k * n) / ((1.0 - e.powf(1.0 / k)).ln());
    (m / 8.0) as usize // bits to bytes.
}

impl ABloom {
    pub fn new(mut mem_size: usize) -> ABloom {
        if mem_size == 0 {
            mem_size = 1;
        }

        ABloom {
            nbits: (mem_size as u64) * 8,
            bytes: vec![0; mem_size],
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> ABloom {
        ABloom {
            nbits: (bytes.len() as u64) * 8,
            bytes,
        }
    }

    pub fn mem_size(&self) -> usize {
        self.bytes.len()
    }

    pub fn borrow_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn num_bits(&self) -> u64 {
        self.nbits
    }

    pub fn count_set_bits(&self) -> u64 {
        count_set_bits(&self.bytes)
    }

    pub fn utilization(&self) -> f64 {
        let n = count_set_bits(&self.bytes);
        (n as f64) / (self.nbits as f64)
    }

    // Like utilization but uses a small sample
    // to become a constant time operation.
    pub fn estimate_utilization(&self) -> f64 {
        const SAMPLE_ESTIMATE_BYTES: usize = 1024 * 1024;
        let sample_size = std::cmp::min(SAMPLE_ESTIMATE_BYTES, self.bytes.len());
        let n = count_set_bits(&self.bytes[0..sample_size]);
        (n as f64) / ((sample_size * 8) as f64)
    }

    pub fn estimate_false_positive_rate(&self) -> f64 {
        const N: u64 = 10000;
        let mut false_positives = 0;
        for _i in 0..N {
            if self.probably_has(&address::Address::random()) {
                false_positives += 1;
            }
        }
        (false_positives as f64) / (N as f64)
    }

    pub fn estimate_add_count(&self) -> f64 {
        let m = self.nbits as f64;
        let x = self.count_set_bits() as f64;
        let k = K as f64;
        //Refer to bloom filter wiki: Approximating the number of items in a Bloom filter.
        (-m / k) * (1.0 - (x / m)).ln()
    }

    pub fn add(&mut self, addr: &address::Address) {
        for i in 0..K {
            let offset_buf = addr.bytes[i * 8..(i * 8 + 8)].try_into().unwrap();
            let bit_offset: u64 = u64::from_le_bytes(offset_buf) % self.nbits;
            let shift = bit_offset & 7;
            let byte_offset: usize = ((bit_offset & !7) >> 3).try_into().unwrap();
            self.bytes[byte_offset] |= 1 << shift;
        }
    }

    pub fn probably_has(&self, addr: &address::Address) -> bool {
        for i in 0..K {
            let offset_buf = addr.bytes[i * 8..(i * 8 + 8)].try_into().unwrap();
            let bit_offset: u64 = u64::from_le_bytes(offset_buf) % self.nbits;
            let shift = bit_offset & 7;
            let byte_offset: usize = ((bit_offset & !7) >> 3).try_into().unwrap();
            if (self.bytes[byte_offset] & (1 << shift)) == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::address;
    use super::super::crypto;
    use super::*;

    #[test]
    fn test_abloom() {
        crypto::init();

        let mut abloom = ABloom::new(8 * 1024 * 1024);

        for _i in 0..10000 {
            let addr = address::Address::random();
            abloom.add(&addr);
            assert!(abloom.probably_has(&addr));
        }
    }

    #[test]
    fn test_approximate_mem_size() {
        crypto::init();
        for n in [20000, 100000].iter() {
            for p in [0.01, 0.05, 0.1, 0.5].iter() {
                let mut abloom = ABloom::new(approximate_mem_size_upper_bound(*p, *n));

                for _i in 0..*n {
                    let addr = address::Address::random();
                    abloom.add(&addr);
                    assert!(abloom.probably_has(&addr));
                }

                let estimated_false_positives = abloom.estimate_false_positive_rate();
                let prediction_delta = *p - estimated_false_positives;

                eprintln!("n={}", n);
                eprintln!("p={}", p);
                eprintln!("mem_size={}", abloom.mem_size());
                eprintln!(
                    "estimated_false_positive_rate={}",
                    estimated_false_positives,
                );
                eprintln!("estimated_add_count={}", abloom.estimate_add_count());
                eprintln!("utilization={}", abloom.utilization());
                eprintln!("estimated_utilization={}", abloom.estimate_utilization());
                eprintln!("prediction_delta={}", prediction_delta);
                // This test relies on probabilities to pass, if it is flaky, we can tune it.
                assert!(prediction_delta < 0.020);
            }
        }
    }
}
