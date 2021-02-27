use super::address::*;
use std::convert::TryInto;

// AWCache is the 'address walk cache' designed to let bupstash
// efficiently skip data during garbage collection while also
// keeping a bound on memory use.
//
// The current implementation is a direct mapped cache. On hash collision
// a value simply evicts the existing value. We could use something fancier like an lru,
// but we need benchmarks to show it improves anything over such a simple implementaion.

pub struct AWCache {
    dm_cache_ents: Vec<Address>,
    pub add_count: u64,
    pub hit_count: u64,
}

impl AWCache {
    pub fn new(cache_ents: usize) -> AWCache {
        AWCache {
            dm_cache_ents: vec![Address::from_bytes(&[0; ADDRESS_SZ]); cache_ents],
            add_count: 0,
            hit_count: 0,
        }
    }

    pub fn add(&mut self, addr: &Address) -> bool {
        self.add_count += 1;
        let offset_buf = addr.bytes[0..8].try_into().unwrap();
        let offset: u64 = u64::from_le_bytes(offset_buf) % (self.dm_cache_ents.len() as u64);
        let mut tmp = *addr;
        std::mem::swap(
            &mut tmp,
            self.dm_cache_ents.get_mut(offset as usize).unwrap(),
        );
        let new_val = tmp != *addr;
        if !new_val {
            self.hit_count += 1;
        }
        new_val
    }

    pub fn utilization(&self) -> f64 {
        let mut utilized = 0;
        for a in self.dm_cache_ents.iter() {
            if a.bytes != [0; ADDRESS_SZ] {
                utilized += 1
            }
        }
        (utilized as f64) / (self.dm_cache_ents.len() as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::super::crypto;
    use super::*;

    #[test]
    fn test_awcache() {
        crypto::init();

        let mut cache = AWCache::new(4 * 1024);

        let addresses: Vec<Address> = (0..1000).map(|_| Address::random()).collect();

        for a in addresses.iter() {
            cache.add(&a);
            assert!(!cache.add(&a));
        }

        cache.hit_count = 0;
        cache.add_count = 0;

        for a in addresses.iter() {
            cache.add(&a);
        }

        assert!(cache.hit_count != 0);
        eprintln!("cache hit_count: {}/{}", cache.hit_count, cache.add_count);
        eprintln!("cache utilization: {}", cache.utilization());
    }
}
