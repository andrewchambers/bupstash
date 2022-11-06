// This file contains high performance rolling hash implementations used by bupstash
// for data deduplication - see https://en.wikipedia.org/wiki/Rolling_hash for more context.
//
// Bupstash initially used gear hash as described in the article above, but
// has since adopted a modified SIMD compatible gear hash developed by Quentin Carbonneaux.
//
// The implementations use const generics to select how many instances of gear hash
// are interleaved and can be experimented with via 'bupstash rollsum-benchmark'.
//
// Note that at the time of writing portable-simd is an unstable rust feature,
// so to experiment with it you must run a nightly compiler and use the following flags:
//
// RUSTFLAGS="-C target-cpu=native" cargo build --release --features simd-rollsum
//
use std::sync::Arc;

#[derive(Clone)]
pub struct GearTab {
    pub data: Arc<[u32; 256]>,
}

impl GearTab {
    pub fn from_array(data: [u32; 256]) -> GearTab {
        GearTab {
            data: Arc::new(data),
        }
    }

    #[inline(always)]
    unsafe fn get_unchecked(&self, i: usize) -> u32 {
        *self.data.get_unchecked(i)
    }
}

pub trait RollsumSplitter {
    fn window_size(&self) -> Option<usize>;
    fn roll_bytes(&mut self, buf: &[u8]) -> Option<usize>;
    fn reset(&mut self);
}

// The split mask controls the probability of content split point
// we keep it as a constant for performance. It is important to note
// that because we are shifting our gear hashes to the left, mask the top bits.
const SPLIT_MASK: u32 = 0xfffff800; // A split every 2^21 bytes or ~ 2MiB.

#[cfg(not(feature = "simd-rollsum"))]
pub type FastGearHasher = InterleavedGearHasher<8>;

#[cfg(feature = "simd-rollsum")]
pub type FastGearHasher = SimdInterleavedGearHasher<8>;

#[derive(Clone)]
pub struct GearHasher {
    tab: GearTab,
    h: u32,
}

impl GearHasher {
    pub fn new(tab: GearTab) -> Self {
        GearHasher { tab, h: 0 }
    }
}

impl RollsumSplitter for GearHasher {
    #[inline(always)]
    fn window_size(&self) -> Option<usize> {
        Some(32)
    }

    fn roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        let mut h = self.h;
        unsafe {
            for offset in 0..buf.len() {
                let b = *buf.get_unchecked(offset);
                let gv = self.tab.get_unchecked(b as usize);
                h = (h << 1).wrapping_add(gv);
                // The chunk mask uses the upper bits, as that has influence from
                // the whole chunk window, where the bottom bits do not.
                if (h & SPLIT_MASK) == 0 {
                    self.h = h;
                    return Some(offset + 1);
                }
            }
        }
        self.h = h;
        None
    }

    fn reset(&mut self) {
        self.h = 0
    }
}

#[derive(Clone)]
pub struct InterleavedGearHasher<const N: usize> {
    tab: GearTab,
    align: usize,
    h: [u32; N],
}

impl<const N: usize> InterleavedGearHasher<N> {
    pub fn new(tab: GearTab) -> Self {
        InterleavedGearHasher {
            tab,
            align: 0,
            h: [0; N],
        }
    }

    fn unaligned_roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        unsafe {
            for offset in 0..buf.len() {
                let b = *buf.get_unchecked(offset);
                let gv = self.tab.get_unchecked(b as usize);
                let ha = (*self.h.get_unchecked(self.align) << 1).wrapping_add(gv);
                *self.h.get_unchecked_mut(self.align) = ha;
                self.align = (self.align + 1) % N;
                if ha & SPLIT_MASK == 0 {
                    return Some(offset + 1);
                }
            }
        }
        None
    }

    fn aligned_roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        // We put everything into registers to make the optimizers job easier.
        let end = buf.len();
        let aligned_end = end - (end % N);
        let mut h = self.h;
        let mut splits: [bool; N] = [false; N];
        let mut offset = 0;

        unsafe {
            while offset < aligned_end {
                for i in 0..N {
                    let b = *buf.get_unchecked(offset + i);
                    let gvi = self.tab.get_unchecked(b as usize);
                    *h.get_unchecked_mut(i) = (h.get_unchecked(i) << 1).wrapping_add(gvi);
                    *splits.get_unchecked_mut(i) = *h.get_unchecked(i) & SPLIT_MASK == 0;
                }

                for i in 0..N {
                    *self.h.get_unchecked_mut(i) = *h.get_unchecked(i);
                    if *splits.get_unchecked(i) {
                        self.align = (i + 1) % N;
                        return Some(offset + i + 1);
                    }
                }

                self.h = h;
                offset += N;
            }
        }
        self.unaligned_roll_bytes(&buf[aligned_end..end])
            .map(|n| aligned_end + n)
    }
}

impl<const N: usize> RollsumSplitter for InterleavedGearHasher<N> {
    #[inline(always)]
    fn window_size(&self) -> Option<usize> {
        Some(32 * N)
    }

    fn roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        let mut align_adjust = 0;
        if self.align != 0 {
            align_adjust = (N - self.align).min(buf.len());
            if let Some(n) = self.unaligned_roll_bytes(&buf[0..align_adjust]) {
                return Some(n);
            }
        }
        self.aligned_roll_bytes(&buf[align_adjust..])
            .map(|n| align_adjust + n)
    }

    #[inline]
    fn reset(&mut self) {
        self.align = 0;
        self.h = [0; N];
    }
}

#[cfg(feature = "simd-rollsum")]
#[derive(Clone)]
pub struct SimdInterleavedGearHasher<const N: usize>
where
    std::simd::LaneCount<N>: std::simd::SupportedLaneCount,
{
    tab: GearTab,
    align: usize,
    h: [u32; N],
}

#[cfg(feature = "simd-rollsum")]
impl<const N: usize> SimdInterleavedGearHasher<N>
where
    std::simd::LaneCount<N>: std::simd::SupportedLaneCount,
{
    pub fn new(tab: GearTab) -> Self {
        SimdInterleavedGearHasher {
            tab,
            align: 0,
            h: [0; N],
        }
    }

    fn unaligned_roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        unsafe {
            for offset in 0..buf.len() {
                let b = *buf.get_unchecked(offset);
                let gv = self.tab.get_unchecked(b as usize);
                let ha = (*self.h.get_unchecked(self.align) << 1).wrapping_add(gv);
                *self.h.get_unchecked_mut(self.align) = ha;
                self.align = (self.align + 1) % N;
                if ha & SPLIT_MASK == 0 {
                    return Some(offset + 1);
                }
            }
        }
        None
    }

    fn aligned_roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        use std::simd::{Simd, SimdUint};

        let aligned_end = buf.len() - (buf.len() % N);
        let end = buf.len();
        let mut gv: Simd<u32, N> = Simd::splat(0);
        let mut h = Simd::from(self.h);
        let mut offset = 0;

        unsafe {
            while offset < aligned_end {
                for i in 0..N {
                    gv[i] = self
                        .tab
                        .get_unchecked(*buf.get_unchecked(offset + i) as usize);
                }
                h = (h << Simd::splat(1)) + gv;
                let masked = h & Simd::splat(SPLIT_MASK);
                if masked.reduce_min() == 0 {
                    for i in 0..N {
                        *self.h.get_unchecked_mut(i) = h[i];
                        if masked[i] == 0 {
                            self.align = (i + 1) % N;
                            return Some(offset + i + 1);
                        }
                    }
                }
                self.h = *h.as_array();
                offset += N;
            }
        }

        self.unaligned_roll_bytes(&buf[aligned_end..end])
            .map(|n| aligned_end + n)
    }
}

#[cfg(feature = "simd-rollsum")]
impl<const N: usize> RollsumSplitter for SimdInterleavedGearHasher<N>
where
    std::simd::LaneCount<N>: std::simd::SupportedLaneCount,
{
    #[inline(always)]
    fn window_size(&self) -> Option<usize> {
        Some(32 * N)
    }

    fn roll_bytes(&mut self, buf: &[u8]) -> Option<usize> {
        let mut align_adjust = 0;
        if self.align != 0 {
            align_adjust = (N - self.align).min(buf.len());
            if let Some(n) = self.unaligned_roll_bytes(&buf[0..align_adjust]) {
                return Some(n);
            }
        }
        self.aligned_roll_bytes(&buf[align_adjust..])
            .map(|n| align_adjust + n)
    }

    #[inline]
    fn reset(&mut self) {
        self.align = 0;
        self.h = [0; N];
    }
}

#[cfg(test)]
pub static TEST_GEAR_TAB_DATA: [u32; 256] = [
    0x67ed26b7, 0x32da500c, 0x53d0fee0, 0xce387dc7, 0xcd406d90, 0x2e83a4d4, 0x9fc9a38d, 0xb67259dc,
    0xca6b1722, 0x6d2ea08c, 0x235cea2e, 0x3149bb5f, 0x1beda787, 0x2a6b77d5, 0x2f22d9ac, 0x91fc0544,
    0xe413acfa, 0x5a30ff7a, 0xad6fdde0, 0x444fd0f5, 0x7ad87864, 0x58c5ff05, 0x8d2ec336, 0x2371f853,
    0x550f8572, 0x6aa448dd, 0x7c9ddbcf, 0x95221e14, 0x2a82ec33, 0xcbec5a78, 0xc6795a0d, 0x243995b7,
    0x1c909a2f, 0x4fded51c, 0x635d334b, 0x0e2b9999, 0x2702968d, 0x856de1d5, 0x3325d60e, 0xeb6a7502,
    0xec2a9844, 0x0905835a, 0xa1820375, 0xa4be5cab, 0x96a6c058, 0x2c2ccd70, 0xba40fce3, 0xd794c46b,
    0x8fbae83e, 0xc3aa7899, 0x3d3ff8ed, 0xa0d42b5b, 0x571c0c97, 0xd2811516, 0xf7e7b96c, 0x4fd2fcbd,
    0xe2fdec94, 0x282cc436, 0x78e8e95c, 0x80a3b613, 0xcfbee20c, 0xd4a32d1c, 0x2a12ff13, 0x6af82936,
    0xe5630258, 0x8efa6a98, 0x294fb2d1, 0xdeb57086, 0x5f0fddb3, 0xeceda7ce, 0x4c87305f, 0x3a6d3307,
    0xe22d2942, 0x9d060217, 0x1e42ed02, 0xb6f63b52, 0x4367f39f, 0x055cf262, 0x03a461b2, 0x5ef9e382,
    0x386bc03a, 0x2a1e79c7, 0xf1a0058b, 0xd4d2dea9, 0x56baf37d, 0x5daff6cc, 0xf03a951d, 0xaef7de45,
    0xa8f4581e, 0x3960b555, 0xffbfff6d, 0xbe702a23, 0x8f5b6d6f, 0x061739fb, 0x98696f47, 0x3fd596d4,
    0x151eac6b, 0xa9fcc4f5, 0x69181a12, 0x3ac5a107, 0xb5198fe7, 0x96bcb1da, 0x1b5ddf8e, 0xc757d650,
    0x65865c3a, 0x8fc0a41a, 0x87435536, 0x99eda6f2, 0x41874794, 0x29cff4e8, 0xb70efd9a, 0x3103f6e7,
    0x84d2453b, 0x15a450bd, 0x74f49af1, 0x60f664b1, 0xa1c86935, 0xfdafbce1, 0xe36353e3, 0x5d9ba739,
    0xbc0559ba, 0x708b0054, 0xd41d808c, 0xb2f31723, 0x9027c41f, 0xf136d165, 0xb5374b12, 0x9420a6ac,
    0x273958b6, 0xe6c2fad0, 0xebdc1f21, 0xfb33af8b, 0xc71c25cd, 0xe9a2d8e5, 0xbeb38a50, 0xbceb7cc2,
    0x4e4e73f0, 0xcd6c251d, 0xde4c032c, 0x4b04ac30, 0x725b8b21, 0x4eb8c33b, 0x20d07b75, 0x0567aa63,
    0xb56b2bb7, 0xc1f5fd3a, 0xcafd35ca, 0x470dd4da, 0xfe4f94cd, 0xfb8de424, 0xe8dbcf40, 0xfe50a37a,
    0x62db5b5d, 0xf32f4ab6, 0x2c4a8a51, 0x18473dc0, 0xfe0cbb6e, 0xfe399efd, 0xdf34ecc9, 0x6ccd5055,
    0x46097073, 0x139135c2, 0x721c76f6, 0x1c6a94b4, 0x6eee014d, 0x8a508e02, 0x3da538f5, 0x280d394f,
    0x5248a0c4, 0x3ce94c6c, 0x9a71ad3a, 0x8493dd05, 0xe43f0ab6, 0x18e4ed42, 0x6c5c0e09, 0x42b06ec9,
    0x8d330343, 0xa45b6f59, 0x2a573c0c, 0xd7fd3de6, 0xeedeab68, 0x5c84dafc, 0xbbd1b1a8, 0xa3ce1ad1,
    0x85b70bed, 0xb6add07f, 0xa531309c, 0x8f8ab852, 0x564de332, 0xeac9ed0c, 0x73da402c, 0x3ec52761,
    0x43af2f4d, 0xd6ff45c8, 0x4c367462, 0xd553bd6a, 0x44724855, 0x3b2aa728, 0x56e5eb65, 0xeaf16173,
    0x33fa42ff, 0xd714bb5d, 0xfbd0a3b9, 0xaf517134, 0x9416c8cd, 0x534cf94f, 0x548947c2, 0x34193569,
    0x32f4389a, 0xfe7028bc, 0xed73b1ed, 0x9db95770, 0x468e3922, 0x0440c3cd, 0x60059a62, 0x33504562,
    0x2b229fbd, 0x5174dca5, 0xf7028752, 0xd63c6aa8, 0x31276f38, 0x0646721c, 0xb0191da8, 0xe00e6de0,
    0x9eac1a6e, 0x9f7628a5, 0xed6c06ea, 0x0bb8af15, 0xf119fb12, 0x38693c1c, 0x732bc0fe, 0x84953275,
    0xb82ec888, 0x33a4f1b3, 0x3099835e, 0x028a8782, 0x5fdd51d7, 0xc6c717b3, 0xb06caf71, 0x17c8c111,
    0x61bad754, 0x9fd03061, 0xe09df1af, 0x3bc9eb73, 0x85878413, 0x9889aaf2, 0x3f5a9e46, 0x42c9f01f,
    0x9984a4f4, 0xd5de43cc, 0xd294daed, 0xbecba2d2, 0xf1f6e72c, 0x5551128a, 0x83af87e2, 0x6f0342ba,
];

#[cfg(test)]
mod tests {
    use super::super::crypto::randombytes;
    use super::*;

    #[test]
    fn gear_hasher_rolls() {
        let mut rs = GearHasher::new(GearTab::from_array(TEST_GEAR_TAB_DATA));
        let window_size = rs.window_size().unwrap();
        for i in 0..window_size {
            rs.roll_bytes(&[i as u8]);
        }
        let h1 = rs.h;
        for _i in 0..window_size {
            rs.roll_bytes(&[0xff]);
        }
        let h2 = rs.h;
        for i in 0..window_size {
            rs.roll_bytes(&[i as u8]);
        }
        let h3 = rs.h;
        for _i in 0..window_size {
            rs.roll_bytes(&[0xff]);
        }
        let h4 = rs.h;

        assert_eq!(h1, h3);
        assert_eq!(h2, h4);
    }

    #[test]
    fn interleaved_gear_hasher_rolls() {
        let mut rs = InterleavedGearHasher::<4>::new(GearTab::from_array(TEST_GEAR_TAB_DATA));
        let window_size = rs.window_size().unwrap();
        for i in 0..window_size {
            rs.roll_bytes(&[i as u8]);
        }
        let h1 = rs.h;
        for _i in 0..window_size {
            rs.roll_bytes(&[0xff]);
        }
        let h2 = rs.h;
        for i in 0..window_size {
            rs.roll_bytes(&[i as u8]);
        }
        let h3 = rs.h;
        for _i in 0..window_size {
            rs.roll_bytes(&[0xff]);
        }
        let h4 = rs.h;
        assert_eq!(h1, h3);
        assert_eq!(h2, h4);
    }

    #[test]
    fn gear_hasher_matches_interleaved_1() {
        let tab = GearTab::from_array(TEST_GEAR_TAB_DATA);
        let mut rs1 = GearHasher::new(tab.clone());
        let mut rs2 = InterleavedGearHasher::<1>::new(tab);
        let mut data = vec![0; 1024 * 1024];
        for _ in 0..10 {
            randombytes(&mut data);
            let mut data = &data[..];
            loop {
                let split1 = rs1.roll_bytes(data);
                let split2 = rs2.roll_bytes(data);
                assert_eq!(rs1.h, rs2.h[0]);
                assert_eq!(split1, split2);
                match split1 {
                    Some(n) => data = &data[n..],
                    None => break,
                }
            }
        }
    }

    #[test]
    fn fast_gear_hasher_matches_interleaved_8() {
        let tab = GearTab::from_array(TEST_GEAR_TAB_DATA);
        let mut rs1 = FastGearHasher::new(tab.clone());
        let mut rs2 = InterleavedGearHasher::<8>::new(tab);
        let mut data = vec![0; 1024 * 1024];
        for _ in 0..10 {
            randombytes(&mut data);
            let mut data = &data[..];
            loop {
                let split1 = rs1.roll_bytes(data);
                let split2 = rs2.roll_bytes(data);
                assert_eq!(rs1.h, rs2.h);
                assert_eq!(split1, split2);
                match split1 {
                    Some(n) => data = &data[n..],
                    None => break,
                }
            }
        }
    }

    #[test]
    fn interleaved_gear_hasher_aligned_roll_bytes_same_as_unaligned_roll_bytes() {
        let mut rs1 = InterleavedGearHasher::<4>::new(GearTab::from_array(TEST_GEAR_TAB_DATA));
        let mut rs2 = rs1.clone();
        let mut data = vec![0; 1024 * 1024];
        for _ in 0..10 {
            randombytes(&mut data);
            let mut data = &data[..];
            loop {
                let split1 = rs1.roll_bytes(data);
                let split2 = rs2.unaligned_roll_bytes(data);
                assert_eq!(rs1.h, rs2.h);
                assert_eq!(split1, split2);
                match split1 {
                    Some(n) => data = &data[n..],
                    None => break,
                }
            }
        }
    }

    #[cfg(feature = "simd-rollsum")]
    #[test]
    fn simd_interleaved_gear_hasher() {
        let tab = GearTab::from_array(TEST_GEAR_TAB_DATA);
        let mut rs1 = InterleavedGearHasher::<4>::new(tab.clone());
        let mut rs2 = SimdInterleavedGearHasher::<4>::new(tab);
        let mut data = vec![0; 1024 * 1024];
        for _ in 0..10 {
            randombytes(&mut data);
            let mut data = &data[..];
            loop {
                let split1 = rs1.roll_bytes(data);
                let split2 = rs2.roll_bytes(data);
                assert_eq!(rs1.h, rs2.h);
                assert_eq!(split1, split2);
                match split1 {
                    Some(n) => data = &data[n..],
                    None => break,
                }
            }
        }
    }
}
