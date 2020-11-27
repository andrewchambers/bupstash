
pub const WINDOW_SIZE: usize = 64;

// An implementation of 'gear hash'.
#[derive(Copy, Clone)]
pub struct Rollsum {
    h: u64,
}

impl Default for Rollsum {
    fn default() -> Self {
        Rollsum { h: 0 }
    }
}

impl Rollsum {
    /// Create new Rollsum engine with default chunking settings
    pub fn new() -> Self {
        Default::default()
    }

    #[inline(always)]
    pub fn roll_byte(&mut self, newch: u8) -> bool {
        let mut h = self.h;
        // The << 1 rolls out previous values after 64 shifts.
        let gv = unsafe { *GEAR_TAB.get_unchecked(newch as usize) };
        h = (h << 1).wrapping_add(gv);
        self.h = h;
        // The chunk mask uses the upper bits, as that has influence from
        // the whole chunk window, where the bottom bits do not.
        h.leading_ones() == 40
    }

    #[inline]
    pub fn reset(&mut self) {
        *self = Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollsum_rolls() {
        let mut rs = Rollsum::new();
        for i in 0..WINDOW_SIZE {
            rs.roll_byte(i as u8);
        }
        let h1 = rs.h;
        for _i in 0..WINDOW_SIZE {
            rs.roll_byte(0xff);
        }
        let h2 = rs.h;
        for i in 0..WINDOW_SIZE {
            rs.roll_byte(i as u8);
        }
        let h3 = rs.h;
        for _i in 0..WINDOW_SIZE {
            rs.roll_byte(0xff);
        }
        let h4 = rs.h;

        assert_eq!(h1, h3);
        assert_eq!(h2, h4);
    }
}

// generated with support/geartab.janet
static GEAR_TAB: [u64; 256] = [
    0x8d97bdf967ed26b7,
    0xa20575ac32da500c,
    0xb8e588bd53d0fee0,
    0xc68481b5ce387dc7,
    0x7bc01994cd406d90,
    0x5bca91512e83a4d4,
    0x2e4f411c9fc9a38d,
    0x0099cdd9b67259dc,
    0x7c1ebc4cca6b1722,
    0xfc3dd11a6d2ea08c,
    0x3d66664a235cea2e,
    0x3a8c079e3149bb5f,
    0xc1dcfdb31beda787,
    0x0c127a892a6b77d5,
    0x6cdbfef82f22d9ac,
    0xca3ecb9391fc0544,
    0xebd012bee413acfa,
    0xfc692ee55a30ff7a,
    0x0b1892dbad6fdde0,
    0x27b85d12444fd0f5,
    0x184870e77ad87864,
    0x645b023258c5ff05,
    0x171cc5e28d2ec336,
    0xdc7f197f2371f853,
    0xa0203426550f8572,
    0xb712bd406aa448dd,
    0xf8d2210d7c9ddbcf,
    0x4e45946295221e14,
    0x75895ea72a82ec33,
    0x38b44a3fcbec5a78,
    0x6df26b71c6795a0d,
    0x7369a2a7243995b7,
    0x869d4abe1c909a2f,
    0xed9e07114fded51c,
    0xf9cb99f3635d334b,
    0x8058d6690e2b9999,
    0xe85b5f1a2702968d,
    0xec2b770a856de1d5,
    0x07555f7d3325d60e,
    0xa2af9bceeb6a7502,
    0xf8d68f77ec2a9844,
    0x51f3f8280905835a,
    0x74070a9da1820375,
    0x1eada824a4be5cab,
    0x742f1e9d96a6c058,
    0x08826f0a2c2ccd70,
    0xbe4ac073ba40fce3,
    0x0d30d9f8d794c46b,
    0x62bf42338fbae83e,
    0xd20eaa8cc3aa7899,
    0xb9435ae23d3ff8ed,
    0x1fdccdb9a0d42b5b,
    0x2e2f97f2571c0c97,
    0xe5af98e5d2811516,
    0x0e501d12f7e7b96c,
    0x8aba0ff14fd2fcbd,
    0xd56eab4de2fdec94,
    0x3ed2f12a282cc436,
    0x995db2c978e8e95c,
    0xe9582b1c80a3b613,
    0x7a580a25cfbee20c,
    0xaac39e9bd4a32d1c,
    0x2d3e3d422a12ff13,
    0xc87c04b16af82936,
    0xb38c2e11e5630258,
    0x0b7ebff48efa6a98,
    0xb9340de9294fb2d1,
    0x4f75fcd9deb57086,
    0x16d044e05f0fddb3,
    0xa3077281eceda7ce,
    0xcd171e684c87305f,
    0x69b4236d3a6d3307,
    0xd2d18d66e22d2942,
    0x668c487d9d060217,
    0xd817f6d91e42ed02,
    0x6df39509b6f63b52,
    0x396b3e534367f39f,
    0x5883e2f2055cf262,
    0x5a33f1b303a461b2,
    0xaa0e530e5ef9e382,
    0xe2dac2b1386bc03a,
    0x483f37f32a1e79c7,
    0xf47e896df1a0058b,
    0x61408524d4d2dea9,
    0x610bbd9c56baf37d,
    0x1350b4625daff6cc,
    0xda0005dbf03a951d,
    0xe7961549aef7de45,
    0x1a57605ba8f4581e,
    0x255d50523960b555,
    0x52dcf83fffbfff6d,
    0xb59a69a0be702a23,
    0x81b1f06d8f5b6d6f,
    0x40485c77061739fb,
    0x9c9c249998696f47,
    0xbaba05303fd596d4,
    0x1c2e46f6151eac6b,
    0xe577f9f0a9fcc4f5,
    0xe568d6a069181a12,
    0x80f9c1b33ac5a107,
    0xe5eb4824b5198fe7,
    0x9e939ccb96bcb1da,
    0xc698f9151b5ddf8e,
    0x2ea8e919c757d650,
    0xb3db027765865c3a,
    0xa805c7c78fc0a41a,
    0x9dbef41e87435536,
    0xaf53a71c99eda6f2,
    0xe36f579c41874794,
    0xa59a0f5329cff4e8,
    0x5a2db7a1b70efd9a,
    0x1a045b563103f6e7,
    0x9a4c5cb984d2453b,
    0x31a3787a15a450bd,
    0x57ce965374f49af1,
    0x5e3e4c3060f664b1,
    0xd9796ad3a1c86935,
    0xa31d655cfdafbce1,
    0x83d04aafe36353e3,
    0xf0d9e3035d9ba739,
    0x4b76897bbc0559ba,
    0xfe67320c708b0054,
    0xd6e06387d41d808c,
    0x256536d9b2f31723,
    0xacdc8bd99027c41f,
    0x86328689f136d165,
    0x4fd7f39ab5374b12,
    0x9d8b59be9420a6ac,
    0x87ec1f46273958b6,
    0x014d4e8de6c2fad0,
    0xe706f930ebdc1f21,
    0x086bda38fb33af8b,
    0x19351ca4c71c25cd,
    0xfe838ed7e9a2d8e5,
    0xc9a38426beb38a50,
    0x9351dad3bceb7cc2,
    0x521046b54e4e73f0,
    0x2ea1f7eecd6c251d,
    0xeca6620dde4c032c,
    0x211984244b04ac30,
    0xa8720762725b8b21,
    0x9d231bd44eb8c33b,
    0xcaa752c720d07b75,
    0x40b9aa230567aa63,
    0xd24052b8b56b2bb7,
    0x9801b7d7c1f5fd3a,
    0x1a4088d0cafd35ca,
    0xbe4610f0470dd4da,
    0xd1598a3bfe4f94cd,
    0x351d7954fb8de424,
    0x43ed0ef3e8dbcf40,
    0xc9482d6bfe50a37a,
    0x1d58d28f62db5b5d,
    0x18a2fb0ff32f4ab6,
    0x9922a59f2c4a8a51,
    0xc5d4106f18473dc0,
    0x2ab6a607fe0cbb6e,
    0xe9eb2e95fe399efd,
    0x371bf0bbdf34ecc9,
    0xddba7ff16ccd5055,
    0x0924bb9c46097073,
    0xdc0e6ba7139135c2,
    0x1f9e10fa721c76f6,
    0x78b68ee21c6a94b4,
    0xdbaae55f6eee014d,
    0xe8d3917c8a508e02,
    0xb70dfb303da538f5,
    0x77d6fe05280d394f,
    0x6c10187b5248a0c4,
    0xc92f2adc3ce94c6c,
    0x4ff063349a71ad3a,
    0x9c599afc8493dd05,
    0x65966d40e43f0ab6,
    0xac96a07a18e4ed42,
    0x52896e696c5c0e09,
    0x1e96b3bb42b06ec9,
    0x83e301bd8d330343,
    0x5c37ce16a45b6f59,
    0x2bf8d8f82a573c0c,
    0xaae2b9bdd7fd3de6,
    0xc2e09e04eedeab68,
    0x47c5ba7a5c84dafc,
    0x700155dfbbd1b1a8,
    0xcf10cf82a3ce1ad1,
    0xef5a883c85b70bed,
    0x1d3f5475b6add07f,
    0x51a936fca531309c,
    0x13aa903e8f8ab852,
    0x84af8ae6564de332,
    0xd2477840eac9ed0c,
    0x839f006373da402c,
    0x7a75c5ae3ec52761,
    0x7cd2903643af2f4d,
    0x672f39f3d6ff45c8,
    0xf67818cf4c367462,
    0x75977981d553bd6a,
    0xea55f10544724855,
    0xfc14ac503b2aa728,
    0xd935614956e5eb65,
    0xed881401eaf16173,
    0x8d9856bf33fa42ff,
    0xe8d430b5d714bb5d,
    0x151ee279fbd0a3b9,
    0x5bbdf69faf517134,
    0xaf6155579416c8cd,
    0x6d3ffb15534cf94f,
    0x759f400e548947c2,
    0x0a83dd2a34193569,
    0xec63d56f32f4389a,
    0x9ae25046fe7028bc,
    0xc4891e2fed73b1ed,
    0x1521bf349db95770,
    0x51ba07e1468e3922,
    0x25b6f4eb0440c3cd,
    0xf6a430b960059a62,
    0xfd9140b133504562,
    0xba7bf2d72b229fbd,
    0x83c1bb445174dca5,
    0xaa1ae086f7028752,
    0x2756cc08d63c6aa8,
    0x60a90cfb31276f38,
    0x124d0c5f0646721c,
    0x460038a0b0191da8,
    0x34d53860e00e6de0,
    0x2ddb26c79eac1a6e,
    0xd46e3f179f7628a5,
    0x4041ff09ed6c06ea,
    0xcd2d7d1e0bb8af15,
    0x886f101af119fb12,
    0xe7c26b0a38693c1c,
    0xb86bf430732bc0fe,
    0x04b133ab84953275,
    0x5b0748f1b82ec888,
    0xd852c68433a4f1b3,
    0xdfe167193099835e,
    0x57a1b4c3028a8782,
    0xd685dd4c5fdd51d7,
    0x4dcab755c6c717b3,
    0x956bf645b06caf71,
    0xb0c7474417c8c111,
    0x3a6913b461bad754,
    0x99571b099fd03061,
    0xd0e8d718e09df1af,
    0x6c17a8873bc9eb73,
    0x312db8a585878413,
    0xbf74c74e9889aaf2,
    0x9f8ba04d3f5a9e46,
    0x15be96b242c9f01f,
    0x180ae12a9984a4f4,
    0x51a815abd5de43cc,
    0x9fc05998d294daed,
    0x673349cfbecba2d2,
    0x55519054f1f6e72c,
    0x17a401925551128a,
    0xb6da6ace83af87e2,
    0xc44c4fef6f0342ba,
];
