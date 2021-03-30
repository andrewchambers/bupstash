use serde::{Deserialize, Serialize};
use std::io::Write;

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VersionedIndexEntry {
    V1(V1IndexEntry),
    V2(IndexEntry),
}

const CURRENT_INDEX_ENTRY_KIND: u8 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum IndexEntryKind {
    Other,
    Regular,
    Symlink,
    Char,
    Block,
    Directory,
    Fifo,
}

// Deprecated format kept for backwards compatibility.
// Was deprecated to add support for adding checksums
// for individual files. This is an important feature
// for snapshot diffs as well as bandwidth efficient restore.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct V1IndexEntry {
    pub path: String,
    pub mode: serde_bare::Uint,
    pub size: serde_bare::Uint,
    pub uid: serde_bare::Uint,
    pub gid: serde_bare::Uint,
    pub mtime: serde_bare::Uint,
    pub mtime_nsec: serde_bare::Uint,
    pub ctime: serde_bare::Uint,
    pub ctime_nsec: serde_bare::Uint,
    pub dev: serde_bare::Uint,
    pub ino: serde_bare::Uint,
    pub nlink: serde_bare::Uint,
    pub link_target: Option<String>,
    pub dev_major: serde_bare::Uint,
    pub dev_minor: serde_bare::Uint,
    pub xattrs: Option<std::collections::BTreeMap<String, Vec<u8>>>,
    pub offsets: IndexEntryOffsets,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IndexEntry {
    pub path: String,
    pub mode: serde_bare::Uint,
    pub size: serde_bare::Uint,
    pub uid: serde_bare::Uint,
    pub gid: serde_bare::Uint,
    pub mtime: serde_bare::Uint,
    pub mtime_nsec: serde_bare::Uint,
    pub ctime: serde_bare::Uint,
    pub ctime_nsec: serde_bare::Uint,
    pub norm_dev: serde_bare::Uint,
    pub ino: serde_bare::Uint,
    pub nlink: serde_bare::Uint,
    pub link_target: Option<String>,
    pub dev_major: serde_bare::Uint,
    pub dev_minor: serde_bare::Uint,
    pub xattrs: Option<std::collections::BTreeMap<String, Vec<u8>>>,
    pub offsets: IndexEntryOffsets,
    pub data_hash: ContentCryptoHash,
}

// We can add more masks as needed.
pub const INDEX_COMPARE_MASK_MODE: u64 = 1 << 0;
pub const INDEX_COMPARE_MASK_SIZE: u64 = 1 << 1;
pub const INDEX_COMPARE_MASK_DATA_HASH: u64 = 1 << 2;
pub const INDEX_COMPARE_MASK_MTIME: u64 = 1 << 3;
pub const INDEX_COMPARE_MASK_CTIME: u64 = 1 << 4;
pub const INDEX_COMPARE_MASK_DEV: u64 = 1 << 5;
pub const INDEX_COMPARE_MASK_UID: u64 = 1 << 6;
pub const INDEX_COMPARE_MASK_GID: u64 = 1 << 7;
pub const INDEX_COMPARE_MASK_INO: u64 = 1 << 8;
pub const INDEX_COMPARE_MASK_NLINK: u64 = 1 << 9;
pub const INDEX_COMPARE_MASK_LINK_TARGET: u64 = 1 << 10;
pub const INDEX_COMPARE_MASK_DEV_NUMS: u64 = 1 << 11;
pub const INDEX_COMPARE_MASK_XATTRS: u64 = 1 << 12;
pub const INDEX_COMPARE_MASK_OFFSETS: u64 = 1 << 13;

impl IndexEntry {
    pub fn masked_compare_eq(&self, compare_mask: u64, other: &Self) -> bool {
        self.path == other.path
            && ((compare_mask & INDEX_COMPARE_MASK_MODE != 0) || self.mode == other.mode)
            && ((compare_mask & INDEX_COMPARE_MASK_SIZE != 0) || self.size == other.size)
            && ((compare_mask & INDEX_COMPARE_MASK_DATA_HASH != 0)
                || self.data_hash == other.data_hash)
            && ((compare_mask & INDEX_COMPARE_MASK_UID != 0) || self.uid == other.uid)
            && ((compare_mask & INDEX_COMPARE_MASK_GID != 0) || self.gid == other.gid)
            && ((compare_mask & INDEX_COMPARE_MASK_MTIME != 0)
                || (self.mtime == other.mtime && self.mtime_nsec == other.mtime_nsec))
            && ((compare_mask & INDEX_COMPARE_MASK_CTIME != 0)
                || (self.ctime == other.ctime && self.ctime_nsec == other.ctime_nsec))
            && ((compare_mask & INDEX_COMPARE_MASK_DEV != 0) || self.norm_dev == other.norm_dev)
            && ((compare_mask & INDEX_COMPARE_MASK_XATTRS != 0) || self.xattrs == other.xattrs)
            && ((compare_mask & INDEX_COMPARE_MASK_INO != 0) || self.ino == other.ino)
            && ((compare_mask & INDEX_COMPARE_MASK_NLINK != 0) || self.nlink == other.nlink)
            && ((compare_mask & INDEX_COMPARE_MASK_LINK_TARGET != 0)
                || self.link_target == other.link_target)
            && ((compare_mask & INDEX_COMPARE_MASK_DEV_NUMS != 0)
                || (self.dev_major == other.dev_major && self.dev_minor == other.dev_minor))
            && ((compare_mask & INDEX_COMPARE_MASK_OFFSETS != 0) || self.offsets == other.offsets)
    }
}

// Migration path from index entry without hash.
impl From<V1IndexEntry> for IndexEntry {
    fn from(ent: V1IndexEntry) -> Self {
        IndexEntry {
            path: ent.path,
            mode: ent.mode,
            size: ent.size,
            uid: ent.uid,
            gid: ent.gid,
            mtime: ent.mtime,
            mtime_nsec: ent.mtime_nsec,
            ctime: ent.ctime,
            ctime_nsec: ent.ctime_nsec,
            norm_dev: ent.dev,
            ino: ent.ino,
            nlink: ent.nlink,
            link_target: ent.link_target,
            dev_major: ent.dev_major,
            dev_minor: ent.dev_minor,
            xattrs: ent.xattrs,
            offsets: ent.offsets,
            data_hash: ContentCryptoHash::None,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub struct IndexEntryOffsets {
    pub data_chunk_idx: serde_bare::Uint,
    pub data_chunk_end_idx: serde_bare::Uint,
    pub data_chunk_offset: serde_bare::Uint,
    pub data_chunk_end_offset: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum ContentCryptoHash {
    None,
    Blake3([u8; 32]),
}

impl IndexEntry {
    pub fn kind(&self) -> IndexEntryKind {
        match self.mode.0 as libc::mode_t & libc::S_IFMT {
            libc::S_IFREG => IndexEntryKind::Regular,
            libc::S_IFLNK => IndexEntryKind::Symlink,
            libc::S_IFCHR => IndexEntryKind::Char,
            libc::S_IFBLK => IndexEntryKind::Block,
            libc::S_IFDIR => IndexEntryKind::Directory,
            libc::S_IFIFO => IndexEntryKind::Fifo,
            _ => IndexEntryKind::Other,
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self.mode.0 as libc::mode_t & libc::S_IFMT, libc::S_IFREG)
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.mode.0 as libc::mode_t & libc::S_IFMT, libc::S_IFDIR)
    }

    pub fn display_mode(&self) -> String {
        let mode = self.mode.0 as libc::mode_t;

        let mut result = String::with_capacity(10);

        result.push(match self.kind() {
            IndexEntryKind::Other => '?',
            IndexEntryKind::Regular => '-',
            IndexEntryKind::Symlink => 'l',
            IndexEntryKind::Char => 'c',
            IndexEntryKind::Block => 'b',
            IndexEntryKind::Directory => 'd',
            IndexEntryKind::Fifo => 'p',
        });
        result.push(if (mode & libc::S_IRUSR) != 0 {
            'r'
        } else {
            '-'
        });
        result.push(if (mode & libc::S_IWUSR) != 0 {
            'w'
        } else {
            '-'
        });
        result.push(if (mode & libc::S_ISUID) != 0 {
            if (mode & libc::S_IXUSR) != 0 {
                's'
            } else {
                'S'
            }
        } else if (mode & libc::S_IXUSR) != 0 {
            'x'
        } else {
            '-'
        });

        result.push(if (mode & libc::S_IRGRP) != 0 {
            'r'
        } else {
            '-'
        });
        result.push(if (mode & libc::S_IWGRP) != 0 {
            'w'
        } else {
            '-'
        });
        result.push(if (mode & libc::S_ISGID) != 0 {
            if (mode & libc::S_IXGRP) != 0 {
                's'
            } else {
                'S'
            }
        } else if (mode & libc::S_IXGRP) != 0 {
            'x'
        } else {
            '-'
        });

        result.push(if (mode & libc::S_IROTH) != 0 {
            'r'
        } else {
            '-'
        });
        result.push(if (mode & libc::S_IWOTH) != 0 {
            'w'
        } else {
            '-'
        });
        result.push(if (mode & libc::S_ISVTX) != 0 {
            if (mode & libc::S_IXOTH) != 0 {
                't'
            } else {
                'T'
            }
        } else if (mode & libc::S_IXOTH) != 0 {
            'x'
        } else {
            '-'
        });

        result
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HTreeDataRange {
    pub start_idx: serde_bare::Uint,
    pub end_idx: serde_bare::Uint,
}

pub struct PickMap {
    pub is_subtar: bool,
    pub data_chunk_ranges: Vec<HTreeDataRange>,
    pub incomplete_data_chunks: std::collections::HashMap<u64, rangemap::RangeSet<usize>>,
    pub index: CompressedIndex,
}

pub fn pick(path: &str, index: &CompressedIndex) -> Result<PickMap, anyhow::Error> {
    let mut iter = index.iter();
    while let Some(ent) = iter.next() {
        let ent = ent?;

        if ent.path != path {
            continue;
        }

        match ent.kind() {
            IndexEntryKind::Directory => {
                let prefix = if ent.path == "." {
                    "".to_string()
                } else {
                    format!("{}/", ent.path)
                };

                let mut data_chunk_ranges: Vec<HTreeDataRange> = Vec::new();
                let mut incomplete_data_chunks: std::collections::HashMap<
                    u64,
                    rangemap::RangeSet<usize>,
                > = std::collections::HashMap::new();

                let mut sub_index_writer = CompressedIndexWriter::new();
                sub_index_writer.add(&ent);

                for ent in iter {
                    let ent = ent?;

                    // Match the directory and its children.
                    if !ent.path.starts_with(&prefix) {
                        continue;
                    }

                    sub_index_writer.add(&ent);

                    if ent.size.0 == 0 {
                        continue;
                    }

                    // Either coalesce the existing range or insert a new range.
                    if !data_chunk_ranges.is_empty()
                        && ((data_chunk_ranges.last().unwrap().end_idx
                            == ent.offsets.data_chunk_idx)
                            || (data_chunk_ranges.last().unwrap().end_idx.0 + 1
                                == ent.offsets.data_chunk_idx.0))
                    {
                        data_chunk_ranges.last_mut().unwrap().end_idx =
                            ent.offsets.data_chunk_end_idx
                    } else {
                        data_chunk_ranges.push(HTreeDataRange {
                            start_idx: ent.offsets.data_chunk_idx,
                            end_idx: ent.offsets.data_chunk_end_idx,
                        })
                    }

                    if ent.offsets.data_chunk_idx == ent.offsets.data_chunk_end_idx {
                        let range = ent.offsets.data_chunk_offset.0 as usize
                            ..ent.offsets.data_chunk_end_offset.0 as usize;

                        match incomplete_data_chunks.get_mut(&ent.offsets.data_chunk_idx.0) {
                            Some(range_set) => {
                                range_set.insert(range);
                            }
                            None => {
                                let mut range_set = rangemap::RangeSet::new();
                                range_set.insert(range);
                                incomplete_data_chunks
                                    .insert(ent.offsets.data_chunk_idx.0, range_set);
                            }
                        }
                    } else {
                        let start_range = ent.offsets.data_chunk_offset.0 as usize..usize::MAX;
                        let end_range = 0..ent.offsets.data_chunk_end_offset.0 as usize;

                        match incomplete_data_chunks.get_mut(&ent.offsets.data_chunk_idx.0) {
                            Some(range_set) => {
                                range_set.insert(start_range);
                            }
                            None => {
                                let mut range_set = rangemap::RangeSet::new();
                                range_set.insert(start_range);
                                incomplete_data_chunks
                                    .insert(ent.offsets.data_chunk_idx.0, range_set);
                            }
                        }

                        if ent.offsets.data_chunk_end_offset.0 != 0 {
                            let mut range_set = rangemap::RangeSet::new();
                            range_set.insert(end_range);
                            let old = incomplete_data_chunks
                                .insert(ent.offsets.data_chunk_end_idx.0, range_set);

                            // Because our end chunk is a never before seen index, this
                            // range set must be none.
                            assert!(ent.offsets.data_chunk_idx != ent.offsets.data_chunk_end_idx);
                            assert!(old.is_none());
                        } else {
                            data_chunk_ranges.last_mut().unwrap().end_idx.0 -= 1;
                        }
                    }
                }

                return Ok(PickMap {
                    is_subtar: true,
                    data_chunk_ranges,
                    incomplete_data_chunks,
                    index: sub_index_writer.finish(),
                });
            }
            IndexEntryKind::Regular => {
                let mut incomplete_data_chunks = std::collections::HashMap::new();

                let mut sub_index_writer = CompressedIndexWriter::new();
                sub_index_writer.add(&ent);
                let sub_index = sub_index_writer.finish();

                if ent.size.0 == 0 {
                    return Ok(PickMap {
                        is_subtar: false,
                        data_chunk_ranges: vec![],
                        index: sub_index,
                        incomplete_data_chunks,
                    });
                }

                let mut range_adjust = 0;

                if ent.offsets.data_chunk_idx == ent.offsets.data_chunk_end_idx {
                    let mut range_set = rangemap::RangeSet::new();

                    range_set.insert(
                        ent.offsets.data_chunk_offset.0 as usize
                            ..ent.offsets.data_chunk_end_offset.0 as usize,
                    );

                    incomplete_data_chunks.insert(ent.offsets.data_chunk_idx.0, range_set);
                } else {
                    let mut start_range_set = rangemap::RangeSet::new();
                    start_range_set.insert(ent.offsets.data_chunk_offset.0 as usize..usize::MAX);

                    incomplete_data_chunks.insert(ent.offsets.data_chunk_idx.0, start_range_set);

                    if ent.offsets.data_chunk_end_offset.0 != 0 {
                        let mut end_range_set = rangemap::RangeSet::new();
                        end_range_set.insert(0..ent.offsets.data_chunk_end_offset.0 as usize);

                        incomplete_data_chunks
                            .insert(ent.offsets.data_chunk_end_idx.0, end_range_set);
                    } else {
                        range_adjust = 1;
                    }
                }

                return Ok(PickMap {
                    is_subtar: false,
                    data_chunk_ranges: vec![HTreeDataRange {
                        start_idx: ent.offsets.data_chunk_idx,
                        end_idx: serde_bare::Uint(ent.offsets.data_chunk_end_idx.0 - range_adjust),
                    }],
                    incomplete_data_chunks,
                    index: sub_index,
                });
            }
            kind => anyhow::bail!(
                "unable to pick {} - unsupported directory entry type: {:?}",
                path,
                kind
            ),
        }
    }

    anyhow::bail!("{} not found in content index", path)
}

// The index can get huge when we have millions of files, so we use a compressed index in memory.
pub struct CompressedIndex {
    compressed_ents: Vec<u8>,
}

impl CompressedIndex {
    pub fn from_vec(compressed_ents: Vec<u8>) -> Self {
        CompressedIndex { compressed_ents }
    }

    pub fn iter(&self) -> CompressedIndexIterator {
        CompressedIndexIterator {
            reader: lz4::Decoder::new(std::io::Cursor::new(&self.compressed_ents)).unwrap(),
        }
    }
}

pub struct CompressedIndexIterator<'a> {
    reader: lz4::Decoder<std::io::Cursor<&'a Vec<u8>>>,
}

impl<'a> Iterator for CompressedIndexIterator<'a> {
    type Item = Result<IndexEntry, anyhow::Error>;

    fn next(&mut self) -> Option<Result<IndexEntry, anyhow::Error>> {
        match serde_bare::from_reader(&mut self.reader) {
            Ok(VersionedIndexEntry::V1(ent)) => Some(Ok(ent.into())),
            Ok(VersionedIndexEntry::V2(ent)) => Some(Ok(ent)),
            Err(serde_bare::error::Error::Io(err))
                if err.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                None
            }
            Err(err) => Some(Err(err.into())),
        }
    }
}

pub struct CompressedIndexWriter {
    encoder: lz4::Encoder<std::io::Cursor<Vec<u8>>>,
}

impl CompressedIndexWriter {
    pub fn new() -> Self {
        CompressedIndexWriter {
            encoder: lz4::EncoderBuilder::new()
                .checksum(lz4::ContentChecksum::NoChecksum)
                .build(std::io::Cursor::new(Vec::new()))
                .unwrap(),
        }
    }

    pub fn add(&mut self, ent: &IndexEntry) {
        // Manually write BARE kind so we don't need to copy the ent.
        self.encoder.write_all(&[CURRENT_INDEX_ENTRY_KIND]).unwrap();
        self.encoder
            .write_all(&serde_bare::to_vec(ent).unwrap())
            .unwrap();
    }

    pub fn finish(self) -> CompressedIndex {
        let (index_cursor, compress_result) = self.encoder.finish();
        compress_result.unwrap();
        CompressedIndex::from_vec(index_cursor.into_inner())
    }
}

impl Default for CompressedIndexWriter {
    fn default() -> Self {
        CompressedIndexWriter::new()
    }
}

pub fn path_cmp(l: &str, r: &str) -> std::cmp::Ordering {
    // This sort order is aimed at creating better compression while creating a sensible
    // order within the backup archives.
    //
    // '.' is always first.
    // Tar entries with fewer slashes come next.
    // Finally compare lexically.
    //
    // Experiments with sorting priority based on file extension did not show
    // any consistent or measurable improvement, we could revisit in the future.
    if l == r {
        std::cmp::Ordering::Equal
    } else if l == "." {
        std::cmp::Ordering::Greater
    } else if r == "." {
        std::cmp::Ordering::Less
    } else if l.chars().filter(|c| *c == '/').count() < r.chars().filter(|c| *c == '/').count() {
        std::cmp::Ordering::Greater
    } else {
        l.cmp(r)
    }
}

pub fn diff(
    left_index: &CompressedIndex,
    right_index: &CompressedIndex,
    compare_mask: u64,
    on_diff_ent: &mut dyn FnMut(char, &IndexEntry) -> Result<(), anyhow::Error>,
) -> Result<(), anyhow::Error> {
    let mut liter = left_index.iter();
    let mut riter = right_index.iter();
    let mut lent = liter.next();
    let mut rent = riter.next();

    while lent.is_some() && rent.is_some() {
        let l = lent.as_ref().unwrap().as_ref().unwrap();
        let r = rent.as_ref().unwrap().as_ref().unwrap();
        match path_cmp(&l.path, &r.path) {
            std::cmp::Ordering::Equal => {
                if !l.masked_compare_eq(compare_mask, r) {
                    on_diff_ent('-', l)?;
                    on_diff_ent('+', r)?;
                }
                lent = liter.next();
                rent = riter.next();
            }
            std::cmp::Ordering::Less => {
                on_diff_ent('-', l)?;
                lent = liter.next();
            }
            std::cmp::Ordering::Greater => {
                on_diff_ent('+', r)?;
                rent = riter.next();
            }
        }
    }
    while lent.is_some() {
        let l = lent.unwrap().unwrap();
        on_diff_ent('-', &l)?;
        lent = liter.next();
    }
    while rent.is_some() {
        let r = rent.unwrap().unwrap();
        on_diff_ent('+', &r)?;
        rent = riter.next();
    }
    Ok(())
}
