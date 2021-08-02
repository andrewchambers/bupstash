use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

pub type Xattrs = BTreeMap<String, Vec<u8>>;

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VersionedIndexEntry {
    V1(V1IndexEntry),
    V2(V2IndexEntry),
    V3(IndexEntry),
}

const CURRENT_INDEX_ENTRY_KIND: u8 = 2;

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

impl IndexEntryKind {
    pub fn is_file(&self) -> bool {
        matches!(self, IndexEntryKind::Regular)
    }
    pub fn is_dir(&self) -> bool {
        matches!(self, IndexEntryKind::Directory)
    }
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
    pub xattrs: Option<Xattrs>,
    pub data_cursor: AbsoluteDataCursor,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct V2IndexEntry {
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
    pub xattrs: Option<Xattrs>,
    pub data_cursor: AbsoluteDataCursor,
    pub data_hash: ContentCryptoHash,
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
    pub xattrs: Option<Xattrs>,
    pub data_cursor: RelativeDataCursor,
    pub data_hash: ContentCryptoHash,
}

// We can add more masks as needed.
pub const INDEX_COMPARE_MASK_TYPE: u64 = 1 << 0;
pub const INDEX_COMPARE_MASK_PERMS: u64 = 1 << 1;
pub const INDEX_COMPARE_MASK_SIZE: u64 = 1 << 2;
pub const INDEX_COMPARE_MASK_DATA_HASH: u64 = 1 << 3;
pub const INDEX_COMPARE_MASK_MTIME: u64 = 1 << 4;
pub const INDEX_COMPARE_MASK_CTIME: u64 = 1 << 5;
pub const INDEX_COMPARE_MASK_DEV: u64 = 1 << 6;
pub const INDEX_COMPARE_MASK_UID: u64 = 1 << 7;
pub const INDEX_COMPARE_MASK_GID: u64 = 1 << 8;
pub const INDEX_COMPARE_MASK_INO: u64 = 1 << 9;
pub const INDEX_COMPARE_MASK_NLINK: u64 = 1 << 10;
pub const INDEX_COMPARE_MASK_LINK_TARGET: u64 = 1 << 11;
pub const INDEX_COMPARE_MASK_DEVNOS: u64 = 1 << 12;
pub const INDEX_COMPARE_MASK_XATTRS: u64 = 1 << 13;
pub const INDEX_COMPARE_MASK_DATA_CURSORS: u64 = 1 << 14;

impl IndexEntry {
    pub fn masked_compare_eq(&self, compare_mask: u64, other: &Self) -> bool {
        self.path == other.path
            && ((compare_mask & INDEX_COMPARE_MASK_TYPE != 0)
                || (self.mode.0 as libc::mode_t & libc::S_IFMT)
                    == (other.mode.0 as libc::mode_t & libc::S_IFMT))
            && ((compare_mask & INDEX_COMPARE_MASK_PERMS != 0)
                || (self.mode.0 as libc::mode_t & !libc::S_IFMT)
                    == (other.mode.0 as libc::mode_t & !libc::S_IFMT))
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
            && ((compare_mask & INDEX_COMPARE_MASK_DEVNOS != 0)
                || (self.dev_major == other.dev_major && self.dev_minor == other.dev_minor))
            && ((compare_mask & INDEX_COMPARE_MASK_DATA_CURSORS != 0)
                || self.data_cursor == other.data_cursor)
    }
}

// Deprecated, kept around for backwards compatibility.
// It was a mistake to keep absolute data cursors as they
// encode the entry position which degrades deduplication.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub struct AbsoluteDataCursor {
    pub chunk_start_idx: serde_bare::Uint,
    pub chunk_end_idx: serde_bare::Uint,
    pub start_byte_offset: serde_bare::Uint,
    pub end_byte_offset: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub struct RelativeDataCursor {
    pub chunk_delta: serde_bare::Uint,
    pub start_byte_offset: serde_bare::Uint,
    pub end_byte_offset: serde_bare::Uint,
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

    pub fn is_symlink(&self) -> bool {
        (self.mode.0 as libc::mode_t & libc::S_IFMT) == libc::S_IFLNK
    }

    pub fn is_file(&self) -> bool {
        (self.mode.0 as libc::mode_t & libc::S_IFMT) == libc::S_IFREG
    }

    pub fn is_dir(&self) -> bool {
        (self.mode.0 as libc::mode_t & libc::S_IFMT) == libc::S_IFDIR
    }

    pub fn is_dev_node(&self) -> bool {
        (self.mode.0 as libc::mode_t & libc::S_IFMT) == libc::S_IFBLK
            || (self.mode.0 as libc::mode_t & libc::S_IFMT) == libc::S_IFCHR
    }

    pub fn type_display_char(&self) -> char {
        match self.kind() {
            IndexEntryKind::Other => '?',
            IndexEntryKind::Regular => 'f',
            IndexEntryKind::Symlink => 'l',
            IndexEntryKind::Char => 'c',
            IndexEntryKind::Block => 'b',
            IndexEntryKind::Directory => 'd',
            IndexEntryKind::Fifo => 'p',
        }
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

#[derive(Debug)]
pub struct DataMap {
    pub data_chunk_ranges: Vec<HTreeDataRange>,
    pub incomplete_data_chunks: HashMap<u64, rangemap::RangeSet<usize>>,
}

fn add_ent_to_data_map(
    ent: &IndexEntry,
    cur_chunk_idx: u64,
    data_chunk_ranges: &mut Vec<HTreeDataRange>,
    incomplete_data_chunks: &mut HashMap<u64, rangemap::RangeSet<usize>>,
) {
    if ent.size.0 == 0 {
        return;
    }
    // Either coalesce the existing range or insert a new range.
    if !data_chunk_ranges.is_empty()
        && ((data_chunk_ranges.last().unwrap().end_idx.0 == cur_chunk_idx)
            || (data_chunk_ranges.last().unwrap().end_idx.0 + 1 == cur_chunk_idx))
    {
        data_chunk_ranges.last_mut().unwrap().end_idx.0 =
            cur_chunk_idx + ent.data_cursor.chunk_delta.0
    } else {
        data_chunk_ranges.push(HTreeDataRange {
            start_idx: serde_bare::Uint(cur_chunk_idx),
            end_idx: serde_bare::Uint(cur_chunk_idx + ent.data_cursor.chunk_delta.0),
        })
    }

    if ent.data_cursor.chunk_delta.0 == 0 {
        let range = ent.data_cursor.start_byte_offset.0 as usize
            ..ent.data_cursor.end_byte_offset.0 as usize;

        match incomplete_data_chunks.get_mut(&cur_chunk_idx) {
            Some(range_set) => {
                range_set.insert(range);
            }
            None => {
                let mut range_set = rangemap::RangeSet::new();
                range_set.insert(range);
                incomplete_data_chunks.insert(cur_chunk_idx, range_set);
            }
        }
    } else {
        let start_range = ent.data_cursor.start_byte_offset.0 as usize..usize::MAX;
        let end_range = 0..ent.data_cursor.end_byte_offset.0 as usize;

        match incomplete_data_chunks.get_mut(&cur_chunk_idx) {
            Some(range_set) => {
                range_set.insert(start_range);
            }
            None => {
                let mut range_set = rangemap::RangeSet::new();
                range_set.insert(start_range);
                incomplete_data_chunks.insert(cur_chunk_idx, range_set);
            }
        }

        if ent.data_cursor.end_byte_offset.0 != 0 {
            let mut range_set = rangemap::RangeSet::new();
            range_set.insert(end_range);
            let old = incomplete_data_chunks
                .insert(cur_chunk_idx + ent.data_cursor.chunk_delta.0, range_set);
            // Because our end chunk is a never before seen index, this
            // range set must be none.
            assert!(old.is_none());
        } else {
            data_chunk_ranges.last_mut().unwrap().end_idx.0 -= 1;
        }
    }

    if let Some(range_set) = incomplete_data_chunks.get(&cur_chunk_idx) {
        if let Some(range) = range_set.get(&(usize::MAX - 1)) {
            if range.start == 0 {
                // The range completely covers the chunk, it is no longer incomplete.
                incomplete_data_chunks.remove(&cur_chunk_idx);
            }
        }
    }
}

pub fn data_map_for_predicate(
    file_index: &CompressedIndex,
    predicate: &dyn Fn(&IndexEntry) -> bool,
) -> Result<DataMap, anyhow::Error> {
    let mut cur_chunk_idx = 0;
    let mut data_chunk_ranges: Vec<HTreeDataRange> = Vec::new();
    let mut incomplete_data_chunks: HashMap<u64, rangemap::RangeSet<usize>> = HashMap::new();

    for ent in file_index.iter() {
        let ent = ent?;
        // Post 1.0 we could perhaps be able to remove this check.
        if ent.data_cursor.chunk_delta.0 == u64::MAX {
            anyhow::bail!("this index was created by an older version of bupstash and we longer supports pick operations on it due to an unfortunate bug");
        }
        if predicate(&ent) {
            add_ent_to_data_map(
                &ent,
                cur_chunk_idx,
                &mut data_chunk_ranges,
                &mut incomplete_data_chunks,
            );
        }
        cur_chunk_idx += ent.data_cursor.chunk_delta.0;
    }
    Ok(DataMap {
        data_chunk_ranges,
        incomplete_data_chunks,
    })
}

pub fn pick(
    path: &str,
    file_index: &CompressedIndex,
) -> Result<(Option<CompressedIndex>, DataMap), anyhow::Error> {
    let mut cur_chunk_idx = 0;
    let mut iter = file_index.iter();

    while let Some(ent) = iter.next() {
        let mut ent = ent?;

        // Post 1.0 we could perhaps be able to remove this check.
        if ent.data_cursor.chunk_delta.0 == u64::MAX {
            anyhow::bail!("this index was created by an older version of bupstash and we longer supports pick operations on it due to an unfortunate bug");
        }

        if ent.path == path {
            match ent.kind() {
                IndexEntryKind::Directory => {
                    let mut data_chunk_ranges: Vec<HTreeDataRange> = Vec::new();
                    let mut incomplete_data_chunks: HashMap<u64, rangemap::RangeSet<usize>> =
                        HashMap::new();

                    let mut sub_index_writer = CompressedIndexWriter::new();

                    ent.path = ".".to_string();
                    sub_index_writer.add(&ent);

                    let strip_prefix = if path == "." {
                        "".to_string()
                    } else {
                        format!("{}/", path)
                    };

                    cur_chunk_idx += ent.data_cursor.chunk_delta.0;

                    let mut found_children = false;

                    for ent in iter {
                        let mut ent = ent?;

                        // Match the directory and children.
                        if !ent.path.starts_with(&strip_prefix) {
                            cur_chunk_idx += ent.data_cursor.chunk_delta.0;
                            if found_children {
                                // We have processed all children, exit early.
                                break;
                            } else {
                                // We are still skipping the dir siblings and their children.
                                continue;
                            }
                        }
                        found_children = true;

                        ent.path = ent.path[strip_prefix.len()..].to_string();

                        sub_index_writer.add(&ent);

                        add_ent_to_data_map(
                            &ent,
                            cur_chunk_idx,
                            &mut data_chunk_ranges,
                            &mut incomplete_data_chunks,
                        );

                        cur_chunk_idx += ent.data_cursor.chunk_delta.0;
                    }

                    return Ok((
                        Some(sub_index_writer.finish()),
                        DataMap {
                            data_chunk_ranges,
                            incomplete_data_chunks,
                        },
                    ));
                }
                IndexEntryKind::Regular => {
                    let mut data_chunk_ranges: Vec<HTreeDataRange> = Vec::new();
                    let mut incomplete_data_chunks: HashMap<u64, rangemap::RangeSet<usize>> =
                        HashMap::new();

                    add_ent_to_data_map(
                        &ent,
                        cur_chunk_idx,
                        &mut data_chunk_ranges,
                        &mut incomplete_data_chunks,
                    );

                    return Ok((
                        None,
                        DataMap {
                            data_chunk_ranges,
                            incomplete_data_chunks,
                        },
                    ));
                }
                kind => anyhow::bail!(
                    "unable to pick {} - unsupported directory entry type: {:?}",
                    path,
                    kind
                ),
            }
        }

        cur_chunk_idx += ent.data_cursor.chunk_delta.0;
    }
    anyhow::bail!("{} not found in content index", path)
}

pub fn pick_dir_without_data(
    path: &str,
    file_index: &CompressedIndex,
) -> Result<CompressedIndex, anyhow::Error> {
    let mut iter = file_index.iter();
    while let Some(ent) = iter.next() {
        let mut ent = ent?;
        // Post 1.0 we could perhaps be able to remove this check.
        if ent.data_cursor.chunk_delta.0 == u64::MAX {
            anyhow::bail!("this index was created by an older version of bupstash and we longer supports pick operations on it due to an unfortunate bug");
        }
        if ent.path != path {
            continue;
        }
        match ent.kind() {
            IndexEntryKind::Directory => {
                let mut sub_index_writer = CompressedIndexWriter::new();
                ent.path = ".".to_string();
                sub_index_writer.add(&ent);

                let strip_prefix = if path == "." {
                    "".to_string()
                } else {
                    format!("{}/", path)
                };

                for ent in iter {
                    let mut ent = ent?;
                    if !ent.path.starts_with(&strip_prefix) {
                        continue;
                    }
                    ent.path = ent.path[strip_prefix.len()..].to_string();
                    sub_index_writer.add(&ent);
                }
                return Ok(sub_index_writer.finish());
            }
            _ => anyhow::bail!(
                "unable to pick {} in this context, it is not a directory",
                path,
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

    pub fn compressed_size(&self) -> usize {
        self.compressed_ents.len()
    }
}

pub struct CompressedIndexIterator<'a> {
    reader: lz4::Decoder<std::io::Cursor<&'a Vec<u8>>>,
}

impl<'a> Iterator for CompressedIndexIterator<'a> {
    type Item = Result<IndexEntry, anyhow::Error>;

    fn next(&mut self) -> Option<Result<IndexEntry, anyhow::Error>> {
        match serde_bare::from_reader(&mut self.reader) {
            Ok(VersionedIndexEntry::V1(ent)) => Some(Ok(IndexEntry {
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
                data_cursor: RelativeDataCursor {
                    chunk_delta: serde_bare::Uint(u64::MAX),
                    start_byte_offset: serde_bare::Uint(u64::MAX),
                    end_byte_offset: serde_bare::Uint(u64::MAX),
                },
                data_hash: ContentCryptoHash::None,
            })),
            Ok(VersionedIndexEntry::V2(ent)) => Some(Ok(IndexEntry {
                path: ent.path,
                mode: ent.mode,
                size: ent.size,
                uid: ent.uid,
                gid: ent.gid,
                mtime: ent.mtime,
                mtime_nsec: ent.mtime_nsec,
                ctime: ent.ctime,
                ctime_nsec: ent.ctime_nsec,
                norm_dev: ent.norm_dev,
                ino: ent.ino,
                nlink: ent.nlink,
                link_target: ent.link_target,
                dev_major: ent.dev_major,
                dev_minor: ent.dev_minor,
                xattrs: ent.xattrs,
                data_cursor: RelativeDataCursor {
                    chunk_delta: serde_bare::Uint(u64::MAX),
                    start_byte_offset: serde_bare::Uint(u64::MAX),
                    end_byte_offset: serde_bare::Uint(u64::MAX),
                },
                data_hash: ent.data_hash,
            })),
            Ok(VersionedIndexEntry::V3(ent)) => Some(Ok(ent)),
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
    // This path comparison is designed such that our
    // 'put' indexer always produces lists of files that are
    // sorted according to it's order. This lets our diff
    // assume they are sorted.
    //
    // '.' is always first.
    // Children directories always come after parents.
    // However, importantly, 'uncles and aunties' come before 'neices and nephews'
    //
    // As an example, here is an ordering:
    // a/b, a/c, a/b/c, a/c/c
    //
    // a/c comes before a/b/c because a/c is a sibling to a/b.
    //
    // This ordering makes sense when you know we store entries grouped by
    // directory, then walk to children in order.
    //
    // Note, we could consider sorting such a similar suffix is together, but
    // experiments with sorting priority based on file extension did not show
    // any consistent or measurable improvement, we could revisit in the future.
    use std::cmp::Ordering::*;
    if l == r {
        Equal
    } else if l == "." {
        Less
    } else if r == "." {
        Greater
    } else {
        let mut liter = l.split('/');
        let mut riter = r.split('/');
        loop {
            match (liter.next(), riter.next()) {
                (Some(lelem), Some(relem)) => match lelem.cmp(relem) {
                    Equal => (),
                    Greater => match (liter.next(), riter.next()) {
                        (None, Some(_)) => return Less,
                        _ => return Greater,
                    },
                    Less => match (liter.next(), riter.next()) {
                        (Some(_), None) => return Greater,
                        _ => return Less,
                    },
                },
                (Some(_), None) => return Greater,
                (None, Some(_)) => return Less,
                (None, None) => unreachable!(),
            }
        }
    }
}

pub enum DiffStat {
    Unchanged,
    Removed,
    Added,
}

pub fn diff(
    left_index: &CompressedIndex,
    right_index: &CompressedIndex,
    compare_mask: u64,
    on_diff_ent: &mut dyn FnMut(DiffStat, &IndexEntry) -> Result<(), anyhow::Error>,
) -> Result<(), anyhow::Error> {
    let mut liter = left_index.iter();
    let mut riter = right_index.iter();
    let mut lent = liter.next();
    let mut rent = riter.next();

    while lent.is_some() && rent.is_some() {
        let l = lent.as_ref().unwrap().as_ref().unwrap();
        let r = rent.as_ref().unwrap().as_ref().unwrap();

        // Post 1.0 we could perhaps be able to remove this check.
        if l.data_cursor.chunk_delta.0 == u64::MAX || r.data_cursor.chunk_delta.0 == u64::MAX {
            anyhow::bail!("index was created by an older version of bupstash and we longer supports diff operations on it due to an unfortunate bug");
        }

        match path_cmp(&l.path, &r.path) {
            std::cmp::Ordering::Equal => {
                if l.masked_compare_eq(compare_mask, r) {
                    on_diff_ent(DiffStat::Unchanged, r)?;
                } else {
                    on_diff_ent(DiffStat::Removed, l)?;
                    on_diff_ent(DiffStat::Added, r)?;
                }
                lent = liter.next();
                rent = riter.next();
            }
            std::cmp::Ordering::Less => {
                on_diff_ent(DiffStat::Removed, l)?;
                lent = liter.next();
            }
            std::cmp::Ordering::Greater => {
                on_diff_ent(DiffStat::Added, r)?;
                rent = riter.next();
            }
        }
    }
    while lent.is_some() {
        let l = lent.unwrap().unwrap();
        on_diff_ent(DiffStat::Removed, &l)?;
        lent = liter.next();
    }
    while rent.is_some() {
        let r = rent.unwrap().unwrap();
        on_diff_ent(DiffStat::Added, &r)?;
        rent = riter.next();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_path_cmp() {
        use std::cmp::Ordering::*;

        assert!(path_cmp(".", ".") == Equal);
        assert!(path_cmp(".", "a") == Less);
        assert!(path_cmp("a", ".") == Greater);
        assert!(path_cmp("a", "b/c/e") == Less);
        assert!(path_cmp("b/c/e", "a") == Greater);
        assert!(path_cmp("a", "b") == Less);
        assert!(path_cmp("a/b/c", "b") == Greater);
        assert!(path_cmp("a/b/c", "d/e") == Less);
        assert!(path_cmp("a/b/a", "a/b/c") == Less);
        assert!(path_cmp("a/b/c", "a/b/c") == Equal);
        assert!(path_cmp("b/a/d", "b/z") == Greater);
        assert!(path_cmp("b/z", "b/a/d",) == Less);
        assert!(path_cmp("b/z/d", "b/a/d") == Greater);
        assert!(path_cmp("b/a/d", "b/z/d") == Less);

        let mut v = vec![
            "a/x.txt",
            ".",
            "a/y",
            "b",
            "b/c/d",
            "b/derp.txt",
            "c/d/slurm",
        ];
        v.sort_by(|l, r| path_cmp(l, r));
        assert_eq!(
            v,
            vec![
                ".",
                "b",
                "a/x.txt",
                "a/y",
                "b/derp.txt",
                "b/c/d",
                "c/d/slurm",
            ]
        );
    }

    #[test]
    fn test_index_mode_bits() {
        // If there are platforms where these do not
        // line up we will need to translate to a canonical mode.
        assert!(libc::S_IFIFO == 4096);
        assert!(libc::S_IFCHR == 8192);
        assert!(libc::S_IFBLK == 24576);
        assert!(libc::S_IFDIR == 16384);
        assert!(libc::S_IFREG == 32768);
        assert!(libc::S_IFLNK == 40960);
        assert!(libc::S_IFSOCK == 49152);
        assert!(libc::S_IFMT == 61440);
        assert!(libc::S_IEXEC == 64);
        assert!(libc::S_IWRITE == 128);
        assert!(libc::S_IREAD == 256);
        assert!(libc::S_IRWXU == 448);
        assert!(libc::S_IXUSR == 64);
        assert!(libc::S_IWUSR == 128);
        assert!(libc::S_IRUSR == 256);
        assert!(libc::S_IRWXG == 56);
        assert!(libc::S_IXGRP == 8);
        assert!(libc::S_IWGRP == 16);
        assert!(libc::S_IRGRP == 32);
        assert!(libc::S_IRWXO == 7);
        assert!(libc::S_IXOTH == 1);
        assert!(libc::S_IWOTH == 2);
        assert!(libc::S_IROTH == 4);
    }
}
