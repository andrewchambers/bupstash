use serde::{Deserialize, Serialize};
use std::io::Write;

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VersionedIndexEntry {
    V1(IndexEntry),
}

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
    pub dev: serde_bare::Uint,
    pub ino: serde_bare::Uint,
    pub nlink: serde_bare::Uint,
    pub link_target: Option<String>,
    pub dev_major: serde_bare::Uint,
    pub dev_minor: serde_bare::Uint,
    pub xattrs: Option<std::collections::BTreeMap<String, Vec<u8>>>,
    pub offsets: IndexEntryOffsets,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct IndexEntryOffsets {
    pub data_chunk_idx: serde_bare::Uint,
    pub data_chunk_end_idx: serde_bare::Uint,
    pub data_chunk_offset: serde_bare::Uint,
    pub data_chunk_end_offset: serde_bare::Uint,
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
            Ok(VersionedIndexEntry::V1(ent)) => Some(Ok(ent)),
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
        self.encoder.write(&[0]).unwrap();
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
