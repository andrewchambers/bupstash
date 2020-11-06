use serde::{Deserialize, Serialize};

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
    pub tar_size: serde_bare::Uint,
    pub ctime: serde_bare::Uint,
    pub ctime_nsec: serde_bare::Uint,
    pub data_chunk_idx: serde_bare::Uint,
    pub data_chunk_content_idx: serde_bare::Uint,
    pub data_chunk_content_end_idx: serde_bare::Uint,
    pub data_chunk_end_idx: serde_bare::Uint,
    pub data_chunk_offset: serde_bare::Uint,
    pub data_chunk_content_offset: serde_bare::Uint,
    pub data_chunk_content_end_offset: serde_bare::Uint,
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
    pub start_idx: u64,
    pub end_idx: u64,
}

pub struct PickMap {
    pub is_subtar: bool,
    pub size: u64,
    pub data_chunk_ranges: Vec<HTreeDataRange>,
    pub incomplete_data_chunks: std::collections::HashMap<u64, rangemap::RangeSet<usize>>,
}

pub fn pick(path: &str, index: &[VersionedIndexEntry]) -> Result<PickMap, failure::Error> {
    for i in 0..index.len() {
        let VersionedIndexEntry::V1(ent) = &index[i];

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

                let mut size = 0;
                let mut data_chunk_ranges: Vec<HTreeDataRange> = Vec::new();
                let mut incomplete_data_chunks: std::collections::HashMap<
                    u64,
                    rangemap::RangeSet<usize>,
                > = std::collections::HashMap::new();

                for (j, VersionedIndexEntry::V1(ref ent)) in index.iter().enumerate().skip(i) {
                    // Match the directory and its children.
                    if !(j == i || ent.path.starts_with(&prefix)) {
                        continue;
                    }

                    size += ent.tar_size.0;

                    // Either coalesce the existing range or insert a new range.
                    if !data_chunk_ranges.is_empty()
                        && ((data_chunk_ranges.last().unwrap().end_idx == ent.data_chunk_idx.0)
                            || (data_chunk_ranges.last().unwrap().end_idx + 1
                                == ent.data_chunk_idx.0))
                    {
                        data_chunk_ranges.last_mut().unwrap().end_idx = ent.data_chunk_end_idx.0
                    } else {
                        data_chunk_ranges.push(HTreeDataRange {
                            start_idx: ent.data_chunk_idx.0,
                            end_idx: ent.data_chunk_end_idx.0,
                        })
                    }

                    if ent.data_chunk_idx == ent.data_chunk_end_idx {
                        let range =
                            ent.data_chunk_offset.0 as usize..ent.data_chunk_end_offset.0 as usize;

                        match incomplete_data_chunks.get_mut(&ent.data_chunk_idx.0) {
                            Some(range_set) => {
                                range_set.insert(range);
                            }
                            None => {
                                let mut range_set = rangemap::RangeSet::new();
                                range_set.insert(range);
                                incomplete_data_chunks.insert(ent.data_chunk_idx.0, range_set);
                            }
                        }
                    } else {
                        let start_range = ent.data_chunk_offset.0 as usize..usize::MAX;
                        let end_range = 0..ent.data_chunk_end_offset.0 as usize;

                        match incomplete_data_chunks.get_mut(&ent.data_chunk_idx.0) {
                            Some(range_set) => {
                                range_set.insert(start_range);
                            }
                            None => {
                                let mut range_set = rangemap::RangeSet::new();
                                range_set.insert(start_range);
                                incomplete_data_chunks.insert(ent.data_chunk_idx.0, range_set);
                            }
                        }

                        match incomplete_data_chunks.get_mut(&ent.data_chunk_end_idx.0) {
                            Some(range_set) => {
                                range_set.insert(end_range);
                            }
                            None => {
                                let mut range_set = rangemap::RangeSet::new();
                                range_set.insert(end_range);
                                incomplete_data_chunks.insert(ent.data_chunk_end_idx.0, range_set);
                            }
                        }
                    }
                }

                return Ok(PickMap {
                    is_subtar: true,
                    size,
                    data_chunk_ranges,
                    incomplete_data_chunks,
                });
            }
            IndexEntryKind::Regular => {
                let mut incomplete_data_chunks = std::collections::HashMap::new();

                if ent.data_chunk_content_idx == ent.data_chunk_content_end_idx {
                    let mut range_set = rangemap::RangeSet::new();

                    range_set.insert(
                        ent.data_chunk_content_offset.0 as usize
                            ..ent.data_chunk_content_end_offset.0 as usize,
                    );

                    incomplete_data_chunks.insert(ent.data_chunk_content_idx.0, range_set);
                } else {
                    let mut start_range_set = rangemap::RangeSet::new();
                    start_range_set.insert(ent.data_chunk_content_offset.0 as usize..usize::MAX);

                    incomplete_data_chunks.insert(ent.data_chunk_content_idx.0, start_range_set);

                    let mut end_range_set = rangemap::RangeSet::new();
                    end_range_set.insert(0..ent.data_chunk_content_end_offset.0 as usize);

                    incomplete_data_chunks.insert(ent.data_chunk_content_end_idx.0, end_range_set);
                }

                return Ok(PickMap {
                    is_subtar: false,
                    size: ent.size.0,
                    data_chunk_ranges: vec![HTreeDataRange {
                        start_idx: ent.data_chunk_content_idx.0,
                        end_idx: ent.data_chunk_content_end_idx.0,
                    }],
                    incomplete_data_chunks,
                });
            }
            kind => failure::bail!(
                "unable to pick {} - unsupported directory entry type: {:?}",
                path,
                kind
            ),
        }
    }

    failure::bail!("{} not found in content index", path)
}
