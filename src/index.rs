use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VersionedIndexEntry {
    V1(IndexEntry),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    pub kind: IndexEntryKind,
    pub perms: serde_bare::Uint,
    pub size: serde_bare::Uint,
    pub data_chunk_idx: serde_bare::Uint,
    pub data_chunk_content_idx: serde_bare::Uint,
    pub data_chunk_content_end_idx: serde_bare::Uint,
    pub data_chunk_end_idx: serde_bare::Uint,
    pub data_chunk_offset: serde_bare::Uint,
    pub data_chunk_content_offset: serde_bare::Uint,
    pub data_chunk_content_end_offset: serde_bare::Uint,
    pub data_chunk_end_offset: serde_bare::Uint,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HTreeDataRange {
    pub start_idx: u64,
    pub end_idx: u64,
}

pub struct PickMap {
    pub is_subtar: bool,
    pub data_chunk_ranges: Vec<HTreeDataRange>,
    pub incomplete_data_chunks: std::collections::HashMap<u64, rangemap::RangeSet<usize>>,
}

pub fn pick(path: &str, index: &Vec<VersionedIndexEntry>) -> Result<PickMap, failure::Error> {
    for i in 0..index.len() {
        let ent = &index[i];
        let ent = match ent {
            VersionedIndexEntry::V1(ref ent) => ent,
        };

        if ent.path != path {
            continue;
        }

        match ent.kind {
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

                for j in i..index.len() {
                    let ent = &index[j];
                    let ent = match ent {
                        VersionedIndexEntry::V1(ref ent) => ent,
                    };

                    // Match the directory and its children.
                    if !(j == i || ent.path.starts_with(&prefix)) {
                        continue;
                    }

                    dbg!(&ent.path);

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
                    data_chunk_ranges: vec![HTreeDataRange {
                        start_idx: ent.data_chunk_content_idx.0,
                        end_idx: ent.data_chunk_content_end_idx.0,
                    }],
                    incomplete_data_chunks,
                });
            }
            _ => failure::bail!(
                "unable to pick {} - unsupported directory entry type: {:?}",
                path,
                ent.kind
            ),
        }
    }

    failure::bail!("{} not found in content index", path)
}
