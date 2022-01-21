use super::fsutil;
use super::index;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct CombinedMetadata {
    stat: std::fs::Metadata,
    xattrs: Option<index::Xattrs>,
    sparse: bool,
    data_hash: index::ContentCryptoHash,
}

enum FsMetadataRequest {
    SymlinkMetadata { path: PathBuf },
    Done,
}

struct FsMetadataFetcher {
    dispatch_tx: crossbeam_channel::Sender<FsMetadataRequest>,
    result_rx: crossbeam_channel::Receiver<(PathBuf, std::io::Result<CombinedMetadata>)>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct FsMetadataFetcherOptions {
    num_workers: usize,
    want_xattrs: bool,
    want_sparseness: bool,
    want_hash: bool,
}

impl Drop for FsMetadataFetcher {
    fn drop(&mut self) {
        for _i in 0..self.workers.len() {
            self.dispatch_tx.send(FsMetadataRequest::Done).unwrap();
        }
        for w in self.workers.drain(..) {
            w.join().unwrap()
        }
    }
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "linux",
    target_os = "solaris"
))]
fn probe_sparse(path: &Path, stat: &std::fs::Metadata) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;

    // Heuristic that filters away expensive check.
    if (stat.blocks() * 512) >= stat.size() {
        return Ok(false);
    }

    // Use lseek to confirm that there is a hole.

    let mut offset = 0;
    let f = std::fs::File::open(path)?;

    match nix::unistd::lseek(f.as_raw_fd(), offset, nix::unistd::Whence::SeekHole) {
        Ok(next) => offset = next,
        Err(_) => return Ok(false),
    }

    let hole_start = offset;

    match nix::unistd::lseek(f.as_raw_fd(), offset, nix::unistd::Whence::SeekData) {
        Ok(next) => offset = next,
        Err(nix::Error::ENXIO) => {
            /* There is no more data, seek to the end. */
            match nix::unistd::lseek(f.as_raw_fd(), 0, nix::unistd::Whence::SeekEnd) {
                Ok(next) => offset = next,
                Err(err) => return Err(err.into()),
            }
        }
        Err(_) => return Ok(false),
    }

    let hole_size = offset - hole_start;

    Ok(hole_size != 0)
}

#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "linux",
    target_os = "solaris"
)))]
fn probe_sparse(_path: &Path, stat: &std::fs::Metadata) -> std::io::Result<bool> {
    Ok((stat.blocks() * 512) < stat.size())
}

fn get_metadata(path: &Path, opts: &FsMetadataFetcherOptions) -> std::io::Result<CombinedMetadata> {
    let mut xattrs = None;

    let stat = path.symlink_metadata()?;

    if opts.want_xattrs && (stat.is_file() || stat.is_dir()) {
        match xattr::list(path) {
            Ok(attrs) => {
                for attr in attrs {
                    match xattr::get(path, &attr) {
                        Ok(Some(value)) => {
                            if xattrs.is_none() {
                                xattrs = Some(index::Xattrs::new())
                            }
                            match xattrs {
                                Some(ref mut xattrs) => {
                                    xattrs.insert(attr, value);
                                }
                                _ => unreachable!(),
                            }
                        }
                        Ok(None) => (), // The file had it's xattr removed, assume it never had it.
                        Err(err) if fsutil::likely_smear_error(&err) => (), // The file was modified, assume it never had this xattr.
                        Err(err) => return Err(err),
                    }
                }
            }
            Err(err) if fsutil::likely_smear_error(&err) => (), // The file was modified, assume no xattrs for what we have.
            Err(err) => return Err(err),
        }
    }

    let data_hash = if stat.is_file() && opts.want_hash {
        let mut hasher = blake3::Hasher::new();
        let mut f = std::fs::File::open(path)?;
        std::io::copy(&mut f, &mut hasher)?;
        index::ContentCryptoHash::Blake3(hasher.finalize().into())
    } else {
        index::ContentCryptoHash::None
    };

    let sparse = if opts.want_sparseness && stat.is_file() {
        match probe_sparse(path, &stat) {
            Ok(sparse) => sparse,
            Err(err) if fsutil::likely_smear_error(&err) => false,
            Err(err) => return Err(err),
        }
    } else {
        false
    };

    Ok(CombinedMetadata {
        stat,
        xattrs,
        sparse,
        data_hash,
    })
}

impl FsMetadataFetcher {
    fn new(opts: FsMetadataFetcherOptions) -> FsMetadataFetcher {
        let num_workers = opts.num_workers.max(1);
        let (dispatch_tx, dispatch_rx) = crossbeam_channel::bounded(0);
        let (result_tx, result_rx) = crossbeam_channel::bounded(0);
        let mut workers = Vec::new();
        for _i in 0..num_workers {
            let opts = opts.clone();
            let result_tx = result_tx.clone();
            let dispatch_rx = dispatch_rx.clone();
            let worker = std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn(move || loop {
                    match dispatch_rx.recv() {
                        Ok(FsMetadataRequest::SymlinkMetadata { path }) => {
                            let r = get_metadata(&path, &opts);
                            let _ = result_tx.send((path, r));
                        }
                        Ok(FsMetadataRequest::Done) => break,
                        Err(_) => break,
                    }
                })
                .unwrap();
            workers.push(worker)
        }
        FsMetadataFetcher {
            dispatch_tx,
            result_rx,
            workers,
        }
    }

    fn parallel_get_metadata(
        &mut self,
        mut paths: Vec<PathBuf>,
    ) -> Vec<(PathBuf, std::io::Result<CombinedMetadata>)> {
        let mut results = Vec::with_capacity(paths.len());
        let mut in_flight = 0;
        for path in paths.drain(..) {
            if in_flight >= self.workers.len() {
                results.push(self.result_rx.recv().unwrap());
                in_flight -= 1;
            }
            self.dispatch_tx
                .send(FsMetadataRequest::SymlinkMetadata { path })
                .unwrap();
            in_flight += 1;
        }
        while in_flight != 0 {
            results.push(self.result_rx.recv().unwrap());
            in_flight -= 1;
        }
        results
    }
}

#[derive(Default)]
pub struct DevNormalizer {
    count: u64,
    tab: std::collections::HashMap<u64, u64>,
}

impl DevNormalizer {
    pub fn new() -> Self {
        DevNormalizer {
            count: 0,
            tab: std::collections::HashMap::new(),
        }
    }

    pub fn normalize(&mut self, dev: u64) -> u64 {
        match self.tab.get(&dev) {
            Some(nd) => *nd,
            None => {
                let nd = self.count;
                self.count += 1;
                self.tab.insert(dev, nd);
                nd
            }
        }
    }
}

pub fn metadata_to_index_ent(
    dev_normalizer: &mut DevNormalizer,
    full_path: &std::path::Path,
    index_path: &std::path::Path,
    metadata: &std::fs::Metadata,
    xattrs: Option<index::Xattrs>,
    sparse: bool,
    data_hash: index::ContentCryptoHash,
) -> Result<index::IndexEntry, std::io::Error> {
    let t = metadata.file_type();

    let (dev_major, dev_minor) = if t.is_block_device() || t.is_char_device() {
        (
            fsutil::dev_major(metadata.rdev()),
            fsutil::dev_minor(metadata.rdev()),
        )
    } else {
        (0, 0)
    };

    Ok(index::IndexEntry {
        path: index_path.to_owned(),
        size: serde_bare::Uint(if metadata.is_file() {
            metadata.size()
        } else {
            0
        }),
        uid: serde_bare::Uint(metadata.uid() as u64),
        gid: serde_bare::Uint(metadata.gid() as u64),
        mode: serde_bare::Uint(metadata.permissions().mode() as u64),
        ctime: serde_bare::Uint(metadata.ctime() as u64),
        ctime_nsec: serde_bare::Uint(metadata.ctime_nsec() as u64),
        mtime: serde_bare::Uint(metadata.mtime() as u64),
        mtime_nsec: serde_bare::Uint(metadata.mtime_nsec() as u64),
        nlink: serde_bare::Uint(metadata.nlink()),
        link_target: if t.is_symlink() {
            Some(std::fs::read_link(&full_path)?)
        } else {
            None
        },
        dev_major: serde_bare::Uint(dev_major as u64),
        dev_minor: serde_bare::Uint(dev_minor as u64),
        norm_dev: serde_bare::Uint(dev_normalizer.normalize(metadata.dev())),
        ino: serde_bare::Uint(metadata.ino()),
        sparse,
        xattrs,
        // Dummy value, set by caller.
        data_cursor: index::RelativeDataCursor {
            chunk_delta: serde_bare::Uint(0),
            start_byte_offset: serde_bare::Uint(0),
            end_byte_offset: serde_bare::Uint(0),
        },
        data_hash,
    })
}

pub struct IndexedDir {
    pub dir_path: PathBuf,
    pub ent_paths: Vec<PathBuf>,
    pub index_ents: Vec<index::IndexEntry>,
    pub excluded_paths: Vec<PathBuf>,
}

pub struct FsIndexer {
    base: PathBuf,
    base_dev: u64,
    dev_normalizer: DevNormalizer,
    opts: FsIndexerOptions,
    work_stack: Vec<Vec<PathBuf>>,
    filler_children: std::collections::HashMap<PathBuf, Vec<PathBuf>>,
    metadata_fetcher: FsMetadataFetcher,
}

pub struct FsIndexerOptions {
    pub exclusions: globset::GlobSet,
    /// File names that if present exclude the whole directory
    pub exclusion_markers: std::collections::HashSet<std::ffi::OsString>,
    pub want_xattrs: bool,
    pub want_sparseness: bool,
    pub want_hash: bool,
    pub one_file_system: bool,
}

pub struct BackgroundFsIndexer {
    indexer_thread: Option<std::thread::JoinHandle<()>>,
    indexed_dir_rx: Option<crossbeam_channel::Receiver<Result<IndexedDir, anyhow::Error>>>,
}

impl Iterator for BackgroundFsIndexer {
    type Item = Result<IndexedDir, anyhow::Error>;

    fn next(&mut self) -> Option<Result<IndexedDir, anyhow::Error>> {
        match self.indexed_dir_rx.as_mut().unwrap().recv() {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }
}

impl Drop for BackgroundFsIndexer {
    fn drop(&mut self) {
        std::mem::drop(self.indexed_dir_rx.take());
        self.indexer_thread.take().unwrap().join().unwrap();
    }
}

impl FsIndexer {
    pub fn new(paths: &[PathBuf], opts: FsIndexerOptions) -> Result<FsIndexer, anyhow::Error> {
        // We process absolute paths.
        let mut absolute_paths = Vec::new();
        for p in paths.iter() {
            let p = match fsutil::absolute_path(p) {
                Ok(p) => p,
                Err(err) => anyhow::bail!("unable to get absolute path {:?}: {}", p, err),
            };
            absolute_paths.push(p)
        }

        // Remove duplicate paths.
        absolute_paths.sort();
        absolute_paths.dedup();

        // Prune away paths that encapsulate eachother, for example
        // 'put /a /a/b'  is really just 'put /a'.
        let mut root_paths = Vec::new();
        let mut i = 0;
        while i < absolute_paths.len() {
            let mut j = i + 1;
            loop {
                match (&absolute_paths[i], absolute_paths.get(j)) {
                    (_, None) => break,
                    (a, Some(b)) => {
                        if fsutil::common_path(a, b).unwrap() != *a {
                            break;
                        }
                    }
                }
                j += 1;
            }
            root_paths.push(absolute_paths[i].clone());
            i = j;
        }

        for p in root_paths.iter() {
            if !p.is_dir() {
                anyhow::bail!("cannot index {:?}: is it not a directory", p)
            }
        }

        // We should always have at least "/" in common.
        let base = fsutil::common_path_all(&root_paths).unwrap();

        // Gather all 'filler' dirs, these are stand alone dirs we insert
        // into our index to help maintain proper order.
        // So if a user puts a/b and a/c, then a is a filler.
        let mut filler_dirs = std::collections::HashSet::new();

        if root_paths.len() != 1 {
            // If we have more than one root_path at this point,
            // base must be a filler dir by definition.
            filler_dirs.insert(base.clone());

            for p in root_paths.iter() {
                let mut p = p.clone();
                p.pop();
                while p != base {
                    filler_dirs.insert(p.clone());
                    p.pop();
                }
            }
        }

        let mut filler_children = std::collections::HashMap::<PathBuf, Vec<PathBuf>>::new();

        // Build a prepopulated table of filler directory children.
        for p in filler_dirs.drain().chain(root_paths.drain(..)) {
            let parent = if let Some(parent) = p.parent() {
                parent.to_owned()
            } else {
                // We use empty path to represent the parent of / as a special case.
                "".into()
            };

            match filler_children.get_mut(&parent) {
                Some(v) => {
                    v.push(p);
                }
                None => {
                    filler_children.insert(parent, vec![p]);
                }
            }
        }

        for (_, v) in filler_children.iter_mut() {
            v.sort_by(|l, r| index::path_cmp(l, r))
        }

        let start_dir = if let Some(base_parent) = base.parent() {
            base_parent.to_owned()
        } else {
            // Special case for the parent of /.
            "".into()
        };

        let start_md_dir = if base.parent().is_some() {
            start_dir.clone()
        } else {
            "/".into()
        };

        let start_md = match start_md_dir.metadata() {
            Ok(md) => md,
            Err(err) => anyhow::bail!("error reading {:?}: {}", start_md_dir, err),
        };

        let metadata_fetcher_opts = FsMetadataFetcherOptions {
            num_workers: 4,
            want_xattrs: opts.want_xattrs,
            want_sparseness: opts.want_sparseness,
            want_hash: opts.want_hash,
        };

        Ok(FsIndexer {
            opts,
            base,
            base_dev: start_md.dev(),
            filler_children,
            work_stack: vec![vec![start_dir]],
            dev_normalizer: DevNormalizer::new(),
            metadata_fetcher: FsMetadataFetcher::new(metadata_fetcher_opts),
        })
    }

    fn walk_dir(&mut self, dir_path: PathBuf) -> Result<IndexedDir, anyhow::Error> {
        let mut dir_ent_paths = match self.filler_children.get(&dir_path) {
            Some(children) => children.clone(),
            None => {
                let mut dir_ents = match std::fs::read_dir(&dir_path) {
                    Ok(dir_ents) => {
                        let dir_ents: Result<Vec<_>, _> = dir_ents.collect();
                        dir_ents?
                    }
                    Err(err) if fsutil::likely_smear_error(&err) => {
                        return Ok(IndexedDir {
                            dir_path,
                            ent_paths: vec![],
                            index_ents: vec![],
                            excluded_paths: vec![],
                        })
                    }
                    Err(err) => {
                        return Err(anyhow::format_err!("error reading {:?}: {}", dir_path, err))
                    }
                };

                dir_ents.drain(..).map(|x| x.path()).collect()
            }
        };

        let mut index_ents = Vec::with_capacity(dir_ent_paths.len());
        let mut ent_paths = Vec::with_capacity(dir_ent_paths.len());
        let mut excluded_paths = Vec::new();
        let mut to_recurse = Vec::new();

        if !self.opts.exclusion_markers.is_empty() {
            for p in dir_ent_paths.iter() {
                if self.opts.exclusion_markers.contains(p.file_name().unwrap()) {
                    dir_ent_paths.retain(|p| {
                        if !self.opts.exclusion_markers.contains(p.file_name().unwrap()) {
                            excluded_paths.push(p.to_owned());
                            return false;
                        };
                        true
                    });
                    break;
                }
            }
        }

        dir_ent_paths.retain(|p| {
            if self.opts.exclusions.is_match(p) {
                excluded_paths.push(p.to_owned());
                false
            } else {
                true
            }
        });

        let mut dir_ents = self.metadata_fetcher.parallel_get_metadata(dir_ent_paths);

        dir_ents.sort_by(|l, r| {
            index::path_cmp(
                l.0.file_name().unwrap().as_ref(),
                r.0.file_name().unwrap().as_ref(),
            )
        });

        excluded_paths.sort_by(|l, r| {
            index::path_cmp(
                l.file_name().unwrap().as_ref(),
                r.file_name().unwrap().as_ref(),
            )
        });

        'process_dir_ents: for (dir_ent_path, md_result) in dir_ents.drain(..) {
            match md_result {
                Ok(CombinedMetadata {
                    stat,
                    xattrs,
                    sparse,
                    data_hash,
                }) => {
                    if stat.file_type().is_socket() {
                        continue 'process_dir_ents;
                    }

                    let index_ent_path = if dir_ent_path == self.base {
                        ".".into()
                    } else {
                        dir_ent_path.strip_prefix(&self.base).unwrap().to_path_buf()
                    };

                    let index_ent = match metadata_to_index_ent(
                        &mut self.dev_normalizer,
                        &dir_ent_path,
                        &index_ent_path,
                        &stat,
                        xattrs,
                        sparse,
                        data_hash,
                    ) {
                        Ok(index_ent) => index_ent,
                        Err(err) if fsutil::likely_smear_error(&err) => continue 'process_dir_ents,
                        Err(err) => {
                            return Err(anyhow::format_err!(
                                "error creating index entry for {:?}: {}",
                                dir_ent_path,
                                err
                            ))
                        }
                    };

                    if stat.is_dir()
                        && ((self.base_dev == stat.dev()) || !self.opts.one_file_system)
                    {
                        to_recurse.push(dir_ent_path.clone());
                    }

                    ent_paths.push(dir_ent_path);
                    index_ents.push(index_ent);
                }
                Err(err) if fsutil::likely_smear_error(&err) => (),
                Err(err) => {
                    return Err(anyhow::format_err!(
                        "error reading {:?}: {}",
                        dir_ent_path,
                        err
                    ))
                }
            }
        }

        if !to_recurse.is_empty() {
            to_recurse.reverse();
            self.work_stack.push(to_recurse)
        }

        Ok(IndexedDir {
            dir_path,
            ent_paths,
            index_ents,
            excluded_paths,
        })
    }

    pub fn background(self) -> BackgroundFsIndexer {
        // The bound controls how many directories worth of stats we buffer in memory.
        // We could probably make this configurable somehow (env var?).
        let (indexed_dir_tx, indexed_dir_rx) = crossbeam_channel::bounded(1);

        let indexer_thread = std::thread::spawn(move || {
            for indexed_dir in self {
                if indexed_dir_tx.send(indexed_dir).is_err() {
                    break;
                }
            }
        });

        BackgroundFsIndexer {
            indexer_thread: Some(indexer_thread),
            indexed_dir_rx: Some(indexed_dir_rx),
        }
    }
}

impl Iterator for FsIndexer {
    type Item = Result<IndexedDir, anyhow::Error>;

    fn next(&mut self) -> Option<Result<IndexedDir, anyhow::Error>> {
        match self.work_stack.last_mut() {
            Some(v) => {
                if let Some(p) = v.pop() {
                    Some(self.walk_dir(p))
                } else {
                    self.work_stack.pop();
                    self.next()
                }
            }
            None => None,
        }
    }
}
