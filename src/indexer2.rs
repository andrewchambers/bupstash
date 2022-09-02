use super::fsutil;
use super::index;
use std::collections::{HashMap, VecDeque};
// use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
// use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/*

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

fn index_entry_from_fs(base_path: &Path, path: &Path, opts: &FsIndexerOptions) -> std::io::Result<CombinedMetadata> {

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
                                    xattrs.insert(attr.into_vec(), value);
                                }
                                _ => unreachable!(),
                            }
                        }
                        Ok(None) => (), // The file had it's xattr removed, assume it never had it.
                        Err(err) if fsutil::likely_smear_error(&err) => (), // The file was modified, assume it never had this xattr.
                        Err(err)
                            if opts.ignore_permission_errors
                                && err.kind() == std::io::ErrorKind::PermissionDenied => {}
                        Err(err) => return Err(err),
                    }
                }
            }
            Err(err) if fsutil::likely_smear_error(&err) => (), // The file was modified, assume no xattrs for what we have.
            Err(err)
                if opts.ignore_permission_errors
                    && err.kind() == std::io::ErrorKind::PermissionDenied => {}
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
            Err(err)
                if opts.ignore_permission_errors
                    && err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                false
            }
            Err(err) => return Err(err),
        }
    } else {
        false
    };

    let ft = stat.file_type();
    let (dev_major, dev_minor) = if ft.is_block_device() || ft.is_char_device() {
        (
            fsutil::dev_major(metadata.rdev()),
            fsutil::dev_minor(metadata.rdev()),
        )
    } else {
        (0, 0)
    };

    let link_target = if ft.is_symlink() {
            Some(std::fs::read_link(path)?)
        } else {
            None
        };

    index::IndexEntry {
        path: index_path.to_owned(),
        size: serde_bare::Uint(if stat.is_file() {
            stat.size()
        } else {
            0
        }),
        uid: serde_bare::Uint(stat.uid() as u64),
        gid: serde_bare::Uint(stat.gid() as u64),
        mode: serde_bare::Uint(stat.permissions().mode() as u64),
        ctime: serde_bare::Uint(stat.ctime() as u64),
        ctime_nsec: serde_bare::Uint(stat.ctime_nsec() as u64),
        mtime: serde_bare::Uint(stat.mtime() as u64),
        mtime_nsec: serde_bare::Uint(stat.mtime_nsec() as u64),
        nlink: serde_bare::Uint(stat.nlink()),
        dev_major: serde_bare::Uint(dev_major as u64),
        dev_minor: serde_bare::Uint(dev_minor as u64),
        // To be normalized later in the pipeline.
        norm_dev: serde_bare::Uint(metadata.dev()),
        ino: serde_bare::Uint(metadata.ino()),
        // Dummy value, set by caller.
        data_cursor: index::RelativeDataCursor {
            chunk_delta: serde_bare::Uint(0),
            start_byte_offset: serde_bare::Uint(0),
            end_byte_offset: serde_bare::Uint(0),
        },
        sparse,
        xattrs,
        link_target,
        data_hash,
    }

    Ok(CombinedMetadata {
        stat,
        xattrs,
        sparse,
        data_hash,
    })
}
*/

#[derive(Default)]
pub struct DevNormalizer {
    count: u64,
    tab: HashMap<u64, u64>,
}

impl DevNormalizer {
    pub fn new() -> Self {
        DevNormalizer {
            count: 0,
            tab: HashMap::new(),
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

pub struct FsIndexerOptions {
    pub exclusions: globset::GlobSet,
    pub exclusion_markers: std::collections::HashSet<std::ffi::OsString>,
    pub want_xattrs: bool,
    pub want_sparseness: bool,
    pub want_hash: bool,
    pub one_file_system: bool,
    pub ignore_permission_errors: bool,
}

pub struct FsWalkerOptions {
    pub exclusions: globset::GlobSet,
    pub exclusion_markers: std::collections::HashSet<std::ffi::OsString>,
    pub one_file_system: bool,
    pub ignore_permission_errors: bool,
}

pub struct FsWalker {
    opts: FsWalkerOptions,
    base_dev: u64,
    prefilled_children: HashMap<PathBuf, Vec<(PathBuf, std::fs::FileType)>>,
    buffered: VecDeque<PathBuf>,
    work_stack: Vec<Vec<PathBuf>>,
}

impl FsWalker {
    pub fn new(
        paths: &[PathBuf],
        opts: FsWalkerOptions,
    ) -> Result<(PathBuf, FsWalker), anyhow::Error> {
        if paths.is_empty() {
            anyhow::bail!("no paths specified");
        }

        // We process absolute paths so we can deal with common prefixes.
        let mut absolute_paths = Vec::new();
        for p in paths.iter() {
            let p = match fsutil::absolute_path(p) {
                Ok(p) => p,
                Err(err) => anyhow::bail!("unable to get absolute path of {:?}: {}", p, err),
            };
            absolute_paths.push(p)
        }

        if absolute_paths.len() == 1 {
            match absolute_paths[0].metadata() {
                Ok(stat) => {
                    if !stat.is_dir() {
                        // Special case walking a single file,
                        return Ok((
                            absolute_paths[0].clone(),
                            FsWalker {
                                opts,
                                base_dev: stat.dev(),
                                prefilled_children: HashMap::new(),
                                buffered: VecDeque::from(absolute_paths),
                                work_stack: Vec::new(),
                            },
                        ));
                    }
                }
                Err(err) => anyhow::bail!("unable to stat {:?}: {}", absolute_paths[0], err),
            };
        }

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

        // We should always have at least "/" in common.
        let base = fsutil::common_path_all(&root_paths).unwrap();

        // Gather all 'filler' dirs, these are stand alone dirs we insert
        // into our index to help maintain proper order.
        // So if a user puts a/b and a/c, then a is a filler.
        let mut filler_dirs = std::collections::HashSet::new();

        let mut prefilled_children = HashMap::<PathBuf, Vec<(PathBuf, std::fs::FileType)>>::new();

        if root_paths.len() > 1 {
            // We have more than one root_path so
            // base must be a filler dir by definition.
            filler_dirs.insert(base.clone());

            for p in root_paths.iter() {
                dbg!(&p);
                let mut p = p.clone();
                p.pop();
                while p != base {
                    dbg!(&p);
                    filler_dirs.insert(p.clone());
                    p.pop();
                }
            }
        }

        // Build a prepopulated table of filler directory children.
        for p in filler_dirs.drain().chain(root_paths.drain(..)) {
            let stat = match p.metadata() {
                Ok(stat) => stat,
                Err(err) => anyhow::bail!("unable to stat {:?}: {}", p, err),
            };

            let parent = if let Some(parent) = p.parent() {
                parent.to_owned()
            } else {
                // We use empty path to represent the parent of / as a special case.
                "".into()
            };

            match prefilled_children.get_mut(&parent) {
                Some(v) => {
                    v.push((p, stat.file_type()));
                }
                None => {
                    prefilled_children.insert(parent, vec![(p, stat.file_type())]);
                }
            }
        }

        for (_, v) in prefilled_children.iter_mut() {
            v.sort_by(|l, r| index::path_cmp(&l.0, &r.0))
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

        Ok((
            base,
            FsWalker {
                opts,
                base_dev: start_md.dev(),
                prefilled_children,
                buffered: VecDeque::new(),
                work_stack: vec![vec![start_dir]],
            },
        ))
    }

    fn walk_dir(&mut self, dir_path: PathBuf) -> Result<(), anyhow::Error> {
        let mut children = match self.prefilled_children.remove(&dir_path) {
            Some(children) => children,
            None => match std::fs::read_dir(&dir_path) {
                Ok(dir_ents) => {
                    let mut children = Vec::with_capacity(8);
                    for dir_ent in dir_ents {
                        let dir_ent = dir_ent?;
                        children.push((dir_ent.path(), dir_ent.file_type()?))
                    }
                    children
                }
                Err(err)
                    if fsutil::likely_smear_error(&err)
                        || (self.opts.ignore_permission_errors
                            && err.kind() == std::io::ErrorKind::PermissionDenied) =>
                {
                    Vec::new()
                }
                Err(err) => {
                    return Err(anyhow::format_err!("error reading {:?}: {}", dir_path, err))
                }
            },
        };

        let mut to_recurse: Vec<PathBuf> = Vec::new();

        if !self.opts.exclusion_markers.is_empty() {
            for p in children.iter() {
                if self
                    .opts
                    .exclusion_markers
                    .contains(p.0.file_name().unwrap())
                {
                    children.retain(|p| {
                        if !self
                            .opts
                            .exclusion_markers
                            .contains(p.0.file_name().unwrap())
                        {
                            return false;
                        };
                        true
                    });
                    break;
                }
            }
        }

        children.retain(|p| !self.opts.exclusions.is_match(&p.0));

        children.sort_by(|l, r| {
            index::path_cmp(
                l.0.file_name().unwrap().as_ref(),
                r.0.file_name().unwrap().as_ref(),
            )
        });

        for (child_path, child_file_type) in children.drain(..) {
            if child_file_type.is_socket() {
                continue;
            }

            if child_file_type.is_dir() {
                if self.opts.one_file_system {
                    todo!();
                }
                to_recurse.push(child_path.clone());
            }

            self.buffered.push_back(child_path);
        }

        if !to_recurse.is_empty() {
            to_recurse.reverse();
            self.work_stack.push(to_recurse)
        }

        Ok(())
    }
}

impl Iterator for FsWalker {
    type Item = Result<PathBuf, anyhow::Error>;

    fn next(&mut self) -> Option<Result<PathBuf, anyhow::Error>> {
        loop {
            if let Some(v) = self.buffered.pop_front() {
                return Some(Ok(v));
            }
            match self.work_stack.last_mut() {
                Some(v) => {
                    if let Some(p) = v.pop() {
                        match self.walk_dir(p) {
                            Ok(_) => continue,
                            Err(err) => return Some(Err(err)),
                        }
                    } else {
                        self.work_stack.pop();
                        continue;
                    }
                }
                None => return None,
            }
        }
    }
}
