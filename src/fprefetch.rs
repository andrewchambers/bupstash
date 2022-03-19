// fprefetcher is a file opening queue used by the put command.
// The idea is there is a queue of files you are interested
// in reading in the near future and it lets the OS know the
// intention via whatever readahead mechanism your OS provides.

use std::collections::VecDeque;
use std::fs::File;
use std::path::PathBuf;

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        use std::os::unix::fs::OpenOptionsExt;
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "macos")] {
      // Nothing is needed.
    } else if #[cfg(target_os = "openbsd")] {
      // Nothing is needed.
    } else {
      use std::os::unix::io::AsRawFd;
      const NUM_PREFETCHED_BYTES: libc::off_t = 128 * 1024 * 1024;
    }
}

const NUM_PREOPENED_FILES: usize = 3;

#[derive(Default)]
pub struct ReadaheadFileOpener {
    unopened: VecDeque<PathBuf>,
    opened: VecDeque<(PathBuf, std::io::Result<File>)>,
}

fn open_file_for_streaming(fpath: &std::path::Path) -> std::io::Result<File> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            // Try with O_NOATIME first; if it fails, e.g. because the user we
            // run as is not the file owner, retry without..
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOATIME)
                .open(fpath)
                .or_else(|error| {
                    match error.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            std::fs::OpenOptions::new()
                                .read(true)
                                .open(fpath)
                        }
                        _ => Err(error)
                    }
                })?;
        } else {
          let f = std::fs::OpenOptions::new()
              .read(true)
              .open(fpath)?;
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(target_os = "macos")] {
            // XXX can we do anything here?
            // Perhaps F_RDADVISE ?
        } else if #[cfg(target_os = "openbsd")] {
            // XXX can we do anything here?
        } else {
            // We would like to use something like POSIX_FADV_NOREUSE to preserve
            // the user page cache... this is actually a NOOP on linux.
            // Instead we can at least boost performance by hinting our access pattern.
            match nix::fcntl::posix_fadvise(
                f.as_raw_fd(),
                0,
                0,
                nix::fcntl::PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL,
            ) {
                Ok(_) => (),
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("fadvise POSIX_FADV_SEQUENTIAL failed: {}", err),
                    ))
                }
            };

            match nix::fcntl::posix_fadvise(
                f.as_raw_fd(),
                0,
                NUM_PREFETCHED_BYTES,
                nix::fcntl::PosixFadviseAdvice::POSIX_FADV_WILLNEED,
            ) {
                Ok(_) => (),
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("fadvise POSIX_FADV_WILLNEED failed: {}", err),
                    ))
                }
            };
        }
    }

    Ok(f)
}

impl ReadaheadFileOpener {
    pub fn new() -> ReadaheadFileOpener {
        ReadaheadFileOpener {
            unopened: VecDeque::new(),
            opened: VecDeque::new(),
        }
    }

    pub fn add_to_queue(&mut self, p: PathBuf) {
        self.unopened.push_back(p);
    }

    pub fn next_file(&mut self) -> Option<(PathBuf, std::io::Result<File>)> {
        while !self.unopened.is_empty() && self.opened.len() < NUM_PREOPENED_FILES {
            let p = self.unopened.pop_front().unwrap();
            let r = open_file_for_streaming(&p);
            self.opened.push_back((p, r))
        }
        self.opened.pop_front()
    }
}
