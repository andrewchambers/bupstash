use rand::Rng;

use std::fs;
use std::io::Write;
use std::path::Path;
// Does NOT sync the directory. A sync of the directory still needs to be
// done to ensure the atomic rename is persisted.
// That sync can be done once at the end of an 'upload session'.
pub fn atomic_add_file_no_parent_sync(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let temp_path = p
        .to_string_lossy()
        .chars()
        .chain(
            std::iter::repeat(())
                .map(|()| rand::thread_rng().sample(rand::distributions::Alphanumeric))
                .take(8),
        )
        .chain(".tmp".chars())
        .collect::<String>();

    let mut tmp_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    tmp_file.write_all(contents)?;
    tmp_file.sync_all()?;
    std::fs::rename(temp_path, p)?;
    Ok(())
}

pub fn sync_dir(p: &Path) -> Result<(), std::io::Error> {
    let dir = fs::File::open(p)?;
    dir.sync_all()?;
    Ok(())
}

pub fn atomic_add_file_with_parent_sync(p: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    atomic_add_file_no_parent_sync(p, contents)?;
    sync_dir(p.parent().unwrap())?;
    Ok(())
}

pub fn atomic_add_dir_with_parent_sync(p: &Path) -> Result<(), std::io::Error> {
    fs::DirBuilder::new().create(p)?;
    sync_dir(p.parent().unwrap())?;
    Ok(())
}
