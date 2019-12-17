use std::fs;
use std::path::Path;

pub fn create_empty_file(p: &Path) -> Result<(), std::io::Error> {
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    f.sync_all()?;
    Ok(())
}

pub fn sync_dir(p: &Path) -> Result<(), std::io::Error> {
    let dir = fs::File::open(p)?;
    dir.sync_all()?;
    Ok(())
}
