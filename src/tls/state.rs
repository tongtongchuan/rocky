use std::{
    fs::{DirBuilder, File},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};
use serde::{Serialize, de::DeserializeOwned};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const OWNER_READ_WRITE: Mode = Mode::RUSR.union(Mode::WUSR);

pub(super) struct StateDir {
    dir: File,
    _lock: File,
}

impl StateDir {
    pub(super) fn open(path: &Path) -> Result<Self> {
        DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(path)
            .with_context(|| format!("create certificate state directory {}", path.display()))?;
        let dir = File::from(
            fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("open certificate state directory {}", path.display()))?,
        );
        check_owner(&dir).with_context(|| format!("state directory {}", path.display()))?;

        let lock = File::from(
            fs::openat(
                &dir,
                "lock",
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                OWNER_READ_WRITE,
            )
            .context("open certificate state lock")?,
        );
        check_record(&lock).context("certificate state lock")?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .with_context(|| format!("lock certificate state directory {}", path.display()))?;
        Ok(Self { dir, _lock: lock })
    }

    pub(super) fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let file = match fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("open state record {name}")),
        };
        check_record(&file).with_context(|| format!("check state record {name}"))?;
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read state record {name}"))?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "state record {name} is too large"
        );
        let record = serde_json::from_slice(&bytes)
            .with_context(|| format!("decode state record {name}"))?;
        Ok(Some(record))
    }

    pub(super) fn write<T: Serialize>(&self, name: &str, record: &T) -> Result<()> {
        let bytes = serde_json::to_vec(record).context("encode private state record")?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "state record {name} is too large"
        );
        let temporary = format!(".write-{:032x}", rand::random::<u128>());
        let mut file = File::from(
            fs::openat(
                &self.dir,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                OWNER_READ_WRITE,
            )
            .context("create temporary private state record")?,
        );
        let result: Result<()> = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::renameat(&self.dir, temporary.as_str(), &self.dir, name)?;
            self.dir.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.dir, temporary.as_str(), AtFlags::empty());
        }
        result.with_context(|| format!("persist state record {name}"))
    }

    pub(super) fn remove(&self, name: &str) -> Result<()> {
        match fs::unlinkat(&self.dir, name, AtFlags::empty()) {
            Ok(()) => self
                .dir
                .sync_all()
                .with_context(|| format!("sync removal of {name}")),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(err) => Err(err).with_context(|| format!("remove state record {name}")),
        }
    }
}

fn check_owner(file: &File) -> Result<std::fs::Metadata> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw(),
        "must be owned by the daemon account"
    );
    ensure!(
        metadata.mode() & 0o077 == 0,
        "must be accessible only to its owner"
    );
    Ok(metadata)
}

fn check_record(file: &File) -> Result<()> {
    let meta = check_owner(file)?;
    ensure!(
        meta.is_file() && meta.nlink() == 1,
        "must be a regular file with one link"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn state_is_private_locked_and_atomically_replaced() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("state");
        let state = StateDir::open(&path)?;
        assert!(StateDir::open(&path).is_err());
        assert_eq!(state.read::<u64>("record")?, None);
        state.write("record", &42u64)?;
        state.write("record", &98u64)?;
        assert_eq!(state.read::<u64>("record")?, Some(98));
        assert_eq!(
            std::fs::metadata(path.join("record"))?.mode() & 0o777,
            0o600
        );
        state.remove("record")?;
        symlink("lock", path.join("record"))?;
        assert!(state.read::<u64>("record").is_err());
        drop(state);
        assert!(StateDir::open(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        assert!(StateDir::open(&path).is_err());
        Ok(())
    }
}
