use std::{
    fs::{self, DirBuilder, File, Permissions},
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{FlockOperation, Mode, OFlags};
use serde_json::{Value, json};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    task::JoinSet,
    time,
};

use crate::runtime::Runtime;

const MAX_CLIENTS: usize = 16;
const IO_DEADLINE: Duration = Duration::from_secs(5);

pub struct Admin {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    _lock: File,
}

impl Admin {
    pub fn bind(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("admin_socket has no parent directory")?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("create administration directory {}", parent.display()))?;
        let metadata = fs::metadata(parent)?;
        let owner = metadata.uid();
        let uid = rustix::process::geteuid().as_raw();
        ensure!(
            metadata.is_dir() && (owner == 0 || owner == uid) && metadata.mode() & 0o022 == 0,
            "administration directory {} must be controlled by the daemon or root",
            parent.display()
        );
        let lock = lock_socket_path(path, uid)?;
        let listener = bind_socket(path, uid)
            .with_context(|| format!("bind administration socket {}", path.display()))?;
        let metadata = fs::symlink_metadata(path)?;
        let admin = Self {
            listener,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            _lock: lock,
        };
        fs::set_permissions(path, Permissions::from_mode(0o600))
            .context("set administration socket permissions")?;
        Ok(admin)
    }

    pub async fn serve(&self, runtime: Arc<Runtime>) -> Result<()> {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = clients.join_next(), if !clients.is_empty() => {},
                accepted = self.listener.accept() => {
                    let (socket, _) = accepted.context("accept administration connection")?;
                    let uid = rustix::process::geteuid().as_raw();
                    if clients.len() >= MAX_CLIENTS || !socket.peer_cred().is_ok_and(|peer| peer.uid() == uid || peer.uid() == 0) {
                        continue;
                    }
                    let runtime = Arc::clone(&runtime);
                    clients.spawn(async move {
                        if let Err(error) = request(socket, runtime).await {
                            tracing::debug!(%error, "administration request failed");
                        }
                    });
                }
            }
        }
    }
}

fn lock_socket_path(path: &Path, uid: u32) -> Result<File> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let file = File::from(
        rustix::fs::open(
            lock_path.as_os_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .context("open administration socket lock")?,
    );
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "administration socket lock must be a private file owned by the daemon"
    );
    rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
        .context("administration socket is already in use")?;
    Ok(file)
}

fn bind_socket(path: &Path, uid: u32) -> Result<UnixListener> {
    match UnixListener::bind(path) {
        Ok(listener) => return Ok(listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == uid,
        "the administration path is occupied by a different file"
    );
    let probe = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    probe.set_nonblocking(true)?;
    ensure!(
        probe
            .connect(&SockAddr::unix(path)?)
            .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused),
        "administration socket is already in use"
    );
    // The adjacent lock serializes Rocky processes that can recover this socket.
    fs::remove_file(path)?;
    Ok(UnixListener::bind(path)?)
}

impl Drop for Admin {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && (metadata.dev(), metadata.ino()) == (self.device, self.inode)
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

async fn request(mut socket: UnixStream, runtime: Arc<Runtime>) -> Result<()> {
    let mut line = Vec::new();
    time::timeout(
        IO_DEADLINE,
        BufReader::new(&mut socket)
            .take(32)
            .read_until(b'\n', &mut line),
    )
    .await??;
    let response = match &line[..] {
        b"status\n" => json!({"ok": true, "result": runtime.status()}),
        b"reload\n" => match runtime.reload().await {
            Ok(generation) => json!({"ok": true, "result": {"generation": generation}}),
            Err(error) => json!({"ok": false, "error": format!("{error:#}")}),
        },
        _ => json!({"ok": false, "error": "unknown administration command"}),
    };
    let bytes = serde_json::to_vec(&response)?;
    time::timeout(IO_DEADLINE, socket.write_all(&bytes)).await??;
    Ok(())
}

pub async fn command(path: &Path, command: &'static str) -> Result<Value> {
    let mut socket = time::timeout(IO_DEADLINE, UnixStream::connect(path))
        .await?
        .with_context(|| format!("connect to administration socket {}", path.display()))?;
    time::timeout(IO_DEADLINE, socket.write_all(command.as_bytes())).await??;
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await?;
    let mut response: Value =
        serde_json::from_slice(&bytes).context("invalid administration response")?;
    if response["ok"] == true {
        return Ok(response["result"].take());
    }
    bail!(
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("administration request rejected")
    );
}
