use crate::{
    config::Config,
    firewall::{self, Activation},
};
use std::io;
use tokio::{sync::Notify, task::JoinHandle};

static RECONNECT: Notify = Notify::const_new();
static SHUTDOWN: Notify = Notify::const_new();

pub async fn reconnect() {
    RECONNECT.notified().await;
}
pub async fn shutdown() {
    SHUTDOWN.notified().await;
}

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn signals() -> io::Result<Task> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut intr = signal(SignalKind::interrupt())?;
        let mut hangup = signal(SignalKind::hangup())?;
        let mut quit = signal(SignalKind::quit())?;
        Ok(Task(tokio::spawn(async move {
            tokio::select! {_ = term.recv()=>{}, _ = intr.recv()=>{}, _=hangup.recv()=>{}, _=quit.recv()=>{}};
            SHUTDOWN.notify_one();
        })))
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c};
        let mut intr = ctrl_c()?;
        let mut brk = ctrl_break()?;
        Ok(Task(tokio::spawn(async move {
            tokio::select! {_ = intr.recv()=>{}, _ = brk.recv()=>{}};
            SHUTDOWN.notify_one();
        })))
    }
}

#[cfg(unix)]
mod fifo {
    use super::{Task, RECONNECT};
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{self, Read},
        os::unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
    };
    use tokio::io::unix::AsyncFd;

    struct Created {
        path: PathBuf,
        device: u64,
        inode: u64,
    }
    impl Drop for Created {
        fn drop(&mut self) {
            if fs::symlink_metadata(&self.path).is_ok_and(|m| {
                m.file_type().is_fifo() && m.dev() == self.device && m.ino() == self.inode
            }) {
                if let Err(e) = fs::remove_file(&self.path) {
                    crate::log!(3, "FIFO cleanup: {e}");
                }
            }
        }
    }

    pub(super) struct Pipe {
        _task: Task,
        _created: Option<Created>,
    }
    impl Pipe {
        pub(super) fn open(path: &Path, server: bool) -> io::Result<Self> {
            let name = CString::new(path.as_os_str().as_bytes())?;
            // mkfifo only creates a new name. O_NOFOLLOW avoids following a
            // replacement symlink when opening a caller-provided FIFO.
            let created = if unsafe { libc::mkfifo(name.as_ptr(), 0o666) } == 0 {
                let m = fs::symlink_metadata(path)?;
                Some(Created {
                    path: path.into(),
                    device: m.dev(),
                    inode: m.ino(),
                })
            } else {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e);
                }
                None
            };
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open(path)?;
            if !file.metadata()?.file_type().is_fifo() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--fifo requires a named pipe",
                ));
            }
            // SAFETY: AsyncFd exclusively owns the File, whose descriptor stays
            // open and unchanged until the registration is dropped.
            let fd = unsafe { AsyncFd::register(file) }?;
            let handle = tokio::spawn(async move {
                if let Err(e) = read_commands(fd, server).await {
                    crate::log!(2, "FIFO reader stopped: {e}");
                }
            });
            Ok(Self {
                _task: Task(handle),
                _created: created,
            })
        }
    }
    async fn read_commands(fd: AsyncFd<File>, server: bool) -> io::Result<()> {
        let mut buf = [0; 1024];
        let mut line = Vec::new();
        let mut discard = false;
        loop {
            let mut ready = fd.readable().await?;
            let n = match ready.try_io(|fd| fd.get_ref().read(&mut buf)) {
                Ok(result) => result?,
                Err(_) => continue,
            };
            if n == 0 {
                return Ok(());
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    if !discard {
                        let command = String::from_utf8_lossy(&line);
                        match command.trim() {
                            "reconnect" if !server => RECONNECT.notify_one(),
                            "" => {}
                            _ => crate::log!(3, "unrecognized FIFO command"),
                        }
                    }
                    line.clear();
                    discard = false;
                } else if !discard {
                    if line.len() == 1024 {
                        discard = true;
                        crate::log!(3, "FIFO command is too long");
                    } else {
                        line.push(b);
                    }
                }
            }
            // The original CLI also accepts a single write without a newline.
            if !server && !discard && line == b"reconnect" {
                RECONNECT.notify_one();
                line.clear();
            }
        }
    }
}

pub struct Services {
    #[cfg(unix)]
    _fifo: Option<fifo::Pipe>,
    _firewall: Option<firewall::Firewall>,
    _signals: Task,
}

pub async fn start(c: &Config) -> io::Result<Option<Services>> {
    let sig = signals()?;
    let Activation::Run(firewall) = firewall::activate(c)? else {
        return Ok(None);
    };
    #[cfg(unix)]
    let fifo = c
        .fifo
        .as_ref()
        .map(|path| fifo::Pipe::open(path, c.server))
        .transpose()?;
    #[cfg(windows)]
    if c.fifo.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "named-pipe control requires Unix",
        ));
    }
    Ok(Some(Services {
        #[cfg(unix)]
        _fifo: fifo,
        _firewall: firewall,
        _signals: sig,
    }))
}
