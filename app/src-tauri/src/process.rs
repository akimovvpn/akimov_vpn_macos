//! A pipe-owning supervisor stops local cores even after the app is forcibly terminated.
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

enum Owner {
    Local {
        child: Child,
        pipe: Option<ChildStdin>,
    },
    Service(crate::service::Session),
}
pub struct Process(Owner);

impl Process {
    pub fn spawn(
        exe: &Path,
        dir: &Path,
        cfg: &Path,
        log: &Path,
        elevate: bool,
    ) -> Result<Self, String> {
        if elevate {
            return Ok(Self(Owner::Service(crate::service::start(
                &std::fs::read_to_string(cfg).map_err(|e| e.to_string())?,
            )?)));
        }
        Self::local(
            &std::env::current_exe().map_err(|e| e.to_string())?,
            exe,
            dir,
            cfg,
            log,
        )
    }
    fn local(
        supervisor: &Path,
        exe: &Path,
        dir: &Path,
        cfg: &Path,
        log: &Path,
    ) -> Result<Self, String> {
        let mut child = Command::new(supervisor)
            .arg("--core-supervisor")
            .arg(exe)
            .arg(dir)
            .arg(cfg)
            .arg(log)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let pipe = child.stdin.take();
        Ok(Self(Owner::Local { child, pipe }))
    }
    pub fn kill(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            Owner::Local { pipe, .. } => {
                pipe.take();
                Ok(())
            }
            Owner::Service(session) => session.stop().map_err(std::io::Error::other),
        }
    }
    pub fn wait(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            Owner::Local { child, .. } => child.wait().map(|_| ()),
            Owner::Service(_) => Ok(()),
        }
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<u32>> {
        match &mut self.0 {
            Owner::Local { child, .. } => child
                .try_wait()
                .map(|s| s.map(|s| s.code().unwrap_or(-1) as u32)),
            Owner::Service(session) => session
                .alive()
                .map(|alive| if alive { None } else { Some(0) })
                .map_err(std::io::Error::other),
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}

pub fn supervise(args: &[std::ffi::OsString]) -> Result<(), String> {
    use std::io::Read;
    if args.len() != 4 {
        return Err("Invalid core supervisor arguments.".into());
    }
    let log = std::fs::File::create(&args[3]).map_err(|e| e.to_string())?;
    let mut child = Command::new(&args[0])
        .arg("-d")
        .arg(&args[1])
        .arg("-f")
        .arg(&args[2])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| e.to_string())?;
    let (closed, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = std::io::stdin().read(&mut [0]);
        let _ = closed.send(());
    });
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        if receiver.recv_timeout(Duration::from_millis(100)).is_ok() {
            break;
        }
    }
    terminate(&mut child);
    Ok(())
}

pub fn terminate(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn termination_reaps_the_owned_child() {
        let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        assert!(child.try_wait().unwrap().is_none());
        terminate(&mut child);
        assert!(child.try_wait().unwrap().is_some());
    }
}
