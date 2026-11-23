//! The configured directory is the destination's ref database. Replicas
//! and remote-tracking branches cannot establish that a push is absent.
use keygate_core::{git_land::GitLand, journal::TicketState};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio},
};

pub trait TargetStateProbe {
    fn observe(&self, land: &GitLand) -> io::Result<TicketState>;
}
pub struct GitRefProbe<'a>(pub &'a Path);
impl GitRefProbe<'_> {
    fn command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(self.0);
        cmd
    }
    fn git(&self, args: &[&str]) -> io::Result<Output> {
        self.command().args(args).output()
    }
}
impl TargetStateProbe for GitRefProbe<'_> {
    fn observe(&self, land: &GitLand) -> io::Result<TicketState> {
        if !land.valid() {
            return Err(io::Error::other("invalid CAS binding"));
        }
        let probe = self.git(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{}^{{commit}}", land.reference),
        ])?;
        if !probe.status.success() {
            return Err(io::Error::other("cannot read authoritative ref"));
        }
        let head = std::str::from_utf8(&probe.stdout)
            .map_err(io::Error::other)?
            .trim_end();

        if head == land.new_oid {
            return Ok(TicketState::Committed);
        }
        match self
            .git(&["merge-base", "--is-ancestor", &land.new_oid, head])?
            .status
            .code()
        {
            Some(0) => Ok(TicketState::Committed),
            Some(1) if head == land.expected_old => Ok(TicketState::SafeToRetry),
            Some(1) => Ok(TicketState::Uncertain),
            // A not-yet-received object cannot be in the observed history.
            _ if head == land.expected_old
                && self
                    .git(&[
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        &format!("{}^{{object}}", land.new_oid),
                    ])?
                    .status
                    .code()
                    == Some(1) =>
            {
                Ok(TicketState::SafeToRetry)
            }
            _ => Err(io::Error::other("cannot establish authoritative ancestry")),
        }
    }
}

/// A fresh positive witness for a direct loose branch. Git resolves the ref and
/// checks its object type on every request. The independent loose ref read
/// excludes cached or replaced refs. Other storage layouts and ancestry probes
/// use the complete single-shot verifier.
#[derive(Default)]
pub(crate) struct RefReaders(BTreeMap<PathBuf, Reader>);

struct Reader {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    directory: (u64, u64),
}
impl Drop for Reader {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Reader {
    fn open(path: &Path, directory: (u64, u64)) -> io::Result<Self> {
        let mut child = GitRefProbe(path)
            .command()
            .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            input: child.stdin.take().expect("piped stdin"),
            output: BufReader::new(child.stdout.take().expect("piped stdout")),
            child,
            directory,
        })
    }
    fn matches(&mut self, land: &GitLand) -> io::Result<bool> {
        writeln!(self.input, "{}^{{commit}}", land.reference)?;
        self.input.flush()?;
        let mut line = String::new();
        if self.output.read_line(&mut line)? == 0 {
            return Err(io::Error::other("git reader closed"));
        }
        Ok(line == format!("{} commit\n", land.new_oid))
    }
}
impl RefReaders {
    pub(crate) fn committed(&mut self, path: &Path, land: &GitLand) -> io::Result<bool> {
        if !land.valid() || path.join("commondir").exists() || path.join("reftable").exists() {
            return Ok(false);
        }
        let meta = fs::metadata(path)?;
        let directory = (meta.dev(), meta.ino());
        if self.0.get(path).map(|r| r.directory) != Some(directory) {
            self.0
                .insert(path.to_owned(), Reader::open(path, directory)?);
        }
        let result = self.0.get_mut(path).expect("opened reader").matches(land);
        if result.is_err() {
            self.0.remove(path);
        }
        if !result? {
            return Ok(false);
        }
        Ok(fs::read(path.join(&land.reference))
            .is_ok_and(|bytes| bytes == format!("{}\n", land.new_oid).as_bytes()))
    }
}
