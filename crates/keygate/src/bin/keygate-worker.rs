//! Length-framed worker pool. Each pool serves one attenuated authority.
//!
//! Before any worker starts, the supervisor verifies its sandbox toolchain
//! (prlimit, Bubblewrap and Node, each named by absolute path), and a worker
//! restarted after a timeout or crash runs only if those files are still the
//! ones it verified. The pool's macaroon admits only the rows and paths its
//! `--allow` operations need, and it never enters the jail.
use clap::Parser;
use keygate_broker::{
    client::Client,
    harden::{check_trusted_dirs, effective_uid},
    wire::{read_frame_limited, write_frame},
};
use keygate_core::{
    git_land::GitLand,
    journal::TicketId,
    macaroon::{Caveat, MacaroonError, MacaroonV1},
    proto::{Call, Request, Response, ServiceAuthorize},
    Namespace,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    error::Error,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::{ExitCode, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{mpsc, Mutex},
    time::timeout,
};
use zeroize::Zeroizing;

const LIMIT: usize = 65536;
/// One deadline spans compilation, every VM step, IPC and broker time.
const DEADLINE: Duration = Duration::from_millis(50);
const STARTUP: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(
    name = "keygate-worker",
    about = "Run JavaScript handlers in a sandboxed pool that holds one attenuated capability"
)]
struct Options {
    #[arg(long, required_unless_present = "check_toolchain_only")]
    socket: Option<PathBuf>,
    #[arg(long, required_unless_present = "check_toolchain_only")]
    token_file: Option<PathBuf>,
    #[arg(long, required_unless_present = "check_toolchain_only")]
    seat: Option<String>,
    /// Service row for pod claims and completions (needed when --allow names one).
    #[arg(long)]
    pod_row: Option<String>,
    /// Service row for Git land and reconcile (needed when --allow names one).
    #[arg(long)]
    git_row: Option<String>,
    #[arg(long, required_unless_present = "check_toolchain_only")]
    max_spend_micro_usd: Option<u64>,
    /// Operations granted to this pool (comma separated). The pool's macaroon
    /// admits only the rows and paths they need.
    #[arg(
        long,
        value_delimiter = ',',
        required_unless_present = "check_toolchain_only"
    )]
    allow: Vec<Operation>,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=32))]
    workers: u8,
    #[command(flatten)]
    toolchain: ToolchainOptions,
    /// Verify the toolchain, start one sandboxed worker, print the verified
    /// paths and SHA-256 digests as JSON and exit. Reads no token.
    #[arg(long)]
    check_toolchain_only: bool,
}

/// The sandbox toolchain. Each binary is named by absolute path and PATH is
/// never searched: whoever decides what a bare name resolves to would choose
/// the jail.
#[derive(clap::Args)]
struct ToolchainOptions {
    /// util-linux prlimit.
    #[arg(long, value_name = "ABS_PATH", default_value = "/usr/bin/prlimit", value_parser = absolute_path)]
    prlimit_bin: PathBuf,
    /// Bubblewrap. Where only profiled binaries may create user namespaces
    /// (Ubuntu's AppArmor restriction), name one that has a profile.
    #[arg(long, value_name = "ABS_PATH", default_value = "/usr/bin/bwrap", value_parser = absolute_path)]
    bwrap_bin: PathBuf,
    /// Node.js, bound read-only into each sandbox at its canonical path.
    #[arg(long, value_name = "ABS_PATH", default_value = "/usr/bin/node", value_parser = absolute_path)]
    node_bin: PathBuf,
    /// Expected SHA-256 of the prlimit binary (64 hex digits).
    #[arg(long, value_name = "HEX64", value_parser = sha256_hex)]
    prlimit_sha256: Option<Digest>,
    /// Expected SHA-256 of the Bubblewrap binary.
    #[arg(long, value_name = "HEX64", value_parser = sha256_hex)]
    bwrap_sha256: Option<Digest>,
    /// Expected SHA-256 of the Node binary.
    #[arg(long, value_name = "HEX64", value_parser = sha256_hex)]
    node_sha256: Option<Digest>,
    /// Directory bound read-only into each sandbox, for a Node whose shared
    /// libraries live outside /usr/lib (repeatable).
    #[arg(long = "node-lib-dir", value_name = "ABS_PATH", value_parser = absolute_path)]
    node_lib_dirs: Vec<PathBuf>,
}

type Digest = [u8; 32];

fn sha256_hex(text: &str) -> Result<Digest, String> {
    let mut digest = [0u8; 32];
    hex::decode_to_slice(text, &mut digest)
        .map_err(|_| "expected a SHA-256 digest of 64 hexadecimal digits".to_owned())?;
    Ok(digest)
}

/// Decided by spelling, before the filesystem is asked anything: a relative
/// path resolves against the caller's directory, and `..` climbs out of a
/// directory that no check looked at.
fn check_spelling(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(format!("{} has a `..` component", path.display()));
    }
    Ok(())
}

fn absolute_path(text: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(text);
    check_spelling(&path)?;
    Ok(path)
}

fn misspelt(flag: &str, why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{flag}: {why}"))
}

fn refused(flag: &str, path: &Path, why: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{flag} {}: {why}", path.display()),
    )
}

/// What `lstat` reports about a verified file. Writing to it, replacing it,
/// or changing its mode or owner changes at least one field, and `ctime`
/// cannot be set back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    uid: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Identity {
    fn of(meta: &Metadata) -> Self {
        Identity {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mode: meta.mode(),
            uid: meta.uid(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

/// A toolchain binary that passed every check, named by its canonical path.
#[derive(Debug)]
struct Binary {
    flag: &'static str,
    path: PathBuf,
    identity: Identity,
    sha256: Option<Digest>,
}

impl Binary {
    /// Only `uid` and root may be able to change the file or anything on its
    /// path. It must be a regular executable file owned by one of them that
    /// neither group nor others can write, in a directory neither can write,
    /// below directories [`check_trusted_dirs`] accepts. With a pin (or
    /// `digest`), its SHA-256 is computed from the file that was checked.
    fn verify(
        flag: &'static str,
        path: &Path,
        pin: Option<&Digest>,
        uid: u32,
        digest: bool,
    ) -> io::Result<Self> {
        check_spelling(path).map_err(|why| misspelt(flag, why))?;
        let canonical = std::fs::canonicalize(path).map_err(|e| refused(flag, path, e))?;
        let meta =
            std::fs::symlink_metadata(&canonical).map_err(|e| refused(flag, &canonical, e))?;
        let mode = meta.mode() & 0o7777;
        if !meta.is_file() {
            return Err(refused(flag, &canonical, "not a regular file"));
        }
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(refused(
                flag,
                &canonical,
                format!("owned by uid {}, who could replace it", meta.uid()),
            ));
        }
        if mode & 0o022 != 0 {
            return Err(refused(
                flag,
                &canonical,
                format!("mode {mode:o} lets others write it"),
            ));
        }
        if mode & 0o111 == 0 {
            return Err(refused(
                flag,
                &canonical,
                format!("mode {mode:o} is not executable"),
            ));
        }
        let dir = canonical
            .parent()
            .ok_or_else(|| refused(flag, &canonical, "has no directory"))?;
        let dir_mode = std::fs::symlink_metadata(dir)
            .map_err(|e| refused(flag, dir, e))?
            .mode()
            & 0o7777;
        if dir_mode & 0o022 != 0 {
            return Err(refused(
                flag,
                dir,
                format!("directory mode {dir_mode:o} lets others replace what is in it"),
            ));
        }
        check_trusted_dirs(dir, uid).map_err(|e| refused(flag, &canonical, e))?;
        let identity = Identity::of(&meta);
        let sha256 = if pin.is_some() || digest {
            Some(sha256_of(flag, &canonical, identity)?)
        } else {
            None
        };
        if let (Some(pin), Some(actual)) = (pin, sha256) {
            if *pin != actual {
                return Err(refused(
                    flag,
                    &canonical,
                    format!(
                        "SHA-256 is {}, not the pinned {}",
                        hex::encode(actual),
                        hex::encode(pin)
                    ),
                ));
            }
        }
        Ok(Binary {
            flag,
            path: canonical,
            identity,
            sha256,
        })
    }

    fn unchanged(&self) -> bool {
        std::fs::symlink_metadata(&self.path).is_ok_and(|meta| Identity::of(&meta) == self.identity)
    }
}

/// SHA-256 of the file verified as `identity`, read through one descriptor
/// that must be that same file before and after the read.
fn sha256_of(flag: &str, path: &Path, identity: Identity) -> io::Result<Digest> {
    let mut file = File::open(path).map_err(|e| refused(flag, path, e))?;
    let same = |file: &File| {
        file.metadata()
            .is_ok_and(|meta| Identity::of(&meta) == identity)
    };
    if !same(&file) {
        return Err(refused(flag, path, "changed while it was being verified"));
    }
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => context.update(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(refused(flag, path, e)),
        }
    }
    if !same(&file) {
        return Err(refused(flag, path, "changed while it was being verified"));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(context.finish().as_ref());
    Ok(digest)
}

/// A directory every sandbox can read: held to the binaries' custody rule.
fn verify_lib_dir(path: &Path, uid: u32) -> io::Result<PathBuf> {
    const FLAG: &str = "--node-lib-dir";
    check_spelling(path).map_err(|why| misspelt(FLAG, why))?;
    let canonical = std::fs::canonicalize(path).map_err(|e| refused(FLAG, path, e))?;
    let meta = std::fs::symlink_metadata(&canonical).map_err(|e| refused(FLAG, &canonical, e))?;
    let mode = meta.mode() & 0o7777;
    if !meta.is_dir() {
        return Err(refused(FLAG, &canonical, "not a directory"));
    }
    if mode & 0o022 != 0 {
        return Err(refused(
            FLAG,
            &canonical,
            format!("mode {mode:o} lets others replace what is in it"),
        ));
    }
    check_trusted_dirs(&canonical, uid).map_err(|e| refused(FLAG, &canonical, e))?;
    Ok(canonical)
}

/// The toolchain as verified at startup. Workers run only these files.
struct VerifiedToolchain {
    prlimit: Binary,
    bwrap: Binary,
    node: Binary,
    lib_dirs: Vec<PathBuf>,
}

impl VerifiedToolchain {
    /// `digest` also hashes binaries without a pin, for the startup report.
    fn verify(options: &ToolchainOptions, uid: u32, digest: bool) -> io::Result<Self> {
        let binary = |flag, path: &Path, pin: &Option<Digest>| {
            Binary::verify(flag, path, pin.as_ref(), uid, digest)
        };
        Ok(VerifiedToolchain {
            prlimit: binary(
                "--prlimit-bin",
                &options.prlimit_bin,
                &options.prlimit_sha256,
            )?,
            bwrap: binary("--bwrap-bin", &options.bwrap_bin, &options.bwrap_sha256)?,
            node: binary("--node-bin", &options.node_bin, &options.node_sha256)?,
            lib_dirs: options
                .node_lib_dirs
                .iter()
                .map(|dir| verify_lib_dir(dir, uid))
                .collect::<io::Result<_>>()?,
        })
    }

    /// Before a worker is restarted, each binary must still be the file that
    /// was verified. If one is not, the pool stops rather than run it.
    fn recheck(&self) -> io::Result<()> {
        match [&self.prlimit, &self.bwrap, &self.node]
            .into_iter()
            .find(|binary| !binary.unchanged())
        {
            None => Ok(()),
            Some(binary) => Err(refused(
                binary.flag,
                &binary.path,
                "changed after it was verified; restart the pool to verify it again",
            )),
        }
    }

    /// prlimit bounds the jail's address space, core dumps, descriptors and
    /// file size, then runs Bubblewrap, which gives Node private namespaces,
    /// no capabilities, an empty environment and a read-only root holding
    /// only the runtime.
    fn command(&self) -> Command {
        let node = &self.node.path;
        let mut sandbox = Command::new(&self.prlimit.path);
        sandbox
            .env_clear()
            .current_dir("/")
            .args(["--as=1073741824", "--core=0", "--nofile=64", "--fsize=0"])
            .arg(&self.bwrap.path)
            .args([
                "--unshare-all",
                "--unshare-user",
                "--disable-userns",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                "/usr/lib",
                "/usr/lib",
                "--symlink",
                "usr/lib",
                "/lib",
            ]);
        for dir in ["/usr/lib64", "/usr/share/nodejs"] {
            if Path::new(dir).is_dir() {
                sandbox.args(["--ro-bind", dir, dir]);
            }
        }
        if Path::new("/lib64").exists() {
            sandbox.args(["--symlink", "usr/lib64", "/lib64"]);
        }
        for dir in &self.lib_dirs {
            sandbox.arg("--ro-bind").arg(dir).arg(dir);
        }
        sandbox
            .arg("--ro-bind")
            .arg(node)
            .arg(node)
            .args(["--remount-ro", "/"])
            .arg(node)
            .args([
                "--jitless",
                "--max-old-space-size=48",
                "-e",
                include_str!("context.cjs"),
            ]);
        sandbox
    }

    fn report(&self) -> Value {
        let entry = |binary: &Binary| {
            json!({
                "path": binary.path.display().to_string(),
                "sha256": binary.sha256.map(hex::encode),
            })
        };
        json!({
            "prlimit": entry(&self.prlimit),
            "bwrap": entry(&self.bwrap),
            "node": entry(&self.node),
            "node_lib_dirs": self
                .lib_dirs
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>(),
        })
    }
}

/// An operation a pool can be granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Operation {
    /// Claim a pod task (`--pod-row`, `/pod/claim`).
    #[value(name = "pod.claim")]
    Claim,
    /// Complete a claimed pod task (`--pod-row`, `/pod/done`).
    #[value(name = "pod.done")]
    Done,
    /// Land a Git compare-and-swap (`--git-row`, `/git/land`).
    #[value(name = "git.land")]
    Land,
    /// Settle a land of unknown outcome (`--git-row`, `/git/land`).
    #[value(name = "git.reconcile")]
    Reconcile,
}

impl Operation {
    fn is_pod(self) -> bool {
        matches!(self, Operation::Claim | Operation::Done)
    }

    /// The service path the operation's broker call names. The broker sends
    /// a reconcile's land call through admission again before it probes the
    /// ref, so `git.reconcile` needs exactly the row and path of `git.land`.
    fn path(self) -> &'static str {
        match self {
            Operation::Claim => "/pod/claim",
            Operation::Done => "/pod/done",
            Operation::Land | Operation::Reconcile => "/git/land",
        }
    }
}

/// What one pool may do. Its macaroon names these rows and paths and nothing
/// else, so the token stays this narrow even outside the supervisor.
#[derive(Debug)]
struct Grant {
    operations: Vec<Operation>,
    pod_row: Option<String>,
    git_row: Option<String>,
}

impl Grant {
    fn new(
        allow: &[Operation],
        pod_row: Option<String>,
        git_row: Option<String>,
    ) -> Result<Self, String> {
        let mut operations = allow.to_vec();
        operations.sort_unstable();
        operations.dedup();
        if operations.is_empty() {
            return Err("--allow must name at least one operation".into());
        }
        let pod_row = match (operations.iter().any(|op| op.is_pod()), pod_row) {
            (false, _) => None,
            (true, Some(row)) => Some(row),
            (true, None) => {
                return Err("--allow names a pod operation, which needs --pod-row".into())
            }
        };
        let git_row = match (operations.iter().any(|op| !op.is_pod()), git_row) {
            (false, _) => None,
            (true, Some(row)) => Some(row),
            (true, None) => {
                return Err("--allow names a Git operation, which needs --git-row".into())
            }
        };
        Ok(Grant {
            operations,
            pod_row,
            git_row,
        })
    }

    /// The row a granted operation calls, or `None` if it is not granted.
    fn row(&self, op: Operation) -> Option<&str> {
        if !self.operations.contains(&op) {
            return None;
        }
        if op.is_pod() {
            self.pod_row.as_deref()
        } else {
            self.git_row.as_deref()
        }
    }

    /// The caveats come in a fixed order, and each list follows the
    /// operations' order, so equal grants make byte-identical tokens however
    /// `--allow` was written. Tickets belong to the exact token that opened
    /// them: a `git.reconcile` pool settles what a `git.land` pool with the
    /// same options left uncertain. Granting every operation reproduces the
    /// caveats of earlier releases, which narrowed nothing, so such a pool
    /// keeps its token across the upgrade.
    fn caveats(&self, seat: &str, max_spend_micro_usd: u64) -> Vec<Caveat> {
        let mut rows: Vec<String> = Vec::new();
        let mut paths: Vec<String> = Vec::new();
        for &op in &self.operations {
            if let Some(row) = self.row(op) {
                if !rows.iter().any(|r| r == row) {
                    rows.push(row.to_owned());
                }
            }
            if !paths.iter().any(|p| p == op.path()) {
                paths.push(op.path().to_owned());
            }
        }
        vec![
            Caveat::Seat(seat.to_owned()),
            Caveat::Namespace(Namespace::Service),
            Caveat::Rows(rows),
            Caveat::Methods(vec!["POST".into()]),
            Caveat::PathPrefixes(paths),
            Caveat::MaxSpendMicroUsd(max_spend_micro_usd),
        ]
    }
}

/// The pool's token: the operator's token narrowed to `grant`.
fn attenuate(
    raw: &str,
    seat: &str,
    grant: &Grant,
    max_spend_micro_usd: u64,
) -> Result<Zeroizing<String>, MacaroonError> {
    let mut token = MacaroonV1::decode(raw.trim())?;
    for caveat in grant.caveats(seat, max_spend_micro_usd) {
        token = token.attenuate(caveat)?;
    }
    Ok(Zeroizing::new(token.encode()))
}

/// The broker call for one granted operation.
fn service_call(
    token: &str,
    row: &str,
    op: Operation,
    body: &Value,
    request_id: String,
) -> serde_json::Result<Call> {
    Ok(Call {
        token: token.to_owned(),
        row: row.to_owned(),
        method: "POST".into(),
        path: op.path().into(),
        query: None,
        headers: if op.is_pod() {
            vec![("content-type".into(), "application/json".into())]
        } else {
            vec![]
        },
        body: serde_json::to_vec(body)?,
        request_id: Some(request_id),
        last_event_id: None,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: u64,
    source: String,
    #[serde(default)]
    input: Value,
}

struct Worker {
    _child: Child,
    reader: ChildStdout,
    writer: ChildStdin,
}
fn bad() -> io::Error {
    io::Error::other("invalid worker protocol")
}

impl Worker {
    /// Start a jailed Node from the verified toolchain and wait until it is
    /// ready. `stderr` receives what the jail itself reports.
    async fn start(toolchain: &VerifiedToolchain, stderr: Stdio) -> io::Result<Self> {
        let mut child = toolchain
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()?;
        let mut w = Self {
            reader: child.stdout.take().ok_or_else(bad)?,
            writer: child.stdin.take().ok_or_else(bad)?,
            _child: child,
        };
        let ready = timeout(STARTUP, w.frame()).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the worker was not ready within {STARTUP:?}"),
            )
        })??;
        if ready != json!({"ready":true}) {
            return Err(bad());
        }
        Ok(w)
    }
    async fn frame(&mut self) -> io::Result<Value> {
        let bytes = read_frame_limited(&mut self.reader, LIMIT)
            .await?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "the worker closed its output")
            })?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    async fn invoke(&mut self, job: &Job, bridge: &mut Bridge) -> io::Result<Value> {
        write_frame(&mut self.writer, job).await?;
        for _ in 0..64 {
            let msg = self.frame().await?;
            if msg["done"] == true {
                return Ok(json!({"ok":true,"value":msg["value"]}));
            }
            if msg["failed"] == true {
                return Ok(json!({"ok":false,"reason":"handler"}));
            }
            let answer = match serde_json::from_value(msg["effect"].clone()) {
                Ok(effect) => bridge.apply(effect).await?,
                Err(_) => json!({"ok":false}),
            };
            write_frame(&mut self.writer, &answer).await?;
        }
        Err(bad())
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", content = "body", deny_unknown_fields)]
enum Effect {
    #[serde(rename = "pod.claim")]
    Claim(PodClaim),
    #[serde(rename = "pod.done")]
    Done(PodDone),
    #[serde(rename = "git.land")]
    Land(GitRequest),
    #[serde(rename = "git.reconcile")]
    Reconcile(Reconcile),
}
impl Effect {
    fn operation(&self) -> Operation {
        match self {
            Effect::Claim(_) => Operation::Claim,
            Effect::Done(_) => Operation::Done,
            Effect::Land(_) => Operation::Land,
            Effect::Reconcile(_) => Operation::Reconcile,
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PodClaim {
    pod: String,
    task: String,
    lease_seconds: u32,
    request_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PodDone {
    pod: String,
    task: String,
    fencing_token: String,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitRequest {
    cas: GitLand,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconcile {
    cas: GitLand,
    request_id: String,
    ticket: TicketId,
}

struct Bridge {
    socket: Arc<PathBuf>,
    grant: Arc<Grant>,
    token: Arc<Zeroizing<String>>,
    client: Option<Client>,
}
impl Bridge {
    async fn call(&mut self, request: &Request) -> io::Result<Response> {
        if self.client.is_none() {
            self.client = Some(Client::connect(&self.socket).await?)
        }
        self.client.as_mut().expect("connected").call(request).await
    }
    async fn apply(&mut self, effect: Effect) -> io::Result<Value> {
        let op = effect.operation();
        let Some(row) = self.grant.row(op).map(str::to_owned) else {
            return Ok(json!({"ok":false}));
        };
        let mut ticket = None;
        let (body, id) = match effect {
            Effect::Claim(c) => (
                json!({"pod":c.pod,"task":c.task,"lease_seconds":c.lease_seconds}),
                c.request_id,
            ),
            Effect::Done(c) => (
                json!({"pod":c.pod,"task":c.task,"fencing_token":c.fencing_token}),
                c.request_id,
            ),
            Effect::Land(g) => (serde_json::to_value(g.cas)?, g.request_id),
            Effect::Reconcile(g) => {
                ticket = Some(g.ticket);
                (serde_json::to_value(g.cas)?, g.request_id)
            }
        };
        if id.is_empty() || id.len() > 128 {
            return Ok(json!({"ok":false}));
        }
        let call = service_call(&self.token, &row, op, &body, id)?;
        if let Some(ticket) = ticket {
            return Ok(
                match self
                    .call(&Request::ReconcileGitPush { ticket, call })
                    .await?
                {
                    Response::Authorized { state, .. } => json!({"ok":true,"state":state}),
                    _ => json!({"ok":false}),
                },
            );
        }
        let git = !op.is_pod();
        let ticket = if git {
            match self
                .call(&Request::ServiceAuthorize(ServiceAuthorize {
                    call: call.clone(),
                    stream: false,
                }))
                .await?
            {
                Response::Authorized { ticket, .. } => Some(ticket),
                _ => return Ok(json!({"ok":false})),
            }
        } else {
            None
        };
        match self.call(&Request::ServiceForward(call)).await? {
            Response::Reply { status, body, .. } if (200..300).contains(&status) => {
                if git {
                    return Ok(json!({"ok":true,"ticket":ticket}));
                }
                let fence = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|v| v["fencing_token"].as_str()?.parse::<i64>().ok());
                Ok(match fence {
                    Some(n) if n > 0 => json!({"ok":true,"fencing_token":n.to_string()}),
                    _ => json!({"ok":false}),
                })
            }
            _ => Ok(json!({"ok":false,"ticket":ticket})),
        }
    }
}

/// A pool's checked options.
struct Pool {
    socket: PathBuf,
    token: Zeroizing<String>,
    grant: Grant,
    workers: u8,
}

impl Pool {
    fn new(options: Options, toolchain: &VerifiedToolchain) -> Result<Self, Box<dyn Error>> {
        let (Some(socket), Some(token_file), Some(seat), Some(max_spend_micro_usd)) = (
            options.socket,
            options.token_file,
            options.seat,
            options.max_spend_micro_usd,
        ) else {
            return Err(
                "--socket, --token-file, --seat and --max-spend-micro-usd are required".into(),
            );
        };
        let grant = Grant::new(&options.allow, options.pod_row, options.git_row)?;
        // Every jail can read a library directory, so none may hold what the
        // supervisor keeps from the jail.
        if !toolchain.lib_dirs.is_empty() {
            for (flag, path) in [("--token-file", &token_file), ("--socket", &socket)] {
                let path = resolve(path).map_err(|e| format!("{flag} {}: {e}", path.display()))?;
                if let Some(dir) = toolchain.lib_dirs.iter().find(|dir| path.starts_with(dir)) {
                    return Err(format!(
                        "{flag} {} is inside --node-lib-dir {}, which every sandbox can read",
                        path.display(),
                        dir.display()
                    )
                    .into());
                }
            }
        }
        let raw = Zeroizing::new(
            std::fs::read_to_string(&token_file)
                .map_err(|e| format!("--token-file {}: {e}", token_file.display()))?,
        );
        let token = attenuate(&raw, &seat, &grant, max_spend_micro_usd)?;
        Ok(Pool {
            socket,
            token,
            grant,
            workers: options.workers,
        })
    }
}

/// `path` with every existing component resolved; a socket that does not
/// exist yet is resolved through its directory.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(e);
            };
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            Ok(std::fs::canonicalize(dir)?.join(name))
        }
        resolved => resolved,
    }
}

async fn serve(pool: Pool, toolchain: Arc<VerifiedToolchain>) -> Result<(), Box<dyn Error>> {
    let socket = Arc::new(pool.socket);
    let token = Arc::new(pool.token);
    let grant = Arc::new(pool.grant);
    let (send, recv) = mpsc::channel::<Job>(usize::from(pool.workers));
    let recv = Arc::new(Mutex::new(recv));
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..pool.workers {
        toolchain.recheck()?;
        let first = Worker::start(&toolchain, Stdio::null())
            .await
            .map_err(|e| {
                format!("the sandbox did not start ({e}); --check-toolchain-only shows why")
            })?;
        let mut bridge = Bridge {
            socket: socket.clone(),
            grant: grant.clone(),
            token: token.clone(),
            client: None,
        };
        let (recv, out, toolchain) = (recv.clone(), out.clone(), toolchain.clone());
        tasks.spawn(async move {
            let mut worker = Some(first);
            loop {
                let job = { recv.lock().await.recv().await };
                let Some(job) = job else { break };
                if worker.is_none() {
                    if let Err(changed) = toolchain.recheck() {
                        let reply = json!({"ok":false,"reason":"toolchain","id":job.id});
                        write_frame(&mut *out.lock().await, &reply).await?;
                        return Err(changed);
                    }
                    worker = Worker::start(&toolchain, Stdio::null()).await.ok();
                }
                let mut result = if let Some(w) = &mut worker {
                    match timeout(DEADLINE, w.invoke(&job, &mut bridge)).await {
                        Ok(Ok(value)) => value,
                        failure => {
                            worker.take();
                            bridge.client.take();
                            json!({"ok":false,"reason":if failure.is_err(){"timeout"}else{"worker"}})
                        }
                    }
                } else {
                    json!({"ok":false,"reason":"unavailable"})
                };
                result["id"] = job.id.into();
                write_frame(&mut *out.lock().await, &result).await?;
            }
            Ok::<_, io::Error>(())
        });
    }
    // The queue's receiver lives only in the worker tasks, so sending fails
    // once every one of them has stopped.
    drop(recv);
    write_frame(&mut *out.lock().await, &json!({"ready":true})).await?;
    let mut input = tokio::io::stdin();
    loop {
        tokio::select! {
            frame = read_frame_limited(&mut input, LIMIT) => {
                let Some(bytes) = frame? else { break };
                if send.send(serde_json::from_slice(&bytes)?).await.is_err() {
                    while let Some(ended) = tasks.join_next().await {
                        ended??;
                    }
                    return Err(bad().into());
                }
            }
            Some(ended) = tasks.join_next() => {
                // A worker task ends early only when the pool cannot go on.
                ended??;
                return Err(bad().into());
            }
        }
    }
    drop(send);
    while let Some(ended) = tasks.join_next().await {
        ended??;
    }
    Ok(())
}

async fn run(options: Options) -> Result<(), Box<dyn Error>> {
    let check_only = options.check_toolchain_only;
    let toolchain = VerifiedToolchain::verify(&options.toolchain, effective_uid(), check_only)?;
    if check_only {
        let worker = Worker::start(&toolchain, Stdio::inherit())
            .await
            .map_err(|e| format!("the sandbox did not start: {e}"))?;
        drop(worker);
        println!("{}", toolchain.report());
        return Ok(());
    }
    let pool = Pool::new(options, &toolchain)?;
    serve(pool, Arc::new(toolchain)).await
}

fn main() -> ExitCode {
    let options = Options::parse();
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Box::<dyn Error>::from)
        .and_then(|runtime| {
            let outcome = runtime.block_on(run(options));
            // Standard input is read by a blocking read that cannot be
            // cancelled. A pool that stops on its own must not wait for the
            // caller to write or close it.
            runtime.shutdown_background();
            outcome
        });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keygate-worker: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use keygate_broker::{Broker, BrokerOptions, Caller};
    use keygate_core::{
        config::Config,
        journal::CallKind,
        macaroon::RootId,
        proto::{Code, Refusal},
    };
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use Operation::{Claim, Done, Land, Reconcile};

    const OPERATOR: Caller = Caller { uid: Some(0) };
    const AGENT: Caller = Caller { uid: Some(4242) };
    /// SHA-256 of "abc" (FIPS 180-2, appendix B.1).
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn grant(allow: &[Operation]) -> Grant {
        Grant::new(allow, Some("pods".into()), Some("forge".into())).unwrap()
    }

    fn token(parent: &str, allow: &[Operation]) -> String {
        attenuate(parent, "ci", &grant(allow), 500)
            .unwrap()
            .to_string()
    }

    fn offline_parent() -> String {
        MacaroonV1::mint(
            &[7; 32],
            RootId {
                seat: "ci".into(),
                allowed_uid: None,
                root_epoch: 0,
                nonce: [1; 16],
            },
        )
        .encode()
    }

    /// The `Rows` and `PathPrefixes` a grant puts on its token.
    fn scope(grant: &Grant) -> (Vec<String>, Vec<String>) {
        let (mut rows, mut paths) = (None, None);
        for caveat in grant.caveats("ci", 500) {
            match caveat {
                Caveat::Rows(list) => rows = Some(list),
                Caveat::PathPrefixes(list) => paths = Some(list),
                _ => {}
            }
        }
        (rows.unwrap(), paths.unwrap())
    }

    #[test]
    fn grant_admits_only_the_rows_and_paths_its_operations_use() {
        let check = |allow: &[Operation], rows: &[&str], paths: &[&str]| {
            assert_eq!(
                scope(&grant(allow)),
                (strings(rows), strings(paths)),
                "{allow:?}"
            );
        };
        check(&[Claim], &["pods"], &["/pod/claim"]);
        check(&[Done], &["pods"], &["/pod/done"]);
        check(&[Land], &["forge"], &["/git/land"]);
        check(&[Reconcile], &["forge"], &["/git/land"]);
        check(
            &[Done, Claim, Done],
            &["pods"],
            &["/pod/claim", "/pod/done"],
        );
        check(
            &[Reconcile, Claim],
            &["pods", "forge"],
            &["/pod/claim", "/git/land"],
        );
        check(
            &[Reconcile, Land, Done, Claim],
            &["pods", "forge"],
            &["/pod/claim", "/pod/done", "/git/land"],
        );
        let shared = Grant::new(&[Land, Claim], Some("both".into()), Some("both".into())).unwrap();
        assert_eq!(
            scope(&shared),
            (strings(&["both"]), strings(&["/pod/claim", "/git/land"]))
        );
    }

    #[test]
    fn grant_needs_and_holds_only_the_rows_its_operations_use() {
        let missing = Grant::new(&[Claim], None, Some("forge".into())).unwrap_err();
        assert!(missing.contains("--pod-row"), "{missing}");
        let missing = Grant::new(&[Reconcile], Some("pods".into()), None).unwrap_err();
        assert!(missing.contains("--git-row"), "{missing}");
        assert!(Grant::new(&[], Some("pods".into()), None).is_err());

        let claim_only = grant(&[Claim]);
        assert_eq!(
            claim_only.git_row, None,
            "a row no operation uses is dropped"
        );
        assert_eq!(claim_only.row(Claim), Some("pods"));
        for op in [Done, Land, Reconcile] {
            assert_eq!(claim_only.row(op), None, "{op:?}");
        }
        let reconcile_only = Grant::new(&[Reconcile], None, Some("forge".into())).unwrap();
        assert_eq!(reconcile_only.row(Reconcile), Some("forge"));
        assert_eq!(reconcile_only.row(Land), None);
    }

    #[test]
    fn equal_grants_make_equal_tokens_and_the_full_grant_keeps_its_token() {
        let parent = offline_parent();
        let land = token(&parent, &[Land]);
        assert_eq!(
            token(&parent, &[Reconcile]),
            land,
            "reconcile can settle what land left uncertain"
        );
        assert_eq!(token(&parent, &[Reconcile, Land]), land);
        assert_eq!(
            token(&parent, &[Claim, Land]),
            token(&parent, &[Land, Claim])
        );
        assert_ne!(token(&parent, &[Claim]), token(&parent, &[Done]));

        // The caveats every pool carried before grants were narrowed.
        let mut earlier = MacaroonV1::decode(&parent).unwrap();
        for caveat in [
            Caveat::Seat("ci".into()),
            Caveat::Namespace(Namespace::Service),
            Caveat::Rows(strings(&["pods", "forge"])),
            Caveat::Methods(strings(&["POST"])),
            Caveat::PathPrefixes(strings(&["/pod/claim", "/pod/done", "/git/land"])),
            Caveat::MaxSpendMicroUsd(500),
        ] {
            earlier = earlier.attenuate(caveat).unwrap();
        }
        assert_eq!(
            token(&parent, &[Claim, Done, Land, Reconcile]),
            earlier.encode()
        );
    }

    fn raw(token: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(token.strip_prefix("kgm_").unwrap())
            .unwrap()
    }

    /// #tooth: a pool allowed only `pod.claim` holds a token the broker
    /// refuses for `pod.done` and `git.land`, and its holder cannot widen it.
    #[tokio::test]
    async fn tooth_pod_claim_token_is_refused_for_pod_done_and_git_land() {
        let state = tempfile::tempdir().unwrap();
        Broker::init_state(state.path()).unwrap();
        let config = Config::parse(
            r#"
[broker]
deployment = "development"
pod_seats = { pods = "ci" }
git_land_targets = { forge = "/srv/forge.git" }
[services.pods]
origin = "http://127.0.0.1:9"
methods = ["POST"]
buffered_paths = ["/pod"]
[services.forge]
origin = "http://127.0.0.1:9"
methods = ["POST"]
buffered_paths = ["/git/land"]
"#,
        )
        .unwrap();
        let broker = Broker::open(state.path(), config, BrokerOptions::default()).unwrap();
        let parent = broker.mint("ci", None, vec![], OPERATOR).unwrap();
        let claim_only = token(&parent, &[Claim]);
        let every = token(&parent, &[Claim, Done, Land, Reconcile]);

        // Exactly the calls the bridge sends for each operation.
        let authorize = |token: &str, op: Operation| -> Result<(), Refusal> {
            let (row, body) = match op {
                Claim => ("pods", json!({"pod":"batch","task":"1","lease_seconds":60})),
                Done => (
                    "pods",
                    json!({"pod":"batch","task":"1","fencing_token":"1"}),
                ),
                Land | Reconcile => (
                    "forge",
                    json!({"repo":"forge","reference":"refs/heads/main",
                           "expected_old":"a".repeat(40),"new_oid":"b".repeat(40)}),
                ),
            };
            let call = service_call(token, row, op, &body, format!("{op:?}")).unwrap();
            broker
                .authorize(Namespace::Service, AGENT, call, CallKind::Buffered)
                .map(drop)
        };
        let denied = |result: Result<(), Refusal>, why: &str| {
            let refusal = result.unwrap_err();
            assert_eq!(refusal.code, Code::Denied, "{refusal:?}");
            assert!(refusal.message.contains(why), "{refusal:?}");
        };

        // The broker and its configuration admit all three calls...
        for op in [Claim, Done, Land] {
            authorize(&every, op).unwrap();
        }
        // ...and the claim-only token admits exactly one of them.
        authorize(&claim_only, Claim).unwrap();
        denied(authorize(&claim_only, Done), "path /pod/done not under");
        denied(authorize(&claim_only, Land), "row \"forge\" not in");

        // Appending caveats only narrows: the claim-only caveats still bind.
        let appended = MacaroonV1::decode(&claim_only)
            .unwrap()
            .attenuate(Caveat::Rows(strings(&["pods", "forge"])))
            .unwrap()
            .attenuate(Caveat::PathPrefixes(strings(&["/pod/done", "/git/land"])))
            .unwrap()
            .encode();
        denied(authorize(&appended, Done), "path /pod/done not under");
        denied(authorize(&appended, Land), "row \"forge\" not in");

        // The wide caveat chain does not verify under the claim-only tag.
        let (wide, narrow) = (raw(&every), raw(&claim_only));
        let mut forged = wide[..wide.len() - 32].to_vec();
        forged.extend_from_slice(&narrow[narrow.len() - 32..]);
        let forged = format!("kgm_{}", URL_SAFE_NO_PAD.encode(forged));
        for op in [Done, Land] {
            assert_eq!(authorize(&forged, op).unwrap_err().code, Code::BadToken);
        }
    }

    /// A fresh temporary directory carries the umask's group bits; where
    /// that is 002 the custody checks (rightly) refuse what is inside it.
    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn fixture(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"abc").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn verify(path: &Path) -> io::Result<Binary> {
        Binary::verify("--node-bin", path, None, effective_uid(), false)
    }

    #[test]
    fn toolchain_paths_are_judged_by_spelling_before_any_lookup() {
        for path in ["node", "bin/node", "./node", "/nonexistent/../usr/bin/node"] {
            let err = verify(Path::new(path)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{path}: {err}");
        }
        let parse = |args: &[&str]| {
            Options::try_parse_from(
                ["keygate-worker", "--check-toolchain-only"]
                    .iter()
                    .chain(args),
            )
        };
        assert!(parse(&[]).is_ok());
        for (flag, path) in [
            ("--node-bin", "node"),
            ("--bwrap-bin", "/usr/bin/../bin/bwrap"),
            ("--prlimit-bin", "usr/bin/prlimit"),
            ("--node-lib-dir", "/opt/../usr/lib"),
        ] {
            assert!(parse(&[flag, path]).is_err(), "{flag} {path}");
        }
    }

    #[test]
    fn toolchain_binaries_are_regular_executables_only_their_owner_can_change() {
        let dir = private_dir();
        let good = verify(&fixture(dir.path(), "node", 0o755)).unwrap();
        assert_eq!(
            good.path,
            std::fs::canonicalize(dir.path().join("node")).unwrap()
        );
        for mode in [0o775, 0o757, 0o777, 0o666, 0o722] {
            let err = verify(&fixture(dir.path(), &format!("open-{mode:o}"), mode)).unwrap_err();
            assert!(
                err.to_string().contains("lets others write it"),
                "{mode:o}: {err}"
            );
        }
        let err = verify(&fixture(dir.path(), "plain", 0o644)).unwrap_err();
        assert!(err.to_string().contains("not executable"), "{err}");
        let err = verify(dir.path()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");

        // A symlink is resolved once; what runs is its target.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&good.path, &link).unwrap();
        assert_eq!(verify(&link).unwrap().path, good.path);

        let uid = effective_uid();
        if uid != 0 {
            let err = Binary::verify("--node-bin", &good.path, None, uid + 1, false).unwrap_err();
            assert!(err.to_string().contains("owned by uid"), "{err}");
        }

        // Others who can write the directory can swap the file, sticky or not.
        for mode in [0o777, 0o775, 0o1777] {
            let shared = dir.path().join(format!("shared-{mode:o}"));
            std::fs::create_dir(&shared).unwrap();
            let node = fixture(&shared, "node", 0o755);
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = verify(&node).unwrap_err();
            assert!(
                err.to_string().contains("directory mode"),
                "{mode:o}: {err}"
            );
        }
    }

    #[test]
    fn a_pinned_binary_must_match_its_sha256() {
        let abc = sha256_hex(ABC_SHA256).unwrap();
        let dir = private_dir();
        let path = fixture(dir.path(), "node", 0o755);
        let uid = effective_uid();
        let pinned = Binary::verify("--node-bin", &path, Some(&abc), uid, false).unwrap();
        assert_eq!(pinned.sha256, Some(abc));
        let reported = Binary::verify("--node-bin", &path, None, uid, true).unwrap();
        assert_eq!(reported.sha256, Some(abc));
        assert_eq!(
            verify(&path).unwrap().sha256,
            None,
            "unpinned files are not read"
        );

        let mut wrong = abc;
        wrong[31] ^= 1;
        let err = Binary::verify("--node-bin", &path, Some(&wrong), uid, false).unwrap_err();
        assert!(err.to_string().contains("SHA-256"), "{err}");

        for text in [
            String::new(),
            "ba78".into(),
            "g".repeat(64),
            format!("{ABC_SHA256}00"),
        ] {
            assert!(sha256_hex(&text).is_err(), "{text}");
        }
        assert_eq!(sha256_hex(&ABC_SHA256.to_uppercase()), Ok(abc));
    }

    #[test]
    fn recheck_notices_a_rewritten_replaced_or_rechmodded_binary() {
        let dir = private_dir();
        let verified = |name: &str| verify(&fixture(dir.path(), name, 0o755)).unwrap();
        assert!(verified("kept").unchanged());

        let rewritten = verified("rewritten");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&rewritten.path)
            .unwrap()
            .write_all(b"d")
            .unwrap();
        assert!(!rewritten.unchanged());

        let replaced = verified("replaced");
        std::fs::rename(fixture(dir.path(), "same-bytes", 0o755), &replaced.path).unwrap();
        assert!(!replaced.unchanged(), "same bytes, different file");

        let rechmodded = verified("rechmodded");
        std::fs::set_permissions(&rechmodded.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!rechmodded.unchanged());
    }

    #[test]
    fn library_directories_are_held_to_the_same_custody() {
        let dir = private_dir();
        let uid = effective_uid();
        let lib = dir.path().join("lib");
        std::fs::create_dir(&lib).unwrap();
        std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            verify_lib_dir(&lib, uid).unwrap(),
            std::fs::canonicalize(&lib).unwrap()
        );
        std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(verify_lib_dir(&lib, uid).is_err());
        let file = fixture(dir.path(), "file", 0o755);
        assert!(verify_lib_dir(&file, uid).is_err());
        let err = verify_lib_dir(Path::new("lib"), uid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
