//! `#tooth`: the `keygate-worker` binary end to end. Toolchain checks refuse
//! before anything runs, on any Unix. On Linux a real pool runs handlers in
//! Bubblewrap from the verified toolchain, holds only its grant, and stops
//! when a binary it verified is replaced.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn worker() -> Command {
    Command::new(env!("CARGO_BIN_EXE_keygate-worker"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run a command that must fail, and return what it said.
fn refused(command: &mut Command) -> String {
    let output = command.stdin(Stdio::null()).output().unwrap();
    assert!(!output.status.success(), "accepted: {}", stderr(&output));
    stderr(&output)
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A fresh temporary directory carries the umask's group bits; where that
/// is 002 the custody checks (rightly) refuse what is inside it.
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    chmod(dir.path(), 0o700);
    dir
}

/// SHA-256 of "abc" (FIPS 180-2, appendix B.1), the stand-ins' contents.
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// Stand-ins for prlimit, bwrap and node in a private directory: they pass
/// every check except actually running.
fn stand_ins() -> (tempfile::TempDir, [PathBuf; 3]) {
    let dir = private_dir();
    let tools = ["prlimit", "bwrap", "node"].map(|name| {
        let path = dir.path().join(name);
        std::fs::write(&path, b"abc").unwrap();
        chmod(&path, 0o755);
        path
    });
    (dir, tools)
}

fn toolchain<'a>(
    command: &'a mut Command,
    [prlimit, bwrap, node]: &[PathBuf; 3],
) -> &'a mut Command {
    command
        .arg("--prlimit-bin")
        .arg(prlimit)
        .arg("--bwrap-bin")
        .arg(bwrap)
        .arg("--node-bin")
        .arg(node)
}

const POOL: [&str; 8] = [
    "--seat",
    "ci",
    "--max-spend-micro-usd",
    "5",
    "--allow",
    "pod.claim",
    "--pod-row",
    "pods",
];

#[test]
fn tooth_relative_or_climbing_toolchain_paths_are_refused_before_any_lookup() {
    for (flag, path) in [
        ("--node-bin", "node"),
        ("--bwrap-bin", "/usr/bin/../bin/bwrap"),
        ("--prlimit-bin", "./prlimit"),
        ("--node-lib-dir", "lib"),
    ] {
        let said = refused(worker().args(["--check-toolchain-only", flag, path]));
        assert!(
            said.contains(path) && (said.contains("absolute") || said.contains("`..`")),
            "{flag} {path}: {said}"
        );
    }
    // A pool refuses the same way, before it reads its token.
    let said = refused(
        worker()
            .args(POOL)
            .args(["--socket", "/nonexistent/keygate.sock"])
            .args(["--token-file", "/nonexistent/token"])
            .args(["--node-bin", "node"]),
    );
    assert!(
        said.contains("absolute") && !said.contains("token"),
        "{said}"
    );
}

#[test]
fn tooth_writable_or_mispinned_toolchain_is_refused() {
    let (_dir, tools) = stand_ins();
    let node = &tools[2];
    for mode in [0o666, 0o777, 0o775] {
        chmod(node, mode);
        let said = refused(toolchain(worker().arg("--check-toolchain-only"), &tools));
        assert!(
            said.contains("--node-bin") && said.contains("lets others write it"),
            "{mode:o}: {said}"
        );
    }
    chmod(node, 0o755);
    let wrong = format!("{}0", &ABC_SHA256[..63]);
    let said = refused(toolchain(
        worker().args(["--check-toolchain-only", "--node-sha256", &wrong]),
        &tools,
    ));
    assert!(
        said.contains("--node-bin") && said.contains("SHA-256"),
        "{said}"
    );
    // With the right pins every check passes; only running the stand-ins fails.
    let said = refused(toolchain(
        worker().args(["--check-toolchain-only"]).args([
            "--prlimit-sha256",
            ABC_SHA256,
            "--bwrap-sha256",
            ABC_SHA256,
            "--node-sha256",
            ABC_SHA256,
        ]),
        &tools,
    ));
    assert!(said.contains("the sandbox did not start"), "{said}");
}

#[test]
fn tooth_library_directory_may_not_expose_the_token_or_the_socket() {
    let (_dir, tools) = stand_ins();
    let secrets = private_dir();
    let token = secrets.path().join("token");
    std::fs::write(&token, "kgm_never_read").unwrap();
    let elsewhere = private_dir();
    for (token, socket, flag) in [
        (
            token.clone(),
            elsewhere.path().join("keygate.sock"),
            "--token-file",
        ),
        (
            elsewhere.path().join("token"),
            secrets.path().join("keygate.sock"),
            "--socket",
        ),
    ] {
        let said = refused(
            toolchain(&mut worker(), &tools)
                .args(POOL)
                .arg("--token-file")
                .arg(&token)
                .arg("--socket")
                .arg(&socket)
                .arg("--node-lib-dir")
                .arg(secrets.path()),
        );
        assert!(
            said.contains(flag) && said.contains("which every sandbox can read"),
            "{flag}: {said}"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use keygate_core::macaroon::{MacaroonV1, RootId};
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::process::{Child, ExitStatus};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(20);

    /// Hosts where only profiled binaries may create user namespaces
    /// (Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`) name such a
    /// bwrap in `KEYGATE_WORKER_TEST_BWRAP`.
    fn bwrap() -> PathBuf {
        std::env::var_os("KEYGATE_WORKER_TEST_BWRAP")
            .map_or_else(|| PathBuf::from("/usr/bin/bwrap"), PathBuf::from)
    }

    /// The worker needs a Node whose `vm` has `DONT_CONTEXTIFY`; hosts whose
    /// system Node predates it name another in `KEYGATE_WORKER_TEST_NODE`.
    fn node() -> PathBuf {
        std::env::var_os("KEYGATE_WORKER_TEST_NODE")
            .map_or_else(|| PathBuf::from("/usr/bin/node"), PathBuf::from)
    }

    fn can_dont_contextify(node: &Path) -> bool {
        Command::new(node)
            .args([
                "-e",
                "process.exit(require('vm').constants?.DONT_CONTEXTIFY ? 0 : 1)",
            ])
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Whether this host can build the jail, asked of the tools directly so
    /// that a broken worker cannot pass for a host without support.
    fn host_can_jail() -> bool {
        if !Path::new("/usr/bin/prlimit").exists() {
            eprintln!("SKIPPED: /usr/bin/prlimit is not installed");
            return false;
        }
        if !can_dont_contextify(&node()) {
            eprintln!(
                "SKIPPED: {} is missing or lacks vm.constants.DONT_CONTEXTIFY; set \
                 KEYGATE_WORKER_TEST_NODE to a Node that has it",
                node().display()
            );
            return false;
        }
        let probe = Command::new(bwrap())
            .args(["--unshare-all", "--unshare-user", "--die-with-parent"])
            .args(["--ro-bind", "/", "/", "true"])
            .output();
        match probe {
            Ok(probe) if probe.status.success() => true,
            Ok(probe) => {
                eprintln!(
                    "SKIPPED: {} cannot build the jail here ({}); set KEYGATE_WORKER_TEST_BWRAP \
                     to a bwrap that may create user namespaces",
                    bwrap().display(),
                    stderr(&probe).trim()
                );
                false
            }
            Err(e) => {
                eprintln!("SKIPPED: {} is not available: {e}", bwrap().display());
                false
            }
        }
    }

    fn check(node: &Path, extra: &[&str]) -> Output {
        worker()
            .arg("--check-toolchain-only")
            .arg("--bwrap-bin")
            .arg(bwrap())
            .arg("--node-bin")
            .arg(node)
            .args(extra)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    #[test]
    fn tooth_check_toolchain_only_reports_digests_that_pin_the_real_toolchain() {
        if !host_can_jail() {
            return;
        }
        let output = check(&node(), &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut pins = Vec::new();
        for (role, flag) in [
            ("prlimit", "--prlimit-sha256"),
            ("bwrap", "--bwrap-sha256"),
            ("node", "--node-sha256"),
        ] {
            let path = report[role]["path"].as_str().unwrap();
            assert_eq!(
                Path::new(path),
                std::fs::canonicalize(path).unwrap(),
                "{role}"
            );
            let digest = report[role]["sha256"].as_str().unwrap().to_owned();
            assert_eq!(digest.len(), 64, "{role}");
            pins.push((flag, digest));
        }
        let args: Vec<&str> = pins.iter().flat_map(|(f, d)| [*f, d.as_str()]).collect();
        let pinned = check(&node(), &args);
        assert!(pinned.status.success(), "{}", stderr(&pinned));

        let pinned_node = &pins[2].1;
        let wrong = format!(
            "{}{}",
            &pinned_node[..63],
            if pinned_node.ends_with('0') { '1' } else { '0' }
        );
        let mispinned = check(&node(), &["--node-sha256", &wrong]);
        assert!(!mispinned.status.success());
        assert!(
            stderr(&mispinned).contains("SHA-256"),
            "{}",
            stderr(&mispinned)
        );
    }

    #[test]
    fn tooth_check_toolchain_only_refuses_a_node_without_dont_contextify() {
        let system = Path::new("/usr/bin/node");
        if !host_can_jail() {
            return;
        }
        if !system.exists() || can_dont_contextify(system) {
            eprintln!("SKIPPED: this host has no older system Node to refuse");
            return;
        }
        let output = check(system, &[]);
        assert!(!output.status.success());
        let said = stderr(&output);
        assert!(
            said.contains("DONT_CONTEXTIFY") && said.contains("the sandbox did not start"),
            "{said}"
        );
    }

    /// A running pool on framed pipes.
    struct Pool {
        child: Option<Child>,
        frames: mpsc::Receiver<Value>,
    }

    impl Pool {
        fn start(command: &mut Command) -> Pool {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdout = child.stdout.take().unwrap();
            let (send, frames) = mpsc::channel();
            std::thread::spawn(move || loop {
                let mut size = [0u8; 4];
                if stdout.read_exact(&mut size).is_err() {
                    return;
                }
                let mut body = vec![0u8; u32::from_be_bytes(size) as usize];
                if stdout.read_exact(&mut body).is_err() {
                    return;
                }
                if send.send(serde_json::from_slice(&body).unwrap()).is_err() {
                    return;
                }
            });
            let pool = Pool {
                child: Some(child),
                frames,
            };
            assert_eq!(pool.next(), json!({"ready": true}));
            pool
        }

        fn next(&self) -> Value {
            self.frames
                .recv_timeout(WAIT)
                .expect("the pool sent no frame")
        }

        fn run(&mut self, id: u64, source: &str, input: Value) -> Value {
            let job =
                serde_json::to_vec(&json!({"id": id, "source": source, "input": input})).unwrap();
            let stdin = self.child.as_mut().unwrap().stdin.as_mut().unwrap();
            stdin.write_all(&(job.len() as u32).to_be_bytes()).unwrap();
            stdin.write_all(&job).unwrap();
            stdin.flush().unwrap();
            self.next()
        }

        /// Wait for the pool to exit on its own.
        fn exited(mut self) -> (ExitStatus, String) {
            let mut child = self.child.take().unwrap();
            let deadline = Instant::now() + WAIT;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the pool did not exit");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let mut said = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut said)
                .unwrap();
            (status, said)
        }
    }

    impl Drop for Pool {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// A pool granted only `pod.claim` (though told the Git row too), with
    /// a well-formed token and no broker behind its socket.
    fn claim_pool(dir: &Path, node: &Path) -> Command {
        let token = MacaroonV1::mint(
            &[3; 32],
            RootId {
                seat: "ci".into(),
                allowed_uid: None,
                root_epoch: 0,
                nonce: [5; 16],
            },
        )
        .encode();
        std::fs::write(dir.join("token"), token).unwrap();
        let mut command = worker();
        command
            .args(POOL)
            .args(["--git-row", "forge", "--workers", "1"])
            .arg("--token-file")
            .arg(dir.join("token"))
            .arg("--socket")
            .arg(dir.join("no-broker.sock"))
            .arg("--bwrap-bin")
            .arg(bwrap())
            .arg("--node-bin")
            .arg(node);
        command
    }

    #[test]
    fn tooth_pool_runs_handlers_in_the_jail_and_holds_only_its_grant() {
        if !host_can_jail() {
            return;
        }
        let dir = private_dir();
        let mut pool = Pool::start(&mut claim_pool(dir.path(), &node()));
        assert_eq!(
            pool.run(1, "return input + 2", json!(40)),
            json!({"id": 1, "ok": true, "value": 42})
        );
        assert_eq!(
            pool.run(
                2,
                "return [typeof process, typeof require, typeof fetch]",
                Value::Null
            )["value"],
            json!(["undefined", "undefined", "undefined"])
        );
        // The supervisor answers operations outside the grant itself; the
        // handler sees a refusal and carries on.
        let cas = json!({"repo": "forge", "reference": "refs/heads/main",
                         "expected_old": "a".repeat(40), "new_oid": "b".repeat(40)});
        for (id, source, input) in [
            (
                3,
                "return yield caps.pod.done(input)",
                json!({"pod": "p", "task": "t", "fencing_token": "1", "request_id": "r"}),
            ),
            (
                4,
                "return yield caps.git.land(input)",
                json!({"cas": cas, "request_id": "r"}),
            ),
            (
                5,
                "return yield caps.git.reconcile(input)",
                json!({"cas": cas, "request_id": "r", "ticket": "0".repeat(32)}),
            ),
        ] {
            assert_eq!(
                pool.run(id, source, input),
                json!({"id": id, "ok": true, "value": {"ok": false}}),
                "{source}"
            );
        }
        // The granted operation goes to the broker, and there is none.
        let claim = pool.run(
            6,
            "return yield caps.pod.claim(input)",
            json!({"pod": "p", "task": "t", "lease_seconds": 60, "request_id": "r"}),
        );
        assert_eq!(claim, json!({"id": 6, "ok": false, "reason": "worker"}));
        // A runaway handler is cut at the deadline and its worker replaced.
        assert_eq!(pool.run(7, "for(;;){}", Value::Null)["reason"], "timeout");
        assert_eq!(
            pool.run(8, "return 1", Value::Null),
            json!({"id": 8, "ok": true, "value": 1})
        );
    }

    #[test]
    fn tooth_pool_stops_instead_of_restarting_a_replaced_binary() {
        if !host_can_jail() {
            return;
        }
        let dir = private_dir();
        let copy = dir.path().join("node");
        std::fs::copy(node(), &copy).unwrap();
        chmod(&copy, 0o755);
        let mut pool = Pool::start(&mut claim_pool(dir.path(), &copy));
        assert_eq!(pool.run(1, "return 7", Value::Null)["value"], 7);

        let same_bytes = dir.path().join("same-bytes");
        std::fs::copy(node(), &same_bytes).unwrap();
        chmod(&same_bytes, 0o755);
        std::fs::rename(&same_bytes, &copy).unwrap();
        // The live worker keeps serving; the change matters at a restart.
        assert_eq!(pool.run(2, "return 8", Value::Null)["value"], 8);
        assert_eq!(pool.run(3, "for(;;){}", Value::Null)["reason"], "timeout");
        assert_eq!(
            pool.run(4, "return 9", Value::Null),
            json!({"id": 4, "ok": false, "reason": "toolchain"})
        );
        let (status, said) = pool.exited();
        assert!(!status.success());
        assert!(
            said.contains("--node-bin") && said.contains("changed after it was verified"),
            "{said}"
        );
    }
}
