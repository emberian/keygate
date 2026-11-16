//! `#tooth`: the `keygate` binary end to end. A real daemon process, the
//! real CLI, and a one-thread HTTP upstream.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRET: &str = "ghp_cli_secret_0123456789";

/// Answers every request with a fixed body and records the request heads.
fn upstream() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            seen.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).to_ascii_lowercase());
            let body = br#"{"full_name":"o/r"}"#;
            let _ = write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
            let _ = stream.write_all(body);
        }
    });
    (origin, heads)
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn keygate(state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_keygate"));
    command
        .arg("--state")
        .arg(state)
        .env_remove("KEYGATE_TOKEN")
        .env_remove("KEYGATE_SOCKET");
    command
}

fn run(command: &mut Command, stdin: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn ok(command: &mut Command, stdin: &str) -> String {
    let output = run(command, stdin);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn tooth_cli_init_serve_set_mint_attenuate_forward_revoke() {
    let (origin, heads) = upstream();
    let dir = private_tempdir();
    let state = dir.path().join("state");

    assert!(ok(keygate(&state).arg("init"), "").contains("initialized"));
    assert!(
        !run(keygate(&state).arg("init"), "").status.success(),
        "init must not clobber an existing master key"
    );
    std::fs::write(
        state.join("keygate.toml"),
        format!("[broker]\ndeployment = \"development\"\n[services.gh]\norigin = \"{origin}\"\nbuffered_paths = [\"/repos\"]\n"),
    )
    .unwrap();

    let _daemon = Daemon(
        keygate(&state)
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = state.join("keygate.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "the broker never bound its socket"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(ok(keygate(&state).arg("ls"), "").contains("unset"));
    // The secret goes in on stdin, never argv.
    assert_eq!(
        ok(
            keygate(&state).args(["set", "service", "gh"]),
            &format!("{SECRET}\n")
        ),
        "ok"
    );
    assert!(ok(keygate(&state).arg("ls"), "").contains("active"));

    let root = ok(
        keygate(&state).args([
            "mint",
            "--seat",
            "ci",
            "--namespace",
            "service",
            "--ttl-s",
            "600",
        ]),
        "",
    );
    assert!(root.starts_with("kgm_"));
    // Attenuation is offline: point it at a state dir with no broker at all.
    let nowhere = dir.path().join("nowhere");
    let narrowed = ok(
        keygate(&nowhere).args([
            "attenuate",
            "--token-file",
            "-",
            "--path-prefixes",
            "/repos/o",
            "--methods",
            "GET",
        ]),
        &root,
    );
    assert!(narrowed.len() > root.len());
    let inspected = ok(
        keygate(&nowhere)
            .arg("inspect")
            .env("KEYGATE_TOKEN", &narrowed),
        "",
    );
    assert!(
        inspected.contains("\"seat\": \"ci\"")
            && inspected.contains("/repos/o")
            && inspected.contains("expires_at_unix_s")
    );

    let forward = |token: &str, path: &str| {
        run(
            keygate(&state)
                .args(["forward", "service", "gh", "GET", path])
                .env("KEYGATE_TOKEN", token),
            "",
        )
    };
    let reply = forward(&narrowed, "/repos/o/r");
    assert!(
        reply.status.success(),
        "{}",
        String::from_utf8_lossy(&reply.stderr)
    );
    assert_eq!(reply.stdout, br#"{"full_name":"o/r"}"#);
    assert!(String::from_utf8_lossy(&reply.stderr).contains("status=200"));
    {
        let heads = heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        assert!(heads[0].starts_with("get /repos/o/r http/1.1"));
        assert!(
            heads[0].contains(&format!("authorization: bearer {SECRET}")),
            "the upstream gets the sealed secret"
        );
        assert!(!heads[0].contains("kgm_"), "the macaroon stays home");
    }

    // The narrowed token is refused outside its prefix; the root is not.
    let outside = forward(&narrowed, "/repos/other/r");
    assert!(!outside.status.success());
    assert!(String::from_utf8_lossy(&outside.stderr).contains("denied"));
    assert!(forward(&root, "/repos/other/r").status.success());
    let dotdot = forward(&root, "/repos/o/../../admin");
    assert!(String::from_utf8_lossy(&dotdot.stderr).contains("path_refused"));

    let revoked = ok(keygate(&state).args(["revoke", "service", "gh"]), "");
    assert_eq!(revoked.lines().next(), Some("revoked"));
    assert!(
        revoked.contains("keygate forget"),
        "revoke says the old secret is still guarded"
    );
    let after = forward(&root, "/repos/o/again");
    assert!(!after.status.success());
    assert!(String::from_utf8_lossy(&after.stderr).contains("revoked"));
    assert_eq!(heads.lock().unwrap().len(), 2);

    // Nothing on disk holds the secret in the clear.
    for dir in [state.clone(), state.join("services")] {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
                    "{} holds the plaintext secret",
                    path.display()
                );
            }
        }
    }
}

/// A temp directory nobody else can write. `tempfile` honours the umask,
/// and a group-writable directory above the state directory is (rightly)
/// refused by the broker's custody check.
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

const DEV: &str = "[broker]\ndeployment = \"development\"\n";

/// Initialize `state`, install `config` (keeping the 0600 mode `init`
/// gave the file), and start the broker.
fn start(state: &Path, config: Option<&str>) -> Daemon {
    assert!(ok(keygate(state).arg("init"), "").contains("initialized"));
    if let Some(config) = config {
        std::fs::write(state.join("keygate.toml"), config).unwrap();
    }
    let daemon = Daemon(
        keygate(state)
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = state.join("keygate.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "the broker never bound its socket"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    daemon
}

/// Run a command that is expected to exit on its own. If it is still
/// running after ten seconds (a broker that started when it should have
/// refused), it is killed and reported as having succeeded.
fn exits(command: &mut Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            return Command::new("true").output().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// #tooth (audit 3, 19): the serving process cannot be read by its own
/// uid, and it does not start on a config or state directory that others
/// could have written.
#[cfg(target_os = "linux")]
#[test]
fn tooth_serve_hardens_the_process_and_checks_custody() {
    use std::os::unix::fs::PermissionsExt;
    let (origin, _heads) = upstream();
    let dir = private_tempdir();
    let state = dir.path().join("state");
    let config =
        format!("{DEV}[services.gh]\norigin = \"{origin}\"\nbuffered_paths = [\"/repos\"]\n");
    let daemon = start(&state, Some(&config));
    let pid = daemon.0.id();

    // Control: an ordinary process of ours is readable through /proc.
    let mut plain = Command::new("sleep").arg("30").spawn().unwrap();
    assert!(std::fs::read(format!("/proc/{}/environ", plain.id())).is_ok());
    assert!(std::fs::File::open(format!("/proc/{}/mem", plain.id())).is_ok());
    plain.kill().unwrap();
    plain.wait().unwrap();

    // The broker is not: PR_SET_DUMPABLE=0 hands its /proc entries to root,
    // which also means no ptrace attach and no core file from this uid.
    for file in ["mem", "environ", "maps"] {
        let err = std::fs::File::open(format!("/proc/{pid}/{file}")).err();
        assert_eq!(
            err.map(|e| e.kind()),
            Some(std::io::ErrorKind::PermissionDenied),
            "/proc/{pid}/{file} is readable by the broker's own uid"
        );
    }
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    assert_eq!(
        core.split_whitespace().skip(4).take(2).collect::<Vec<_>>(),
        ["0", "0"],
        "{core}"
    );
    // It still works.
    assert!(ok(keygate(&state).arg("ls"), "").contains("unset"));
    drop(daemon);

    // Custody: each of these refuses to start, and says why.
    let config_path = state.join("keygate.toml");
    let refuses = |why: &str| {
        let output = exits(keygate(&state).arg("serve"));
        assert!(!output.status.success(), "served despite: {why}");
        assert!(stderr(&output).contains(why), "{}", stderr(&output));
    };
    for writable in [0o660, 0o606, 0o666] {
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(writable)).unwrap();
        refuses("writable");
    }
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let real = state.join("real.toml");
    std::fs::rename(&config_path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &config_path).unwrap();
    assert!(
        !exits(keygate(&state).arg("serve")).status.success(),
        "served a symlinked config"
    );
    std::fs::remove_file(&config_path).unwrap();
    std::fs::rename(&real, &config_path).unwrap();
    for loose in [0o750, 0o755] {
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(loose)).unwrap();
        refuses("must be 0700");
    }
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A separated deployment over plain-http loopback, or with no operator
    // list, is a config error.
    std::fs::write(&config_path, config.replace("development", "separated")).unwrap();
    refuses("operator_uids is empty");
    std::fs::write(
        &config_path,
        config.replace("deployment = \"development\"", "operator_uids = [1]"),
    )
    .unwrap();
    refuses("development transport");
}

/// #tooth (audit 3): what `keygate init` writes is a separated deployment,
/// and it boots as one: the initializing uid operates it and is not served
/// as a caller.
#[test]
fn tooth_default_init_boots_separated() {
    let dir = private_tempdir();
    let state = dir.path().join("state");
    let _daemon = start(&state, None);

    let hello = ok(keygate(&state).arg("hello"), "");
    for expected in [
        "\"deployment\": \"separated\"",
        "\"operator\": true",
        "\"caller\": false",
    ] {
        assert!(hello.contains(expected), "{hello}");
    }
    let status = ok(keygate(&state).arg("status"), "");
    assert!(status.contains("\"deployment\": \"separated\""), "{status}");

    // Operating works; calling, from the broker's own uid, does not.
    assert_eq!(
        ok(
            keygate(&state).args(["set", "service", "github"]),
            "ghp_separated_secret_0001\n"
        ),
        "ok"
    );
    let token = ok(keygate(&state).args(["mint", "--seat", "ci"]), "");
    let refused = run(
        keygate(&state)
            .args(["forward", "service", "github", "GET", "/repos/o/r"])
            .env("KEYGATE_TOKEN", &token),
        "",
    );
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("own uid"), "{}", stderr(&refused));
}

/// #tooth (audit 5, 19): rotation retires, `forget` drops, and the CLI
/// will not hand a secret to a listener that is not the expected broker.
#[test]
fn tooth_cli_retire_forget_and_broker_identity() {
    let (origin, _heads) = upstream();
    let dir = private_tempdir();
    let state = dir.path().join("state");
    let config =
        format!("{DEV}[services.gh]\norigin = \"{origin}\"\nbuffered_paths = [\"/repos\"]\n");
    let _daemon = start(&state, Some(&config));
    let ls = || ok(keygate(&state).arg("ls"), "");
    let set = |secret: &str, extra: &[&str]| {
        run(
            keygate(&state).args(["set", "service", "gh"]).args(extra),
            secret,
        )
    };

    assert!(set("ghp_first_secret_000001\n", &[]).status.success());
    assert!(set("ghp_second_secret_00002\n", &[]).status.success());
    assert!(
        ls().contains("gen=2") && ls().contains("retired=1"),
        "{}",
        ls()
    );
    assert_eq!(
        ok(keygate(&state).args(["forget", "service", "gh"]), ""),
        "forgotten"
    );
    assert!(ls().contains("retired=0"), "{}", ls());
    assert!(set("ghp_third_secret_000003\n", &["--forget-retired"])
        .status
        .success());
    assert!(
        ls().contains("gen=3") && ls().contains("retired=0"),
        "{}",
        ls()
    );
    assert!(ok(
        keygate(&state).args(["revoke", "service", "gh", "--forget"]),
        ""
    )
    .starts_with("revoked"));
    assert!(
        ls().contains("revoked") && ls().contains("retired=0"),
        "{}",
        ls()
    );

    // The wrong broker uid: refused before the secret is written to it.
    let wrong = set(
        "ghp_never_sent_secret_04\n",
        &["--broker-uid", "4294967294"],
    );
    assert!(!wrong.status.success());
    assert!(
        stderr(&wrong).contains("not the expected uid"),
        "{}",
        stderr(&wrong)
    );
    assert!(
        ls().contains("gen=3"),
        "nothing reached the broker: {}",
        ls()
    );
    // A directory others can write does not vouch for the socket in it.
    use std::os::unix::fs::PermissionsExt;
    let moved = dir.path().join("shared");
    std::fs::create_dir(&moved).unwrap();
    std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o777)).unwrap();
    let link = moved.join("keygate.sock");
    std::fs::hard_link(state.join("keygate.sock"), &link).unwrap();
    let via_shared = run(keygate(&state).arg("--socket").arg(&link).arg("ls"), "");
    assert!(!via_shared.status.success());
    assert!(
        stderr(&via_shared).contains("could have replaced"),
        "{}",
        stderr(&via_shared)
    );
}

/// #tooth (audit 3): the separated deployment between genuinely different
/// kernel uids. The script enters a private user namespace with a range of
/// subordinate uids, runs the broker as one uid and callers as two others,
/// and checks peer credentials, custody and the own-uid rule for real. No
/// host root and no host accounts are involved; where the host cannot map
/// subordinate uids the test says it was skipped.
#[cfg(target_os = "linux")]
#[test]
fn tooth_real_multi_uid_separation() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/multiuid-acceptance.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg(env!("CARGO_BIN_EXE_keygate"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.code() == Some(77) {
        eprintln!("{}", stdout.trim());
        return;
    }
    assert!(
        output.status.success() && stdout.contains("multiuid: all checks passed"),
        "multi-uid acceptance failed:\n{stdout}\n{}",
        stderr(&output)
    );
    for line in stdout
        .lines()
        .filter(|l| l.starts_with("PASS") || l.starts_with("NOTE"))
    {
        println!("{line}");
    }
    assert!(stdout.matches("PASS:").count() >= 5, "{stdout}");
}
