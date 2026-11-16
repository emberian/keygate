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
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");

    assert!(ok(keygate(&state).arg("init"), "").contains("initialized"));
    assert!(
        !run(keygate(&state).arg("init"), "").status.success(),
        "init must not clobber an existing master key"
    );
    std::fs::write(
        state.join("keygate.toml"),
        format!("[services.gh]\norigin = \"{origin}\"\nbuffered_paths = [\"/repos\"]\n"),
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

    assert_eq!(
        ok(keygate(&state).args(["revoke", "service", "gh"]), ""),
        "revoked"
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
