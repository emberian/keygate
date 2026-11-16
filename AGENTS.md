# `keygate` Engineering Rules (`AGENTS.md`)

1. **Zero macOS Compilation Rule**:
   - **NEVER** execute `cargo` or `rustc` locally on macOS.
   - Run all compilation, clippy, and tests remotely over SSH on a designated Linux build host (`BUILD_HOST`) using an isolated remote directory (`/tmp/keygate-build`) wrapped in `SWARM_MEM_MAX=12G timeout --kill-after=10s 600s`:
     ```bash
     rsync -az --delete --exclude target --exclude .git ./ "$BUILD_HOST":/tmp/keygate-build/
     ssh "$BUILD_HOST" 'cd /tmp/keygate-build && CARGO_TARGET_DIR=/tmp/keygate-build/target timeout --kill-after=10s 600s cargo test --workspace'
     ```
2. **Security & Performance Laws (TigerStyle)**:
   - **Zero `curl` subprocesses and zero sleep-polling**: Use native async Rust I/O (`tokio` + `reqwest`/`hyper` with `rustls`) for both buffered and SSE/chunked streaming upstream calls.
   - **Secret memory hygiene**: Wrap raw credentials in `SecretBytes` (`zeroize` on `Drop`, redacted `Debug`, no `Display`/`Serialize`). Never write raw secrets into logs, errors, argv, or child env.
   - **Audit-before-effect**: Persist `AuditEvent::Begin` to the `0600` append-only audit log (`fsync`/`fdatasync`) *before* transmitting any upstream request; if auditing fails, fail closed without sending.
   - **Zero disk polling on streams**: Revocation uses an in-memory `AtomicU64` / `tokio::sync::watch` epoch map so `revoke` cuts active SSE streams in `<100 µs` with `0` filesystem reads/decrypts per second, while routine `rotate` (`set`) bumps key version without severing healthy in-flight streams unless `--cut-existing` is passed.
   - **Never** include private tailnet IPs or internal hostnames in source, tests, docs, or commit messages.
3. **Commit Discipline**:
   - Inspect `git diff` before committing named files. No `git stash`, no blanket `git add .`.
