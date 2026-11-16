# `keygate` Specification (`SPEC.md`)

A standalone, zero-slop Rust capability-membrane & streaming secret custody broker for multi-agent fleets (`fleet`), multi-tenant cloud sandboxes (`builders.dev`), and `obend` residents.

Eliminates:
1. Plaintext API keys / OAuth tokens / MCP bearers inside agent-readable files or container environments.
2. Co-UID impersonation (`SO_PEERCRED` alone is insufficient when multiple processes/shells share a container UID — `keygate` layers **attenuated BLAKE3 Macaroons** modeled directly as the wire subset of `Obend.Vault.Form` capability membranes).
3. `mini-keys`'s non-streaming LLM blocker, `curl` 20ms sleep-poll latency, `_pool` namespace collisions, `O(N)` ticket directory scans, and 1 Hz disk-decrypt stream polling.

---

## 1. Core Architecture & Capabilities

### 1.1 Dual Credential Namespaces (Strictly Disjoint)
- **`providers/` (`Namespace::Provider`)**: Metered LLM/inference upstreams (Anthropic, OpenAI, Gemini, OpenRouter, custom compatible endpoints) enforcing JSON body model allowlists, `max_tokens` / aggregate output-token caps (including `n`, limited to 1–16), per-call and per-day micro-USD spend ceilings, and per-seat fairness shares. Supports **both** `provider-forward` (whole JSON reply with exact-retry replay) and **`provider-stream`** (live SSE token streaming so real Claude Code / Codex / Gemini CLI turns run through `keygate` with zero raw keys in the sandbox!).
- **`services/` (`Namespace::Service`)**: Arbitrary HTTPS (or loopback HTTP) APIs & event streams (e.g. `mcp.builders.dev`, GitHub REST/GraphQL, webhook endpoints). Each service row configures:
  - Single `origin` (`https://host[:port]`, `http://127.0.0.1[:port]` / `[::1]` only for loopback).
  - Canonical `plain_path` segment prefixes split into `buffered_paths` (whole-reply journaled + replayable) and `stream_paths` (SSE / chunked streaming, retaining closing summary + `Last-Event-ID` reconnect support).
  - Allows `/` as the zero-segment root path; refuses `%`, `.`, `..`, empty segments in other paths, fragments, and unauthorized headers (preventing proxy/router path-normalization differentials; allows only fixed safe headers + configured caller header allowlist such as `Last-Event-ID`).
- Both tables are optional independently (a broker with only `services` or only `providers` boots cleanly; neither configured refuses at startup). Secrets are sealed at rest with `ChaCha20Poly1305` (or AES-256-GCM) under a `0600` master key with domain-separated AAD `("keygate-seal/v1", namespace, row_name)`.

### 1.2 Attenuated Capability Membranes (`Macaroon` + OS Peer Creds)
- Over Unix domain sockets (`SO_PEERCRED` on Linux, `getpeereid` on macOS) *and* optional loopback HTTP proxy mode (`http://127.0.0.1:<port>` for drop-in `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `HTTPS_PROXY`-style base-URL routing inside containers using `Authorization: Bearer kgm_<macaroon>`!):
  - Operator mints a root capability token for a `seat_id` bound to `(allowed_uid_opt, root_epoch)` using chained `BLAKE3` keyed MACs (`MacaroonV1`).
  - Anyone holding a macaroon can **attenuate** it offline by appending caveats (never widening!):
    - `Seat(String)`
    - `Namespace(Provider | Service)`
    - `Rows(Vec<String>)`
    - `Methods(Vec<String>)`
    - `PathPrefixes(Vec<String>)`
    - `Models(Vec<String>)`
    - `MaxRequestBytes(usize)`
    - `MaxSpendMicroUsd(u64)`
    - `ExpiresAtUnixS(u64)`
  - Designed as a strict 1-to-1 first-order subset of `Obend.Vault.Form` residual predicates so future `obend` membrane proofs compile directly to `keygate` caveats.

### 1.3 Multi-Secret Cross-Chunk Prefix-Holdback Stream Scrubber (`EchoGuard`)
- An upstream error page, debug echo, or prompt-injected reflection must **never** leak a sealed bearer back to the caller — even if the secret spans two network read chunks!
- `EchoGuard` builds an automaton (Aho-Corasick / multi-pattern prefix matcher) over active sealed secret bytes (`>= 8` bytes):
  - Scans response status/headers whole before emitting the head frame.
  - On streaming body chunks, emits safe prefix bytes immediately while holding back *only* the longest trailing suffix (`< secret.len()`) that matches a prefix of any guarded secret.
  - If a full match occurs across chunk boundaries, **immediately cuts the stream before emitting a single byte of the secret**, zeroes internal buffers, kills the upstream request, and emits a terminal `withheld: true` closing summary + audit event!

### 1.4 O(1) Indexed Ticket Journal & `<100 µs` Zero-I/O Epoch Revocation
- **Ticket Store**: Append-only WAL journal + in-memory `HashMap<(SeatId, RequestDigest32), TicketId>` index (compacted every `N` ops, `O(1)` lookup on `authorize` and `forward`, eliminating `O(N)` `read_dir` scans!).
  - Exact retry of `authorize` returns the existing live ticket without double-counting budget. Unused `Live` reservations expire after `broker.live_ttl_s` (default 120 seconds); admission durably refunds expired reservations before enforcing budgets. Terminal tickets use the separate `retention_s` setting.
  - Buffered replies and cleanly completed provider SSE streams settle to reported usage when complete counts are available. Anthropic cache-creation/read input counters contribute to input usage. Missing/malformed usage or an abnormal stream ending retains the reservation.
  - Buffered `forward` retains the exact response for `retention_s` so lost-reply retries replay without double-billing or double-POSTing; caller disconnect mid-flight marks ticket `Uncertain` (never re-sent).
  - Streaming `stream` (`provider-stream` / `service-stream`) retains the closing summary (`status, bytes, complete, withheld, revoked`) so retrying a spent stream ticket reports how it ended rather than silently opening a duplicate stream; reconnecting uses a fresh ticket (with optional `last_event_id`).
- **Instant Epoch Revocation vs Smooth Rotation**:
  - Each row holds a `tokio::sync::watch::Sender<RowEpoch { generation: u64, revoked_floor: u64 }>` in memory.
  - `keygate revoke <ns> <row>` advances `revoked_floor`, waking every `tokio::select!` stream relay loop in **`<100 µs` with zero disk reads**, aborting the upstream stream and recording `closed_by: "revoked"`.
  - `keygate revoke-seat <seat>` advances an in-memory watch epoch, cutting buffered calls and streams minted under an earlier seat epoch before persisting and auditing the revocation. Persistence or audit failures are explicit errors; in-memory revocation remains effective.
  - `keygate set <ns> <row>` (routine key rotation) increments `generation` without advancing `revoked_floor` (unless `--cut-existing` is passed), so new requests use the new key while healthy in-flight streams finish undisturbed!

---

## 2. Interfaces (Unix Socket Framing + Loopback HTTP Gateway + CLI)

Each transport limits accepted connections with `broker.max_connections` (default 256). Durable operations run on a shared blocking pool with at most 16 jobs, leaving async relay workers available during disk stalls. Unix pipelining uses bounded read-ahead (one maximum frame plus its length prefix); exceeding that bound closes the connection.

1. **Unix Socket Protocol**: Length-prefixed JSON frames supporting `hello`, `mint-macaroon`, `attenuate`, `provider-authorize`, `provider-forward`, `provider-stream`, `service-authorize`, `service-forward`, `service-stream`, and operator `set` / `revoke` / `ls` / `status`.
2. **Loopback HTTP Gateway (`127.0.0.1` opt-in listener)**:
   - A bare `/v1/<namespace>/<row>` or its trailing-slash form maps to upstream `/`, subject to row path policy. `Last-Event-ID` is forwarded only when allowed by the row; otherwise it is explicitly refused.
   - Accepts `Authorization: Bearer kgm_<macaroon>` on `/v1/provider/<row>/...` and `/v1/service/<row>/...` so unmodified SDKs (`claude`, `codex`, `mcp-agent`, `agent-runner.mjs`) drop straight onto `keygate` by changing **only their base URL + swapping the raw API key for `kgm_<macaroon>`**!
3. **Adversarial `#tooth` Tests**:
   - Secret split across 2, 3, and 1-byte chunks (`"sk-ant-"` | `"secret1"` | `"2345"`) cut with **zero** secret bytes delivered to caller.
   - Offline macaroon tampering (stripping a caveat or widening `MaxSpendMicroUsd`) rejected; offline attenuation narrowing path/TTL accepted.
   - Live SSE stream cut within `<50 ms` on `revoke`, while a second stream under `set` (routine rotation) continues uninterrupted unless `--cut-existing` is specified.
   - Buffered POST exact-retry replays cached response (`upstream_hits == 1`); mid-flight caller disconnect marks `Uncertain` and refuses replay.
   - Audit-failure fault injection (`read-only` audit fd) refuses before any upstream TCP connection is made (`upstream_hits == 0`).
