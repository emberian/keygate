# `keygate` Specification (`SPEC.md`)

A Rust broker that holds upstream credentials (LLM provider keys, service tokens) and lets callers use them through attenuable capability tokens, for buffered and streamed HTTP exchanges.

This document states what the implementation does. Where a number is a design goal rather than a measurement it says so; measurements and the audit trail are in [HARDENING.md](HARDENING.md).

## 0. What keygate does and does not protect

keygate removes these from a caller's environment:

1. Plaintext API keys, OAuth tokens and bearers in files or environment variables the caller can read.
2. The need to give every caller the same unrestricted credential: each caller holds a macaroon that restricts seat, namespace, rows, methods, paths, models, request size, spend and lifetime.
3. Polling: upstream I/O is native async, revocation is an in-memory notification, and ticket lookup is a hash probe.

It relies on, and does not replace, an operating-system boundary:

- **The broker must run under its own uid, with its state directory private to that uid.** A process that shares the broker's uid can read the master key and needs no token. Macaroons and peer credentials decide which *request* is served; they do not isolate processes that can read the broker's files. A `separated` deployment (the default) refuses to serve a peer whose uid is the broker's own, so this misconfiguration fails loudly instead of appearing to work.
- **The response guard is defense in depth.** It withholds reflections of a credential that match a bounded set of patterns (§1.3). It cannot stop an upstream that transforms a credential in a way outside that set.
- **Spend limits are as good as the row's prices and the request's shape.** They bind for text-only requests on a priced row (§1.5). Features whose cost is not determined by the request body are refused unless the operator allows them, and then the limits are no longer bounds.

---

## 1. Architecture

### 1.1 Two credential tables

`providers` and `services` are separate tables, each optional; a broker with neither refuses to start. A row named `x` may exist in both and they are unrelated: separate directories, separate sealing AAD.

- **`providers`** (`Namespace::Provider`): metered LLM upstreams. Each row speaks one `dialect`:

  | dialect | generation endpoint | output cap field |
  |---|---|---|
  | `anthropic-messages` | `POST /v1/messages` | `max_tokens` |
  | `openai-chat` | `POST /v1/chat/completions` | `max_completion_tokens` or `max_tokens` |
  | `openai-responses` | `POST /v1/responses` | `max_output_tokens` |

  A row accepts `POST` at exactly one path: the dialect's endpoint, or the row's `endpoint` override for gateways that mount the same API under a prefix. The model and the output cap are read from the JSON body, so only APIs that select the model in the body are supported. **APIs that select the model in the URL path (Gemini `generateContent`, Bedrock `invoke`, Azure deployment paths) have no dialect and cannot be configured**; their OpenAI-compatible endpoints can, as `openai-chat` with an `endpoint`. `GET`/`HEAD` are allowed under the row's `read_paths` only.
- **`services`** (`Namespace::Service`): other HTTPS APIs and event streams. Each row has one `origin`, allowed `methods`, and plain-path prefixes split into `buffered_paths` (whole reply, journaled, replayable) and `stream_paths` (SSE/chunked, with a retained closing summary).

Common to both:

- `origin` is `https://host[:port]`. Plain `http://127.0.0.1[:port]` / `http://[::1][:port]` is accepted only in a `development` deployment: loopback has no server identity, so any local process that binds the port first is sent the row's secret.
- Paths are `plain_path`: `/` or `/seg/seg`, no `%`, no `.`/`..`, no empty segments, a fixed alphabet. The URL keygate sends must survive URL parsing byte-for-byte.
- Caller headers are forwarded only if they are `accept`, `content-type`, or listed in the row's `caller_headers`. A row cannot list hop-by-hop headers, request-rewriting headers (`x-http-method-override`, `x-original-url`, `forwarded`, `x-forwarded-*`, ...), credential headers, or billing-identity headers (`openai-organization`, `openai-project`); the last group may be set by the operator in `fixed_headers`.
- A keygate token is never sent upstream: a request whose query or forwarded headers contain `kgm_`, or whose body contains the presented token, is refused.
- Secrets are sealed at rest with `ChaCha20Poly1305` under a `0600` master key, AAD `("keygate-seal/v1", namespace, row)`.

### 1.2 Capability tokens (`MacaroonV1`)

- The operator mints a root token for a seat, bound to `(allowed_uid?, root_epoch)`, with chained BLAKE3 keyed MACs.
- Any holder can attenuate offline by appending caveats; all caveats must hold, so appending only narrows: `Seat`, `Namespace`, `Rows`, `Methods`, `PathPrefixes`, `Models`, `MaxRequestBytes`, `MaxSpendMicroUsd`, `ExpiresAtUnixS`.
- `MaxSpendMicroUsd` is cumulative across the token and everything attenuated from it. It is enforced on priced provider rows; a token carrying it is refused on a provider row without prices, where the cap could not bind. Service calls are not metered.
- `ExpiresAtUnixS` is bound to a monotonic deadline at admission (against the sub-second wall clock) so journal or audit contention never extends a capability's lifetime. A request whose deadline passes before `Begin` is refused before touching the network; an open stream whose deadline passes is cut (`closed_by: expired`). A buffered call already in flight is bounded by `buffered_timeout_ms` instead.
- A clock that reads before 2025-06-15 or before the epoch is an error, not a zero: admission fails with `clock_failed`.
- **Tickets belong to the exact token that opened them.** The request digest includes an id derived from the token's verified final tag and its spend scopes, so another token of the same seat, including one attenuated from the first, neither finds the first's reservation nor replays its retained reply.
- Uid-bound tokens are checked against kernel peer credentials on the Unix socket and refused on the HTTP gateway, which has none.

### 1.3 Response guard (`EchoGuard`)

Goal: an upstream that reflects the injected credential (error page, debug echo, model output) should not get it past keygate, including across chunk boundaries.

- **Patterns.** For each guarded secret: the secret, and each of these when it differs: percent-encoding with uppercase and with lowercase hex; JSON escaping of `"` and `\`; the same plus `\/`; the same plus `<`/`>`/`&`.
- **Match.** Any 16 consecutive bytes of a pattern (the whole pattern if shorter). An echo that drops or alters characters still trips while a 16-byte run survives.
- **Which secrets.** Every row's active secret, and its *retired* secrets: after `set` or `revoke` the previous secret is kept, sealed, as a guard-only pattern until the operator runs `forget` (a row with an active secret keeps at most 8; a rotation that would make it 9 is refused and changes nothing; a revocation is never refused and never drops one: the revoked row holds the 8 plus the secret just revoked, 9, the same secrets it held before). **Only `forget`, `set --forget-retired` and `revoke --forget` remove patterns.** A revoked row at 9 needs `forget` before a new secret can be set. A flight takes its secret and a guard containing that secret as one atomic pair and keeps both until it ends, so forgetting a secret never unguards a flight already sent with it.
- **Streaming.** The longest suffix of the stream that is a substring of some pattern (at most 15 bytes) is held back; everything before it is forwarded at once. When a window completes, the stream is cut before any byte of that window was forwarded, the upstream request is aborted, and the closing summary says `withheld`.
- **Head.** Status and headers are scanned whole before a head is emitted. A reply with a `Content-Encoding` other than `identity` is withheld, since it cannot be scanned (keygate requests `identity`).
- **Bounds.** One suffix automaton over all patterns, sparse tables zeroed on drop, built outside any lock a request takes. Total pattern bytes are capped at 64 KiB; a `set` that would exceed the cap is refused and changes nothing.
- **Limits.** Fewer than 16 consecutive bytes pass. Base64 or hex of the secret, case changes, compression and any other transformation pass. Case is never folded.

### 1.4 Ticket journal

Append-only WAL plus an in-memory `(seat, digest) -> ticket` index; lookups are `O(1)`.

An *exact retry* is the same token presenting the same request: same row, method, path, query, forwarded headers, body and request id (`Idempotency-Key` on the gateway). A different request id is a different request, and is how a caller deliberately sends again.

How long a ticket is remembered depends on what is known about it:

| state | meaning | remembered for | an exact retry gets |
|---|---|---|---|
| `Live` | authorized, never sent | `live_ttl_s` (default 120 s), then refunded | the same ticket, no second charge |
| `Replayable` | buffered reply received | `retention_s` (default 900 s) | the retained reply; after the window, a new send |
| `Closed` | stream ended | `retention_s` | its closing summary (`status, bytes, complete, withheld, revoked, closed_by`); after the window, a new stream |
| `Withheld` | reply contained a guarded secret | `retention_s` | a refusal; after the window, a new send |
| `Uncertain` | may have reached the upstream; outcome unknown | at least `retention_s`, **and for as long as the token that sent it could retry** | a refusal (`uncertain`), never a send |

- A call becomes `Uncertain` when its caller disconnects mid-flight, the upstream fails after the request may have been sent, it is cut by revocation or shutdown, or the broker crashes with it in flight.
- An `Uncertain` ticket may be dropped only when its token can no longer present anything: the token's `ExpiresAtUnixS` has passed, or its seat has been revoked past the epoch the token was minted under. The seat's revocation floor is written to the journal itself (and reconciled with the seat file at start), so that decision rests on the journal's own durable record. A token with no expiry on a seat that is never revoked keeps its `Uncertain` tickets indefinitely; they hold no reply body.
- The number of `Uncertain` tickets is capped by `max_uncertain_tickets` (default 10000). At the cap the broker first drops those whose tokens can no longer retry; if it is still full, every *new* request is refused with `no_resend_ledger_full` (HTTP 503) until tokens expire or seats are revoked. No record is dropped to make room. Exact retries of remembered requests are still answered.
- The finite window applies only where the outcome is known. After `retention_s` a completed request's reply is gone, and keygate cannot tell a late retry from a new request: it is sent. Callers that need longer deduplication of completed requests must rely on the upstream's own idempotency support.
- **Exclusive state ownership.** `Broker::open` and `Broker::init_state` acquire a nonblocking exclusive `flock` on `<state>/broker.lock` (`0600`, singly linked regular file, `O_NOFOLLOW`) before opening, recovering, or compacting any mutable file, and retain that descriptor across all `Broker` clones until mutable state is dropped. A duplicate startup fails before touching `journal.wal` or `audit.log`.
- **Write failures and recovery.** Each journal record is appended and `fdatasync`ed before it takes effect in memory. A short write (disk full) is cut back to the last committed byte; that operation fails and the journal stays usable. If the cut-back fails, or `fdatasync` or a compaction's directory sync fails, the journal is poisoned: every later commit is refused until restart, and so is every call. On open, both `journal.wal` and `audit.log` validate every newline-terminated JSON record from byte 0 (refusing complete malformed lines anywhere in the file, including at EOF) and truncate and sync only an unterminated final record left by a crash mid-append; `audit.log` likewise rolls back short writes (`ftruncate` + `fdatasync`) and poisons on failed rollback or `fdatasync` until restart. Newly created intermediate and leaf state directories, namespace directories (`providers/`, `services/`), `master.key`, `keygate.toml`, `journal.wal`, and `audit.log` sync their parent directory entries before acknowledging dependent operations.
- Audit-before-effect: `Begin` is appended and synced to the `0600` audit log before any upstream I/O; if that fails the call is refused.
- A fresh immediate send reserves its budget and starts in flight in one synced journal record. Recovery treats an in-flight ticket as uncertain. The broker checks the capability deadline again after the audit sync and before handing the request to the sender.
- The broker writes outcome audit lines before returning. The next synced audit append or an orderly writer shutdown flushes them. They survive process termination after a successful write. A power loss can discard trailing outcome lines. The journal commits ticket outcomes independently.

### 1.5 Budgets

- Reservation for a generation request:
  `(body_bytes + 4096) tokens at the dearest input price + output_cap * max(n, best_of) tokens at the output price`.
  The dearest input price is the maximum of the input, cache-write (default twice input) and cache-read (default input) prices. A token is at least one byte of the request, so for a text-only request this is an upper bound at the row's prices, assuming at most 4096 tokens of provider-added prompt. `n` and `best_of` are limited to 1..=16. A request with no output cap is refused.
- Complete replies settle to reported usage (input, cache-write, cache-read and output tokens at their own prices): buffered replies, and streams that end cleanly with complete usage (including a single OpenAI Responses terminal `response.completed` or `response.incomplete` event carrying complete `input_tokens` and `output_tokens`; non-terminal `response.*` events, any JSON event after a terminal `response.*` event, duplicate `message_start` events, `response.failed`, and missing or partial usage keep the reservation). Anything else keeps the reservation.
- Ceilings: `per_call_micro_usd`, `per_day_micro_usd`, `per_seat_day_micro_usd`, and `MaxSpendMicroUsd` scopes. A row with a ceiling and no prices is a config error.
- Refused unless listed in the row's `allow`, because they make cost depend on more than the body:
  `server-state` (`previous_response_id`, `conversation`, stored prompts, item references including OpenAI Responses `input` items with omitted or `null` `type` discriminators, file ids, containers, background runs), `remote-input` (images/documents fetched by URL), `server-tools` (provider-run tools, MCP connectors, web search), `premium-tier` (`service_tier: "priority"`, `speed: "fast"`), `inline-media` (inline images, documents, audio), `non-text-output` (`modalities` other than text, Chat Completions `audio`; billed on a channel the row's two token prices do not describe). With any of them allowed, the reservation is not a bound and settled spend can pass a ceiling. Objects stored at the provider belong to the upstream key, not to a seat: with `server-state` allowed, any seat on the row can reference another seat's.
- The request body is parsed strictly: a duplicate key at any depth is refused, and an explicit `null` is treated as absent.

### 1.6 Revocation, rotation, expiry, shutdown

Every flight waits on in-memory `tokio::sync::watch` channels; nothing polls and nothing reads disk.

- `revoke <ns> <row>` raises the row's `revoked_floor` first, in memory, then writes the tombstone. Open streams and in-flight calls on that row are cut. `revoke-seat` does the same for every token minted for a seat.
- `set <ns> <row>` installs a new secret for new requests; flights already running finish on the old one unless `--cut-existing`.
- A stream whose token expires is cut (`closed_by: expired`).
- On `SIGTERM`/`SIGINT` the broker stops accepting, cuts every flight (`closed_by: shutdown`), waits up to `shutdown_grace_ms` for their outcomes to be journaled, and refuses new calls. A flight that does not make it is `InFlight` on disk and returns `Uncertain`.
- Latency: the design goal is that the wake itself costs no I/O. The unit test asserts the notification (send to ready) completes within 100 µs; the integration test asserts a caller observes the cut within 50 ms. Measured figures are in HARDENING.md.

---

## 2. Deployment

`[broker] deployment`:

- **`separated`** (default). `operator_uids` must be listed. A peer whose uid is the broker's own is not served as a caller. Upstreams must be HTTPS. `keygate serve` sets umask 077, `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` (so the broker's own uid cannot `ptrace` it or read `/proc/<pid>/mem`) and refuses to start if it cannot. Linux only.
- **`development`**. Single-uid experiments and tests: the state directory's owner is the operator, same-uid callers are served, plain-HTTP loopback upstreams are allowed. Any process of that uid can read the master key.

Always:

- The state directory must be a real directory owned by the broker's uid with mode `0700`, and **every directory above it** must be owned by that uid or root and not group- or world-writable (sticky directories such as `/tmp` excepted). A private leaf under a directory someone else can write can be renamed away and replaced. The broker resolves the path once and uses the canonical one.
- `keygate.toml` must be a regular file owned by that uid or root, not group- or world-writable, under the same kind of path: whoever can write it chooses where secrets are sent.
- Custody files are opened without following symlinks, without blocking on a FIFO, only if regular, and with bounded reads.
- The socket is bound under a private name and renamed into place with its configured mode.

`scripts/multiuid-acceptance.sh <keygate-binary>` checks the separated deployment between genuinely different kernel uids without host root: it runs the broker as one uid and callers as two others inside a private user namespace and verifies peer credentials, custody and the own-uid rule.

What keygate cannot do for you: create the separate uid, make the socket reachable by callers (set `socket` and `socket_mode`, e.g. a group-readable socket in a root-owned directory), or stop a caller that has other access to the broker's uid.

---

## 3. Interfaces

Each transport limits accepted connections (`max_connections`, default 256). Durable work runs on a blocking pool of at most 16 jobs.

1. **Unix socket**: length-prefixed JSON frames: `hello`, `mint-macaroon`, `attenuate`, `present`, `provider-authorize|forward|stream`, `service-authorize|forward|stream`, and operator `set`, `revoke`, `revoke-seat`, `forget`, `ls`, `status`.
   - Peer uid comes from the kernel (`SO_PEERCRED` / `getpeereid`).
   - A connection may send frames of at most 64 KiB until it `present`s a token that verifies for a row; then up to that row's request size. Frame memory grows only as bytes arrive. A frame must complete within `request_read_timeout_ms`; an idle connection is closed after `idle_timeout_ms`.
   - The client checks who is listening before sending anything. Told a broker uid (`--broker-uid`), it requires exactly that. Otherwise it trusts only a listener that is root or the client's own uid, that owns the socket file, at a path no one else could have rearranged (the same ancestor rule as above).
2. **Loopback HTTP gateway** (opt-in, loopback addresses only): `/v1/provider/<row>/...` and `/v1/service/<row>/...` with the macaroon in `Authorization: Bearer`, `x-api-key` or `x-goog-api-key`. A token in the query is refused.
   - The token and route are verified from the request head. The body is then limited to what that token may send to that row, refused from `Content-Length` alone when it announces more, and must arrive within `request_read_timeout_ms`, as must the head.
   - `Idempotency-Key` (or `x-keygate-request-id`) identifies a request for deduplication; `Idempotency-Key` is also forwarded where the row allows it. Without one, only buffered non-GET calls are deduplicated.
   - Upstream reply headers in `x-keygate-*`, hop-by-hop headers and headers named in `Connection` are not passed to the caller.
3. **CLI**: `init`, `serve`, `hello`, `set` (secret on stdin), `revoke [--forget]`, `revoke-seat`, `forget`, `ls`, `status`, `mint`, `attenuate` and `inspect` (offline), `authorize`, `forward`, `stream`. Secrets and tokens never appear in argv.

## 4. Tests

`#tooth` tests drive the real broker over its real boundaries against local HTTP/SSE servers: the engine API, the Unix socket, the loopback gateway and the `keygate` binary. They include fault injection for journal writes, a run on a filesystem that is actually full (inside a `bwrap` sandbox with a 192 KiB tmpfs), and checks of `/proc` for the hardened process. HARDENING.md lists which test pins which audit finding.
