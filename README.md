# keygate

A Rust broker for scoped access to provider credentials and HTTPS services, including streamed responses.

The broker keeps upstream credentials in a sealed store. Callers hold attenuable capability tokens that restrict seat, namespace, rows, methods, paths, models, request size, expiry and spend. Buffered requests use a durable ticket journal for exact retries; streamed requests record how they ended. Revocation, token expiry and shutdown cut active requests through in-memory notifications. A cross-chunk response guard withholds reflections of a credential.

## Development status

Experimental. Three rounds of security hardening have been applied — including an independent review and a follow-up audit — recorded finding by finding in [HARDENING.md](HARDENING.md), with the test that pins each fix. The suite (unit tests, adversarial integration tests over the real Unix socket and HTTP gateway, fault injection, a run on a genuinely full filesystem, real separated-uid acceptance, and end-to-end tests of the binary) passes on Linux. It also builds without warnings on macOS, where only the worker's unit and refusal tests and the socket-replacement test have been run.

Things that are true whatever the tests say:

- **The broker needs an OS boundary.** Run it under its own uid with a state directory only that uid can read. A process sharing the broker's uid can read the master key; no token scheme changes that. The default `separated` deployment refuses to serve a peer running as the broker's own uid, requires operators to be listed, acquires an exclusive state-directory lock (`broker.lock`) before opening mutable state, and makes the serving process non-dumpable, but creating the uid and making the socket reachable by callers is deployment work keygate cannot do itself.
- **The response guard is defense in depth.** It trips on any 16 consecutive bytes of a credential or of a fixed set of re-encodings of it. Shorter fragments, base64, hex, case changes and other transformations pass.
- **Spend limits bind for text-only requests on rows with prices.** Requests whose cost is not determined by their body (stored conversations, fetched URLs, provider-run tools, premium tiers, inline media, audio or other non-text output) are refused unless a row opts in, and for those the limits are not bounds.
- **Deduplication of completed requests is a finite window.** A retained reply replays for `retention_s` (default 15 minutes); after that an identical request is sent again. A request whose outcome is *unknown* is different: it is remembered, and refused on exact retry, for as long as the token that sent it stays valid.
- **Old secrets stay guarded until you say otherwise.** Rotation and revocation keep the previous secret sealed as a guard-only pattern; only `forget` (or `--forget-retired` / `revoke --forget`) removes it.
- **Provider support is by dialect:** Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and gateways compatible with one of them. APIs that choose the model in the URL path (Gemini `generateContent`, Bedrock, Azure deployment paths) are not supported.

## Build and inspect

Use a Linux build host with Rust installed:

```sh
cargo build --release --locked -p keygate
./target/release/keygate --help
```

`keygate init` creates a state directory, a master key and a starter `keygate.toml` for a `separated` deployment with the initializing user as operator. A minimal arrangement:

1. Create a dedicated user for the broker and run `keygate init` and `keygate serve` as that user.
2. Put the socket where callers under other uids can reach it (`socket`, `socket_mode`), for example a group-accessible socket in a directory only the broker or root can write. Unless the broker is root or the client's own uid, clients must be told its uid (`--broker-uid` or `KEYGATE_BROKER_UID`); they refuse a socket whose path others could have rearranged.
3. Load secrets with `keygate set <provider|service> <row>` (reads stdin), mint tokens with `keygate mint`, and hand callers attenuated tokens.

To check the arrangement between real uids without root, run `scripts/multiuid-acceptance.sh ./target/release/keygate`: it builds a private user namespace, runs the broker as one uid and callers as two others, and verifies the boundary.

`deployment = "development"` allows everything to share one uid and allows plain-HTTP loopback upstreams. It exists for tests and local experiments.

The workspace contains `keygate-core` (sealing, macaroons, guard, journal, audit, config), `keygate-broker` (engine, Unix socket and HTTP gateway) and the `keygate` CLI. See [SPEC.md](SPEC.md) for the design contract; figures there are design goals unless identified as measurements, and the measurements are in HARDENING.md.

## Long-running service clients

Run the broker under a separate uid and give each agent a UID-bound token over
the Unix socket. Configure one service row per origin; two rows may hold the
same upstream bearer, but their tickets are distinct. Renew tokens through an
operator process, without giving the agent operator authority or an unbounded
parent token.

A one-day `ExpiresAtUnixS` with renewal ahead of expiry is a reasonable starting
policy. Use jitter and enough overlap to tolerate renewal failures. Renewal
means minting a fresh token: attenuation cannot extend an expiry. Each request
carries its token; minting a replacement does not change an existing stream.
At its original token's expiry, that stream closes with `closed_by: expired`.
Reconnect with the replacement token and the service's resume cursor when
supported (`last_event_id` requires the row to allow `Last-Event-ID`).

Dispatch on Unix frame codes and stream summaries, not the HTTP gateway's status
mapping:

| Result | Client action |
|---|---|
| `no_secret` | Back off with jitter; retry admission after the operator re-seals the row. |
| `revoked` / `closed_by: revoked` | Re-authorize before opening another stream. Both row and seat revocation use this result; a revoked seat then gets `denied`. |
| `closed_by: expired` | Use the scheduled renewal path and reconnect with a fresh token. |
| `denied` | Stop using that token. Check its known expiry for an expected renewal; otherwise report the policy refusal. Re-sealing a bearer cannot fix it. |
| `method_refused`, `path_refused`, `header_refused`, `too_large` | Correct the request or policy before retrying. |
| `uncertain` | Reconcile the operation with the upstream; do not create a new request to bypass the refusal. |
| `no_resend_ledger_full` | Pause new work and alert the operator; retry admission with backoff while expired records become eligible for collection. |

**Keep retries tied to the original operation and token.** A refreshed or
attenuated token, a different row, or a new request id creates a different
ticket. None inherits the original ticket's no-resend protection. Keep the
original token for exact retries while it is valid and the ticket is retained.
Never automatically resend an uncertain POST under a replacement token or a
failover row. That requires upstream operation-level idempotency or confirmation
of the original outcome. An ended stream's exact retry returns its summary
(`spent: true`), not a reopened stream; a deliberate reconnect is a new request.

The default `max_uncertain_tickets = 10000` is a broker-wide ceiling on unknown
outcomes, not daily request volume. Size it for the number of uncertain outcomes
that can accumulate during the retention/token-lifetime window, including
failure bursts across all agents. A record is eligible for collection only after
both its retention deadline and its owner's expiry (or seat revocation).
Renewing a token does not revoke its predecessor or immediately collect its
records. Tokens with no expiry on a never-revoked seat retain uncertain records
indefinitely. At the ceiling, the broker refuses new requests rather than forget
an outcome that could still be retried.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.

### Running JavaScript handlers

`keygate-worker` supervises a persistent pool on Linux with Bubblewrap, util-linux
`prlimit`, and a Node whose `vm` module has `constants.DONT_CONTEXTIFY` (22.8 or later;
20.18 on the 20 line). Each worker gets
a private user, PID and network namespace, a read-only Node runtime, empty environment
and framed pipes. The Rust supervisor owns the macaroon and the 50 ms invocation
deadline. An interrupted call can already have reached its service. Reuse the same
request ID when retrying or reconciling a Git operation.

Configure `broker.pod_seats` to map each pod service row to its verified seat,
and `broker.pod_micro_usd` to set the charge for a claim or completion. Configure
the row's POST paths and provision its credential for the matching landd pod principal.
Git operations use the existing authoritative `broker.git_land_targets` configuration.

```sh
keygate-worker --socket "$socket" --token-file "$token_file" --seat ci \
  --pod-row pods --git-row forge --max-spend-micro-usd 500 --workers 2 \
  --allow pod.claim,pod.done,git.land,git.reconcile
```

The pool's macaroon admits only the rows and paths its `--allow` operations use:
`pod.claim` and `pod.done` call `--pod-row` at `/pod/claim` and `/pod/done`;
`git.land` and `git.reconcile` call `--git-row` at `/git/land` (the broker admits a
reconcile as the land call it settles). A row no allowed operation uses need not be
given and is not granted. Tickets belong to the exact token that opened them, and
pools with equal options hold equal tokens however `--allow` is ordered, so a
`git.reconcile` pool settles what a `git.land` pool with the same options left
uncertain. A pool granted all four operations holds the token earlier releases gave
every pool. A pool granted fewer now holds a narrower token, and `Uncertain` tickets
it opened before the upgrade cannot be reconciled through it.

The jail runs `/usr/bin/prlimit`, `/usr/bin/bwrap` and `/usr/bin/node` unless
`--prlimit-bin`, `--bwrap-bin` and `--node-bin` name other absolute paths. `PATH` is
never searched, and a relative path or one containing `..` is refused before anything
is looked up. Each binary is resolved to its canonical path and must be a regular
executable file owned by root or the worker's uid, writable by neither group nor
others, in a directory writable by neither, below directories only root or that uid
can rearrange (sticky directories excepted). `--prlimit-sha256`, `--bwrap-sha256`
and `--node-sha256` pin a binary's SHA-256. Node is bound into each sandbox at its
canonical path; `--node-lib-dir` binds another directory its shared libraries need,
under the same rules, and never one that contains the token file or the socket.
Before restarting a worker after a timeout or crash, the supervisor checks that each
binary is still the file it verified (device, inode, size, mode, owner, modification
and change times). If one is not, it answers that job with `"reason":"toolchain"`
and exits with an error; restart the pool to verify the new files.

`keygate-worker --check-toolchain-only`, with the same toolchain options, verifies the
binaries, starts one sandboxed worker, prints the canonical paths and SHA-256 digests
as JSON and exits without reading a token. Use it as a packaging check or systemd
`ExecStartPre`, and to read the digests to pin. When the sandbox does not start, its
standard error carries what Bubblewrap or Node reported. Where only profiled binaries
may create user namespaces (Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`),
`/usr/bin/bwrap` cannot set up the jail's network namespace; name a bwrap whose
AppArmor profile allows `userns` with `--bwrap-bin`.

Use one pool per trust principal. Requests and responses are JSON with a four-byte
big-endian length prefix and a 64 KiB limit. Wait for the ready frame before sending
requests of the form `{"id":1,"source":"return yield caps.pod.claim(input)","input":...}`.
The input to a claim has `pod`, `task`, `lease_seconds` and `request_id`. A completion
takes `fencing_token` in place of `lease_seconds`. Git calls take `cas` and `request_id`,
with the ticket additionally required for reconciliation. The supervisor returns
typed results and request IDs. Realms are private to a worker, principal and exact
handler source. Instances of the same handler can retain realm state between calls.

Run `node --test scripts/worker-context.test.cjs` for the realm and wire checks, and
`cargo test -p keygate --test worker` for the binary: on Linux it runs pools in
Bubblewrap, reading `KEYGATE_WORKER_TEST_BWRAP` and `KEYGATE_WORKER_TEST_NODE` where
the system bwrap may not create user namespaces or the system Node is too old, and
printing `SKIPPED` with the reason when the host cannot build the jail.
With built binaries on PATH, `python3 scripts/worker-acceptance.py` exercises the
jail, real pod transactions, spend refusal and an authoritative Git ref update
whose reply was lost. The benchmark places its journal and database on the
filesystem selected by `TMPDIR` and includes their synchronization latency.
