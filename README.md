# keygate

A Rust broker for scoped access to provider credentials and HTTPS services, including streamed responses.

The broker keeps upstream credentials in a sealed store. Callers hold attenuable capability tokens that restrict seat, namespace, rows, methods, paths, models, request size, expiry and spend. Buffered requests use a durable ticket journal for exact retries; streamed requests record how they ended. Revocation, token expiry and shutdown cut active requests through in-memory notifications. A cross-chunk response guard withholds reflections of a credential.

## Development status

Experimental. Three rounds of security hardening have been applied — including an independent review and a follow-up audit — recorded finding by finding in [HARDENING.md](HARDENING.md), with the test that pins each fix. The suite (unit tests, adversarial integration tests over the real Unix socket and HTTP gateway, fault injection, a run on a genuinely full filesystem, real separated-uid acceptance, and end-to-end tests of the binary) passes on Linux. It has never been built or run on macOS.

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
