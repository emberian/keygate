# keygate hardening record

This file records the second hardening round: a 19-item second-order audit of the tree at `10342d5`, and an eleven-point follow-up review of the fixes while they were in progress (four of those points concern this repository). Every item has a disposition and, where it was fixed, the code that fixes it and the test that would fail without the fix.

Dispositions: **fixed**, **already fixed** (before this round), **fixed differently** (the proposed remedy was replaced, with the reason), **declined in part** (with the reason).

## How the fixes were checked

All figures are from a Linux x86-64 build host (32 cores, rustc 1.99.1), debug build unless stated. The code has never been compiled or run on macOS.

| check | result |
|---|---|
| `cargo test --workspace` | 146 passed, 0 failed, 1 ignored (the benchmark) |
| of which | 69 `keygate-core` unit, 1 full-filesystem sandbox test, 19 `keygate-broker` unit, 35 + 17 broker integration, 5 CLI end-to-end |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| mutation checks | 40 of 40 caught |

**Mutation checks.** A test that passes proves little until it has been seen to fail. For 40 of the properties below, the fix was removed in a scratch copy (one at a time) and the named test was run; in every case it failed. The mutations cover the guard window, variants and retired patterns, the guard byte cap, gateway and socket pre-authentication bounds, the idle timeout, ticket ownership, stream expiry, the fixed provider endpoint, feature refusals, `best_of`, unpriced spend caps, token forwarding, `Idempotency-Key`, reply-header filtering, the own-uid rule, client broker identity, journal rollback (injected and on a real full filesystem), journal poisoning, shutdown, process dumpability, config and ancestor custody, the clock floor, the secret/guard pairing, audio output, the generation counter, and three checks made between real kernel uids.

**Real boundaries exercised.**

- *Full filesystem.* `crates/keygate-core/tests/enospc.rs` re-executes itself in a `bwrap` sandbox whose only writable filesystem is a 192 KiB tmpfs and fills it. Measured run: 799 audit lines, then 468 tickets, then `ENOSPC`; every failed append left both files parseable, nothing was charged for a refused reservation, the journal carried on once space returned, and it replayed after reopening.
- *Different kernel uids.* `scripts/multiuid-acceptance.sh` (run by the CLI test `tooth_real_multi_uid_separation`) enters a user namespace with subordinate uids mapped, builds a throwaway root on tmpfs, and runs the broker as uid 0 with callers as uids 1 and 2. Six checks pass: uid 1 is served with its scoped token; uid 1 cannot read the master key, sealed rows, journal, config or broker memory; uid 1 cannot mint, list, set, revoke or forget; uid 2 cannot use a token bound to uid 1; the broker's own uid is refused as a caller; and the operator's client sends nothing to a listener planted by uid 1.
- *Process memory.* The CLI test starts the real daemon and confirms from `/proc` that its `mem`, `environ` and `maps` cannot be opened by its own uid and that its core limit is 0, with an ordinary child process as the control.
- Skips are reported, not silent: both sandbox tests print `SKIPPED` with the reason when the host lacks `bwrap` or subordinate-uid mapping.

## Measurements

Design goals in SPEC.md are not measurements. These are:

| quantity | measured |
|---|---|
| cut notification, send to waiter ready (unit test, asserted) | under 100 µs |
| `revoke` call to the caller observing the stream end, 40 runs, debug build | min 359 µs, median 463 µs, max 793 µs |
| the same, asserted bound in the integration test | under 50 ms |
| guard build, 1 secret of 108 B (release) | 50 µs, 3 KiB of tables |
| guard build, 32 secrets of 108 B (release) | 1.5 ms, 96 KiB of tables |
| guard build at the 64 KiB pattern cap, 8 secrets of 8 KiB (release) | 17 ms, 1.7 MiB of tables |
| guard scan of SSE-shaped text, single core (release) | 42, 35 and 29 MiB/s for those three guards |
| shutdown drain with one stream and one hung call in flight | under 2 s (asserted), 0 unrecorded |

The earlier specification stated "<100 µs" for revocation as if it were the end-to-end figure. End to end it is a few hundred microseconds in a debug build; what is under 100 µs is the wake itself. The guard is the throughput limit for large streamed bodies: about 30–40 MiB/s per core, far above token streams and below a fast bulk download.

## Audit findings

**1. Crash retention of in-flight tickets (high).** *Already fixed* at `10342d5`: `Journal::open` demotes `InFlight` to `Uncertain` with `now + retention_s` (`journal.rs`, test `tooth_crash_recovery_uses_terminal_retention`). The shutdown half is *fixed* in this round: `Broker::shutdown` cuts every flight, waits up to `shutdown_grace_ms` for outcomes to be journaled and refuses new calls; `serve` calls it on SIGTERM/SIGINT. Test: `tooth_shutdown_cuts_flights_and_records_their_outcomes`.

**2. Journal write failures (high).** The compaction-reopen subclaim was *already fixed* (the compaction's own descriptor becomes the journal). *Fixed* here: `Inner::commit` tracks the committed length; a short write is cut back to it and only that operation fails; a failed cut-back, a failed `fdatasync`, or a failed directory sync after a compaction install poisons the journal, which then refuses every commit until restart. Memory is never ahead of disk. The audit log cuts back torn lines too. Tests: `tooth_short_write_is_rolled_back_and_the_journal_stays_bootable`, `tooth_unremovable_torn_record_poisons_the_journal`, `tooth_fsync_failure_poisons_and_memory_does_not_advance`, `tooth_compaction_directory_sync_failure_poisons`, `tooth_failed_compaction_before_install_changes_nothing`, the full-filesystem test above, and at the broker boundary `tooth_journal_failures_fail_closed_before_the_network`.

**3. Implicit operator and co-uid access (high).** *Fixed differently.* Peer-uid checks cannot protect a broker from its own uid, so the fix is a deployment boundary that is stated, checked and refuses ambiguity: `deployment = "separated"` is the default, requires `operator_uids`, does not serve a peer running as the broker's uid, requires HTTPS upstreams, and `serve` sets `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` and umask 077 before any key is read, refusing to start otherwise (`harden.rs`, `Broker::may_call`). `development` keeps the old single-uid behaviour, by name, for tests. Tests: `tooth_separated_deployment_does_not_serve_the_brokers_own_uid`, `tooth_separated_deployment_refuses_implicit_operator_and_loopback_http`, `tooth_serve_hardens_the_process_and_checks_custody`, `tooth_default_init_boots_separated`, `tooth_real_multi_uid_separation`. Remaining and outside the program: creating the separate uid and a socket path callers can reach.

**4. Guard matched only the complete secret (medium-high).** *Fixed, with a different design.* The guard now trips on any 16 consecutive bytes of a secret or of a fixed set of re-encodings (percent-encoding in both hex cases, three JSON escapings), using one suffix automaton (`echo.rs`). *Declined in part:* ASCII case-folding is not done, because credentials are case-sensitive and folding matches unrelated text; no claim is made about base64, hex or other transformations, and the limits are tested so they stay documented. Tests: `tooth_truncated_and_altered_echoes_trip`, `tooth_encoded_variants_trip`, `tooth_matches_the_naive_definition` (a differential test against the definition written the slow way), `tooth_truncated_altered_and_encoded_echoes_are_withheld`.

**5. Rotated and revoked secrets no longer scrubbed (medium).** *Fixed.* Previous secrets are kept sealed in the row file (seal format 2, format 1 still readable) as guard-only patterns until `keygate forget`; at most 8 per row. Tests: `tooth_retired_secrets_stay_guarded_until_forgotten`, `retired_secrets_round_trip_and_format_1_still_opens`, `tooth_cli_retire_forget_and_broker_identity`.

**6. Guard memory, reallocation and lock hold (medium).** *Fixed.* Tables are sparse (1.7 MiB at the cap, against 256 MiB before), allocated once at final size and zeroed on drop; total pattern bytes are capped at 64 KiB and a `set` over the cap is refused; the holdback is a fixed 16-byte array; the automaton is built outside any lock a request takes. Tests: `tooth_guard_size_is_bounded`, `tooth_guard_budget_is_enforced_at_set`.

**7. Buffering before authentication, no read deadlines (medium).** *Fixed.* Gateway: the token and route are verified from the request head (`Broker::preauthorize`), the body is limited to what that token may send to that row and refused from `Content-Length` alone, and head and body have a deadline. Socket: 64 KiB frame limit until a token is `present`ed, incremental allocation, frame and idle deadlines, bounded read-ahead. Tests: `tooth_gateway_authenticates_and_bounds_before_reading_the_body`, `tooth_unix_frames_are_bounded_before_authentication`, `tooth_frames_are_bounded_before_they_are_buffered`. What remains bounded rather than eliminated: authenticated peers can together hold `max_connections` times a row's `max_request_bytes`.

**8. Budgets.** (a) *Fixed:* a cap on a row with no prices is a config error; a spend-capped token is refused on an unpriced provider row. (b) *Fixed:* server-held input, fetched input, provider-run tools, premium tiers and inline media are refused unless the row's `allow` lists them; the reservation is now an upper bound for text-only requests (one token per body byte plus 4096, at the dearest input price including cache writes). Settlement still records actual usage even above a reservation, which is truthful accounting and is documented. (c) *Fixed:* `best_of` multiplies like `n`. (d) *Fixed by refusal:* `previous_response_id` and the like need `server-state`; with it allowed, cross-seat reference is possible and documented, since stored objects belong to the upstream key. Tests: `tooth_caps_without_prices_are_refused`, `tooth_unmetered_and_server_side_input_is_refused_unless_allowed`, `tooth_reservation_covers_choices_cache_prices_and_null_fields`, `tooth_cache_and_stream_usage_settle_exactly`.

**9. Path-selected models bypass the allowlist (medium).** *Fixed.* A provider row has a `dialect` and accepts `POST` at exactly one endpoint whose body carries the model; Gemini-native, Bedrock and Azure deployment paths cannot be configured. Test: `tooth_provider_rows_reach_one_endpoint_of_their_dialect`.

**10. Tickets shared between tokens of one seat (medium).** *Fixed.* The request digest includes an owner id derived from the verified final tag, and the sorted spend scopes. Tests: `tooth_tickets_belong_to_the_token_that_opened_them`, `tooth_owner_id_is_per_token_and_hides_the_tag`.

**11. Streams outlive token expiry (medium).** *Fixed.* The relay waits on a timer for the token's earliest expiry and closes with `closed_by: expired`. Tests: `tooth_stream_is_cut_when_its_token_expires`, `tooth_cut_watch_expires_on_the_token_deadline`.

**12. Loopback HTTP upstreams and port squatting (medium).** *Fixed differently.* Checking the listener's uid or restricting ports would not make an unauthenticated transport safe, and removing it would break local fixtures. Plain-HTTP loopback is now an explicit development transport: accepted only with `deployment = "development"`, refused with a message that says why otherwise. Test: `tooth_separated_deployment_refuses_implicit_operator_and_loopback_http`.

**13. Dangerous headers not reserved (low-medium).** *Fixed.* Method-override, URL-rewrite and forwarding headers cannot be configured at all; credential headers cannot be opened to callers; billing-identity headers can be fixed by the operator but not sent by callers. Test: `tooth_dangerous_headers_cannot_be_configured`.

**14. Tokens in the query forwarded (low-medium).** *Fixed, and declined in part.* A request whose query or forwarded headers contain a keygate token, or whose body contains the presented token, is refused; `x-goog-api-key` is accepted as a token source and stripped. A token in the query is *not* accepted as authentication, because URLs are logged. Test: `tooth_tokens_never_travel_upstream`.

**15. `Idempotency-Key` consumed, never forwarded (low).** *Fixed.* It is used for deduplication and forwarded where the row lists it. Test: `tooth_idempotency_key_is_forwarded_where_allowed`.

**16. Upstream can spoof `x-keygate-*` and pass hop-by-hop headers (low).** *Fixed.* Test: `tooth_upstream_cannot_spoof_keygate_or_hop_by_hop_headers`.

**17. `null` handled inconsistently (low).** *Fixed.* An explicit `null` is absent everywhere, and one function decides whether a body asks for a stream. Test: `tooth_reservation_covers_choices_cache_prices_and_null_fields`.

**18. Root path.** *Already fixed* at `10342d5` (`/` is the zero-segment path; `path.rs` tests).

**19. Bind window, unverified server, clock fail-open, config custody (low).** *Fixed.* The socket is bound under a private name, given its mode, then renamed into place. The client verifies the listener from kernel peer credentials before sending. A clock before the epoch or before 2025-06-15 is an error (`clock_failed`), never zero. The config must be a regular file owned by the broker or root and not writable by others. Tests: `tooth_client_verifies_the_broker_and_socket_mode_is_never_wider`, `tooth_client_refuses_an_unexpected_listener`, `tooth_broken_clocks_fail_closed`, `tooth_config_custody`.

The audit also noted that it found no upstream request smuggling; nothing in this round changes the properties that note rested on.

## Follow-up review findings

**K-P1. A flight could be paired with a guard that no longer contained its secret.** *Confirmed and fixed.* `snapshot` read the secret, then separately the guard; `set --forget-retired` (and `revoke --forget`) could publish a guard without the old secret in between. The pair is now read under the guard lock and published under it, held only across pointer reads and writes, never across sealing, `fsync` or a build. Test: `tooth_snapshot_pairs_the_secret_with_a_guard_that_contains_it` pauses a reader at exactly that point and shows the writer waits.

**K-P2. Only the state directory itself was checked.** *Confirmed and fixed.* Every ancestor must be owned by the broker or root and not writable by others (sticky excepted); the broker uses the canonical path it checked; the config is held to the same rule. Custody opens no longer follow symlinks, block on FIFOs, accept non-regular files or read without a bound. Tests: `tooth_untrusted_ancestors_are_refused` (which also checks no mode is altered), `tooth_fifo_config_does_not_block`. The check is by path at startup, not by directory descriptor; it relies on the checked ancestors staying trusted, which their ownership and modes ensure.

**K-P3. The client trusted a socket whose owner and listener agreed.** *Confirmed and fixed.* Without an explicit broker uid the client now trusts only a listener that is root or itself, and checks the whole path to the socket. Tests: `tooth_client_checks_the_whole_path_to_the_socket`, and the planted-listener check in the multi-uid script, where a listener bound by uid 1 receives no bytes from the operator's `set`.

**K-P4. Audio output and stored audio ids were not recognised.** *Confirmed and fixed.* `modalities` other than text and Chat Completions `audio` need a new allowance, `non-text-output`; an assistant message's `audio.id` needs `server-state`. No pricing for audio is implemented: with the allowance, the row's caps are not bounds, as for the other allowances. Test: `tooth_unmetered_and_server_side_input_is_refused_unless_allowed` (no upstream connection is made for any refused request).

**Counter bounds.** *Fixed.* A row's generation counter is checked and fails closed one short of its maximum, so a revocation floor can always exceed it; the in-flight count saturates. Seat epochs were already checked. Test: `tooth_generation_counter_does_not_wrap`.

**Multi-uid acceptance.** The earlier note in this round that real multi-uid behaviour could not be exercised without root was wrong. It is exercised, as described above.

The other seven points of that review concern a different project and have no disposition here.

## What is still not true

- keygate does not create the OS boundary it depends on. A broker run as the same uid as its callers, in `development` mode, protects nothing from them.
- The response guard does not catch fewer than 16 consecutive bytes, base64, hex, case changes, or any transformation outside its variant list.
- With any `allow` entry on a provider row, reservations for requests using that feature are not upper bounds.
- Reservations assume the row's configured prices are the highest that apply, and at most 4096 tokens of provider-added prompt.
- Custody checks happen at startup, by path. An administrator who later loosens an ancestor's permissions is not detected until restart.
- The gateway has no peer credentials; any local process holding a valid token can use it there.
- Separated deployment is supported on Linux only.
