# keygate

A Rust broker for scoped access to provider credentials and HTTPS services, including streamed responses.

The broker keeps upstream credentials in a sealed store. Callers hold attenuable capability tokens that restrict seats, routes, models, expiry, and spend. Buffered requests use a durable ticket journal for exact retries; streamed requests record their closing outcome. Revocation wakes active requests through in-memory epoch notifications. A cross-chunk response guard withholds matching credential bytes.

## Development status

This is an experimental implementation undergoing security hardening. The current suite passes, but audits identified gaps in journal failure recovery, operator separation, token-specific ticket ownership, pre-authentication resource bounds, provider dialect handling, and secret retirement. Passing tests do not establish safe deployment in a shared sandbox.

The broker must run behind an OS boundary that prevents callers from reading its keys, state, or memory. Macaroons and Unix peer credentials cannot isolate mutually hostile processes that share unrestricted access to the broker's UID. The response guard is defense in depth; it cannot prevent arbitrary transformations of a leaked credential.

## Build and inspect

Use a Linux build host with Rust installed:

```sh
cargo build --release --locked -p keygate
./target/release/keygate --help
```

`keygate init` creates a starter configuration. Review it and establish broker/operator/caller separation before serving. The workspace contains `keygate-core`, `keygate-broker`, and the `keygate` CLI. See [SPEC.md](SPEC.md) for protocols and the design contract. Latency figures in SPEC are targets unless explicitly identified as measurements.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.
