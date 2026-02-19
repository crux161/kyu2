# External Readiness Checklist (Kyu2)

Date assessed: 2026-02-19
Status updated: 2026-02-19

Release gate:
Do not expose Kyu2 to untrusted external users or networks until all P0 items are completed and verified.

Current implementation status:
- [x] P0 items implemented in code and tests.
- [x] P1 feature work started and merged into the main code path (multiplexing, relay regeneration, telemetry, policy docs).

## P0 Must-Fix Before External Use

1. Redesign nonce/key schedule for authenticated encryption.
Current risk:
- Nonce is derived only from `block_id` (`sankaku-core/src/pipeline.rs:42`, `sankaku-core/src/pipeline.rs:80`).
- Session key is reused across multiple file sends in the same sender session (`sankaku-core/src/session.rs:106`, `sankaku-core/src/session.rs:124`).
Minimum done:
- Derive protocol keys from shared secret with HKDF and transcript binding.
- Separate keys by purpose and direction (payload tx/rx, header tx/rx).
- Guarantee nonce uniqueness per key across all streams/files (include stream scope and packet counter).
- Add negative tests proving nonce reuse cannot occur.

2. Add authenticated handshake and peer identity checks.
Current risk:
- Handshake uses ephemeral DH only; no authenticated peer identity (`sankaku-core/src/handshake.rs:7`, `sankaku-core/src/session.rs:289`).
- Active MITM can proxy key exchange.
Minimum done:
- Add peer authentication model (PSK, static keys, certificates, or Noise pattern with identity binding).
- Bind version/capabilities and endpoint context into transcript.
- Fail closed for unknown/untrusted peers.

3. Bound all untrusted packet-driven allocations and state growth.
Current risk:
- `total_size` and `pkt_size` are parsed from network headers and flow into decoder creation/recovery (`sankaku-core/src/session.rs:336`, `sankaku-core/src/session.rs:350`, `sankaku-core/src/fec.rs:134`).
- Session map grows without explicit hard cap (`sankaku-core/src/session.rs:268`, `sankaku-core/src/session.rs:300`).
Minimum done:
- Enforce strict protocol limits for packet size and protected block size.
- Reject invalid or suspicious headers before decoder allocation.
- Add hard caps for sessions, streams per session, and in-flight decoders.
- Add per-source rate limits and memory budget enforcement.

4. Remove panic paths from runtime network/file handling.
Current risk:
- Runtime `unwrap()` use can crash process on malformed or unexpected data paths (`sankaku-core/src/session.rs:100`, `sankaku-core/src/session.rs:362`, `sankaku-core/src/metadata.rs:23`).
Minimum done:
- Replace runtime `unwrap()`/`expect()` in protocol and IO paths with typed errors.
- Ensure malformed inputs produce structured error events, not panics.
- Add tests for malformed filename/manifest and bad packet geometry paths.

5. Make wire spec and implementation consistent and enforce version checks.
Current risk:
- Packet size conflicts between docs and code (`SPEC.md:17`, `README.md:27`, `sankaku-core/src/session.rs:14`).
- `protocol_version` is carried but not validated/rejected for incompatibility (`sankaku-core/src/handshake.rs:8`, `sankaku-core/src/session.rs:289`).
Minimum done:
- Use shared constants for protocol geometry and publish one canonical spec.
- Reject unsupported protocol versions during handshake.
- Add protocol conformance tests against spec constants.

6. Expand security/reliability tests beyond happy path.
Current risk:
- Test coverage is minimal and mostly happy-path (`sankaku-core/tests/integration_test.rs:4`, `sankaku-wirehair-sys/src/lib.rs:11`).
Minimum done:
- Add integration tests with loss, reorder, duplication, corruption, and forged packets.
- Add parser fuzzing for packet/header decode paths.
- Add long-running soak tests for session churn and stream churn.

7. Make library initialization safe-by-default.
Current risk:
- Correct operation depends on caller remembering to call `init()` (`sankaku-core/src/lib.rs:15`).
Minimum done:
- Use `OnceLock`/`Once` so Wirehair init happens automatically on first use.
- Keep explicit init as optional no-op convenience, not a safety requirement.

8. Enforce release CI gates and clean lint baseline.
Current risk:
- `cargo clippy --workspace --all-targets -- -D warnings` currently fails on core crate issues.
Minimum done:
- CI must pass `fmt`, `clippy -D warnings`, and `test --workspace`.
- Add sanitizers/fuzz job for packet parsing surfaces.
- Require green CI as merge gate for protocol-touching changes.

## P1 Essentials Immediately After P0

1. Align product claims with real capabilities.
Why:
- README claims high-concurrency multiplexing and mesh behavior not yet fully represented in the exposed workflow (`README.md:33`, `sankaku-cli/src/main.rs:42`).
Implement:
- Either ship the missing capabilities or narrow claims to current behavior.

2. Add production observability.
Why:
- Operational diagnosis is hard with ad-hoc stdout events only.
Implement:
- Structured logs, transfer/session metrics, error taxonomy, and trace IDs.

3. Define stable protocol evolution policy.
Why:
- External users need compatibility guarantees.
Implement:
- Versioning rules, deprecation windows, migration tests, and changelog discipline.

4. Improve build/release reproducibility.
Why:
- Current workspace has dependency/version drift and hygiene issues (`Cargo.toml:12`, `Cargo.toml:15`, `.gitignore:5`, `sankaku-core/Cargo.toml:17`, `sankaku-cli/Cargo.toml:11`).
Implement:
- Remove duplicate workspace members.
- Standardize dependency major versions where feasible.
- Decide lockfile policy explicitly for app crates and enforce in CI.

5. Add abuse controls for receiver runtime.
Why:
- Public-facing UDP services need explicit abuse protections beyond correctness.
Implement:
- Rate limiting, session admission control, idle eviction tuning, and configurable quotas.
