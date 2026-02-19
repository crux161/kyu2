# Build and Release Reproducibility (Kyu2)

## Lockfile Policy

- `Cargo.lock` is source-controlled for this repository.
- CI validates lockfile consistency with `cargo generate-lockfile --locked`.
- Dependency updates must be intentional and reviewed.

## Tooling Baseline

- CI gates require:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
- A dedicated adversarial parser/network suite is run as an additional gate.
- A nightly AddressSanitizer adversarial job is configured as a non-blocking signal.

## Determinism Expectations

- Builds must not rely on unstated environment variables except explicit runtime configuration (for example `KYU2_PSK`).
- Wire-format constants are defined in code and reflected in `SPEC.md`.
- Protocol/handshake changes must include test updates in the same PR.

## Release Checklist

- Confirm green CI on the release commit.
- Confirm `SPEC.md`, `README.md`, and protocol constants are synchronized.
- Confirm lockfile and dependency graph are unchanged unless explicitly upgraded.
