# Protocol Evolution Policy (Kyu2)

This document defines compatibility and upgrade rules for external Kyu2 deployments.

## Versioning Model

- `PROTOCOL_VERSION` is the wire-compatibility boundary.
- Patch-level implementation changes are allowed only when the encoded wire format is unchanged.
- Any incompatible field shape, semantic re-interpretation, or handshake behavior change requires a protocol version bump.

## Compatibility Contract

- A node must reject unknown protocol versions during handshake.
- Capability bits are additive and must not silently weaken security.
- Backward-compatible additions must preserve existing field meanings.

## Security Upgrade Rules

- Security-sensitive defaults must fail closed.
- New auth or key schedule logic must be transcript-bound.
- Any cryptographic parameter migration must include tests for mismatch and downgrade rejection.

## Deprecation Windows

- Deprecated versions remain supported for one minor release cycle unless a critical vulnerability requires emergency cutoff.
- Deprecation notices must include the exact protocol version and cutoff date.

## Required Test Gates

Every protocol-touching change must include:

- Positive compatibility tests for expected peers.
- Negative tests for unsupported version/capability combinations.
- Adversarial packet tests for malformed, reordered, duplicated, dropped, and corrupted traffic.
- End-to-end regression tests for multiplexed stream transfer.

## Changelog Discipline

- Every protocol-affecting PR must include a `Protocol:` changelog line.
- Changelog entries must explicitly state whether wire compatibility is preserved.
