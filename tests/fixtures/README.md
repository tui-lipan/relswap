# Release fixtures

This directory is reserved for end-to-end signed release fixtures used by
integration tests.

## Status

No production signed hyprmux release has been published yet (`release-keys.json`
starts empty and fail-closed). Until a real `v*` tag is cut through
`hyprmux`'s `release.yml` and archived here, unit tests use in-memory
`FaultInjector` fixtures with ephemeral Ed25519 keys.

## Expected contents (after the first reference release)

- `*-release.json` — signed schema-v2 manifest (`expires_at` required)
- `*-release.signatures.json` — detached signature envelope
- Per-target archives named `{app}-{version}-{triple}.{tar.gz|zip}`
- Optional: a schema-v1 manifest kept only as a rejection-gate fixture

Do not commit private keys.
