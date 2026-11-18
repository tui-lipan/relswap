# relswap

Signed-release install and update engine with immutable version directories, a durable
activation journal, and crash recovery across enumerated fault points.

Consumers supply an [`App`](https://docs.rs/relswap) identity (name, version, repository URL,
trust anchor, activation strategy). `relswap` never embeds a product key or package version.

## Manifest expiry

Signed manifests carry an `expires_at` timestamp and are rejected once it passes, because a
signature alone never goes stale: without an expiry, someone able to withhold responses could pin
clients to an authentic but obsolete manifest indefinitely. The `relswap manifest` tool defaults to
a one-year window.

Two consequences worth planning for:

- **Installing a pinned old version stops working once its manifest expires.** `install_version()`
  fetches and validates that release's manifest like any other, so a year-old release cannot be
  installed fresh until it is re-signed. If you need indefinitely reproducible installs, sign those
  releases with a longer window.
- **Rollback is unaffected.** `rollback()` activates a version already present on disk and never
  touches the network, so recovering from a bad update keeps working offline and after expiry.

The host clock is tolerated to `EXPIRY_CLOCK_SKEW` (12 hours) so an unsynchronised machine
degrades into a late expiry rather than being unable to update at all.

## License

MIT OR Apache-2.0


### Windows companion files

Set `App::windows_companions` to the exact basenames of files to install beside the
Windows payload, in dependency order. Use an empty slice for applications without
companions. The signed archive can supply the full set or omit it for an older
release. Other archive members stay outside the managed install.

relswap keeps the signed archive alongside the installed files so it can verify their
contents on recovery and rollback without changing the release manifest format. An
older updater can install the payload from a new archive. Reinstall that release with
the new installer to add its companions.
