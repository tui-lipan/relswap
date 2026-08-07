# relswap

Signed-release install and update engine with immutable version directories, a durable
activation journal, and crash recovery across enumerated fault points.

Consumers supply an [`App`](https://docs.rs/relswap) identity (name, version, repository URL,
trust anchor, activation strategy). `relswap` never embeds a product key or package version.

## License

MIT OR Apache-2.0
