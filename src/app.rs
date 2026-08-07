//! Product identity supplied by every `relswap` consumer.

/// Consumer-supplied product and trust configuration.
///
/// All fields are `&'static` so naming helpers can stay allocation-light and so the trust anchor
/// can be compiled in by the caller with `include_bytes!`. This crate never embeds a key file or
/// `CARGO_PKG_VERSION` of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct App {
    /// Archive prefix and Unix payload basename (for example `"hyprmux"`).
    pub name: &'static str,
    /// Caller's `env!("CARGO_PKG_VERSION")`.
    pub version: &'static str,
    /// GitHub (or compatible) repository URL used to resolve release downloads.
    pub repository_url: &'static str,
    /// Raw JSON bytes of a [`crate::release::TrustedKeySet`] (caller's `include_bytes!`).
    pub trust_anchor: &'static [u8],
    /// How the stable command path is activated on each OS.
    pub activation: ActivationStrategy,
    /// Optional pre-activation probe executed after verification and before the pointer switch.
    pub self_test: Option<SelfTest>,
}

/// How a managed installation exposes a stable command path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationStrategy {
    /// Unix: `command_path` is a symlink into `versions/<v>/<name>`.
    UnixSymlink,
    /// Windows: a signed launcher binary under `bin/` reads `active` and execs the payload.
    WindowsLauncher {
        /// Published launcher filename (for example `"hyprmux-launcher.exe"`).
        launcher_name: &'static str,
        /// Launcher wire protocol version written into the release manifest.
        protocol: u32,
    },
}

/// Probe the staged payload before activation.
///
/// Runs `versions/<v>/<payload> <args…>` under a timeout and requires combined stdout/stderr to
/// contain the canonical string of the version being activated. Catches correctly signed binaries
/// that cannot run on the host (for example a glibc mismatch) and binaries that do not report the
/// version the manifest claims they are.
///
/// The expected substring is always derived from the version under activation, never from
/// [`App::version`]: during an update the staged payload is a *different* version than the running
/// binary, so a caller-supplied constant could only ever match a first install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfTest {
    /// Arguments passed to the staged payload (for example `&["--version"]`).
    pub args: &'static [&'static str],
    /// Wall-clock timeout for the probe process.
    pub timeout: std::time::Duration,
}

impl App {
    /// Unix payload basename, or `{name}.exe` on Windows targets.
    pub fn payload_name(&self, windows: bool) -> String {
        if windows {
            format!("{}.exe", self.name)
        } else {
            self.name.to_string()
        }
    }

    /// Payload basename for the host this binary was compiled for.
    pub fn host_payload_name(&self) -> String {
        self.payload_name(cfg!(windows))
    }

    /// Windows launcher filename when [`ActivationStrategy::WindowsLauncher`] is configured.
    pub fn launcher_name(&self) -> Option<&'static str> {
        match self.activation {
            ActivationStrategy::UnixSymlink => None,
            ActivationStrategy::WindowsLauncher { launcher_name, .. } => Some(launcher_name),
        }
    }

    /// Windows launcher protocol when configured.
    pub fn launcher_protocol(&self) -> Option<u32> {
        match self.activation {
            ActivationStrategy::UnixSymlink => None,
            ActivationStrategy::WindowsLauncher { protocol, .. } => Some(protocol),
        }
    }

    /// Canonical published metadata filename: `{name}-release.json`.
    pub fn metadata_filename(&self) -> String {
        format!("{}-release.json", self.name)
    }

    /// Canonical published signature filename: `{name}-release.signatures.json`.
    pub fn signature_filename(&self) -> String {
        format!("{}-release.signatures.json", self.name)
    }

    /// Archive root / prefix stem: `{name}-{version}-{triple}`.
    pub fn root_name(&self, version: &semver::Version, triple: &str) -> String {
        format!("{}-{version}-{triple}", self.name)
    }

    /// Prefix used when parsing archive roots: `{name}-`.
    pub fn archive_prefix(&self) -> String {
        format!("{}-", self.name)
    }
}
