//! Storage backends for container root filesystems.
//!
//! sdme supports pluggable strategies for a container's writable root. The
//! default `overlay` backend keeps the base rootfs immutable and layers a
//! per-container overlayfs `upper`/`work`/`merged` on top (the original sdme
//! model): clones are instant, but the container root is itself an overlay
//! mount, so nested containers cannot create their own overlay and `--userns`
//! may fall back to a recursive chown.
//!
//! The `btrfs` backend gives each container a real filesystem via a
//! copy-on-write subvolume snapshot of the base rootfs. Because the root is a
//! genuine filesystem, nested containers work, `--userns` uses native idmapped
//! mounts (preserving suid bits and xattrs without a chown pass), and
//! per-container disk quotas are available through btrfs qgroups. It runs
//! either directly on a btrfs datadir (Mode A) or inside a shared loopback
//! btrfs pool image on any other filesystem (Mode B).
//!
//! Backend selection is per container, recorded in the `STORAGE` state key and
//! resolved from [`crate::config::Config`] at create time. Containers created
//! before this key existed, and any with an empty value, resolve to
//! [`Backend::Overlay`], so the abstraction is a no-op for existing containers.

pub mod btrfs;
pub mod pool;

use anyhow::{bail, Result};

use crate::State;

/// The storage strategy for a container's writable root filesystem.
///
/// This is a closed set dispatched by `match` (mirroring [`crate::export::RawFs`]);
/// each variant's behavior lives in its module (`overlay`, `btrfs`, `pool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// overlayfs `upper`/`work`/`merged` layered on an immutable lower rootfs.
    #[default]
    Overlay,
    /// A copy-on-write btrfs subvolume snapshot of the base rootfs.
    Btrfs,
}

impl Backend {
    /// The token used in the state file, config, and the `--storage` flag.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Overlay => "overlay",
            Backend::Btrfs => "btrfs",
        }
    }

    /// Parse a backend token from config or the CLI. An empty string selects
    /// the default (`overlay`); any other unknown token is an error.
    pub fn parse(s: &str) -> Result<Backend> {
        match s {
            "" | "overlay" => Ok(Backend::Overlay),
            "btrfs" => Ok(Backend::Btrfs),
            other => bail!("unknown storage backend {other:?}: expected \"overlay\" or \"btrfs\""),
        }
    }

    /// Resolve the backend recorded for a container. A missing or empty
    /// `STORAGE` key resolves to [`Backend::Overlay`], so pre-existing
    /// containers keep their original behavior.
    pub fn from_state(state: &State) -> Backend {
        state
            .get_nonempty("STORAGE")
            .and_then(|s| Backend::parse(s).ok())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_as_str_roundtrip() {
        assert_eq!(Backend::parse("overlay").unwrap(), Backend::Overlay);
        assert_eq!(Backend::parse("btrfs").unwrap(), Backend::Btrfs);
        // Empty selects the default.
        assert_eq!(Backend::parse("").unwrap(), Backend::Overlay);
        // Unknown backends are rejected, not silently defaulted.
        assert!(Backend::parse("zfs").is_err());
        // as_str is the inverse of parse.
        assert_eq!(Backend::Overlay.as_str(), "overlay");
        assert_eq!(Backend::Btrfs.as_str(), "btrfs");
        assert_eq!(
            Backend::parse(Backend::Btrfs.as_str()).unwrap(),
            Backend::Btrfs
        );
    }

    #[test]
    fn from_state_defaults_to_overlay() {
        let mut state = State::new();
        // Missing STORAGE key -> overlay (the historical default).
        assert_eq!(Backend::from_state(&state), Backend::Overlay);
        // Empty value is treated as unset.
        state.set("STORAGE", "");
        assert_eq!(Backend::from_state(&state), Backend::Overlay);
        state.set("STORAGE", "btrfs");
        assert_eq!(Backend::from_state(&state), Backend::Btrfs);
        state.set("STORAGE", "overlay");
        assert_eq!(Backend::from_state(&state), Backend::Overlay);
    }
}
