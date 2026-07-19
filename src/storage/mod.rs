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
//! The `--storage` flag and the `default_storage_backend` config also accept
//! `auto` (the effective default): overlay in a nested (user-namespaced)
//! context, where btrfs roots cannot boot, and the configured default
//! otherwise. See `crate::nested` for the nested-context handling.

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

    /// Parse a backend token from the state file. An empty string selects the
    /// default (`overlay`); any other token is an error. `auto` is not a
    /// backend: it is a resolution token accepted by `--storage` and
    /// `default_storage_backend`, never recorded in state.
    pub fn parse(s: &str) -> Result<Backend> {
        match s {
            "" | "overlay" => Ok(Backend::Overlay),
            "btrfs" => Ok(Backend::Btrfs),
            other => bail!("unknown storage backend {other:?}: expected \"overlay\" or \"btrfs\""),
        }
    }

    /// Resolve the backend for a new container from the `--storage` flag (if
    /// given) and the configured default. `nested` reports that sdme runs
    /// inside a user-namespaced container (see `crate::nested`).
    ///
    /// `auto` (explicit, or the effective default when no flag is given)
    /// selects overlay in a nested context, where btrfs roots cannot boot,
    /// and the configured default otherwise. An explicit `btrfs` flag is
    /// honored verbatim on the host but is a hard error in a nested context:
    /// no silent downgrade. An explicit flag is otherwise passed to
    /// [`Backend::parse`]; create-time validation rejects btrfs on a host
    /// rootfs. A btrfs *default* (from `default_storage_backend`) falls back
    /// to overlay for host-rootfs containers, which cannot use btrfs, so
    /// setting the default to btrfs does not break plain `sdme new`/`create`.
    pub fn resolve(
        flag: Option<&str>,
        default: &str,
        host_rootfs: bool,
        nested: bool,
    ) -> Result<Backend> {
        match flag {
            Some("btrfs") if nested => bail!(
                "btrfs storage cannot boot inside a user-namespaced container: \
                 btrfs superblocks are not ownable by a nested user namespace, \
                 so nspawn's mount setup fails. Use --storage overlay, or drop \
                 the flag: auto (the default) selects overlay here."
            ),
            Some("auto") | None => Self::resolve_auto(default, host_rootfs, nested),
            Some(s) => Backend::parse(s),
        }
    }

    /// Auto selection: overlay in a nested context (btrfs roots cannot boot
    /// there); the configured default otherwise, with the historical
    /// host-rootfs fallback to overlay.
    fn resolve_auto(default: &str, host_rootfs: bool, nested: bool) -> Result<Backend> {
        if nested {
            if default == "btrfs" {
                eprintln!(
                    "note: nested (user-namespaced) context detected; auto-selecting overlay \
                     storage because btrfs roots cannot boot here"
                );
            }
            return Ok(Backend::Overlay);
        }
        let backend = match default {
            "" | "auto" => Backend::Overlay,
            other => Backend::parse(other)?,
        };
        Ok(if backend == Backend::Btrfs && host_rootfs {
            Backend::Overlay
        } else {
            backend
        })
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
    fn resolve_honors_flag_and_defaults() {
        // Explicit flag wins verbatim on the host, regardless of rootfs kind.
        // btrfs on a host rootfs is left for create-time validation to reject.
        assert_eq!(
            Backend::resolve(Some("btrfs"), "overlay", false, false).unwrap(),
            Backend::Btrfs
        );
        assert_eq!(
            Backend::resolve(Some("btrfs"), "overlay", true, false).unwrap(),
            Backend::Btrfs
        );
        assert_eq!(
            Backend::resolve(Some("overlay"), "btrfs", false, false).unwrap(),
            Backend::Overlay
        );
        assert!(Backend::resolve(Some("zfs"), "", false, false).is_err());
        // Overlay is valid in a nested context.
        assert_eq!(
            Backend::resolve(Some("overlay"), "btrfs", false, true).unwrap(),
            Backend::Overlay
        );
    }

    #[test]
    fn resolve_btrfs_flag_is_hard_error_when_nested() {
        // No silent downgrade of an explicit request.
        assert!(Backend::resolve(Some("btrfs"), "overlay", false, true).is_err());
        assert!(Backend::resolve(Some("btrfs"), "btrfs", false, true).is_err());
    }

    #[test]
    fn resolve_auto_selects_overlay_when_nested() {
        // auto, explicit or via no flag, forces overlay in a nested context
        // even when the configured default is btrfs.
        assert_eq!(
            Backend::resolve(Some("auto"), "btrfs", false, true).unwrap(),
            Backend::Overlay
        );
        assert_eq!(
            Backend::resolve(None, "btrfs", false, true).unwrap(),
            Backend::Overlay
        );
        assert_eq!(
            Backend::resolve(None, "", false, true).unwrap(),
            Backend::Overlay
        );
    }

    #[test]
    fn resolve_auto_on_host_uses_configured_default() {
        // auto on the host falls through to the configured default.
        assert_eq!(
            Backend::resolve(Some("auto"), "btrfs", false, false).unwrap(),
            Backend::Btrfs
        );
        assert_eq!(
            Backend::resolve(None, "auto", false, false).unwrap(),
            Backend::Overlay
        );
    }

    #[test]
    fn resolve_btrfs_default_falls_back_on_host_rootfs() {
        // btrfs default + imported rootfs -> btrfs. This is the kube pod path,
        // which always uses an imported base rootfs and should honor a btrfs
        // default from config.
        assert_eq!(
            Backend::resolve(None, "btrfs", false, false).unwrap(),
            Backend::Btrfs
        );
        // btrfs default + host rootfs -> overlay fallback (no error).
        assert_eq!(
            Backend::resolve(None, "btrfs", true, false).unwrap(),
            Backend::Overlay
        );
        // overlay/empty default is unaffected by rootfs kind.
        assert_eq!(
            Backend::resolve(None, "", true, false).unwrap(),
            Backend::Overlay
        );
        assert_eq!(
            Backend::resolve(None, "overlay", false, false).unwrap(),
            Backend::Overlay
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
