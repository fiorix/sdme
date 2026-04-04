//! Unused resource analysis and cleanup.
//!
//! The prune command scans all resource types (filesystems, containers,
//! pods, secrets, configmaps, volumes, stale transactions) and collects
//! items that can be safely removed. The analysis phase is read-only;
//! removal happens only after user confirmation.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use std::sync::atomic::Ordering;

use crate::{check_interrupted, containers, kube, pod, rootfs, txn, State, INTERRUPTED};

/// Category of a prunable resource, ordered by display and removal priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneCategory {
    /// Imported rootfs with no containers using it.
    Filesystem,
    /// Container with unhealthy status.
    Container,
    /// Pod with no containers attached.
    Pod,
    /// Kube secret (copied at create time, not runtime-bound).
    Secret,
    /// Kube configmap (copied at create time, not runtime-bound).
    ConfigMap,
    /// Orphaned volume directory.
    Volume,
    /// Stale transaction staging directory.
    StaleTransaction,
}

impl PruneCategory {
    /// Short prefix for `--except` syntax.
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Filesystem => "fs",
            Self::Container => "container",
            Self::Pod => "pod",
            Self::Secret => "secret",
            Self::ConfigMap => "configmap",
            Self::Volume => "volume",
            Self::StaleTransaction => "txn",
        }
    }

    /// Human-readable label for display headings.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Filesystem => "Filesystems",
            Self::Container => "Containers",
            Self::Pod => "Pods",
            Self::Secret => "Secrets",
            Self::ConfigMap => "ConfigMaps",
            Self::Volume => "Volumes",
            Self::StaleTransaction => "Stale transactions",
        }
    }
}

/// Display ordering of categories: filesystems first, stale transactions last.
const DISPLAY_ORDER: [PruneCategory; 7] = [
    PruneCategory::Filesystem,
    PruneCategory::Container,
    PruneCategory::Pod,
    PruneCategory::Secret,
    PruneCategory::ConfigMap,
    PruneCategory::Volume,
    PruneCategory::StaleTransaction,
];

/// Removal ordering: stale transactions first (no lock), then follows lock
/// ordering (fs, containers, pods, secrets, configmaps), volumes last.
const REMOVAL_ORDER: [PruneCategory; 7] = [
    PruneCategory::StaleTransaction,
    PruneCategory::Filesystem,
    PruneCategory::Container,
    PruneCategory::Pod,
    PruneCategory::Secret,
    PruneCategory::ConfigMap,
    PruneCategory::Volume,
];

/// A single item that can be pruned.
pub struct PrunableItem {
    /// Category for grouping and removal ordering.
    pub category: PruneCategory,
    /// Name of the item (used in `--except` matching and display).
    pub name: String,
    /// Human-readable reason this item is prunable.
    pub reason: String,
}

/// Check whether an item should be excluded based on `--except` entries.
///
/// Entries can be `category:name` (exact category match) or plain `name`
/// (matches all categories).
pub fn is_excluded(item: &PrunableItem, except: &[String]) -> bool {
    let prefix = item.category.prefix();
    except.iter().any(|entry| match entry.split_once(':') {
        Some((cat, name)) => cat == prefix && name == item.name,
        None => entry == &item.name,
    })
}

/// Scan all resource types and return items that can be pruned.
///
/// The configured `default_base_fs` is always excluded from filesystem
/// pruning. This function does not acquire locks or modify any state,
/// but it does query systemd D-Bus for container health (same as `sdme ps`).
pub fn analyze(datadir: &Path, default_base_fs: &str) -> Result<Vec<PrunableItem>> {
    let mut items = Vec::new();

    // 1. Unused filesystems: no containers and not the default base.
    let fs_entries = rootfs::list(datadir)?;
    for entry in &fs_entries {
        if entry.containers.is_empty() && entry.name != default_base_fs {
            items.push(PrunableItem {
                category: PruneCategory::Filesystem,
                name: entry.name.clone(),
                reason: "unused (no containers)".to_string(),
            });
        }
    }

    check_interrupted()?;

    // 2. Unhealthy containers: anything not "ok" or "ready".
    let ct_entries = containers::list(datadir)?;
    for entry in &ct_entries {
        if entry.health != "ok" && entry.health != "ready" {
            items.push(PrunableItem {
                category: PruneCategory::Container,
                name: entry.name.clone(),
                reason: entry.health.clone(),
            });
        }
    }

    check_interrupted()?;

    // 3. Unused pods: no containers reference them.
    let pod_entries = pod::list(datadir)?;
    for p in &pod_entries {
        if p.containers.is_empty() {
            items.push(PrunableItem {
                category: PruneCategory::Pod,
                name: p.name.clone(),
                reason: "no containers attached".to_string(),
            });
        }
    }

    check_interrupted()?;

    // 4. All secrets (copied at create time, not runtime-bound).
    let secrets = kube::secret::list(datadir)?;
    for s in &secrets {
        items.push(PrunableItem {
            category: PruneCategory::Secret,
            name: s.name.clone(),
            reason: "not referenced at runtime".to_string(),
        });
    }

    check_interrupted()?;

    // 5. All configmaps (copied at create time, not runtime-bound).
    let configmaps = kube::configmap::list(datadir)?;
    for cm in &configmaps {
        items.push(PrunableItem {
            category: PruneCategory::ConfigMap,
            name: cm.name.clone(),
            reason: "not referenced at runtime".to_string(),
        });
    }

    check_interrupted()?;

    // 6. Orphaned volumes: no container references the volume path.
    let volumes_dir = datadir.join("volumes");
    if volumes_dir.is_dir() {
        // Collect all BINDS values from container state files for matching.
        let mut all_binds = HashSet::new();
        let state_dir = datadir.join("state");
        if state_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&state_dir) {
                for entry in entries.flatten() {
                    if let Ok(state) = State::read_from(&entry.path()) {
                        for bind in state.get_list("BINDS", '|') {
                            all_binds.insert(bind);
                        }
                    }
                }
            }
        }

        if let Ok(entries) = fs::read_dir(&volumes_dir) {
            let mut vol_names: Vec<String> = Vec::new();
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = entry.file_name().to_str() {
                        vol_names.push(name.to_string());
                    }
                }
            }
            vol_names.sort();

            let volumes_prefix = volumes_dir.to_string_lossy();
            for name in vol_names {
                // A volume is orphaned if no BINDS value contains its path.
                let vol_path = format!("{}/{}", volumes_prefix, name);
                let referenced = all_binds.iter().any(|b| b.contains(&vol_path));
                if !referenced {
                    items.push(PrunableItem {
                        category: PruneCategory::Volume,
                        name,
                        reason: "orphaned (no matching container)".to_string(),
                    });
                }
            }
        }
    }

    check_interrupted()?;

    // 7. Stale transaction staging directories.
    let fs_dir = datadir.join("fs");
    let stale = txn::find_all_stale_txns(&fs_dir)?;
    for path in &stale {
        if let Some(fname) = path.file_name() {
            items.push(PrunableItem {
                category: PruneCategory::StaleTransaction,
                name: fname.to_string_lossy().into_owned(),
                reason: "stale (creator PID not running)".to_string(),
            });
        }
    }

    Ok(items)
}

/// Print categorized analysis to stderr.
///
/// Groups items by category with counts and reasons, followed by a total
/// line and an `--except` hint. If secrets or configmaps are present,
/// adds a note explaining they are copied at kube create time.
pub fn display(items: &[PrunableItem], excluded_count: usize, default_base_fs: &str) {
    let mut has_secrets_or_configmaps = false;

    for cat in &DISPLAY_ORDER {
        let group: Vec<&PrunableItem> = items.iter().filter(|i| i.category == *cat).collect();
        if group.is_empty() {
            continue;
        }

        if *cat == PruneCategory::Secret || *cat == PruneCategory::ConfigMap {
            has_secrets_or_configmaps = true;
        }

        let name_w = group.iter().map(|i| i.name.len()).max().unwrap_or(0);
        eprintln!("\n{} ({}):", cat.label(), group.len());
        for item in &group {
            eprintln!("  {:<name_w$}  {}", item.name, item.reason);
        }
    }

    eprintln!();

    if !default_base_fs.is_empty() {
        eprintln!("default base fs '{}' is always excluded", default_base_fs);
    }
    if excluded_count > 0 {
        eprintln!("{excluded_count} item(s) excluded via --except");
    }

    eprintln!("total: {} item(s) to prune", items.len());

    if has_secrets_or_configmaps {
        eprintln!(
            "hint: secrets and configmaps are copied at kube create time;\n      \
             use --except to keep items needed for future kube apply"
        );
    }

    // Build --except suggestion with category:name for ambiguous names.
    // Truncate to a few examples when the list is long.
    let mut name_count = std::collections::HashMap::new();
    for item in items {
        *name_count.entry(&item.name).or_insert(0u32) += 1;
    }
    let suggestions: Vec<String> = items
        .iter()
        .map(|item| {
            if name_count[&item.name] > 1 {
                format!("{}:{}", item.category.prefix(), item.name)
            } else {
                item.name.clone()
            }
        })
        .collect();

    if !suggestions.is_empty() {
        const MAX_SUGGESTIONS: usize = 5;
        if suggestions.len() <= MAX_SUGGESTIONS {
            eprintln!(
                "\nto exclude items: sdme prune --except={}",
                suggestions.join(",")
            );
        } else {
            let preview: Vec<&str> = suggestions
                .iter()
                .take(MAX_SUGGESTIONS)
                .map(|s| s.as_str())
                .collect();
            eprintln!(
                "\nto exclude items: sdme prune --except={},... ({} more)",
                preview.join(","),
                suggestions.len() - MAX_SUGGESTIONS
            );
        }
    }
}

/// Remove prunable items in lock order.
///
/// Follows the lock ordering: fs, containers, pods, secrets, configmaps.
/// Stale transactions are cleaned first (no lock needed), orphaned volumes
/// last. Each item calls [`check_interrupted`] before acting. Errors are
/// collected rather than aborting.
pub fn execute(
    items: &[PrunableItem],
    datadir: &Path,
    auto_gc: bool,
    verbose: bool,
) -> (usize, Vec<(String, anyhow::Error)>) {
    let mut succeeded = 0usize;
    let mut errors: Vec<(String, anyhow::Error)> = Vec::new();

    for cat in &REMOVAL_ORDER {
        let group: Vec<&PrunableItem> = items.iter().filter(|i| i.category == *cat).collect();
        for item in &group {
            if check_interrupted().is_err() {
                return (succeeded, errors);
            }

            let result = match cat {
                PruneCategory::StaleTransaction => {
                    let path = datadir.join("fs").join(&item.name);
                    remove_stale_txn(&path, verbose)
                }
                PruneCategory::Filesystem => rootfs::remove(datadir, &item.name, auto_gc, verbose),
                PruneCategory::Container => containers::remove(datadir, &item.name, verbose),
                PruneCategory::Pod => pod::remove(datadir, &item.name, true, verbose),
                PruneCategory::Secret => {
                    kube::secret::remove(datadir, std::slice::from_ref(&item.name))
                }
                PruneCategory::ConfigMap => {
                    kube::configmap::remove(datadir, std::slice::from_ref(&item.name))
                }
                PruneCategory::Volume => {
                    let path = datadir.join("volumes").join(&item.name);
                    crate::copy::safe_remove_dir(&path)
                }
            };

            match result {
                Ok(()) => {
                    println!("{}", item.name);
                    succeeded += 1;
                }
                Err(e) => {
                    errors.push((item.name.clone(), e));
                }
            }

            // Break immediately on signal so we don't start the next removal.
            if INTERRUPTED.load(Ordering::Relaxed) {
                break;
            }
        }
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }
    }

    (succeeded, errors)
}

/// Remove a single stale transaction directory.
fn remove_stale_txn(path: &Path, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!(
            "prune: removing {}",
            path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
        );
    }
    if path.is_dir() {
        crate::copy::safe_remove_dir(path)?;
    } else if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_excluded_plain_name() {
        let item = PrunableItem {
            category: PruneCategory::Secret,
            name: "myapp".to_string(),
            reason: "test".to_string(),
        };
        let except = vec!["myapp".to_string()];
        assert!(is_excluded(&item, &except));
    }

    #[test]
    fn test_is_excluded_prefixed_name() {
        let item = PrunableItem {
            category: PruneCategory::Secret,
            name: "myapp".to_string(),
            reason: "test".to_string(),
        };
        let except = vec!["secret:myapp".to_string()];
        assert!(is_excluded(&item, &except));
    }

    #[test]
    fn test_is_excluded_wrong_prefix() {
        let item = PrunableItem {
            category: PruneCategory::Secret,
            name: "myapp".to_string(),
            reason: "test".to_string(),
        };
        let except = vec!["container:myapp".to_string()];
        assert!(!is_excluded(&item, &except));
    }

    #[test]
    fn test_is_excluded_no_match() {
        let item = PrunableItem {
            category: PruneCategory::Filesystem,
            name: "ubuntu".to_string(),
            reason: "test".to_string(),
        };
        let except = vec!["debian".to_string()];
        assert!(!is_excluded(&item, &except));
    }

    #[test]
    fn test_category_prefix_roundtrip() {
        let categories = [
            PruneCategory::Filesystem,
            PruneCategory::Container,
            PruneCategory::Pod,
            PruneCategory::Secret,
            PruneCategory::ConfigMap,
            PruneCategory::Volume,
            PruneCategory::StaleTransaction,
        ];
        let prefixes: Vec<&str> = categories.iter().map(|c| c.prefix()).collect();
        // All prefixes must be unique.
        let unique: HashSet<&str> = prefixes.iter().copied().collect();
        assert_eq!(prefixes.len(), unique.len());
    }

    #[test]
    fn test_analyze_empty_datadir() {
        let dir = std::env::temp_dir().join(format!("sdme-test-prune-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let result = analyze(&dir, "").unwrap();
        assert!(result.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
