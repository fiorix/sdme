//! Directory copy import.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::copy::*;

/// Import a rootfs from a local directory by copying the tree.
pub(super) fn do_import(source: &Path, staging: &Path, verbose: bool) -> Result<()> {
    // Create the staging directory and copy the root directory's metadata.
    fs::create_dir(staging)
        .with_context(|| format!("failed to create staging dir {}", staging.display()))?;
    copy_metadata(source, staging)
        .with_context(|| format!("failed to copy metadata for {}", source.display()))?;
    copy_xattrs(source, staging)?;

    if verbose {
        eprintln!("copying {} -> {}", source.display(), staging.display());
    }

    copy_tree(source, staging, verbose)
}
