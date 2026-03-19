//! Directory copy import.

use anyhow::{Context, Result};
use std::path::Path;

use crate::copy::*;

/// Import a rootfs from a local directory by copying the tree.
///
/// The staging directory must already exist (created by the caller's [`Txn`](crate::txn::Txn)).
pub(super) fn do_import(source: &Path, staging: &Path, verbose: bool) -> Result<()> {
    copy_metadata(source, staging)
        .with_context(|| format!("failed to copy metadata for {}", source.display()))?;
    copy_xattrs(source, staging)?;

    if verbose {
        eprintln!("copying {} -> {}", source.display(), staging.display());
    }

    copy_tree(source, staging, verbose)
}
