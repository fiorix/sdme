//! Content-addressable OCI blob cache keyed by SHA-256 digest.
//!
//! On-disk layout:
//! ```text
//! {cache_dir}/
//! |-- sha256/
//! |   +-- {hex_digest}       # compressed layer blob, as received
//! +-- index                  # KEY=VALUE metadata
//! ```
//!
//! Index format (one entry per line):
//! ```text
//! sha256:abcdef...=1048576,1710345600
//! ```
//! Where: `{digest}={size_bytes},{last_access_unix_epoch}`

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::parse_size;

/// A content-addressable OCI blob cache.
pub struct BlobCache {
    dir: PathBuf,
    max_size: u64,
}

/// Information about the cache.
pub struct CacheInfo {
    /// Absolute path to the cache directory.
    pub dir: PathBuf,
    /// Number of blobs currently stored.
    pub blob_count: usize,
    /// Total size of all cached blobs in bytes.
    pub total_size: u64,
    /// Maximum allowed cache size in bytes.
    pub max_size: u64,
}

/// A single cache entry.
pub struct CacheEntry {
    /// Content-addressable digest (e.g. `sha256:abcdef...`).
    pub digest: String,
    /// Blob size in bytes.
    pub size: u64,
    /// Last access time as Unix epoch seconds.
    pub last_access: u64,
}

/// Parsed index: digest to (size, atime).
type Index = Vec<(String, u64, u64)>;

/// Extract the hex portion of a `sha256:` digest, or `None` when the digest
/// is not exactly `sha256:` followed by 64 lowercase hex characters.
///
/// Digests come from registry descriptors and are untrusted: an unchecked
/// suffix can be an absolute path or contain `..` components, which would
/// make cache lookups read, write, or delete files outside the cache
/// directory. Every operation that maps a digest to a filesystem path must
/// go through this check.
pub(crate) fn parse_sha256_hex(digest: &str) -> Option<&str> {
    let hex = digest.strip_prefix("sha256:")?;
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Some(hex)
    } else {
        None
    }
}

impl BlobCache {
    /// Create from config. Resolves cache_dir relative to datadir.
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let dir = if cfg.oci_cache_dir.is_empty() {
            cfg.datadir.join("cache").join("oci")
        } else {
            let p = PathBuf::from(&cfg.oci_cache_dir);
            if !p.is_absolute() {
                bail!(
                    "oci_cache_dir must be an absolute path: {}",
                    cfg.oci_cache_dir
                );
            }
            p
        };
        let max_size = parse_size(&cfg.oci_cache_max_size)
            .with_context(|| format!("invalid oci_cache_max_size: {}", cfg.oci_cache_max_size))?;
        Ok(Self { dir, max_size })
    }

    /// Cache directory path.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the cache is enabled (max_size > 0).
    pub fn is_enabled(&self) -> bool {
        self.max_size > 0
    }

    /// Check if a blob is cached. Returns path if hit, updates atime in index.
    pub fn get(&self, digest: &str, verbose: bool) -> Option<PathBuf> {
        if !self.is_enabled() {
            return None;
        }
        let Some(hex) = parse_sha256_hex(digest) else {
            if verbose {
                eprintln!("cache: ignoring malformed digest: {digest}");
            }
            return None;
        };
        let blob_path = self.dir.join("sha256").join(hex);
        if !blob_path.exists() {
            if verbose {
                eprintln!("cache miss: {digest}");
            }
            // Clean stale index entry if present.
            if let Err(e) = self.remove_index_entry(digest) {
                eprintln!("warning: cache: failed to remove stale index entry for {digest}: {e}");
            }
            return None;
        }

        // Verify file size matches index.
        let meta = fs::metadata(&blob_path).ok()?;
        let file_size = meta.len();

        let mut index = self.load_index().ok()?;
        let found = index.iter_mut().find(|(d, _, _)| d == digest);
        match found {
            Some(entry) => {
                if entry.1 != file_size {
                    if verbose {
                        eprintln!("cache miss: {digest} (size mismatch)");
                    }
                    // Remove stale entry and file.
                    if let Err(e) = fs::remove_file(&blob_path) {
                        eprintln!("warning: cache: failed to remove stale blob {digest}: {e}");
                    }
                    if let Err(e) = self.remove_index_entry(digest) {
                        eprintln!(
                            "warning: cache: failed to remove stale index entry for {digest}: {e}"
                        );
                    }
                    return None;
                }
                // Update atime.
                entry.2 = now_epoch();
                if let Err(e) = self.save_index(&index) {
                    eprintln!("warning: cache: failed to save index after atime update: {e}");
                }
            }
            None => {
                // File exists but not in index; stale file.
                if verbose {
                    eprintln!("cache miss: {digest} (not in index)");
                }
                let _ = fs::remove_file(&blob_path);
                return None;
            }
        }

        if verbose {
            eprintln!("cache hit: {digest}");
        }
        Some(blob_path)
    }

    /// Store a blob in the cache. Copies from source path. Runs LRU eviction if over limit.
    pub fn put(&self, digest: &str, source: &Path, verbose: bool) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let Some(hex) = parse_sha256_hex(digest) else {
            bail!("malformed or unsupported digest: {digest}");
        };

        let sha_dir = self.dir.join("sha256");
        fs::create_dir_all(&sha_dir)
            .with_context(|| format!("failed to create cache dir {}", sha_dir.display()))?;

        let final_path = sha_dir.join(hex);
        let tmp_path = sha_dir.join(format!(".{hex}.tmp"));

        // Atomic write: copy to tmp, then rename.
        fs::copy(source, &tmp_path)
            .with_context(|| format!("failed to copy blob to cache: {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &final_path).with_context(|| {
            let _ = fs::remove_file(&tmp_path);
            format!(
                "failed to rename {} to {}",
                tmp_path.display(),
                final_path.display()
            )
        })?;

        let file_size = fs::metadata(&final_path)
            .with_context(|| format!("failed to stat {}", final_path.display()))?
            .len();

        // Update index under lock.
        let _lock = self.lock()?;
        let mut index = self.load_index().unwrap_or_default();

        // Remove existing entry for this digest if any.
        index.retain(|(d, _, _)| d != digest);
        index.push((digest.to_string(), file_size, now_epoch()));
        self.save_index(&index)?;
        drop(_lock);

        if verbose {
            eprintln!("cache: stored {digest} ({file_size} bytes)");
        }

        // Run eviction if over limit.
        self.evict(verbose)?;

        Ok(())
    }

    /// Return cache info: directory, blob count, total size, max size.
    pub fn info(&self) -> Result<CacheInfo> {
        let index = self.load_index().unwrap_or_default();
        let total_size: u64 = index.iter().map(|(_, s, _)| s).sum();
        Ok(CacheInfo {
            dir: self.dir.clone(),
            blob_count: index.len(),
            total_size,
            max_size: self.max_size,
        })
    }

    /// List all cached entries (digest, size, last accessed).
    pub fn list(&self) -> Result<Vec<CacheEntry>> {
        let index = self.load_index().unwrap_or_default();
        Ok(index
            .into_iter()
            .map(|(digest, size, last_access)| CacheEntry {
                digest,
                size,
                last_access,
            })
            .collect())
    }

    /// Evict LRU entries to bring cache under max_size. If `all`, remove everything.
    pub fn clean(&self, all: bool, verbose: bool) -> Result<u64> {
        if all {
            return self.clean_all(verbose);
        }
        self.evict(verbose)
    }

    // --- Internal helpers ---

    fn lock(&self) -> Result<FdLock> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("failed to create cache dir {}", self.dir.display()))?;
        let lock_path = self.dir.join(".lock");
        FdLock::new(&lock_path)
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index")
    }

    fn load_index(&self) -> Result<Index> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read cache index {}", path.display()))?;
        parse_index(&content)
    }

    fn save_index(&self, index: &Index) -> Result<()> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("failed to create cache dir {}", self.dir.display()))?;
        let path = self.index_path();
        let data = serialize_index(index);
        crate::atomic_write(&path, data.as_bytes())
            .with_context(|| format!("failed to write cache index {}", path.display()))
    }

    fn remove_index_entry(&self, digest: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut index = self.load_index().unwrap_or_default();
        let before = index.len();
        index.retain(|(d, _, _)| d != digest);
        if index.len() != before {
            self.save_index(&index)?;
        }
        Ok(())
    }

    fn evict(&self, verbose: bool) -> Result<u64> {
        let _lock = self.lock()?;
        let mut index = self.load_index().unwrap_or_default();
        let total: u64 = index.iter().map(|(_, s, _)| s).sum();
        if total <= self.max_size {
            return Ok(0);
        }

        // Sort by atime ascending (oldest first).
        index.sort_by_key(|(_, _, atime)| *atime);

        let mut freed: u64 = 0;
        let mut current = total;
        let mut to_remove = HashSet::new();

        for (digest, size, _) in &index {
            if current <= self.max_size {
                break;
            }
            // Malformed index entries are dropped from the index below but
            // must never name a filesystem path.
            if let Some(hex) = parse_sha256_hex(digest) {
                let blob_path = self.dir.join("sha256").join(hex);
                if let Err(e) = fs::remove_file(&blob_path) {
                    if verbose {
                        eprintln!("warning: cache: failed to evict blob {digest}: {e}");
                    }
                } else {
                    if verbose {
                        eprintln!("cache: evicted {digest} ({size} bytes)");
                    }
                    freed += size;
                    current -= size;
                }
            }
            to_remove.insert(digest.clone());
        }

        index.retain(|(d, _, _)| !to_remove.contains(d));
        self.save_index(&index)?;

        Ok(freed)
    }

    fn clean_all(&self, verbose: bool) -> Result<u64> {
        let _lock = self.lock()?;
        let index = self.load_index().unwrap_or_default();
        let mut freed: u64 = 0;

        for (digest, size, _) in &index {
            if let Some(hex) = parse_sha256_hex(digest) {
                let blob_path = self.dir.join("sha256").join(hex);
                if fs::remove_file(&blob_path).is_ok() {
                    if verbose {
                        eprintln!("cache: evicted {digest} ({size} bytes)");
                    }
                    freed += size;
                }
            }
        }

        // Remove the index file.
        let _ = fs::remove_file(self.index_path());
        // Remove the sha256 directory if empty.
        let _ = fs::remove_dir(self.dir.join("sha256"));
        // Remove cached OCI manifests.
        let manifests_dir = self.dir.join("manifests");
        if manifests_dir.is_dir() {
            if verbose {
                eprintln!("cache: removing manifest cache");
            }
            let _ = fs::remove_dir_all(&manifests_dir);
        }

        Ok(freed)
    }
}

// --- Index serialization ---

fn parse_index(content: &str) -> Result<Index> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (digest, rest) = line
            .split_once('=')
            .with_context(|| format!("invalid cache index line: {line}"))?;
        let (size_str, atime_str) = rest
            .split_once(',')
            .with_context(|| format!("invalid cache index value: {rest}"))?;
        let size: u64 = size_str
            .parse()
            .with_context(|| format!("invalid size in cache index: {size_str}"))?;
        let atime: u64 = atime_str
            .parse()
            .with_context(|| format!("invalid atime in cache index: {atime_str}"))?;
        entries.push((digest.to_string(), size, atime));
    }
    Ok(entries)
}

fn serialize_index(index: &Index) -> String {
    let mut out = String::new();
    for (digest, size, atime) in index {
        out.push_str(digest);
        out.push('=');
        out.push_str(&size.to_string());
        out.push(',');
        out.push_str(&atime.to_string());
        out.push('\n');
    }
    out
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format bytes as a human-readable size string.
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut val = bytes as f64;
    for unit in UNITS {
        if val < 1024.0 || *unit == "T" {
            if val == val.floor() {
                return format!("{}{unit}", val as u64);
            }
            return format!("{val:.1}{unit}");
        }
        val /= 1024.0;
    }
    unreachable!()
}

// --- File locking ---

struct FdLock {
    fd: i32,
}

impl FdLock {
    fn new(path: &Path) -> Result<Self> {
        let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .context("invalid lock path")?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
        if fd < 0 {
            bail!(
                "failed to open lock file {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            unsafe { libc::close(fd) };
            bail!(
                "failed to lock {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { fd })
    }
}

impl Drop for FdLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;
    use std::fs::File;
    use std::io::Write;

    fn test_config(dir: &Path, max_size: &str) -> Config {
        Config {
            oci_cache_dir: dir.to_string_lossy().into_owned(),
            oci_cache_max_size: max_size.to_string(),
            ..Config::default()
        }
    }

    fn write_test_blob(path: &Path, data: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = File::create(path).unwrap();
        f.write_all(data).unwrap();
    }

    #[test]
    fn test_cache_disabled() {
        let tmp = TempDataDir::new("cache-disabled");
        let cfg = test_config(tmp.path(), "0");
        let cache = BlobCache::from_config(&cfg).unwrap();
        assert!(!cache.is_enabled());
        assert!(cache.get("sha256:abc123", false).is_none());

        // put should be a no-op
        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"hello");
        cache.put("sha256:abc123", &blob, false).unwrap();
        assert!(cache.get("sha256:abc123", false).is_none());
    }

    #[test]
    fn test_cache_put_get() {
        let tmp = TempDataDir::new("cache-put-get");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();
        assert!(cache.is_enabled());

        // Create a test blob.
        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"layer data here");

        let digest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        // Miss before put.
        assert!(cache.get(digest, false).is_none());

        // Put.
        cache.put(digest, &blob, false).unwrap();

        // Hit after put.
        let path = cache.get(digest, false).unwrap();
        assert!(path.exists());
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"layer data here");
    }

    #[test]
    fn test_cache_miss() {
        let tmp = TempDataDir::new("cache-miss");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        assert!(cache.get(&digest64('0'), false).is_none());
    }

    #[test]
    fn test_cache_index_roundtrip() {
        let index: Index = vec![
            ("sha256:aaa".to_string(), 100, 1000),
            ("sha256:bbb".to_string(), 200, 2000),
        ];
        let serialized = serialize_index(&index);
        let parsed = parse_index(&serialized).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "sha256:aaa");
        assert_eq!(parsed[0].1, 100);
        assert_eq!(parsed[0].2, 1000);
        assert_eq!(parsed[1].0, "sha256:bbb");
        assert_eq!(parsed[1].1, 200);
        assert_eq!(parsed[1].2, 2000);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let tmp = TempDataDir::new("cache-eviction");
        let cache_dir = tmp.path().join("cache");
        // 30 bytes max: will trigger eviction after two 20-byte blobs.
        let cfg = test_config(&cache_dir, "30");
        let cache = BlobCache::from_config(&cfg).unwrap();

        let blob1 = tmp.path().join("blob1");
        write_test_blob(&blob1, &[0u8; 20]);
        let blob2 = tmp.path().join("blob2");
        write_test_blob(&blob2, &[1u8; 20]);

        let d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let d2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        cache.put(d1, &blob1, false).unwrap();
        cache.put(d2, &blob2, false).unwrap();

        // d1 should have been evicted (oldest).
        assert!(cache.get(d1, false).is_none());
        // d2 should still be there.
        assert!(cache.get(d2, false).is_some());
    }

    #[test]
    fn test_cache_stale_index() {
        let tmp = TempDataDir::new("cache-stale");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        // Create a blob and cache it.
        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"data");
        let digest = digest64('a');
        cache.put(&digest, &blob, false).unwrap();

        // Now delete the blob file directly (simulate stale state).
        let blob_path = cache_dir.join("sha256").join("a".repeat(64));
        fs::remove_file(&blob_path).unwrap();

        // get should return None and clean the index.
        assert!(cache.get(&digest, false).is_none());
    }

    #[test]
    fn test_cache_info() {
        let tmp = TempDataDir::new("cache-info");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        let info = cache.info().unwrap();
        assert_eq!(info.blob_count, 0);
        assert_eq!(info.total_size, 0);
        assert_eq!(info.max_size, 1024 * 1024 * 1024);

        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"data123");
        cache.put(&digest64('d'), &blob, false).unwrap();

        let info = cache.info().unwrap();
        assert_eq!(info.blob_count, 1);
        assert_eq!(info.total_size, 7);
    }

    #[test]
    fn test_cache_clean_all() {
        let tmp = TempDataDir::new("cache-clean-all");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"data");
        cache.put(&digest64('e'), &blob, false).unwrap();
        cache.put(&digest64('f'), &blob, false).unwrap();

        let freed = cache.clean(true, false).unwrap();
        assert!(freed > 0);

        let info = cache.info().unwrap();
        assert_eq!(info.blob_count, 0);
    }

    #[test]
    fn test_cache_list() {
        let tmp = TempDataDir::new("cache-list");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"data");
        let digest = digest64('9');
        cache.put(&digest, &blob, false).unwrap();

        let entries = cache.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].digest, digest);
        assert_eq!(entries[0].size, 4);
    }

    fn digest64(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    #[test]
    fn test_parse_sha256_hex() {
        let good = digest64('a');
        assert_eq!(parse_sha256_hex(&good), Some(&"a".repeat(64)[..]));
        assert_eq!(
            parse_sha256_hex(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );

        // Absolute path, traversal, wrong length, non-hex, uppercase,
        // unsupported algorithm, missing prefix, empty suffix.
        for bad in [
            "sha256:/etc/passwd",
            "sha256:../escape",
            "sha256:",
            "sha256:abcd",
            "plain",
            &format!("sha256:{}", "a".repeat(63)),
            &format!("sha256:{}", "a".repeat(65)),
            &format!("sha256:{}", "g".repeat(64)),
            &format!("sha256:{}", "A".repeat(64)),
            &format!("sha512:{}", "a".repeat(128)),
        ] {
            assert_eq!(parse_sha256_hex(bad), None, "accepted {bad}");
        }
    }

    #[test]
    fn test_cache_get_malformed_digest_preserves_outside_files() {
        let tmp = TempDataDir::new("cache-malformed-get");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        // Sentinel outside the cache, named by an absolute digest suffix.
        let sentinel = tmp.path().join("sentinel.txt");
        write_test_blob(&sentinel, b"do not delete");
        let abs_digest = format!("sha256:{}", sentinel.display());

        // Empty index: the lookup must not touch the named file.
        assert!(cache.get(&abs_digest, false).is_none());
        assert_eq!(fs::read(&sentinel).unwrap(), b"do not delete");

        // A `..` suffix must not name a file next to the blob directory.
        fs::create_dir_all(cache_dir.join("sha256")).unwrap();
        let neighbor = cache_dir.join("neighbor.txt");
        write_test_blob(&neighbor, b"neighbor data");
        assert!(cache.get("sha256:../neighbor.txt", false).is_none());
        assert_eq!(fs::read(&neighbor).unwrap(), b"neighbor data");

        // Wrong length, non-hex content, and unsupported formats.
        for bad in [
            "sha256:",
            "sha256:abcd",
            "not-a-digest",
            &format!("sha256:{}", "a".repeat(63)),
            &format!("sha256:{}", "a".repeat(65)),
            &format!("sha256:{}", "g".repeat(64)),
            &format!("sha256:{}", "A".repeat(64)),
            &format!("sha512:{}", "a".repeat(128)),
        ] {
            assert!(cache.get(bad, false).is_none(), "digest accepted: {bad}");
        }

        // Populated cache: a valid entry must survive malformed lookups.
        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"real layer");
        let good = digest64('a');
        cache.put(&good, &blob, false).unwrap();

        assert!(cache.get(&abs_digest, false).is_none());
        assert_eq!(fs::read(&sentinel).unwrap(), b"do not delete");

        // A traversal suffix resolving to the cached blob must not delete it
        // as stale.
        let traversal = format!("sha256:../sha256/{}", "a".repeat(64));
        assert!(cache.get(&traversal, false).is_none());
        let hit = cache
            .get(&good, false)
            .expect("valid digest must still hit");
        assert_eq!(fs::read(&hit).unwrap(), b"real layer");
    }

    #[test]
    fn test_cache_put_rejects_malformed_digest() {
        let tmp = TempDataDir::new("cache-malformed-put");
        let cache_dir = tmp.path().join("cache");
        let cfg = test_config(&cache_dir, "1G");
        let cache = BlobCache::from_config(&cfg).unwrap();

        let blob = tmp.path().join("blob");
        write_test_blob(&blob, b"layer bytes");

        // An absolute suffix must not create a file outside the cache.
        let escape = tmp.path().join("escape-target");
        let abs_digest = format!("sha256:{}", escape.display());
        assert!(cache.put(&abs_digest, &blob, false).is_err());
        assert!(!escape.exists());

        for bad in [
            "sha256:../traversal",
            "sha256:abcd",
            "plain-hex-without-prefix",
            &format!("sha512:{}", "a".repeat(128)),
        ] {
            assert!(cache.put(bad, &blob, false).is_err(), "put accepted {bad}");
        }

        // Valid digests still store and load.
        let good = digest64('b');
        cache.put(&good, &blob, false).unwrap();
        let hit = cache.get(&good, false).unwrap();
        assert_eq!(fs::read(&hit).unwrap(), b"layer bytes");
    }

    #[test]
    fn test_cache_eviction_skips_malformed_index_entries() {
        let tmp = TempDataDir::new("cache-malformed-evict");
        let cache_dir = tmp.path().join("cache");
        fs::create_dir_all(cache_dir.join("sha256")).unwrap();

        // Sentinel outside the cache, named by a malicious index entry.
        let sentinel = tmp.path().join("evict-sentinel");
        write_test_blob(&sentinel, b"keep me");
        let evil_digest = format!("sha256:{}", sentinel.display());

        // A valid blob sharing the index.
        let good = digest64('c');
        let good_path = cache_dir.join("sha256").join("c".repeat(64));
        write_test_blob(&good_path, b"real blob");

        let index: Index = vec![(evil_digest, 7, 1000), (good.clone(), 9, 2000)];
        fs::write(cache_dir.join("index"), serialize_index(&index)).unwrap();

        // Force LRU eviction over the hand-written index.
        let cfg = test_config(&cache_dir, "1");
        let cache = BlobCache::from_config(&cfg).unwrap();
        cache.clean(false, false).unwrap();
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep me");
        assert!(!good_path.exists(), "valid blob should have been evicted");

        // Rebuild and exercise clean(all).
        write_test_blob(&good_path, b"real blob");
        fs::write(
            cache_dir.join("index"),
            serialize_index(&vec![
                (format!("sha256:{}", sentinel.display()), 7, 1000),
                (good, 9, 2000),
            ]),
        )
        .unwrap();
        cache.clean(true, false).unwrap();
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep me");
        assert!(!good_path.exists());
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0B");
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(1024), "1K");
        assert_eq!(format_size(1536), "1.5K");
        assert_eq!(format_size(1048576), "1M");
        assert_eq!(format_size(1073741824), "1G");
        assert_eq!(format_size(1099511627776), "1T");
    }
}
