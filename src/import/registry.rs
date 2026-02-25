//! OCI registry image pull support.
//!
//! Pulls container images directly from OCI-compatible registries using the
//! OCI Distribution Spec. Supports anonymous bearer token authentication.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::check_interrupted;

use super::oci::unpack_oci_layer;
use super::{build_http_agent, detect_compression_magic, get_decoder, proxy_from_env, MAX_DOWNLOAD_SIZE};

/// Parsed OCI image reference (e.g. `quay.io/centos/centos:stream10`).
#[derive(Debug, PartialEq)]
pub(super) struct ImageReference {
    /// Registry hostname (e.g. `registry-1.docker.io`, `quay.io`).
    pub(super) registry: String,
    /// Repository path (e.g. `library/nginx`, `centos/centos`).
    pub(super) repository: String,
    /// Tag or digest reference (e.g. `latest`, `stream10`).
    pub(super) reference: String,
}

impl ImageReference {
    /// Parse a source string into an image reference.
    ///
    /// Returns `Some(...)` when the source looks like a registry URI:
    /// - Contains at least one `/`
    /// - Doesn't start with `/` or `.` (filesystem paths)
    /// - First component (before `/`) contains a `.` (domain name)
    ///
    /// Docker Hub special case: `docker.io` → `registry-1.docker.io`,
    /// single-component repos get `library/` prefix.
    pub fn parse(source: &str) -> Option<Self> {
        // Reject filesystem paths.
        if source.starts_with('/') || source.starts_with('.') {
            return None;
        }

        // Reject URLs — they're handled by the Url source kind.
        if source.starts_with("http://") || source.starts_with("https://") {
            return None;
        }

        // Must contain at least one `/`.
        let slash_pos = source.find('/')?;

        // First component must contain a `.` (domain name).
        let first_component = &source[..slash_pos];
        if !first_component.contains('.') {
            return None;
        }

        let mut registry = first_component.to_string();
        let rest = &source[slash_pos + 1..];

        // Split tag from the rest. Tag is after the last `:`, but only if
        // it doesn't contain a `/` (to avoid confusing port numbers).
        let (repository, reference) = if let Some(colon_pos) = rest.rfind(':') {
            let potential_tag = &rest[colon_pos + 1..];
            if potential_tag.contains('/') {
                (rest.to_string(), "latest".to_string())
            } else {
                (rest[..colon_pos].to_string(), potential_tag.to_string())
            }
        } else {
            (rest.to_string(), "latest".to_string())
        };

        if repository.is_empty() {
            return None;
        }

        // Docker Hub special cases.
        if registry == "docker.io" || registry == "index.docker.io" {
            registry = "registry-1.docker.io".to_string();
        }
        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };

        Some(Self {
            registry,
            repository,
            reference,
        })
    }
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}:{}", self.registry, self.repository, self.reference)
    }
}

// --- Auth ---

/// Parse a `WWW-Authenticate: Bearer realm="...",service="..."` header.
fn parse_www_authenticate(header: &str) -> Option<(String, String)> {
    let header = header.strip_prefix("Bearer ")?;

    let mut realm = None;
    let mut service = None;

    for part in split_auth_params(header) {
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim_matches('"');
            match key.trim() {
                "realm" => realm = Some(value.to_string()),
                "service" => service = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Some((realm?, service.unwrap_or_default()))
}

/// Split auth header parameters, respecting quoted values.
fn split_auth_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, ch) in s.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        parts.push(s[start..].trim());
    }
    parts
}

/// Build a ureq agent that does not convert non-2xx status codes to errors.
///
/// Used for the `/v2/` auth probe where we need to inspect the 401 response headers.
fn build_noerror_agent() -> Result<ureq::Agent> {
    let mut config = ureq::Agent::config_builder();
    config = config.http_status_as_error(false);
    if let Some(proxy_uri) = proxy_from_env() {
        let proxy = ureq::Proxy::new(&proxy_uri)
            .with_context(|| format!("invalid proxy URI: {proxy_uri}"))?;
        config = config.proxy(Some(proxy));
    }
    Ok(config.build().into())
}

/// Obtain a bearer token for pulling from a registry (anonymous auth).
///
/// Probes `GET /v2/` with a single request:
/// - 200 → no auth needed, returns `None`.
/// - 401 → parses `WWW-Authenticate: Bearer realm="...",service="..."`,
///   requests a token from the realm, returns it.
/// - Other → error.
///
/// Note: tokens have a TTL (typically 300–600s). For images with many large
/// layers on slow connections, the token may expire mid-pull, causing a 401
/// on a subsequent blob download. This is an uncommon edge case; fixing it
/// properly requires token refresh logic.
fn obtain_token(
    agent: &ureq::Agent,
    registry: &str,
    repository: &str,
    verbose: bool,
) -> Result<Option<String>> {
    let v2_url = format!("https://{registry}/v2/");
    if verbose {
        eprintln!("probing {v2_url}");
    }

    // Use an agent that doesn't error on non-2xx so we can read 401 headers.
    let probe_agent = build_noerror_agent()?;
    let response = probe_agent
        .get(&v2_url)
        .call()
        .with_context(|| format!("failed to probe {v2_url}"))?;

    let status = response.status();
    if status == 200 {
        if verbose {
            eprintln!("registry requires no authentication");
        }
        return Ok(None);
    }
    if status != 401 {
        bail!("registry returned HTTP {status} from {v2_url} (expected 200 or 401)");
    }

    let www_auth = response
        .headers()
        .get("www-authenticate")
        .with_context(|| format!("401 from {v2_url} missing WWW-Authenticate header"))?
        .to_str()
        .with_context(|| "WWW-Authenticate header contains invalid characters")?
        .to_string();

    if verbose {
        eprintln!("WWW-Authenticate: {www_auth}");
    }

    let (realm, service) = parse_www_authenticate(&www_auth)
        .with_context(|| format!("failed to parse WWW-Authenticate header: {www_auth}"))?;

    let token_url = if service.is_empty() {
        format!("{realm}?scope=repository:{repository}:pull")
    } else {
        format!("{realm}?service={service}&scope=repository:{repository}:pull")
    };

    if verbose {
        eprintln!("requesting token from {token_url}");
    }

    let token_body = agent
        .get(&token_url)
        .call()
        .with_context(|| format!("failed to request auth token from {token_url}"))?
        .into_body()
        .read_to_string()
        .with_context(|| "failed to read token response body")?;

    let token_response: serde_json::Value =
        serde_json::from_str(&token_body).with_context(|| "failed to parse token response")?;

    let token = token_response
        .get("token")
        .or_else(|| token_response.get("access_token"))
        .and_then(|v: &serde_json::Value| v.as_str())
        .with_context(|| "token response missing 'token' field")?
        .to_string();

    if verbose {
        eprintln!("obtained bearer token ({} chars)", token.len());
    }

    Ok(Some(token))
}

// --- Manifest resolution ---

/// Media types we accept for manifests.
const MANIFEST_ACCEPT: &str = "\
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.docker.distribution.manifest.list.v2+json";

/// A layer descriptor from an image manifest.
#[derive(serde::Deserialize, Debug)]
struct LayerDescriptor {
    digest: String,
    #[allow(dead_code)]
    size: u64,
    #[serde(rename = "mediaType")]
    #[allow(dead_code)]
    media_type: Option<String>,
}

/// An image manifest (OCI or Docker v2).
#[derive(serde::Deserialize, Debug)]
struct ImageManifest {
    layers: Vec<LayerDescriptor>,
}

/// A platform descriptor from a manifest list/index.
#[derive(serde::Deserialize, Debug)]
struct PlatformDescriptor {
    digest: String,
    #[serde(rename = "mediaType")]
    #[allow(dead_code)]
    media_type: Option<String>,
    platform: Option<Platform>,
}

/// Platform information in a manifest list entry.
#[derive(serde::Deserialize, Debug)]
struct Platform {
    architecture: String,
    os: String,
}

/// A manifest list/index.
#[derive(serde::Deserialize, Debug)]
struct ManifestList {
    manifests: Vec<PlatformDescriptor>,
}

/// Map Rust's `std::env::consts::ARCH` to OCI architecture strings.
fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "s390x" => "s390x",
        "powerpc64" => "ppc64le",
        "riscv64" => "riscv64",
        other => other,
    }
}

/// Fetch a manifest (or manifest list) from a registry.
fn fetch_manifest(
    agent: &ureq::Agent,
    registry: &str,
    repository: &str,
    reference: &str,
    token: Option<&str>,
    verbose: bool,
) -> Result<serde_json::Value> {
    let url = format!("https://{registry}/v2/{repository}/manifests/{reference}");
    if verbose {
        eprintln!("fetching manifest: {url}");
    }

    let mut request = agent.get(&url).header("Accept", MANIFEST_ACCEPT);

    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }

    let body_str = request
        .call()
        .with_context(|| format!("failed to fetch manifest from {url}"))?
        .into_body()
        .read_to_string()
        .with_context(|| format!("failed to read manifest body from {url}"))?;

    let body: serde_json::Value =
        serde_json::from_str(&body_str).with_context(|| format!("failed to parse manifest from {url}"))?;

    Ok(body)
}

/// Resolve a manifest to an image manifest, following manifest list indirection.
fn resolve_manifest(
    agent: &ureq::Agent,
    registry: &str,
    repository: &str,
    reference: &str,
    token: Option<&str>,
    verbose: bool,
) -> Result<ImageManifest> {
    let manifest = fetch_manifest(agent, registry, repository, reference, token, verbose)?;

    // Check if this is a direct image manifest (has "layers").
    if manifest.get("layers").is_some() {
        return serde_json::from_value(manifest).context("failed to parse image manifest");
    }

    // Must be a manifest list/index — select the right platform.
    if manifest.get("manifests").is_some() {
        let list: ManifestList =
            serde_json::from_value(manifest).context("failed to parse manifest list")?;

        let arch = host_arch();
        if verbose {
            eprintln!("manifest list with {} entries, selecting linux/{arch}", list.manifests.len());
        }

        let entry = list
            .manifests
            .iter()
            .find(|m| {
                m.platform
                    .as_ref()
                    .map(|p| p.os == "linux" && p.architecture == arch)
                    .unwrap_or(false)
            })
            .with_context(|| {
                let available: Vec<String> = list
                    .manifests
                    .iter()
                    .filter_map(|m| {
                        m.platform
                            .as_ref()
                            .map(|p| format!("{}/{}", p.os, p.architecture))
                    })
                    .collect();
                format!(
                    "no manifest for linux/{arch}; available platforms: {}",
                    available.join(", ")
                )
            })?;

        if verbose {
            eprintln!("selected platform manifest: {}", entry.digest);
        }

        // Fetch the platform-specific manifest by digest.
        let platform_manifest =
            fetch_manifest(agent, registry, repository, &entry.digest, token, verbose)?;

        return serde_json::from_value(platform_manifest)
            .context("failed to parse platform-specific image manifest");
    }

    bail!("manifest has neither 'layers' nor 'manifests' field");
}

// --- Layer download + extraction ---

/// Download a blob to a file while verifying its SHA-256 digest.
fn download_blob(
    agent: &ureq::Agent,
    registry: &str,
    repository: &str,
    digest: &str,
    dest: &Path,
    token: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let url = format!("https://{registry}/v2/{repository}/blobs/{digest}");
    if verbose {
        eprintln!("downloading blob: {digest}");
    }

    let mut request = agent.get(&url);
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }

    let mut reader = request
        .call()
        .with_context(|| {
            format!(
                "failed to download blob {digest} from {registry} \
                 (if this is a 401 error, the auth token may have expired)"
            )
        })?
        .into_body()
        .into_reader();

    let mut file =
        File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;

    loop {
        check_interrupted()?;
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("failed to read blob {digest}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write blob to {}", dest.display()))?;
        hasher.update(&buf[..n]);
        total += n as u64;
        if total > MAX_DOWNLOAD_SIZE {
            bail!(
                "blob {digest} exceeds maximum download size of {} bytes",
                MAX_DOWNLOAD_SIZE
            );
        }
    }

    if verbose {
        eprintln!("downloaded {total} bytes");
    }

    // Verify digest.
    let computed = format!("sha256:{:x}", hasher.finalize());
    if computed != digest {
        bail!("digest mismatch for blob: expected {digest}, got {computed}");
    }

    Ok(())
}

/// Import an image from an OCI registry.
///
/// Downloads layers one at a time to temp files, verifies digests,
/// and extracts each layer using the OCI whiteout-aware extractor.
pub(super) fn import_registry_image(
    image: &ImageReference,
    staging_dir: &Path,
    rootfs_dir: &Path,
    verbose: bool,
) -> Result<()> {
    eprintln!("pulling {image}");

    let agent = build_http_agent(verbose)?;
    let token = obtain_token(&agent, &image.registry, &image.repository, verbose)?;
    let token_ref = token.as_deref();

    let manifest = resolve_manifest(
        &agent,
        &image.registry,
        &image.repository,
        &image.reference,
        token_ref,
        verbose,
    )?;

    if manifest.layers.is_empty() {
        bail!("image manifest contains no layers");
    }

    if verbose {
        eprintln!("image has {} layer(s)", manifest.layers.len());
    }

    fs::create_dir_all(staging_dir)
        .with_context(|| format!("failed to create staging dir {}", staging_dir.display()))?;

    // Download and extract layers one at a time.
    for (i, layer) in manifest.layers.iter().enumerate() {
        check_interrupted()?;

        let temp_path = rootfs_dir.join(format!(".layer-{i}.tmp"));

        let result = (|| -> Result<()> {
            eprintln!(
                "extracting layer {}/{}: {}",
                i + 1,
                manifest.layers.len(),
                layer.digest
            );

            download_blob(
                &agent,
                &image.registry,
                &image.repository,
                &layer.digest,
                &temp_path,
                token_ref,
                verbose,
            )?;

            // Detect compression from magic bytes.
            let mut file = File::open(&temp_path)
                .with_context(|| format!("failed to open {}", temp_path.display()))?;
            let mut magic = [0u8; 6];
            let n = file.read(&mut magic)?;
            drop(file);

            let compression = detect_compression_magic(&magic[..n])?;
            let file = File::open(&temp_path)?;
            let decoder = get_decoder(file, &compression)?;

            unpack_oci_layer(decoder, staging_dir)?;

            Ok(())
        })();

        // Clean up temp file regardless of success/failure.
        let _ = fs::remove_file(&temp_path);

        result?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let img = ImageReference::parse("quay.io/centos/centos:stream10").unwrap();
        assert_eq!(img.registry, "quay.io");
        assert_eq!(img.repository, "centos/centos");
        assert_eq!(img.reference, "stream10");
    }

    #[test]
    fn test_parse_default_tag() {
        let img = ImageReference::parse("quay.io/nginx/nginx-unprivileged").unwrap();
        assert_eq!(img.registry, "quay.io");
        assert_eq!(img.repository, "nginx/nginx-unprivileged");
        assert_eq!(img.reference, "latest");
    }

    #[test]
    fn test_parse_nested_path() {
        let img = ImageReference::parse("ghcr.io/org/sub/repo:v1.0").unwrap();
        assert_eq!(img.registry, "ghcr.io");
        assert_eq!(img.repository, "org/sub/repo");
        assert_eq!(img.reference, "v1.0");
    }

    #[test]
    fn test_parse_docker_hub() {
        let img = ImageReference::parse("docker.io/nginx:latest").unwrap();
        assert_eq!(img.registry, "registry-1.docker.io");
        assert_eq!(img.repository, "library/nginx");
        assert_eq!(img.reference, "latest");
    }

    #[test]
    fn test_parse_docker_hub_with_org() {
        let img = ImageReference::parse("docker.io/myorg/myrepo:v2").unwrap();
        assert_eq!(img.registry, "registry-1.docker.io");
        assert_eq!(img.repository, "myorg/myrepo");
        assert_eq!(img.reference, "v2");
    }

    #[test]
    fn test_parse_index_docker_io() {
        let img = ImageReference::parse("index.docker.io/library/alpine:3.19").unwrap();
        assert_eq!(img.registry, "registry-1.docker.io");
        assert_eq!(img.repository, "library/alpine");
        assert_eq!(img.reference, "3.19");
    }

    #[test]
    fn test_parse_rejects_filesystem_paths() {
        assert!(ImageReference::parse("/tmp/some/path").is_none());
        assert!(ImageReference::parse("./relative/path").is_none());
        assert!(ImageReference::parse("../parent/path").is_none());
    }

    #[test]
    fn test_parse_rejects_urls() {
        assert!(ImageReference::parse("https://example.com/rootfs.tar.gz").is_none());
        assert!(ImageReference::parse("http://example.com/rootfs.tar").is_none());
    }

    #[test]
    fn test_parse_rejects_no_domain() {
        // First component must contain a dot.
        assert!(ImageReference::parse("localrepo/image:tag").is_none());
    }

    #[test]
    fn test_parse_rejects_no_slash() {
        // Must contain at least one slash.
        assert!(ImageReference::parse("quay.io").is_none());
    }

    #[test]
    fn test_parse_rejects_empty_repo() {
        assert!(ImageReference::parse("quay.io/").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_basic() {
        let header =
            r#"Bearer realm="https://auth.example.com/token",service="registry.example.com""#;
        let (realm, service) = parse_www_authenticate(header).unwrap();
        assert_eq!(realm, "https://auth.example.com/token");
        assert_eq!(service, "registry.example.com");
    }

    #[test]
    fn test_parse_www_authenticate_extra_params() {
        let header = r#"Bearer realm="https://auth.quay.io/v2/auth",service="quay.io",scope="repository:centos/centos:pull""#;
        let (realm, service) = parse_www_authenticate(header).unwrap();
        assert_eq!(realm, "https://auth.quay.io/v2/auth");
        assert_eq!(service, "quay.io");
    }

    #[test]
    fn test_parse_www_authenticate_no_service() {
        let header = r#"Bearer realm="https://auth.example.com/token""#;
        let (realm, service) = parse_www_authenticate(header).unwrap();
        assert_eq!(realm, "https://auth.example.com/token");
        assert_eq!(service, "");
    }

    #[test]
    fn test_parse_www_authenticate_not_bearer() {
        assert!(parse_www_authenticate("Basic realm=\"test\"").is_none());
    }

    #[test]
    fn test_host_arch() {
        let arch = host_arch();
        // Should return a non-empty string.
        assert!(!arch.is_empty());
        // On common CI architectures, verify the mapping.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "amd64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "arm64");
    }

    #[test]
    #[ignore] // Requires network access.
    fn test_pull_small_image() {
        use crate::import::tests::INTERRUPT_LOCK;

        let _lock = INTERRUPT_LOCK.lock().unwrap();

        let dest = std::env::temp_dir().join(format!(
            "sdme-test-registry-pull-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let rootfs_dir = std::env::temp_dir().join(format!(
            "sdme-test-registry-rootfs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dest);
        let _ = fs::remove_dir_all(&rootfs_dir);
        fs::create_dir_all(&rootfs_dir).unwrap();

        let image = ImageReference::parse("quay.io/centos-bootc/centos-bootc:stream10").unwrap();
        import_registry_image(&image, &dest, &rootfs_dir, true).unwrap();

        // Basic sanity checks.
        assert!(dest.is_dir());
        assert!(dest.join("usr").is_dir() || dest.join("bin").is_dir());

        let _ = crate::copy::make_removable(&dest);
        let _ = fs::remove_dir_all(&dest);
        let _ = fs::remove_dir_all(&rootfs_dir);
    }
}
