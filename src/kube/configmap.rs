//! Kubernetes configmap store for sdme.
//!
//! ConfigMaps are stored on disk at `{datadir}/configmaps/{name}/data/{key}` and
//! referenced by name in pod YAML volume specs. Files are created with
//! standard permissions (dirs `0o755`, files `0o644`).

use std::path::Path;

use anyhow::Result;

use super::store::{self, StoreConfig, StoreInfo};

const CONFIG: StoreConfig = StoreConfig {
    subdir: "configmaps",
    noun: "configmap",
    cli_cmd: "sdme kube configmap create",
    dir_mode: 0o755,
    file_mode: 0o644,
};

/// Summary of a stored configmap (name, key count, creation time).
pub type ConfigMapInfo = StoreInfo;

/// Create a new configmap from literal key-value pairs and/or files.
pub fn create(
    datadir: &Path,
    name: &str,
    literals: &[(String, String)],
    files: &[(String, String)],
) -> Result<()> {
    store::create(&CONFIG, datadir, name, literals, files)
}

/// List all stored configmaps.
pub fn list(datadir: &Path) -> Result<Vec<ConfigMapInfo>> {
    store::list(&CONFIG, datadir)
}

/// Remove configmaps by name.
pub fn remove(datadir: &Path, names: &[String]) -> Result<()> {
    store::remove(&CONFIG, datadir, names)
}

/// Read all key-value data from a stored configmap.
pub fn read_data(datadir: &Path, name: &str) -> Result<Vec<(String, Vec<u8>)>> {
    store::read_data(&CONFIG, datadir, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> TempDataDir {
        TempDataDir::new("kube-configmap")
    }

    #[test]
    fn test_create_and_list() {
        let tmp = tmp();
        create(
            tmp.path(),
            "app-config",
            &[
                ("database-url".into(), "postgres://localhost/db".into()),
                ("log-level".into(), "info".into()),
            ],
            &[],
        )
        .unwrap();

        let configmaps = list(tmp.path()).unwrap();
        assert_eq!(configmaps.len(), 1);
        assert_eq!(configmaps[0].name, "app-config");
        assert_eq!(configmaps[0].keys, 2);
        assert!(!configmaps[0].created.is_empty());
    }

    #[test]
    fn test_create_from_file() {
        let tmp = tmp();
        let file_path = tmp.path().join("config.yaml");
        fs::write(&file_path, b"key: value\n").unwrap();

        create(
            tmp.path(),
            "file-config",
            &[],
            &[("config".into(), file_path.to_str().unwrap().into())],
        )
        .unwrap();

        let data = read_data(tmp.path(), "file-config").unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].0, "config");
        assert_eq!(data[0].1, b"key: value\n");
    }

    #[test]
    fn test_create_rejects_invalid_name() {
        let tmp = tmp();
        let err = create(tmp.path(), "INVALID", &[("k".into(), "v".into())], &[]).unwrap_err();
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn test_create_rejects_duplicate() {
        let tmp = tmp();
        create(tmp.path(), "my-config", &[("k".into(), "v".into())], &[]).unwrap();
        let err = create(tmp.path(), "my-config", &[("k".into(), "v".into())], &[]).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_create_rejects_no_data() {
        let tmp = tmp();
        let err = create(tmp.path(), "empty", &[], &[]).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn test_create_rejects_duplicate_key() {
        let tmp = tmp();
        let err = create(
            tmp.path(),
            "dup-key",
            &[("k".into(), "v1".into()), ("k".into(), "v2".into())],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate key"));
    }

    #[test]
    fn test_create_rejects_bad_key() {
        let tmp = tmp();
        for (i, bad_key) in ["", "../etc", "foo/bar", ".hidden"].iter().enumerate() {
            let name = format!("bad-key-{i}");
            let err =
                create(tmp.path(), &name, &[(bad_key.to_string(), "v".into())], &[]).unwrap_err();
            assert!(
                err.to_string().contains("configmap key"),
                "should reject key '{bad_key}': {err}"
            );
        }
    }

    #[test]
    fn test_remove() {
        let tmp = tmp();
        create(tmp.path(), "to-remove", &[("k".into(), "v".into())], &[]).unwrap();
        remove(tmp.path(), &["to-remove".into()]).unwrap();

        let configmaps = list(tmp.path()).unwrap();
        assert!(configmaps.is_empty());
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = tmp();
        let err = remove(tmp.path(), &["nonexistent".into()]).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_read_data() {
        let tmp = tmp();
        create(
            tmp.path(),
            "read-test",
            &[
                ("alpha".into(), "aaa".into()),
                ("beta".into(), "bbb".into()),
            ],
            &[],
        )
        .unwrap();

        let data = read_data(tmp.path(), "read-test").unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].0, "alpha");
        assert_eq!(data[0].1, b"aaa");
        assert_eq!(data[1].0, "beta");
        assert_eq!(data[1].1, b"bbb");
    }

    #[test]
    fn test_read_not_found() {
        let tmp = tmp();
        let err = read_data(tmp.path(), "nope").unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("sdme kube configmap create"));
    }

    #[test]
    fn test_list_empty() {
        let tmp = tmp();
        let configmaps = list(tmp.path()).unwrap();
        assert!(configmaps.is_empty());
    }

    #[test]
    fn test_permissions() {
        let tmp = tmp();
        create(
            tmp.path(),
            "perm-test",
            &[("key".into(), "val".into())],
            &[],
        )
        .unwrap();

        let configmap_dir = tmp.path().join("configmaps").join("perm-test");
        let dir_mode = fs::metadata(&configmap_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755);

        let data_dir = configmap_dir.join("data");
        let data_mode = fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(data_mode, 0o755);

        let file_path = data_dir.join("key");
        let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o644);
    }
}
