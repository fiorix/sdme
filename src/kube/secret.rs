//! Kubernetes secret store for sdme.
//!
//! Secrets are stored on disk at `{datadir}/secrets/{name}/data/{key}` and
//! referenced by name in pod YAML volume specs. Files are created with
//! restrictive permissions (dirs `0o700`, files `0o600`).

use std::path::Path;

use anyhow::Result;

use super::store::{self, StoreConfig, StoreInfo};

const CONFIG: StoreConfig = StoreConfig {
    subdir: "secrets",
    noun: "secret",
    cli_cmd: "sdme kube secret create",
    dir_mode: 0o700,
    file_mode: 0o600,
};

/// Summary of a stored secret (name, key count, creation time).
pub type SecretInfo = StoreInfo;

/// Create a new secret from literal key-value pairs and/or files.
pub fn create(
    datadir: &Path,
    name: &str,
    literals: &[(String, String)],
    files: &[(String, String)],
) -> Result<()> {
    store::create(&CONFIG, datadir, name, literals, files)
}

/// List all stored secrets.
pub fn list(datadir: &Path) -> Result<Vec<SecretInfo>> {
    store::list(&CONFIG, datadir)
}

/// Remove secrets by name.
pub fn remove(datadir: &Path, names: &[String]) -> Result<()> {
    store::remove(&CONFIG, datadir, names)
}

/// Read all key-value data from a stored secret.
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
        TempDataDir::new("kube-secret")
    }

    #[test]
    fn test_create_and_list() {
        let tmp = tmp();
        create(
            tmp.path(),
            "db-creds",
            &[
                ("username".into(), "admin".into()),
                ("password".into(), "hunter2".into()),
            ],
            &[],
        )
        .unwrap();

        let secrets = list(tmp.path()).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "db-creds");
        assert_eq!(secrets[0].keys, 2);
        assert!(!secrets[0].created.is_empty());
    }

    #[test]
    fn test_create_from_file() {
        let tmp = tmp();
        let file_path = tmp.path().join("cert.pem");
        fs::write(&file_path, b"CERT DATA").unwrap();

        create(
            tmp.path(),
            "tls-cert",
            &[],
            &[("cert".into(), file_path.to_str().unwrap().into())],
        )
        .unwrap();

        let data = read_data(tmp.path(), "tls-cert").unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].0, "cert");
        assert_eq!(data[0].1, b"CERT DATA");
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
        create(tmp.path(), "my-secret", &[("k".into(), "v".into())], &[]).unwrap();
        let err = create(tmp.path(), "my-secret", &[("k".into(), "v".into())], &[]).unwrap_err();
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
                err.to_string().contains("secret key"),
                "should reject key '{bad_key}': {err}"
            );
        }
    }

    #[test]
    fn test_remove() {
        let tmp = tmp();
        create(tmp.path(), "to-remove", &[("k".into(), "v".into())], &[]).unwrap();
        remove(tmp.path(), &["to-remove".into()]).unwrap();

        let secrets = list(tmp.path()).unwrap();
        assert!(secrets.is_empty());
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
        assert!(err.to_string().contains("sdme kube secret create"));
    }

    #[test]
    fn test_list_empty() {
        let tmp = tmp();
        let secrets = list(tmp.path()).unwrap();
        assert!(secrets.is_empty());
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

        let secret_dir = tmp.path().join("secrets").join("perm-test");
        let dir_mode = fs::metadata(&secret_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let data_dir = secret_dir.join("data");
        let data_mode = fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(data_mode, 0o700);

        let file_path = data_dir.join("key");
        let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
    }
}
