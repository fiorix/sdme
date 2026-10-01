//! Kubernetes Pod YAML support for sdme.

pub mod configmap;
pub(crate) mod create;
mod plan;
pub mod secret;
mod store;
mod types;

pub use create::{kube_create, kube_delete, KubeCreateOptions};

/// Grace period, in seconds, of a pod whose YAML does not set
/// `terminationGracePeriodSeconds`. Matches the Kubernetes default.
pub(crate) const DEFAULT_TERMINATION_GRACE_SECS: u32 = 30;
pub(crate) use plan::KubeProbes;
pub(crate) use plan::ProbeCheck;
