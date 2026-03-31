//! Dev Container specification support for sdme.
//!
//! Implements the [Dev Container specification](https://containers.dev/implementors/spec/)
//! to create development environments from `.devcontainer/devcontainer.json` files.
//!
//! # Supported features
//!
//! - `image`: OCI image reference (imported as sdme rootfs)
//! - `workspaceFolder` / `workspaceMount`: workspace directory mapping
//! - `remoteUser` / `containerUser`: user configuration
//! - `remoteEnv` / `containerEnv`: environment variables
//! - `mounts`: additional bind mounts
//! - `forwardPorts`: port forwarding
//! - `onCreateCommand`, `postCreateCommand`, `postStartCommand`: lifecycle hooks
//! - `features`: basic support for well-known Dev Container Features
//! - `capAdd`: Linux capability additions
//! - JSONC (JSON with comments) support
//!
//! # CLI
//!
//! ```text
//! sdme devcontainer up [--workspace-folder PATH]
//! sdme devcontainer exec [NAME] -- COMMAND
//! sdme devcontainer stop [NAME]
//! sdme devcontainer rm [NAME]
//! ```

pub(crate) mod create;
pub(crate) mod plan;
mod types;

pub use create::{
    devcontainer_exec, devcontainer_rm, devcontainer_stop, devcontainer_up, DevcontainerUpOptions,
};
pub use plan::find_config;
