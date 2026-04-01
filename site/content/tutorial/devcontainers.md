+++
title = "Dev Containers"
description = "Create reproducible development environments from devcontainer.json files."
weight = 13
+++

sdme supports the [Dev Container specification](https://containers.dev/),
the same format used by VS Code Remote Containers, GitHub Codespaces,
and other tools. Place a `devcontainer.json` in your project and
`sdme devcontainer up` will create a ready-to-use development
environment.

See also the [architecture documentation](@/docs/architecture.md#18-dev-container-support)
for implementation details.

## Prerequisites

Import a base image first. Most devcontainer.json files reference
an OCI image, and sdme will pull and import it automatically. No
extra setup is needed beyond having sdme installed.

## A minimal example

Create a `.devcontainer/devcontainer.json` in your project:

```json
{
    "image": "ubuntu:22.04",
    "postCreateCommand": "apt-get update && apt-get install -y git curl"
}
```

Bring it up:

```bash
cd /path/to/project
sudo sdme devcontainer up
```

sdme will:
1. Find `.devcontainer/devcontainer.json`
2. Pull `ubuntu:22.04` from Docker Hub and import it as a rootfs
3. Create a container with your project directory bind-mounted at `/workspace`
4. Start the container
5. Run `postCreateCommand` inside it

## Running commands

Execute commands inside the devcontainer:

```bash
sudo sdme devcontainer exec dc-myproject -- npm test
sudo sdme devcontainer exec dc-myproject -- bash
```

The container name is `dc-<project>`, derived from the `name` field
in devcontainer.json or the workspace directory name.

## Workspace mounting

By default, the host workspace folder is mounted at `/workspace`
inside the container. Override with `workspaceFolder`:

```json
{
    "image": "ubuntu:22.04",
    "workspaceFolder": "/home/dev/app"
}
```

To customize the mount itself (e.g. read-only):

```json
{
    "image": "ubuntu:22.04",
    "workspaceMount": "source=${localWorkspaceFolder},target=/app,type=bind,readonly",
    "workspaceFolder": "/app"
}
```

Set `workspaceMount` to an empty string to disable the automatic
workspace mount entirely.

## User configuration

Run commands as a specific user with `remoteUser`:

```json
{
    "image": "ubuntu:22.04",
    "remoteUser": "vscode",
    "postCreateCommand": "whoami"
}
```

Lifecycle commands and `sdme devcontainer exec` will run as this
user via `machinectl shell --uid`.

## Environment variables

```json
{
    "image": "ubuntu:22.04",
    "containerEnv": {
        "NODE_ENV": "development"
    },
    "remoteEnv": {
        "PATH": "${containerEnv:PATH}:/custom/bin",
        "PROJECT_ROOT": "${containerWorkspaceFolder}"
    }
}
```

Variable substitution is supported:
- `${localWorkspaceFolder}` — host workspace path
- `${containerWorkspaceFolder}` — container workspace path
- `${localWorkspaceFolderBasename}` — workspace directory name
- `${localEnv:VAR}` — host environment variable

## Additional mounts

Bind-mount host paths into the container:

```json
{
    "image": "ubuntu:22.04",
    "mounts": [
        {
            "type": "bind",
            "source": "${localEnv:HOME}/.ssh",
            "target": "/home/vscode/.ssh",
            "readonly": true
        },
        "source=${localEnv:HOME}/.gitconfig,target=/root/.gitconfig,type=bind,readonly"
    ]
}
```

Both structured objects and Docker-style strings are supported.

> **Note:** Only bind mounts are supported. Volume and tmpfs mount
> types are skipped with a warning.

## Port forwarding

Forward ports from the container to the host:

```json
{
    "image": "node:20",
    "forwardPorts": [3000, "8080:80"],
    "postCreateCommand": "npm install && npm start"
}
```

When ports are specified, the container automatically gets a private
network with a virtual ethernet link. Use `sdme ps` to see the
container's IP address.

## Lifecycle hooks

Five hooks run at different stages of the container lifecycle:

```json
{
    "image": "ubuntu:22.04",
    "onCreateCommand": "apt-get update && apt-get install -y build-essential",
    "postCreateCommand": "npm install",
    "postStartCommand": "echo 'Container started'"
}
```

Execution order: `onCreateCommand` → `updateContentCommand` →
`postCreateCommand` → `postStartCommand` → `postAttachCommand`.

Each hook accepts three formats:

```json
{
    "postCreateCommand": "npm install",

    "postCreateCommand": ["npm install", "npm run build"],

    "postCreateCommand": {
        "install": "npm install",
        "build": "npm run build"
    }
}
```

## Features

Basic support for well-known Dev Container Features:

```json
{
    "image": "ubuntu:22.04",
    "features": {
        "ghcr.io/devcontainers/features/node:1": {
            "version": "20"
        },
        "ghcr.io/devcontainers/features/python:1": {
            "version": "3"
        },
        "ghcr.io/devcontainers/features/git:1": {}
    }
}
```

Supported features: `node`, `python`, `git` from the official
`ghcr.io/devcontainers/features/` namespace. Other features are
skipped with a warning.

## Capabilities

Add Linux capabilities to the container:

```json
{
    "image": "ubuntu:22.04",
    "capAdd": ["SYS_PTRACE"]
}
```

## JSONC support

Comments are supported in devcontainer.json:

```jsonc
{
    // Development image
    "image": "ubuntu:22.04",
    /* Multi-line
       comment */
    "postCreateCommand": "echo hello"
}
```

## Managing the devcontainer

```bash
# Bring up (idempotent — re-runs postStartCommand if already running)
sudo sdme devcontainer up

# Bring up from a specific workspace
sudo sdme devcontainer up --workspace-folder /path/to/project

# Force rebuild
sudo sdme devcontainer up --rebuild

# Execute a command
sudo sdme devcontainer exec dc-myproject -- make test

# Stop
sudo sdme devcontainer stop dc-myproject

# Remove (deletes container AND rootfs)
sudo sdme devcontainer rm dc-myproject
```

## Full example

A complete devcontainer.json for a Node.js project:

```json
{
    "name": "My Node App",
    "image": "ubuntu:22.04",
    "workspaceFolder": "/workspace",
    "remoteUser": "root",

    "features": {
        "ghcr.io/devcontainers/features/node:1": {
            "version": "20"
        },
        "ghcr.io/devcontainers/features/git:1": {}
    },

    "forwardPorts": [3000],

    "mounts": [
        {
            "type": "bind",
            "source": "${localEnv:HOME}/.ssh",
            "target": "/root/.ssh",
            "readonly": true
        }
    ],

    "containerEnv": {
        "NODE_ENV": "development"
    },

    "onCreateCommand": "npm install",
    "postStartCommand": "npm run dev"
}
```

```bash
cd /path/to/project
sudo sdme devcontainer up
# Container dc-my-node-app is running with:
#   - Node.js 20 and git installed
#   - Port 3000 forwarded
#   - SSH keys available (read-only)
#   - npm install completed
#   - npm run dev started

sudo sdme devcontainer exec dc-my-node-app -- npm test
```

## Limitations

- **Dockerfile builds**: the `build` key is parsed but not yet
  supported. Build your image externally and reference it via `image`.
- **Docker Compose**: `dockerComposeFile` is not supported.
- **Volume/tmpfs mounts**: only bind mounts work.
- **Features**: only `node`, `python`, and `git` from the official
  namespace. Custom features are skipped.
- **Customizations**: `customizations.vscode` is parsed but not
  acted on (sdme is not an IDE).
