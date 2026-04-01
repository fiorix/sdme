+++
title = "Building Root Filesystems"
description = "Build custom root filesystems with sdme fs build using Dockerfile-like configs."
weight = 12
+++

The `sdme fs build` command creates custom root filesystems from a
simple build config. The config format uses `FROM`, `RUN`, and `COPY`
directives, similar to a Dockerfile. Each `RUN` step executes inside
a booted systemd-nspawn container, so you get a real systemd
environment with working package managers, services, and networking.

Builds are resumable: if a `RUN` step fails, re-running the same
command picks up where it left off. Use `--no-cache` to start fresh.

## Prerequisites

You need a base rootfs to build from. If you don't have one:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

## Example: Ollama with GPU passthrough

This example builds a rootfs with Ollama installed, then runs it
with NVIDIA GPU access for local LLM inference.

### The build config

Create `ollama.build`:

```
FROM ubuntu
RUN apt update
RUN apt install -y curl zstd pciutils libnvidia-compute-580 nvidia-utils-580
RUN curl -fsSL https://ollama.com/install.sh | sh
RUN mkdir -p /etc/systemd/system/ollama.service.d
RUN printf '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0"\n' > /etc/systemd/system/ollama.service.d/override.conf
```

The `libnvidia-compute` and `nvidia-utils` version must match the driver
version installed on the host, otherwise `nvidia-smi` and GPU access may
not work inside the container.

The last two `RUN` steps configure Ollama to listen on all interfaces
so that other containers on the same network zone can connect to it.

### Build the rootfs

```sh
sudo sdme fs build ollama ./ollama.build
```

### Start a container

Bind mount the NVIDIA device nodes so the container can access the
GPU:

```sh
sudo sdme new ollama -r ollama \
    --hardened -t 180 --network-zone ai \
    -b /dev/nvidia0:/dev/nvidia0 \
    -b /dev/nvidia1:/dev/nvidia1 \
    -b /dev/nvidiactl:/dev/nvidiactl \
    -b /dev/nvidia-modeset:/dev/nvidia-modeset \
    -b /dev/nvidia-uvm:/dev/nvidia-uvm \
    -b /dev/nvidia-uvm-tools:/dev/nvidia-uvm-tools
```

The `-t 180` increases the boot timeout to 180 seconds. This is
needed because `--hardened` enables user namespace isolation, which
causes systemd-nspawn to recursively chown the entire rootfs on
first boot to remap UIDs. Subsequent boots are fast since the
ownership is already set. On systemd 256+, sdme uses idmapped rootfs
mounts instead of chown, eliminating the first-boot delay entirely.

Once the container is created and you land on a shell, pull a model:

```sh
ollama pull devstral-small-2:24b
```

Exit the shell to return to the host. The Ollama container keeps
running in the background. Next, we'll build an AI agent that
connects to it.

## Example: multi-stage build with COPY fs

Build configs support copying files from one rootfs into another
using the `COPY fs:<name>:<path>` syntax. This lets you compile
software in a builder rootfs and copy just the binary into a clean
runtime rootfs, keeping it clean.

This example builds [picoclaw](https://github.com/sipeed/picoclaw)
with native WhatsApp support in a builder rootfs, then copies the
binary into a minimal runtime rootfs.

### Stage 1: builder

Create `picoclaw-builder.build`:

```
FROM ubuntu
RUN apt-get update && apt-get install -y golang git make curl
RUN git clone https://github.com/sipeed/picoclaw /usr/src/picoclaw
RUN cd /usr/src/picoclaw && git checkout v0.2.4
RUN export HOME=/root GOPATH=/root/go && cd /usr/src/picoclaw && make deps
RUN export HOME=/root GOPATH=/root/go && cd /usr/src/picoclaw && GO_BUILD_TAGS="goolm,stdjson,whatsapp_native" make build
RUN cp /usr/src/picoclaw/build/picoclaw /usr/local/bin/picoclaw
```

Build it:

```sh
sudo sdme fs build picoclaw-builder ./picoclaw-builder.build
```

### Stage 2: runtime

Create `picoclaw-runtime.build`:

```
FROM ubuntu
RUN apt update && apt install -y curl less iproute2 netcat-openbsd vim tmux
COPY fs:picoclaw-builder:/usr/local/bin/picoclaw /usr/local/bin/picoclaw
```

The `COPY fs:picoclaw-builder:` prefix tells sdme to copy from the
`picoclaw-builder` rootfs rather than the host filesystem.

Build it:

```sh
sudo sdme fs build picoclaw-runtime ./picoclaw-runtime.build
```

### Start the container

```sh
sudo sdme new pico-foobar -r picoclaw-runtime -t 180 --hardened --network-zone ai
```

Once you're on the container's shell, let's initialise and configure picoclaw:

```sh
picoclaw onboard
```

Config:

```sh
cat << EOF > ~/.picoclaw/config.json
{
  "version": 1,
  "agents": {
    "defaults": {
      "workspace": "/root/.picoclaw/workspace",
      "restrict_to_workspace": true,
      "allow_read_outside_workspace": false,
      "provider": "ollama",
      "model_name": "default"
    }
  },
  "channels": {
    "telegram": {
      "enabled": false,
      "token": "send /newbot to @BotMaster on telegram, paste the token here",
      "allow_from": [
        "send /start to @userinfobot on telegram, paste the ID here"
      ]
    },
    "whatsapp": {
      "enabled": true,
      "use_native": true,
      "allowFrom": [
        "<your-full-number>@s.whatsapp.net"
      ]
    }
  },
  "model_list": [
    {
      "model_name": "default",
      "model": "ollama/devstral-small-2:24b",
      "api_base": "http://ollama:11434/v1"
    }
  ]
}
EOF
```

Test the setup running the interactive agent:

<pre class="diagram">root@pico-foobar:~# picoclaw agent

██████╗ ██╗ ██████╗ ██████╗  ██████╗██╗      █████╗ ██╗    ██╗
██╔══██╗██║██╔════╝██╔═══██╗██╔════╝██║     ██╔══██╗██║    ██║
██████╔╝██║██║     ██║   ██║██║     ██║     ███████║██║ █╗ ██║
██╔═══╝ ██║██║     ██║   ██║██║     ██║     ██╔══██║██║███╗██║
██║     ██║╚██████╗╚██████╔╝╚██████╗███████╗██║  ██║╚███╔███╔╝
╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝

🦞 Interactive mode (Ctrl+C to exit)

🦞 You: hello world

🦞 Hello, world! 🌍

Nice to meet you! I'm PicoClaw, your practical AI assistant ready to help.

What can I do for you today?
</pre>

Run the gateway so that it connects to Telegram and WhatsApp.

The WhatsApp integration will print a QRCode on the terminal to connect
to the account. It's best to use a separate phone/number for this.

<pre class="diagram">root@pico-foobar:~# picoclaw gateway

██████╗ ██╗ ██████╗ ██████╗  ██████╗██╗      █████╗ ██╗    ██╗
██╔══██╗██║██╔════╝██╔═══██╗██╔════╝██║     ██╔══██╗██║    ██║
██████╔╝██║██║     ██║   ██║██║     ██║     ███████║██║ █╗ ██║
██╔═══╝ ██║██║     ██║   ██║██║     ██║     ██╔══██║██║███╗██║
██║     ██║╚██████╗╚██████╔╝╚██████╗███████╗██║  ██║╚███╔███╔╝
╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝


📦 Agent Status:
  • Tools: 14 loaded
  • Skills: 7/7 available
✓ Cron service started
✓ Heartbeat service started
✓ Channels enabled: [telegram whatsapp_native]
✓ Health endpoints available at http://127.0.0.1:18790/health, /ready and /reload (POST)
✓ Gateway started on 127.0.0.1:18790
Press Ctrl+C to stop
</pre>

From here on, the agent should be ready to chat on the enabled channels.

## Build config reference

See `sdme fs build --help` for the full reference, including
resumable builds, cache invalidation, and COPY source prefixes.
