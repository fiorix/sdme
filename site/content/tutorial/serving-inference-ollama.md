+++
title = "Serving Inference: Ollama on NVIDIA"
description = "Build and run Ollama inside an sdme container with NVIDIA GPU passthrough for local LLM inference."
weight = 100

[extra]
category = "apps"
+++

This tutorial builds a rootfs with Ollama installed, then runs it
with NVIDIA GPU access for local LLM inference.

## Prerequisites

You need a base rootfs to build from. Import one if you haven't
already:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

See [Using a Different Root Filesystem](/tutorial/different-rootfs/)
for other supported distributions.

## The build config

Create `ollama.sdme`:

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

## Build the rootfs

```sh
sudo sdme fs build ollama ./ollama.sdme
```

## Start a container

Bind mount the NVIDIA device nodes so the container can access the
GPU:

```sh
sudo sdme new ollama -r ollama \
    --hardened --network-zone=inference \
    -b /dev/nvidia0:/dev/nvidia0 \
    -b /dev/nvidia1:/dev/nvidia1 \
    -b /dev/nvidiactl:/dev/nvidiactl \
    -b /dev/nvidia-modeset:/dev/nvidia-modeset \
    -b /dev/nvidia-uvm:/dev/nvidia-uvm \
    -b /dev/nvidia-uvm-tools:/dev/nvidia-uvm-tools
```

The `--hardened` flag enables user namespace isolation. sdme probes
idmap support at create time and, when the kernel does not support
idmapped mounts (a kernel feature that remaps file ownership
without changing files on disk) on overlayfs, pre-shifts UIDs
before boot. On kernels that do support idmapped mounts (6.6+),
this step is skipped entirely.

Once the container is created and you land on a shell, pull a model:

```sh
ollama pull devstral-small-2:24b
```

Exit the shell to return to the host. The Ollama container keeps
running in the background.

## Test from another container

Create a client container on the same network zone:

```sh
sudo sdme new client -r ubuntu --network-zone=inference --hardened
```

Inside the client, install curl and list available models:

```sh
apt update && apt install -y curl
curl http://ollama:11434/api/tags
```

Send a quick test query:

```sh
curl http://ollama:11434/api/generate -d '{
  "model": "devstral-small-2:24b",
  "prompt": "hello",
  "stream": false
}'
```

Exit and delete the client when done:

```sh
exit
sudo sdme rm client
```

## Next steps

With an inference server running, you can connect an AI agent to
it. See [Running PicoClaw](/tutorial/running-agents-picoclaw/) or
[Running OpenClaw](/tutorial/running-agents-openclaw/).
