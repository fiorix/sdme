+++
title = "Serving Inference: vLLM on NVIDIA"
description = "Build and run vLLM inside an sdme container with NVIDIA GPU passthrough for high-throughput LLM serving."
weight = 100

[extra]
category = "apps"
+++

This tutorial builds a rootfs with vLLM installed as a systemd
service, then runs it with NVIDIA GPU access for OpenAI-compatible
LLM inference.

## Prerequisites

You need a base rootfs to build from. Import one if you haven't
already:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

See [Using a Different Root Filesystem](/tutorial/different-rootfs/)
for other supported distributions.

## The build config

vLLM runs inside a Python virtualenv with CUDA support. The build
config installs the NVIDIA userspace libraries, creates the venv,
and copies in a systemd service unit with its config file.

Create `vllm.conf`:

```
MODEL="Jackrong/Qwen3.5-9B-Claude-4.6-Opus-Reasoning-Distilled-v2"
SERVE_ARGS="--tensor-parallel-size 4 --max-model-len 131072 --gpu-memory-utilization 0.85 --enforce-eager --enable-auto-tool-choice --tool-call-parser hermes --trust-remote-code --served-model-name qwopus-9b --reasoning-parser qwen3"
```

The `MODEL` variable sets the Hugging Face model to serve.
`SERVE_ARGS` configures vLLM: `--tensor-parallel-size 4` splits the
model across 4 GPUs, `--max-model-len 131072` sets the context
window, and `--enable-auto-tool-choice` enables function calling.

Create `vllm.service`:

```ini
[Unit]
Description=vLLM Inference Server
After=network.target
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
Type=simple
EnvironmentFile=/etc/vllm.conf
ExecStart=/bin/bash -c 'exec /opt/vllm/bin/vllm serve "$MODEL" --host 0.0.0.0 --port 8000 --dtype half $SERVE_ARGS'
TimeoutStopSec=10
KillMode=mixed
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Create `vllm-runtime.sdme`:

```
FROM ubuntu
RUN apt update
RUN apt install -y python3 python3-pip python3-venv nvidia-cuda-toolkit ninja-build libnvidia-compute-590 nvidia-utils-590 curl jq lsof vim tmux less pciutils iproute2
RUN python3 -m venv /opt/vllm && \
    /opt/vllm/bin/pip install --upgrade pip && \
    /opt/vllm/bin/pip install vllm --extra-index-url https://download.pytorch.org/whl/cu129 && \
    /opt/vllm/bin/pip install 'transformers>=4.56,<5' && \
    /opt/vllm/bin/pip install 'huggingface_hub[cli]'
COPY vllm.conf /etc/vllm.conf
COPY vllm.service /etc/systemd/system/vllm.service
```

The `libnvidia-compute` and `nvidia-utils` version must match the
driver version installed on the host, otherwise GPU access will not
work inside the container.

## Build the rootfs

```sh
sudo sdme fs build vllm-runtime ./vllm-runtime.sdme
```

## Start a container

Bind mount the NVIDIA device nodes so the container can access the
GPUs:

```sh
sudo sdme new vllm -r vllm-runtime \
    --hardened --network-zone=inference \
    -b /dev/nvidia0:/dev/nvidia0 \
    -b /dev/nvidia1:/dev/nvidia1 \
    -b /dev/nvidia2:/dev/nvidia2 \
    -b /dev/nvidia3:/dev/nvidia3 \
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

Once the container boots, download the model before starting
the service. The `huggingface_hub` CLI was installed during the
build:

```sh
/opt/vllm/bin/hf download Jackrong/Qwen3.5-9B-Claude-4.6-Opus-Reasoning-Distilled-v2
```

Then enable and start the vLLM service:

```sh
systemctl enable --now vllm
```

vLLM serves an OpenAI-compatible API on port 8000, accessible
from other containers on the same network zone at
`http://vllm:8000/v1`.

To change the model or serving parameters, edit `/etc/vllm.conf`
and restart the service:

```sh
systemctl restart vllm
```

## Test from another container

Create a client container on the same network zone:

```sh
sudo sdme new client -r ubuntu --network-zone=inference --hardened
```

Inside the client, install curl and list available models:

```sh
apt update && apt install -y curl
curl http://vllm:8000/v1/models
```

Send a quick test query:

```sh
curl http://vllm:8000/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "model": "qwopus-9b",
  "messages": [{"role": "user", "content": "hello"}]
}'
```

Exit and delete the client when done:

```sh
exit
sudo sdme rm client
```

## Next steps

With an inference server running, you can connect an AI agent to
it. See [Running OpenClaw](/tutorial/running-agents-openclaw/).
