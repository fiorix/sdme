+++
title = "Running OpenClaw"
description = "Build and run OpenClaw AI agent inside an sdme container with Telegram and WhatsApp support."
weight = 103

[extra]
category = "apps"
+++

This tutorial builds a rootfs with
[OpenClaw](https://github.com/nichochar/openclaw) installed as a
systemd service, connecting to a vLLM inference server on the same
network zone.

## Prerequisites

You need a base rootfs to build from. Import one if you haven't
already:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

See [Using a Different Root Filesystem](/tutorial/different-rootfs/)
for other supported distributions.

You also need an inference server running on the `inference` network
zone. See [Serving Inference: vLLM on NVIDIA](/tutorial/serving-inference-vllm/)
or [Serving Inference: Ollama on NVIDIA](/tutorial/serving-inference-ollama/).

## The build config

OpenClaw runs on Node.js. The build config installs Node.js,
OpenClaw with its Telegram and WhatsApp dependencies, and copies
in a systemd service unit with a config file.

Create `openclaw-config.json`:

```json
{
  "agents": {
    "defaults": {
      "workspace": "/root/.openclaw/workspace",
      "model": {
        "primary": "vllm/qwopus-9b"
      }
    }
  },
  "models": {
    "providers": {
      "vllm": {
        "baseUrl": "http://vllm:8000/v1",
        "apiKey": "none",
        "api": "openai-responses",
        "models": [
          {
            "id": "vllm/qwopus-9b",
            "name": "qwopus-9b",
            "contextWindow": 131072,
            "maxTokens": 8192
          }
        ]
      }
    }
  },
  "channels": {
    "telegram": {
      "botToken": "send /newbot to @BotFather on Telegram, paste the token here",
      "enabled": true,
      "allowFrom": [
        "tg:send /start to @userinfobot on Telegram, paste your ID here"
      ]
    },
    "whatsapp": {
      "enabled": true,
      "allowFrom": [
        "<your-full-number>@s.whatsapp.net"
      ]
    }
  }
}
```

The `models.providers.vllm.baseUrl` points to the vLLM container
by hostname on the `inference` network zone. Adjust the model name
and parameters to match your vLLM configuration.

Create `openclaw.service`:

```ini
[Unit]
Description=OpenClaw AI Agent
After=network.target
StartLimitBurst=3
StartLimitIntervalSec=60

[Service]
Type=simple
ExecStart=/usr/bin/openclaw gateway
TimeoutStopSec=10
KillMode=mixed
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Create `openclaw.sdme`:

```
FROM ubuntu
RUN apt update
RUN apt install -y curl git
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && apt install -y nodejs
RUN npm install -g openclaw@latest && cd /usr/lib/node_modules/openclaw && npm install grammy @grammyjs/runner @grammyjs/transformer-throttler @buape/carbon
RUN mkdir -p /root/.openclaw
COPY openclaw-config.json /root/.openclaw/openclaw.json
COPY openclaw.service /etc/systemd/system/openclaw.service
```

## Build the rootfs

```sh
sudo sdme fs build openclaw-runtime ./openclaw.sdme
```

## Start a container

```sh
sudo sdme new openclaw -r openclaw-runtime --hardened --network-zone=inference
```

The `--hardened` flag enables user namespace isolation. The
`--network-zone=inference` places the container on the same network
as your inference server, so OpenClaw can reach it by hostname.

Once the container boots, enable and start the service:

```sh
systemctl enable --now openclaw
```

## Linking WhatsApp

To link a WhatsApp account, join the container from the host and
run the channel login command:

```sh
sudo sdme join openclaw
openclaw channels login --verbose
```

This prints a QR code on the terminal. Scan it with WhatsApp on
your phone to link the device. It's best to use a separate
phone/number for this.

From here on, the agent should be ready to chat on the enabled
channels.
