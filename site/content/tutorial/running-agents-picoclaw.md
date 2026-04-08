+++
title = "Running PicoClaw"
description = "Build and run PicoClaw AI agent inside an sdme container with multi-stage builds."
weight = 102

[extra]
category = "apps"
+++

This tutorial uses a multi-stage build to compile
[PicoClaw](https://github.com/sipeed/picoclaw) with native WhatsApp
support, then copies the binary into a clean runtime rootfs.

## Prerequisites

You need a base rootfs to build from. Import one if you haven't
already:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

See [Using a Different Root Filesystem](/tutorial/different-rootfs/)
for other supported distributions.

You also need an inference server running on the `inference` network
zone. See [Serving Inference: Ollama on NVIDIA](/tutorial/serving-inference-ollama/)
or [Serving Inference: vLLM on NVIDIA](/tutorial/serving-inference-vllm/).

## Stage 1: builder

Create `picoclaw-builder.sdme`:

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
sudo sdme fs build picoclaw-builder ./picoclaw-builder.sdme
```

## Stage 2: runtime

Create `picoclaw-runtime.sdme`:

```
FROM ubuntu
RUN apt update && apt install -y curl less iproute2 netcat-openbsd vim tmux
COPY fs:picoclaw-builder:/usr/local/bin/picoclaw /usr/local/bin/picoclaw
```

The `COPY fs:picoclaw-builder:` prefix tells sdme to copy from the
`picoclaw-builder` rootfs rather than the host filesystem.

Build it:

```sh
sudo sdme fs build picoclaw-runtime ./picoclaw-runtime.sdme
```

## Start the container

```sh
sudo sdme new pico-foobar -r picoclaw-runtime --hardened --network-zone=inference
```

Once you're on the container's shell, initialise and configure picoclaw:

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
