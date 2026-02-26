# Using sdme on macOS

sdme requires Linux with systemd. On a Mac, you can get a local Linux VM using [lima-vm](https://lima-vm.io/).

> **Note:** If your Mac has an Apple Silicon chip (M1, M2, etc.), the VM runs Linux on aarch64. Not all binaries and container images will work out of the box. Make sure what you're running supports `arm64`/`aarch64`.

## Set up a Linux VM

Install lima:

```bash
brew install lima
```

Create and start a VM:

```bash
limactl create --name=dev template:ubuntu
limactl start dev
```

You can pick other distros. Run `limactl create` interactively to see available templates.

Shell into the VM:

```bash
limactl shell dev
```

From here on, all commands run inside the VM.

## Install sdme

```bash
curl -fsSL https://fiorix.github.io/sdme/install.sh | sudo sh
```

## Run your first container

```bash
sudo sdme new
```

Check that systemd is running inside the container:

```bash
systemctl status
```

