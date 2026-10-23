# Ephemeral Containers

An ephemeral container lives for a single run: any stop removes it, together with its root filesystem, its state, and everything nspawn set up for it (port forwards, bind mounts, network interfaces). This tutorial shows the two ways to start one, `sdme new` and `sdme create`, and what ends each of them: leaving a shell, losing a terminal, a service that finishes, a failing health check, or a plain `sdme stop`.

By contrast, a container made with plain `sdme new` stays on disk after you leave its shell, until you remove it with `sdme rm`.

## Before you start

The examples use an Ubuntu root filesystem (see the [different rootfs](different-rootfs.md) tutorial) and, later on, nginx imported as an OCI application (see the [OCI applications](oci-apps.md) tutorial):

```sh
sudo sdme fs import docker.io/ubuntu
sudo sdme fs import docker.io/nginx --base-fs ubuntu
```

## A throwaway shell

Add `--ephemeral` to `sdme new`:

```sh
sudo sdme new --ephemeral -r ubuntu
```

You get a shell in a fresh container, as with plain `sdme new`. Install packages, break things, then leave:

```sh
exit
```

The container is gone:

```sh
sudo sdme ps
```

## Running one command

Give the command after `--`. The container boots, runs it, and is removed when it finishes:

```sh
sudo sdme new --ephemeral -r ubuntu -- cat /etc/os-release
```

When the output does not go to a terminal (a script, a CI job, a redirect), sdme exits with the command's exit status, so a job can be checked like any other command:

```sh
sudo sdme new --ephemeral -r ubuntu -- sh -c 'exit 3' > /dev/null
echo $?
```

This prints `3`. On a terminal the command runs in an interactive session, and sdme exits with 0 after it.

Bind mounts work as usual, for example to run a project's tests against a clean system:

```sh
sudo sdme new --ephemeral -r ubuntu -b "$PWD:/src:ro" -- ls /src > files.txt
```

## What ends a `new --ephemeral` container

The container belongs to the `sdme new` session that started it. It ends when that session ends, however that happens:

```
You do                                          The container
----------------------------------------------  -------------
exit the shell, or the -- command finishes      is removed
close the terminal or lose the SSH connection   is removed
press Ctrl+C while it boots                     is removed
run 'sdme stop' or 'sdme rm' on it              is removed
reboot inside the container                     is removed
'sdme join' it from another terminal, exit      keeps running
```

Only the session that started the container counts. Try it with two terminals. In the first, start a named container:

```sh
sudo sdme new --ephemeral -r ubuntu --name scratch
```

In the second, join it, look around, and leave:

```sh
sudo sdme join scratch
exit
sudo sdme ps
```

`scratch` is still running; `sdme ps` shows `ephemeral` in its ENABLED column. Now leave the shell in the first terminal, and `sdme ps` no longer lists it.

## Detached containers with `sdme create`

`sdme create --ephemeral` starts the container in the background (it implies `--started`) and returns. There is no session to end it, so it runs until you stop it or one of the triggers in the next sections fires:

```sh
sudo sdme create --ephemeral -r ubuntu --name worker
sudo sdme join worker
exit
sudo sdme ps
```

Leaving the `join` shell does not touch `worker`. Stopping it removes it:

```sh
sudo sdme stop worker
sudo sdme ps
```

`sdme stop` returns once the container is gone. `sdme rm worker` does the same. `sdme restart`, `sdme enable`, and `sdme set` refuse ephemeral containers, because a stop would remove them.

## Stopping when a service finishes

`--main-service` names a systemd unit inside the container whose end stops the container, successful or not. This fits batch work: the container exists for as long as its job runs.

```sh
sudo sdme create --ephemeral -r ubuntu --name job --main-service backup.service
sudo sdme exec job systemd-run --unit=backup sh -c 'echo backing up; sleep 10'
```

About ten seconds later `job` is gone. In practice the main service is a unit that ships in your root filesystem (see [building root filesystems](building-rootfs.md)) and starts at boot; here `systemd-run` creates it after the fact.

sdme installs a drop-in for each main service that makes the container's systemd exit when the unit finishes. A few details:

- `--main-service` is repeatable; the first main service to finish ends the container.
- A main service's own `Restart=` policy is respected: the container ends once systemd gives up restarting the unit.
- The service's exit status becomes the container's, and it is recorded in the journal (see below).

## OCI applications

For an OCI application rootfs, the application's service is the main service by default. The container runs as long as the application does:

```sh
sudo sdme create --ephemeral -r nginx --name web --network-veth
```

If nginx exits or crashes, `web` is removed. Simulate a crash:

```sh
sudo sdme exec web systemctl kill --signal=KILL sdme-oci-nginx.service
sudo sdme ps
```

To keep the container when the application ends, use `--no-main-service`. `--main-service` replaces the default with units of your choice.

Ephemeral containers do not get host directories for the volumes an image declares (`--no-oci-volumes` is implied): that data lives in the container and goes away with it. Use `-b` for data that must outlive the container.

## Health checks

A health check stops the container when it fails several times in a row. sdme runs the checks from the host on a timer:

```sh
sudo sdme create --ephemeral -r nginx --name web --network-veth \
    --health-http 80/
```

By default the check runs every 30 seconds, each attempt may take up to 30 seconds, and 3 consecutive failures stop the container. Each setting has a flag:

```sh
sudo sdme create --ephemeral -r nginx --name web --network-veth \
    --no-main-service --health-http 80/ \
    --health-interval 5 --health-retries 2 --health-start-period 10
```

This container waits 10 seconds after boot, then checks every 5 seconds. `--no-main-service` makes the health check, not the end of nginx, the reason it goes away. Stop nginx:

```sh
sudo sdme exec web systemctl stop sdme-oci-nginx.service
```

Within about 10 seconds the two failed checks remove `web`.

There are three kinds of checks; use one per container:

```
Flag                       Healthy when
-------------------------  ------------------------------------------------
--health-http PORT[/PATH]  GET http://127.0.0.1:PORT/PATH returns 2xx or 3xx
--health-tcp PORT          a TCP connection to 127.0.0.1:PORT succeeds
--health-cmd CMD           CMD, run with /bin/sh -c, exits 0
```

HTTP and TCP checks connect from inside the container's network namespace, so they work with images that have neither curl nor a shell. `--health-cmd` runs in the container's base system, not inside an OCI application's root, so for OCI applications prefer `--health-http` or `--health-tcp`:

```sh
sudo sdme create --ephemeral -r ubuntu --name box \
    --health-cmd 'systemctl is-active --quiet systemd-journald'
```

Health checks combine with main services and, for `sdme new`, with the session: whichever fires first ends the container.

## Watching an ephemeral container

While it runs, an ephemeral container works like any other: `sdme ps`, `sdme logs`, `sdme join`, `sdme exec`, and `sdme cp` all apply.

After it is removed, its name is no longer known to sdme, but the journal keeps its logs, including a line from the teardown that records how the container stopped:

```sh
sudo journalctl -u sdme-ephemeral@web.service | grep 'tore down'
```

```
tore down ephemeral container 'web' (result=success, exit-status=0)
```

Health check results are in their own unit:

```sh
sudo journalctl -u sdme-health@web.service
```

## Leftovers after a crash

If the host crashes or loses power, an ephemeral container cannot be torn down. It is left on disk, stopped. `sdme ps` lists it, `sdme start` refuses it, and `sdme prune` lists it as an ephemeral orphan:

```sh
sudo sdme prune --dry-run
```

Remove it with `sdme prune` or `sdme rm`.

## Summary

```
Command                                  Ends when
---------------------------------------  ----------------------------------
sdme new --ephemeral                     the shell or the session ends
sdme new --ephemeral -- CMD              CMD finishes or the session ends
sdme create --ephemeral                  'sdme stop' or 'sdme rm'
plus --main-service UNIT                 UNIT finishes
plus an OCI rootfs (default)             the OCI application finishes
plus --health-http, -tcp, or -cmd        --health-retries checks fail
```

Every variation also ends with `sdme stop`, `sdme rm`, or a reboot inside the container. The [architecture](../architecture.md#ephemeral-containers) document explains how ephemeral containers are built on transient systemd units.
