# sdme

This is more of a manifesto than a project.

The tool in here, the systemd machine editor (sdme), manages containers
built on systemd-nspawn and overlayfs. It cooperates with machined,
D-Bus, and the broader systemd ecosystem.

It was inspired by [virtme-ng](https://github.com/arighi/virtme-ng),
but instead of booting a VM, it boots up a systemd-nspawn container.

Learn about the tool from the [usage](docs/usage.md) documentation. In
there you will find a practical guide for installing and using sdme as a
beginner or experienced user.


# Why?

I wrote exactly zero lines of this code. Not one. Every line was written
by AI, directed by me.

It's 2026 and I've been a systems engineer for a while. I wanted to
understand what vibe coding actually looks like on a real project.
Because of experience and situation, I decided to play with systemd
booted containers as first class citizens on Linux.

Not that they aren't. But with sdme I am now able to spin up a
systemd-nspawn container running the distro of my choice, imported from
a directory or a URL, or an OCI registry, and I can join this container
and use it like a normal machine.

If you have infinite time and look through the
[architecture](docs/architecture.md) you'll see where I started: really
wanted to mimic what virtme-ng does, cloning the host's root filesystem
with an overlayfs on / and booting up a container. It's what you get by
default just running `sudo sdme new` and from there... I went... far.

Once I got the lifecycle of the clone rootfs working, I thought it would
be natural to allow using any other rootfs, not just my own. Importing a
directory meant trying to recognise something like /etc/os-release, and
checking for the existence of systemd and dbus inside so it would be
more or less certain to be able to boot. That became the `sdme fs`
command, primarily for importing debootstrap'ed rootfs. On a digression
I made it also import QCOW2 disk images. I find it crazy how assisted
coding can do these things so fast: look into the partition table, infer
where the rootfs is, run the checks, and import it. Now we can import
directories and cloud images. There is no cloud-init support, but you
can configure things after boot.

From there it felt natural to add a build system. `sdme fs build` takes
a stripped-down Dockerfile-like config with FROM, COPY, and RUN
directives, spins up a temporary container from an existing rootfs,
executes the operations inside it, and captures the merged overlayfs as
a new rootfs. This means you can compose custom rootfs on top of any
imported base: install packages, drop in config files, run setup
scripts, and get a reusable snapshot out the other end without touching
the original.

These containers are quite cool because you can join and install
packages and common services from the existing distros, it all works
well. But they are also boring for my learning experience. Do what, now?
Sit and run something inside? Meh.

Actually, half true. Convenience was my initial driver for supporting
[OCI containers](docs/oci.md). We all know off the top of our head
docker.io/ubuntu but I bet you wouldn't tell me the qcow2 URL for any
distro outside your own maybe. Using debootstrap is fine but I wanted to
ensure the systemd container ecosystem can be enriched by ecosystems
that already exist but are not easily accessible from systemd-nspawn.

So, enabling to download from an OCI registry and strip out all but the
rootfs was the first step. The next step was distinguishing base OS
images (Debian, Ubuntu) from app images (nginx, redis, mysql). In sdme,
base OS imports work like directory imports: detect the distro, install
systemd and D-Bus, done. App images are different: sdme creates a
systemd container with one of your existing rootfs and places the OCI
app inside it as a chroot with its own network namespace. A systemd
service manages the lifecycle. It was [tricky](docs/hacks.md) to get
right, but it works.

Once those were working, we needed pods. A pod is a shared network
namespace. You can place the entire nspawn container in a pod, or place
only the OCI app in one, sharing it across apps in other containers on
the same host. This is useful for composing control-plane
instrumentation alongside application workloads on separate loopbacks.

The last stage of the journey was
[security hardening](docs/security.md). Spent time adding the most
relevant security options in an attempt to bring sdme containers on par
with Docker and Podman. The models are quite different and I think the
end result is very acceptable.

My takeaways from this journey in creating sdme:

- I'm totally sold on vibe coding; I can do kettlebells while vibing
- It's a long and iterative process, there are no magic prompts
- It takes significant time to define, review, and refine your craft
- The choice of language matters less than domain knowledge; I'm new to Rust
- The verification tasks are insanely useful and AI is really good at this

The question I had to answer for myself was: what happens to two decades
of systems knowledge when AI can write code faster than I can type? Does
the experience become obsolete, or does it become a multiplier?

My bet is on multiplier. Deep domain knowledge becomes a multiplier when
paired with AI's analytical capability, particularly for verification:
building the loop of test, review, fix, and converge.


# Project Stats

In ~11 days we built a 19.7k-line Rust systems tool with 140 commits,
335 tests, support for 6 import source types, 4 distro families, 2
CPU architectures (with hand-written ELF emitters), 3 security tiers,
OCI registry pulling, pod networking, and a full container lifecycle
manager -- averaging ~13 commits and ~1,800 lines of gross churn per
day.

## Project Timeline

- **First commit:** 2026-02-21
- **Latest commit:** 2026-03-03
- **Span:** 11 days (10 active coding days)
- **Total commits:** 140

## Commits Per Day

| Date   | Commits |
|--------|---------|
| Feb 21 | 2       |
| Feb 22 | 28      |
| Feb 23 | 5       |
| Feb 24 | 8       |
| Feb 25 | 21      |
| Feb 26 | 10      |
| Feb 27 | 9       |
| Feb 28 | 22      |
| Mar 01 | 19      |
| Mar 02 | 10      |
| Mar 03 | 6       |

Average: ~13 commits/day.

## Commits Per Week

| Week                | Commits |
|---------------------|---------|
| W08 (Feb 21-23)     | 30      |
| W09 (Feb 24-Mar 2)  | 94      |
| W10 (Mar 3+)        | 16      |

## Lines of Code

| Metric                                      | Value        |
|----------------------------------------------|--------------|
| Rust source (src/)                           | 19,744 lines |
| Total project (rs+toml+md+sh+yml)            | 25,694 lines |
| Gross churn (all-time insertions+deletions)  | 19,538 lines |
| Total insertions                             | 6,063        |
| Total deletions                              | 13,475       |

The negative net (more deletions than insertions) reflects heavy
refactoring -- the codebase was aggressively shrunk and restructured
over its lifetime. The gross churn of ~19.5k means roughly 1x the
entire current codebase was rewritten/reworked.

### Lines Changed Per Day

| Date   | Inserted | Deleted | Net    |
|--------|----------|---------|--------|
| Feb 21 | +2,398   | -170    | +2,228 |
| Feb 22 | +210     | -3,110  | -2,900 |
| Feb 23 | +22      | -204    | -182   |
| Feb 24 | +103     | -683    | -580   |
| Feb 25 | +431     | -2,553  | -2,122 |
| Feb 26 | +0       | -293    | -293   |
| Feb 27 | +623     | -104    | +519   |
| Feb 28 | +2,204   | -3,365  | -1,161 |
| Mar 01 | +52      | -2,702  | -2,650 |
| Mar 02 | +20      | -134    | -114   |
| Mar 03 | +0       | -157    | -157   |

### Largest Source Files

| File                   | Lines | Purpose                     |
|------------------------|-------|-----------------------------|
| src/import/mod.rs      | 3,317 | Rootfs import orchestration  |
| src/main.rs            | 1,646 | CLI + command dispatch       |
| src/containers.rs      | 1,641 | Container lifecycle          |
| src/systemd.rs         | 1,334 | D-Bus + unit management      |
| src/import/registry.rs | 981   | OCI registry client          |
| src/build.rs           | 987   | Rootfs build system          |
| src/import/oci.rs      | 841   | OCI image extraction         |

## Test Coverage

335 unique test functions across 24 test modules (every source file
has a `mod tests`).

Test areas include:

- Container create/remove lifecycle (umask, opaque dirs, security,
  userns, volumes)
- OCI import (layers, whiteouts, manifests, tarballs, symlink escape
  prevention)
- OCI registry (Docker Hub, quay.io, reference parsing, auth)
- OCI app images (ports, volumes, env, user resolution, stop signals,
  working dir)
- Security hardening (capabilities, seccomp, AppArmor,
  strict/hardened validation)
- Network config (ports, bridges, zones, private network)
- Bind mounts + env vars (parsing, validation, state roundtrip,
  nspawn arg generation)
- Pod lifecycle (create, remove, reference blocking)
- Distro detection (Debian, Ubuntu, Fedora, RHEL, AlmaLinux, NixOS,
  unknown)
- Name generation (collision avoidance, vowel mutation)
- ELF generation for drop_privs + devfd_shim (x86_64 + aarch64
  machine code verification)
- State file serialization roundtrips
- Config loading/saving
- Interrupt handling (cooperative cancellation)
- Source detection (directory, tarball, QCOW2, raw image, URL,
  registry)

## Feature Magnitude

### CLI Commands: 16+

`new`, `create`, `start`, `stop`, `join`, `exec`, `rm`, `ps`, `logs`,
`set`, `fs import`, `fs ls`, `fs rm`, `fs build`, `pod new`, `pod ls`,
`pod rm`, `config get/set`, `config apparmor-profile`,
`config completions`

### Import Sources: 6

Directory, tarball (gz/bz2/xz/zstd auto-detected), URL, QCOW2 (via
qemu-nbd), raw disk image, OCI registry.

### Supported OS/Distro Families: 4

| Family  | Distros                                | Package Manager                     |
|---------|----------------------------------------|-------------------------------------|
| Debian  | Debian, Ubuntu, derivatives            | apt-get                             |
| Fedora  | Fedora, CentOS, AlmaLinux, RHEL, Rocky | dnf                                 |
| NixOS   | NixOS                                  | declarative (no imperative install) |
| Unknown | Arch, others                           | best-effort                         |

### OCI Registry Support

Docker Hub (docker.io), Quay (quay.io), GHCR (ghcr.io), and any OCI
Distribution Spec-compliant registry. Supports manifest index
multi-arch resolution, bearer token auth, and SHA-256 digest
verification.

### Architecture Support: 2

- x86_64
- aarch64

Both get custom ELF binaries generated at compile time (drop_privs +
devfd_shim -- raw machine code emitters, not cross-compiled C).

### Security Tiers: 3

1. **Individual flags** -- `--drop-capability`, `--capability`,
   `--no-new-privileges`, `--read-only`, `--system-call-filter`,
   `--apparmor-profile`
2. **`--hardened`** -- userns + private network + no-new-privileges +
   capability drops
3. **`--strict`** -- hardened + Docker-equivalent caps + seccomp +
   AppArmor

### Networking

- Host network (default)
- Private network (`--private-network`)
- Bridge/zone (`--bridge`, `--zone`)
- Port forwarding (`--port`)
- OCI auto-port forwarding
- Pod shared network namespaces (`--pod`, `--oci-pod`)
