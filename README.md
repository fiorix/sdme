# sdme

This is more of a manifesto than a project.

The tool in here, the systemd machine editor (sdme), manages containers
built on systemd-nspawn and overlayfs. It cooperates with machined,
D-Bus, and the broader systemd ecosystem.

Download a static binary from
[fiorix.github.io/sdme](https://fiorix.github.io/sdme/).

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
default just running 'sudo sdme new' and from there I went... far.

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

The last stage of the journey:
[security hardening](docs/security.md). Spent time adding the most
relevant security options in an attempt to bring sdme containers on par
with Docker and Podman. The models are quite different and I think the
end result is very acceptable.

My take aways from this journey in creating sdme:

- I'm totally sold on vibe coding
- It's a long and iterative process, there is no magic
- It takes significant time to iterate, review, and refine
- The verification tasks are insanely useful and AI is really good at
  this

The question I had to answer for myself was: what happens to two decades
of systems knowledge when AI can write code faster than I can type? Does
the experience become obsolete, or does it become a multiplier?

My bet is on multiplier. Deep domain knowledge becomes a multiplier when
paired with AI's analytical capability, particularly for verification:
building the loop of test, review, fix, and converge.
