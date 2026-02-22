# Motivation

**Alexandre Fiori — February 2026**

I wrote exactly zero lines of this code. I've been a manager for years and gradually stopped writing code, until 2026. This project is the result of my first experience vibe coding with agentic support and focusing on design, correctness, and architecture rather than writing the code itself. This is an insanely good time to be a software engineer.

Two weeks later, the project is ~6,200 lines of Rust — a fully functional container manager that talks to systemd over D-Bus, sets up overlayfs copy-on-write storage, imports rootfs from tarballs, URLs, OCI images, and QCOW2 disk images. That trajectory is the point.

## Learning the tool

The first goal was simply to learn Claude Code itself. Not read about it, not watch demos — sit down and build something real with it. Understand what it's good at, where it struggles, how to steer it, when to override it. The only way to develop that intuition is to use it on a problem you already understand deeply enough to evaluate the output.

## Learning how to vibe code

I'm an experienced engineer. I've spent my career in the Linux userspace — building and operating very large distributed systems in production, across millions of servers. I know Unix, networking, systems programming, infrastructure at scale.

But it's 2026 and AI is reshaping how software gets built. The question I needed to answer for myself was: what happens to two decades of systems knowledge when AI can write code faster than I can type? Does the experience become obsolete, or does it become a multiplier?

My bet is on multiplier. Deep domain knowledge — understanding what systemd actually does when you call `StartUnit` over D-Bus, knowing why you need `MS_SLAVE` propagation on your bind mounts, recognizing that a race condition between `systemd-nspawn` registering a machine and your code trying to query it needs a retry loop — that context is exactly what makes AI-assisted development powerful rather than dangerous. You can move at 10x speed, but only if you can evaluate the output and catch the subtle bugs that look correct to someone who doesn't know the domain.

This project was my first step in developing that workflow.

## What to build

Many things came to mind, but I've been working on the Linux Userspace team at Meta for the past year, so I gravitated toward something in that space:

- **systemd and D-Bus**: Interact with systemd programmatically over D-Bus, understand the APIs, and explore the feasibility and gaps around varlink adoption.
- **Overlayfs containers**: Something like [virtme-ng](https://github.com/arighi/virtme-ng) — the idea of setting up an overlayfs on your current rootfs for quick, dirty experiments: install packages, break things, throw it away. Also a handy tool to spin up containers that run a full systemd init inside.
- **Rootfs import**: Once the basic container management worked, the natural next step was making it easy to import existing root filesystems from other distros and OCI container images to use them locally.

The result is [sdme](https://github.com/fiorix/sdme) — based on a previously half-baked tool I was working on — that went from initial commit to a usable container manager in about two weeks. It's a single Rust binary that manages the full lifecycle: create, start, join, exec, stop, remove, with rootfs import from directories, tarballs, URLs, OCI images, and QCOW2 disk images.
