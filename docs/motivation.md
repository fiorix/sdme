# Motivation

**Alexandre Fiori, February 2026**

I wrote exactly zero lines of this code. I've been a manager for years and gradually stopped writing code, until 2026. This project is the result of my first experience vibe coding with agentic support and focusing on design, correctness, and architecture rather than writing the code itself. This is an insanely good time to be a software engineer.

In a few days I've got a fully functional container manager that talks to systemd over D-Bus, sets up overlayfs copy-on-write storage, imports rootfs from tarballs, URLs, OCI images, and QCOW2 disk images. That trajectory is the point.

## Learning the tool

The first goal was simply to learn Claude Code itself. Not read about it, not watch demos. Sit down and build something real with it. Understand what it's good at, where it struggles, how to steer it, when to override it. The only way to develop that intuition is to use it on a problem you already understand deeply enough to evaluate the output.

## Learning how to vibe code

I'm an experienced engineer. I've spent my career in the Linux userspace, building and operating very large distributed systems in production, across millions of servers. I know Unix, networking, systems programming, infrastructure at scale.

But it's 2026 and AI is reshaping how software gets built. The question I needed to answer for myself was: what happens to two decades of systems knowledge when AI can write code faster than I can type? Does the experience become obsolete, or does it become a multiplier?

My bet is on multiplier. Deep domain knowledge (understanding what systemd actually does when you call `StartUnit` over D-Bus, knowing why you need `MS_SLAVE` propagation on your bind mounts, recognizing that a race condition between `systemd-nspawn` registering a machine and your code trying to query it needs a retry loop) that context is exactly what makes AI-assisted development powerful rather than dangerous. You can move at 10x speed, but only if you can evaluate the output and catch the subtle bugs that look correct to someone who doesn't know the domain.

This project was my first step in developing that workflow.
