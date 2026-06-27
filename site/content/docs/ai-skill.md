+++
title = "AI Skill"
description = "Embedded AI agent skill for using and troubleshooting sdme."
weight = 3
template = "doc.html"
+++

sdme ships an AI agent skill for agents that need to use or troubleshoot sdme. The skill covers the sdme operating model, common command workflows, systemd-nspawn and machined diagnostics, lifecycle failures, networking, OCI rootfs handling, and repository validation expectations.

The canonical source lives in the repository at `skills/sdme/SKILL.md`. Release binaries embed that exact file, so the skill always matches the version of sdme being inspected.

Print the embedded skill from any installed binary:

```sh
sdme dump-skill
```

A typical agent workflow is:

```sh
sdme dump-skill > sdme.SKILL.md
```

Then attach or reference `sdme.SKILL.md` when asking an AI agent to diagnose a local sdme issue. This is useful when the installed binary is newer or older than the agent's general knowledge.
