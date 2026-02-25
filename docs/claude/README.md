# Claude Code Agents

This directory contains agent prompts for use with [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Setup

Install the agents as custom slash commands by copying (or symlinking) the `.md` files into `~/.claude/commands/`:

```bash
cp docs/claude/*.md ~/.claude/commands/
```

## Workflow

Two agents handle complementary responsibilities:

- **`/syseng`** — Systems engineer. Implements new functionality, reviews code for correctness and basic security, and handles Linux-specific concerns (systemd, D-Bus, overlayfs, etc.).

- **`/rustacean`** — Rust expert. Reviews all code produced for idiomatic Rust, eliminates duplication, maintains project hygiene (dependencies, clippy, formatting), and ensures the codebase stays clean and consistent.

The general flow: ask the syseng to implement a feature or fix, then ask the rustacean to review the result.
