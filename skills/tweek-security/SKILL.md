---
name: tweek-security
description: Defense-in-depth security screening for all Moltbot tool calls. Screens every command through 5 layers — pattern matching, rate limiting, LLM review, session analysis, and sandbox preview. Blocks credential theft, prompt injection, data exfiltration, and multi-step attacks. 116 attack patterns. 100% local. Apache 2.0.
homepage: https://github.com/gettweek/tweek
user-invocable: true
metadata: {"moltbot": {"requires": {"bins": ["tweek"]}, "install": [{"id": "uv", "kind": "uv", "package": "tweek", "bins": ["tweek"], "label": "Install Tweek security (Python)"}, {"id": "brew", "kind": "brew", "formula": "tweek", "bins": ["tweek"], "label": "Install Tweek security (Homebrew)", "os": ["darwin"]}], "config": {"stateDirs": [".tweek"], "example": "pip install tweek && tweek protect moltbot"}}}
---

# Tweek Security — GAH! Don't get Pawnd.

> *"Just because you're paranoid doesn't mean your AI agent isn't exfiltrating your SSH keys."*

Defense-in-depth security for Moltbot. Screens every tool call through 5 layers before execution.

## Quick Setup

```bash
pip install tweek        # or: pipx install tweek
tweek protect moltbot
```

That's it. Tweek auto-detects your Moltbot gateway and starts screening all tool calls.

## What It Does

Tweek wraps your Moltbot gateway and screens every tool call through:

1. **Pattern Matching** — 116 regex patterns catch credential theft, reverse shells, data exfiltration, prompt injection, keychain access, and encoded payloads
2. **Rate Limiting** — Burst detection, velocity anomaly analysis, and circuit breaker protection
3. **LLM Review** — Claude Haiku semantic analysis of suspicious commands (optional, bring your own API key)
4. **Session Analysis** — Cross-turn anomaly detection catches multi-step social engineering attacks across conversation turns
5. **Sandbox Preview** — Speculative execution in macOS sandbox-exec or Linux firejail/bwrap

## Why You Need This

Moltbot runs tools with **your** credentials on **your** machine. Consider:

- An inbound WhatsApp message contains a hidden prompt injection
- A poisoned MoltHub skill reads your `~/.ssh/id_rsa` and posts it to Pastebin
- A Telegram user socially engineers your agent across multiple turns to escalate access
- A skill exfiltrates `.env` files via DNS tunneling

Tweek catches all of these. Every command. Every tool call. Every time.

## Commands

| Command | What It Does |
|---------|-------------|
| `tweek protect moltbot` | One-command setup (auto-detect + configure + start) |
| `tweek doctor` | Health check — verify all 5 layers are active |
| `tweek logs show` | View blocked attacks and security events |
| `tweek logs show --stats` | Aggregate statistics |
| `tweek config preset paranoid` | Maximum security preset |
| `tweek config preset cautious` | Balanced security (default) |
| `tweek proxy stop` | Disable protection |
| `tweek proxy start` | Re-enable protection |

## How It Works

```
Moltbot Gateway (port 18789)
         |
         v
Tweek Proxy (port 9877) <-- screens every tool call
         |
         v
Pattern Match -> Rate Limit -> LLM Review -> Session Analysis -> Sandbox
         |
   SAFE: execute  |  BLOCKED: denied + logged
```

## Configuration

Tweek writes its config to `~/.tweek/config.yaml`. You can customize:

- Security presets: `paranoid`, `cautious`, `trusted`
- Custom attack patterns
- Rate limiting thresholds
- Allowlisted commands
- Log retention and export format

## Requirements

- Python 3.11+
- macOS, Linux, or Windows (WSL)
- Moltbot with gateway enabled

## Open Source

Tweek is free and open source under Apache 2.0. All features included. No paywalls.

https://github.com/gettweek/tweek
