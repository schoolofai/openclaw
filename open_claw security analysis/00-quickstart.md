# OpenClaw Security Analysis - Quickstart Guide

## Purpose

This documentation suite provides a comprehensive security analysis of [OpenClaw](https://github.com/openclaw/openclaw), an open-source personal AI agent platform. It is written from the perspective of a senior security engineer and ethical hacker, targeting operators who deploy OpenClaw instances on VPS infrastructure (specifically Hetzner Cloud via [RunClaw.io](https://runclaw.io)).

## Audience

- **RunClaw.io operators** deploying managed OpenClaw instances
- **Self-hosted operators** running OpenClaw on bare-metal or VPS
- **Security engineers** auditing OpenClaw deployments
- **Penetration testers** scoping OpenClaw engagements

## Threat Summary

OpenClaw is an AI agent that can execute shell commands, read/write files, access networks, and interact with messaging platforms. This combination creates a significant attack surface across multiple domains:

| Risk Domain | Severity | Primary Concern |
|---|---|---|
| Gateway network exposure | **Critical** | Unauthenticated WebSocket access allows full agent control |
| Credential storage | **High** | Plaintext API keys, bot tokens, OAuth creds on disk |
| Prompt injection | **High** | External messages can manipulate AI behavior |
| Plugin system | **High** | No sandboxing; plugins have full process access |
| Code execution | **Critical** | AI-driven shell execution with configurable guardrails |
| Container escape | **Medium** | Docker misconfiguration can expose host |
| Supply chain | **Medium** | npm lifecycle scripts, unverified plugin updates |

## Documentation Map

### Core Analysis

| Document | Description |
|---|---|
| [01 - Threat Model](01-threat-model.md) | Attack surface decomposition, trust hierarchy, adversary profiles |
| [02 - Authentication Vulnerabilities](02-authentication-vulnerabilities.md) | Gateway auth, device auth, channel token handling, session management |
| [03 - Credential Storage Security](03-credential-storage-security.md) | Secrets on disk, env vars, rotation procedures, leakage vectors |
| [04 - Network Attack Vectors](04-network-attack-vectors.md) | Gateway binding, WebSocket hijacking, mDNS disclosure, TLS gaps |
| [05 - Code Execution Risks](05-code-execution-risks.md) | Shell injection, tool policies, sandbox escapes, elevated execution |
| [06 - Prompt Injection Defense](06-prompt-injection-defense.md) | External content handling, injection patterns, boundary markers |
| [07 - Penetration Testing Playbook](07-penetration-testing-playbook.md) | Step-by-step ethical hacking methodology for OpenClaw deployments |

### Deployment Hardening

| Document | Description |
|---|---|
| [08 - VPS Hardening Guide](08-vps-hardening-guide.md) | Hetzner-specific hardening for RunClaw.io deployments |
| [09 - Docker Security](09-docker-security.md) | Container isolation, image hardening, volume security |
| [10 - Monitoring & Incident Response](10-monitoring-incident-response.md) | Detection, alerting, containment, recovery playbook |

## Quick Security Checklist

Before deploying an OpenClaw instance, verify these critical items:

```
CRITICAL (must fix before production):
[ ] Gateway auth enabled (token or password mode)
[ ] Gateway bound to loopback or behind authenticated reverse proxy
[ ] SSH password authentication disabled
[ ] UFW/iptables configured (allow only 80, 443, 22)
[ ] ~/.openclaw/ permissions set to 0o700
[ ] Config file permissions set to 0o600
[ ] DM policy set to "allowlist" or "pairing" (never "open")
[ ] All bot tokens rotated from defaults
[ ] Fail2ban enabled for SSH

HIGH (should fix before production):
[ ] TLS enabled on gateway (or Tailscale/SSH tunnel)
[ ] mDNS discovery set to "minimal" or "off"
[ ] Logging redaction enabled (redactSensitive: "tools")
[ ] Tool execution sandboxed (sandbox.mode: "all")
[ ] Elevated tools restricted to named allowlist
[ ] Unattended OS security updates enabled
[ ] Container running as non-root user

RECOMMENDED:
[ ] Tailscale or WireGuard for remote access
[ ] Cloudflare proxy for DDoS protection
[ ] Regular credential rotation schedule
[ ] Session transcript pruning policy
[ ] Log rotation configured
[ ] openclaw security audit --deep passes clean
```

## Running the Built-In Security Audit

OpenClaw ships with a security audit command:

```bash
# Basic audit (offline checks)
openclaw security audit

# Deep audit (probes live gateway)
openclaw security audit --deep

# Auto-fix safe issues
openclaw security audit --fix
```

The audit checks gateway exposure, filesystem permissions, DM policies, tool blast radius, plugin hygiene, and model configuration. Always run this after deployment.

## Architecture Context for RunClaw.io

```
Internet
    |
    v
[Cloudflare Proxy] -- DDoS protection, wildcard SSL
    |
    v
[Hetzner VPS] -- UFW firewall (80, 443, 22 only)
    |
    +-- [Caddy] -- Reverse proxy, auto-TLS, security headers
    |       |
    |       v
    |   [OpenClaw Container] -- Non-root, loopback gateway
    |       |
    |       +-- Gateway (WebSocket + HTTP)
    |       +-- Messaging channels (Telegram, Discord, etc.)
    |       +-- AI agent (tool execution, file access)
    |       +-- Media pipeline (upload/download/processing)
    |
    +-- [Fail2ban] -- SSH brute-force protection
    +-- [UFW] -- Network firewall
    +-- [unattended-upgrades] -- Auto security patches
```

## How to Use This Documentation

1. **Start with the Threat Model** (01) to understand the attack surface
2. **Review vulnerability docs** (02-06) for your deployment's relevant attack vectors
3. **Use the Penetration Testing Playbook** (07) to validate your defenses
4. **Follow the VPS Hardening Guide** (08) and Docker Security doc (09) for deployment
5. **Implement Monitoring & IR** (10) for ongoing operational security
