# Threat Model

## Assets

- OpenClaw credentials and state in `~/.openclaw/` (tokens, sessions, allowlists)
- Gateway API authentication secrets
- Model provider credentials (API keys, tokens)
- Runclaw control plane secrets (Appwrite API key, Stripe webhook secret, Hetzner token, Cloudflare token)
- User data and conversations stored in OpenClaw sessions/logs
- VPS root access and Docker control plane

## Trust Boundaries

- Public internet → Runclaw web app/API (Vercel)
- Runclaw control plane → VPS provisioning (Hetzner API, Cloudflare DNS)
- User device → Gateway Control UI or SSH tunnel
- Channel messages → OpenClaw command/tool execution
- OpenClaw tools → Host filesystem and network

## Attacker Types

- **Unauthenticated remote attackers** probing public endpoints
- **Authorized but untrusted users** (e.g., open DMs or broad allowlists)
- **Malicious insiders** with partial credentials
- **Supply-chain risks** (plugins, container images)

## Primary Attack Goals

- Remote control of OpenClaw tools (exec/file/network)
- Exfiltration of credentials from `~/.openclaw/`
- Manipulation of provisioning or billing workflows
- Persistence on VPS (cron, docker, systemd)
- Lateral movement between instances or control plane accounts

## High-Risk Conditions

- Gateway bound to public interface without strong auth
- “Open” DM policies with tools enabled
- Browser/tool control exposed beyond private network
- Unvetted plugins/extensions installed with elevated privileges
- Weak or shared secrets reused across instances
- World-readable `.openclaw` state

## Defensive Strategy

1. **Identity first**: lock down who can talk to the bot
2. **Scope next**: limit what tools can touch, prefer sandboxing
3. **Network last**: keep the Gateway private or strongly authenticated
