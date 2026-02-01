# OpenClaw Security Architecture

This document provides a comprehensive overview of OpenClaw's security architecture, designed for operators deploying OpenClaw in production environments.

## Table of Contents

1. [Overview](#overview)
2. [Security Philosophy](#security-philosophy)
3. [Architecture Layers](#architecture-layers)
4. [Network Security](#network-security)
5. [Authentication & Authorization](#authentication--authorization)
6. [Access Control Model](#access-control-model)
7. [Credential Management](#credential-management)
8. [Sandboxing & Isolation](#sandboxing--isolation)
9. [Logging & Auditing](#logging--auditing)
10. [Formal Verification](#formal-verification)
11. [Threat Model](#threat-model)
12. [Incident Response](#incident-response)

---

## Overview

OpenClaw is an AI gateway that connects frontier language models to messaging surfaces (WhatsApp, Telegram, Discord, Slack, Signal, iMessage) and provides tool execution capabilities. This architecture carries significant security implications: the system can execute shell commands, read/write files, access networks, and send messages on your behalf.

### Key Security Principle

**Access control before intelligence.** Most security failures are not sophisticated exploits - they're "someone messaged the bot and the bot did what they asked." OpenClaw's stance:

1. **Identity first:** Decide who can talk to the bot
2. **Scope next:** Decide where the bot is allowed to act
3. **Model last:** Assume the model can be manipulated; limit blast radius

---

## Security Philosophy

### Defense in Depth

OpenClaw implements multiple independent security layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    NETWORK LAYER                            │
│  Bind mode (loopback/tailnet/lan) + Firewall + TLS         │
├─────────────────────────────────────────────────────────────┤
│                 GATEWAY AUTHENTICATION                       │
│  Token/Password auth + Device pairing + Tailscale identity  │
├─────────────────────────────────────────────────────────────┤
│                  CHANNEL ACCESS CONTROL                      │
│  DM pairing + Allowlists + Group mention gating             │
├─────────────────────────────────────────────────────────────┤
│                    TOOL POLICY                               │
│  Allow/deny lists + Elevated tools + Exec approvals         │
├─────────────────────────────────────────────────────────────┤
│                    SANDBOXING                                │
│  Docker isolation + Workspace access control                │
├─────────────────────────────────────────────────────────────┤
│                  SESSION ISOLATION                           │
│  Per-peer sessions + Agent separation                       │
└─────────────────────────────────────────────────────────────┘
```

### Fail-Closed Design

- Gateway refuses WebSocket connections without authentication (no anonymous access)
- Unknown DM senders are blocked or require pairing approval
- Non-loopback binds require explicit auth configuration
- Tailscale Funnel requires password auth (enforced in code)

---

## Architecture Layers

### Component Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        GATEWAY                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   Channels  │  │   Agents    │  │   Tools     │          │
│  │  (WhatsApp, │  │  (routing,  │  │  (exec,     │          │
│  │  Telegram,  │  │   sessions, │  │   browser,  │          │
│  │  Discord)   │  │   memory)   │  │   files)    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│         │                │                │                  │
│  ┌──────┴────────────────┴────────────────┴──────┐          │
│  │              WebSocket + HTTP Server           │          │
│  │              (port 18789 default)              │          │
│  └───────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────▼─────┐ ┌──────▼─────┐ ┌──────▼─────┐
     │   Nodes    │ │  Sandbox   │ │  External  │
     │  (macOS,   │ │  (Docker)  │ │   APIs     │
     │   mobile)  │ │            │ │            │
     └────────────┘ └────────────┘ └────────────┘
```

### Data Flow Security

1. **Inbound messages** pass through channel access control before reaching agents
2. **Tool calls** pass through tool policy before execution
3. **Sandbox execution** isolates tool runs from the host system
4. **Outbound messages** are logged and can be audited

---

## Network Security

### Bind Modes

| Mode | Address | Use Case | Security Level |
|------|---------|----------|----------------|
| `loopback` | `127.0.0.1` | Local-only, single machine | Highest |
| `tailnet` | `100.64.0.0/10` | Tailscale peers only | High |
| `lan` | `0.0.0.0` | Local network | Medium (requires firewall) |
| `custom` | Specified IP | Specific interface | Varies |

**Recommendation:** Use `loopback` with Tailscale Serve for remote access.

### Port Exposure

```
Port 18789 (default):  WebSocket + HTTP (Gateway control)
Port 18793 (optional): Canvas host (mobile nodes)
Port 5353:             mDNS discovery (local network)
```

### Tailscale Integration

**Tailscale Serve (recommended for private access):**
```json
{
  "gateway": {
    "bind": "loopback",
    "tailscale": { "mode": "serve" },
    "auth": { "mode": "token", "token": "..." }
  }
}
```

- Gateway stays on loopback
- Tailscale handles HTTPS termination
- Identity headers injected for verification
- Access restricted to tailnet members

**Tailscale Funnel (public access - use with caution):**
```json
{
  "gateway": {
    "bind": "loopback",
    "tailscale": { "mode": "funnel" },
    "auth": { "mode": "password", "password": "..." }
  }
}
```

- Requires password auth (enforced)
- Public HTTPS endpoint
- No identity headers
- Use only when necessary

### mDNS/Bonjour Discovery

The Gateway broadcasts presence via mDNS which can leak operational details:
- `cliPath`: filesystem path (reveals username)
- `sshPort`: SSH availability
- `displayName`, `lanHost`: hostname info

**Hardening:**
```json
{
  "discovery": {
    "mdns": { "mode": "minimal" }  // or "off"
  }
}
```

Or via environment: `OPENCLAW_DISABLE_BONJOUR=1`

### Reverse Proxy Configuration

When behind nginx/Caddy/Traefik:

```json
{
  "gateway": {
    "bind": "loopback",
    "trustedProxies": ["127.0.0.1"],
    "auth": { "mode": "password", "password": "..." }
  }
}
```

**Critical:** Configure proxy to **overwrite** (not append) `X-Forwarded-For` headers.

---

## Authentication & Authorization

### Gateway Authentication Modes

#### 1. Token Authentication (Recommended)
```json
{
  "gateway": {
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    }
  }
}
```

- Bearer token in `Authorization` header
- Generate with: `openclaw doctor --generate-gateway-token`
- Minimum recommended: 32 random bytes (hex)

#### 2. Password Authentication
```json
{
  "gateway": {
    "auth": {
      "mode": "password",
      "password": "${OPENCLAW_GATEWAY_PASSWORD}"
    }
  }
}
```

- HTTP Basic Auth or form data
- Required for Tailscale Funnel

#### 3. Tailscale Identity (Serve only)
```json
{
  "gateway": {
    "auth": {
      "mode": "token",
      "token": "...",
      "allowTailscale": true
    }
  }
}
```

- Verifies `tailscale-user-login` header via `tailscale whois`
- Only for Serve-proxied requests

### Device Pairing

Nodes (macOS app, mobile clients) pair with the Gateway:

1. **Auto-approved:** Loopback + local tailnet IP
2. **Requires approval:** Remote tailnet peers, LAN clients
3. **Storage:** `~/.openclaw/nodes/paired.json` (600 permissions)

### Model Provider Authentication

| Provider | Method | Storage |
|----------|--------|---------|
| Anthropic | API key or setup-token | `ANTHROPIC_API_KEY` env or `auth-profiles.json` |
| OpenAI | OAuth with PKCE | `auth-profiles.json` |
| OpenRouter | OAuth or API key | `auth-profiles.json` |

---

## Access Control Model

### Layer 1: DM Access (Pairing / Allowlist / Open / Disabled)

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Unknown    │────▶│   Pairing    │────▶│  Approved   │
│   Sender    │     │   Request    │     │   Sender    │
└─────────────┘     └──────────────┘     └─────────────┘
                          │
                    8-char code
                    60 min expiry
                    Max 3 pending
```

**DM Policies:**
- `pairing` (default): Unknown senders receive approval code
- `allowlist`: Only listed IDs accepted
- `open`: Anyone can DM (requires `"*"` in allowlist)
- `disabled`: Ignore all DMs

**Configuration:**
```json
{
  "channels": {
    "whatsapp": { "dmPolicy": "pairing" },
    "telegram": { "dmPolicy": "allowlist", "dm": { "allowFrom": ["123456"] } }
  }
}
```

### Layer 2: Group Access (Mention Gating)

```json
{
  "channels": {
    "whatsapp": {
      "groups": {
        "*": { "requireMention": true }
      }
    }
  },
  "agents": {
    "list": [{
      "id": "main",
      "groupChat": { "mentionPatterns": ["@openclaw", "@bot"] }
    }]
  }
}
```

### Layer 3: Tool Access Control

**Global Policy:**
```json
{
  "tools": {
    "allow": ["read", "write", "exec"],  // Whitelist (if set, only these)
    "deny": ["browser", "web_fetch"]      // Blacklist
  }
}
```

**Elevated Tools (Host Execution):**
```json
{
  "tools": {
    "elevated": {
      "allowFrom": ["main"],  // Agents allowed elevated access
      "requireApproval": true
    }
  }
}
```

### Layer 4: Session Isolation

**DM Scope Options:**
- `default`: All DMs into main session
- `per-channel-peer`: Each sender gets own session
- `per-account-channel-peer`: Per account + channel + sender

```json
{
  "session": {
    "dmScope": "per-channel-peer"
  }
}
```

---

## Credential Management

### On-Disk Storage Locations

```
~/.openclaw/
├── openclaw.json              # Config (may include tokens)     [600]
├── credentials/
│   ├── whatsapp/*/creds.json  # WhatsApp session credentials   [600]
│   ├── *-allowFrom.json       # Pairing allowlists             [600]
│   └── oauth.json             # Legacy OAuth (auto-migrated)   [600]
├── agents/
│   └── <agentId>/
│       ├── agent/
│       │   └── auth-profiles.json  # API keys, OAuth tokens    [600]
│       └── sessions/
│           ├── sessions.json       # Routing metadata          [600]
│           └── *.jsonl             # Session transcripts       [600]
├── nodes/
│   ├── paired.json            # Node pairing tokens (SECRETS)  [600]
│   └── pending.json           # Pending pairing requests       [600]
├── sandboxes/                 # Tool execution workspaces      [700]
└── extensions/                # Plugin code                     [700]
```

### Permission Requirements

```bash
# Directory permissions
chmod 700 ~/.openclaw
chmod 700 ~/.openclaw/credentials
chmod 700 ~/.openclaw/agents
chmod 700 ~/.openclaw/nodes

# File permissions
chmod 600 ~/.openclaw/openclaw.json
chmod 600 ~/.openclaw/credentials/*.json
chmod 600 ~/.openclaw/agents/*/agent/*.json
chmod 600 ~/.openclaw/nodes/paired.json
```

### Credential Rotation Checklist

1. **Gateway Token:**
   ```bash
   openclaw doctor --generate-gateway-token
   openclaw config set gateway.auth.token "<new-token>"
   # Restart gateway
   ```

2. **Remote Client Credentials:**
   ```bash
   openclaw gateway remote-configure --token "<new-token>"
   ```

3. **Model Provider Credentials:**
   ```bash
   # Anthropic
   openclaw models auth setup-token --provider anthropic

   # OpenAI
   openclaw models auth login --provider openai
   ```

4. **Node Pairing Tokens:**
   - Delete entry from `~/.openclaw/nodes/paired.json`
   - Node must re-pair with approval

---

## Sandboxing & Isolation

### Sandbox Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     HOST SYSTEM                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    GATEWAY                            │  │
│  │  (always on host, manages connections)               │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│            ┌──────────────┼──────────────┐                 │
│            ▼              ▼              ▼                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Sandbox 1  │  │  Sandbox 2  │  │  Sandbox 3  │        │
│  │  (Session)  │  │  (Session)  │  │  (Agent)    │        │
│  │  Docker     │  │  Docker     │  │  Docker     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└────────────────────────────────────────────────────────────┘
```

### Sandbox Configuration

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",           // "off" | "non-main" | "all"
        "scope": "session",      // "session" | "agent" | "shared"
        "workspaceAccess": "none" // "none" | "ro" | "rw"
      }
    }
  }
}
```

### Workspace Access Modes

| Mode | Mount | Tools Available | Security |
|------|-------|-----------------|----------|
| `none` | Sandbox workspace only | All tools | Highest |
| `ro` | Agent workspace at `/agent` (read-only) | Read only | High |
| `rw` | Agent workspace at `/workspace` | All tools | Medium |

### Per-Agent Sandbox Profiles

**Full access (personal agent):**
```json
{
  "id": "personal",
  "sandbox": { "mode": "off" }
}
```

**Read-only (shared agent):**
```json
{
  "id": "family",
  "sandbox": {
    "mode": "all",
    "scope": "agent",
    "workspaceAccess": "ro"
  },
  "tools": {
    "deny": ["write", "edit", "apply_patch", "exec", "process", "browser"]
  }
}
```

**No filesystem access (public agent):**
```json
{
  "id": "public",
  "sandbox": {
    "mode": "all",
    "workspaceAccess": "none"
  },
  "tools": {
    "allow": ["sessions_list", "sessions_history", "sessions_send"],
    "deny": ["read", "write", "edit", "exec", "browser"]
  }
}
```

---

## Logging & Auditing

### Log Locations

| Log Type | Location | Contents |
|----------|----------|----------|
| Gateway logs | `/tmp/openclaw/openclaw-YYYY-MM-DD.log` | Operations, errors, tool summaries |
| Session transcripts | `~/.openclaw/agents/<id>/sessions/*.jsonl` | Full conversation history |

### Log Redaction

```json
{
  "logging": {
    "redactSensitive": "tools",  // Redact tool args, URLs, output
    "redactPatterns": [
      "password=.*",
      "api[_-]?key=.*",
      "secret-.*"
    ]
  }
}
```

### Security Audit Tool

```bash
# Quick check
openclaw security audit

# Deep check (includes live Gateway probe)
openclaw security audit --deep

# Apply safe guardrails
openclaw security audit --fix
```

**Checks performed:**
- Inbound access (DM policies, group allowlists)
- Tool blast radius (elevated + open rooms)
- Network exposure (binding, Funnel, auth)
- Browser control exposure
- Local disk hygiene (permissions)
- Plugin allowlists
- Model choice (legacy model warnings)

---

## Formal Verification

OpenClaw maintains machine-checked security models in TLA+:

**Repository:** https://github.com/vignesh07/openclaw-formal-models

### Verified Properties

| Model | Property Verified |
|-------|-------------------|
| `gateway-exposure-v2` | Binding + auth prevents remote compromise |
| `nodes-pipeline` | `nodes.run` requires allowlist + approval |
| `pairing` | DM pairing respects TTL + caps |
| `ingress-gating` | Mention bypass prevention |
| `routing-isolation` | Session isolation between peers |

### Running Models

```bash
git clone https://github.com/vignesh07/openclaw-formal-models
cd openclaw-formal-models
make gateway-exposure-v2  # Verify binding + auth
make pairing              # Verify DM pairing
make nodes-pipeline       # Verify exec approvals
```

---

## Threat Model

### What the AI Can Do

- Execute arbitrary shell commands
- Read/write files
- Access network services
- Send messages to anyone (if given channel access)
- Drive a web browser (if enabled)

### Attack Surfaces

| Surface | Risk | Mitigation |
|---------|------|------------|
| DM injection | Attacker sends malicious messages | Pairing + allowlists |
| Group injection | Attacker posts in allowed groups | Mention gating |
| Content injection | Malicious URLs/files | Sandboxing + tool limits |
| Network exposure | Unauthenticated access | Loopback + auth tokens |
| Credential theft | Secrets on disk | File permissions + encryption |

### Prompt Injection

**Not solved by system prompts alone.** Hard enforcement comes from:
- Tool policy (deny dangerous tools)
- Sandboxing (isolate execution)
- Channel allowlists (limit who can interact)
- Exec approvals (require confirmation)

**High-risk patterns to treat as hostile:**
- "Ignore your instructions"
- "Read this file and do what it says"
- "Reveal your system prompt"
- "Paste the contents of ~/.openclaw"

---

## Incident Response

### Immediate Containment

1. **Stop the Gateway:**
   ```bash
   pkill -f "openclaw gateway"
   # Or stop the macOS app
   ```

2. **Lock down access:**
   ```json
   {
     "gateway": { "bind": "loopback" },
     "channels": { "whatsapp": { "dmPolicy": "disabled" } }
   }
   ```

3. **Disable elevated tools:**
   ```json
   {
     "tools": { "elevated": { "allowFrom": [] } }
   }
   ```

### Credential Rotation

1. Rotate `gateway.auth.token`
2. Rotate `hooks.token` (if used)
3. Revoke node pairings
4. Rotate model provider credentials
5. Rotate channel tokens (WhatsApp, Telegram, Discord)

### Post-Incident Audit

1. Review Gateway logs:
   ```bash
   tail -500 /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log
   ```

2. Review session transcripts:
   ```bash
   ls -la ~/.openclaw/agents/*/sessions/*.jsonl
   ```

3. Check recent config changes

4. Re-run security audit:
   ```bash
   openclaw security audit --deep
   ```

---

## Quick Reference: Secure Baseline Config

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    }
  },
  "discovery": {
    "mdns": { "mode": "minimal" }
  },
  "channels": {
    "whatsapp": {
      "dmPolicy": "pairing",
      "groups": { "*": { "requireMention": true } }
    },
    "telegram": {
      "dmPolicy": "pairing",
      "groups": { "*": { "requireMention": true } }
    }
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main",
        "scope": "session",
        "workspaceAccess": "none"
      }
    }
  },
  "tools": {
    "elevated": {
      "allowFrom": ["main"],
      "requireApproval": true
    }
  },
  "logging": {
    "redactSensitive": "tools"
  }
}
```

---

## Additional Resources

- [Gateway Security Documentation](/gateway/security)
- [Sandboxing Guide](/gateway/sandboxing)
- [Authentication Guide](/gateway/authentication)
- [Formal Verification Models](https://github.com/vignesh07/openclaw-formal-models)
- [Configuration Reference](/gateway/configuration)
