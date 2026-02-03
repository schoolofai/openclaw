# Attack Surface Map

## Control Plane (Runclaw)

- **Next.js API routes** for provisioning, deletion, and reconciliation
- **Appwrite** data store for users/instances/webhooks/events
- **Stripe webhooks** (signature-verified but still a critical entry point)
- **Hetzner API** tokens used to create/delete servers
- **Cloudflare API** tokens used to create/delete DNS records

Key risks:

- API auth/permission mistakes
- Secret leakage from build logs or environment
- Excessive permissions in Appwrite or API tokens

## Data Plane (OpenClaw VPS)

- **OpenClaw Gateway** HTTP interface (Control UI, APIs)
- **Channel providers** (Discord, Slack, WhatsApp, Telegram, etc.)
- **Tool execution** (shell, file IO, browser, web)
- **Sandbox containers** (if enabled)
- **Reverse proxy** (Caddy) and TLS termination

Key risks:

- Public exposure without auth
- Prompt injection leading to tool misuse
- Plugin/extension supply chain risks
- Weak local file permissions

## Sensitive Storage

- `~/.openclaw/credentials/*`
- `~/.openclaw/agents/*/agent/auth-profiles.json`
- `~/.openclaw/agents/*/sessions/*.jsonl`

## Network Exposure Points

- Gateway bind address/port
- Reverse proxy ingress (80/443)
- SSH (22)
- Optional node interfaces (Canvas host, browser CDP)

## Privileged Execution Points

- `tools.elevated` (host exec)
- Docker socket if mounted
- Systemd/launchd/service restart commands
