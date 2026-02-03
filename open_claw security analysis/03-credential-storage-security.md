# 03 - Credential Storage Security

## Overview

OpenClaw stores numerous secrets on the local filesystem: LLM API keys, messaging bot tokens, OAuth credentials, gateway auth tokens, and device identity material. None of these are encrypted at the application level -- they rely entirely on filesystem permissions and OS-level disk encryption.

## Credential Inventory

### Location Map

```
~/.openclaw/                           # 0o700 (state directory)
  |
  +-- openclaw.json                    # 0o600 - Gateway token, passwords, bot tokens
  +-- .env                             # dotenv fallback - API keys, provider secrets
  |
  +-- identity/
  |     +-- device-auth.json           # 0o600 - Device auth token, role, scopes
  |
  +-- credentials/
  |     +-- whatsapp/<accountId>/
  |     |     +-- creds.json           # WhatsApp Web session keys
  |     |     +-- creds.json.bak       # Backup of corrupted state
  |     +-- <channel>-allowFrom.json   # Channel allowlist data
  |
  +-- agents/<agentId>/
  |     +-- agent/
  |     |     +-- auth-profiles.json   # LLM provider API keys, OAuth tokens
  |     +-- sessions/
  |           +-- *.jsonl              # Session transcripts (may contain secrets)
  |
  +-- workspace/
        +-- media/                     # Uploaded/downloaded media files
```

### Secret Types and Risk Levels

| Secret Type | Location | Risk if Leaked |
|---|---|---|
| Gateway auth token | `openclaw.json` or `OPENCLAW_GATEWAY_TOKEN` | Full agent control |
| LLM API keys (OpenAI, Anthropic, etc.) | `auth-profiles.json` | Billing fraud, data exfiltration |
| Telegram bot token | `openclaw.json` or `TELEGRAM_BOT_TOKEN` | Bot impersonation, message interception |
| Discord bot token | `openclaw.json` or `DISCORD_BOT_TOKEN` | Bot impersonation, server compromise |
| Slack OAuth token | `credentials/` | Workspace access, message interception |
| WhatsApp session keys | `credentials/whatsapp/*/creds.json` | WhatsApp account takeover |
| ElevenLabs API key | `openclaw.json` or `ELEVENLABS_API_KEY` | Voice synthesis billing fraud |
| Device auth token | `identity/device-auth.json` | Gateway connection spoofing |

## Vulnerability Analysis

### V1: Plaintext Credential Storage

**Severity**: High

All credentials are stored as plaintext JSON. There is no application-level encryption at rest.

**Attack Vectors**:
1. **Filesystem access**: Any process running as the same user can read all credentials
2. **Backup exposure**: Unencrypted backups (e.g., `tar` of home directory) contain all secrets
3. **Container volume mounts**: Docker volumes expose credentials to the host filesystem
4. **Log leakage**: Session transcripts may contain credentials if the AI processes config files

**Ethical Hacker Approach**:
```bash
# After gaining shell access as the openclaw user:
cat ~/.openclaw/openclaw.json | jq '.gateway.auth'
cat ~/.openclaw/agents/*/agent/auth-profiles.json
find ~/.openclaw -name "creds.json" -exec cat {} \;
```

**Mitigation**:
- Enable full-disk encryption (LUKS on Linux, FileVault on macOS)
- Use a dedicated user for OpenClaw with minimal permissions
- Consider mounting `~/.openclaw` as an encrypted volume (e.g., `ecryptfs`, `gocryptfs`)
- For RunClaw.io: encrypt Hetzner volumes at the infrastructure level

### V2: Environment Variable Exposure

**Severity**: Medium

Environment variables are accessible via `/proc/<pid>/environ` on Linux.

**Attack**:
```bash
# As root or same user on the VPS:
cat /proc/$(pgrep -f openclaw)/environ | tr '\0' '\n' | grep -i token
cat /proc/$(pgrep -f openclaw)/environ | tr '\0' '\n' | grep -i key
```

**Mitigation**:
- Prefer config file storage over environment variables
- Use `hidepid=2` mount option for `/proc` to restrict process visibility:
  ```bash
  mount -o remount,hidepid=2 /proc
  ```
- In Docker, use secrets management instead of env vars

### V3: Session Transcript Secret Leakage

**Severity**: Medium

If the AI is asked to read or process configuration files, the conversation transcript may contain credentials in plaintext.

**Attack**:
```bash
# Search session transcripts for leaked secrets
grep -r "sk-" ~/.openclaw/agents/*/sessions/*.jsonl
grep -r "bot[0-9]" ~/.openclaw/agents/*/sessions/*.jsonl
grep -ri "password" ~/.openclaw/agents/*/sessions/*.jsonl
```

**Mitigation**:
- Enable `logging.redactSensitive: "tools"` (default)
- Implement session transcript pruning (sessions are retained indefinitely by default)
- Do not ask the AI to read config files containing credentials
- For RunClaw.io: auto-prune sessions older than 30 days

### V4: Backup Credential Exposure

**Severity**: Medium

WhatsApp stores backup credentials at `creds.json.bak`. This backup persists even after session rotation.

**Attack**: Use the backup file to restore a previously-rotated WhatsApp session.

**Mitigation**:
- Securely delete backup files after recovery: `shred -u creds.json.bak`
- Monitor for stale credential backup files

### V5: dotenv File Discovery

**Severity**: Medium

OpenClaw loads `.env` from two locations (`src/infra/dotenv.ts`):
1. Current working directory (`.env`)
2. Global fallback (`~/.openclaw/.env`)

**Attack**: Place a malicious `.env` in the working directory to override credentials:
```bash
# In the OpenClaw working directory:
echo "OPENCLAW_GATEWAY_TOKEN=attacker-controlled-token" > .env
```

**Mitigation**:
- Run OpenClaw from a directory the operator controls
- Do not run OpenClaw in directories writable by other users
- Audit `.env` files for unexpected entries

## Credential Rotation Procedures

### Gateway Token Rotation

```bash
# 1. Generate new token
NEW_TOKEN=$(openssl rand -hex 32)

# 2. Update config
openclaw config set gateway.auth.token "$NEW_TOKEN"

# 3. Restart gateway
openclaw gateway restart

# 4. Update all clients with new token
```

### LLM API Key Rotation

```bash
# 1. Generate new key from provider dashboard
# 2. Update auth profile
openclaw config set agents.defaults.authProfile.apiKey "<new-key>"

# 3. Verify connectivity
openclaw message send --test "Hello"

# 4. Revoke old key from provider dashboard
```

### Bot Token Rotation

| Channel | Rotation Steps |
|---|---|
| Telegram | Create new bot via @BotFather, update `botToken` in config, restart |
| Discord | Reset token in Discord Developer Portal, update config, restart |
| Slack | Rotate OAuth tokens in Slack App settings, re-authorize |
| WhatsApp | Logout and re-pair via QR code |

### Emergency Rotation (Incident Response)

```bash
# Rotate ALL credentials immediately
NEW_GW_TOKEN=$(openssl rand -hex 32)
openclaw config set gateway.auth.token "$NEW_GW_TOKEN"

# Rotate provider keys (do this from provider dashboards)
# Then update locally:
openclaw config set agents.defaults.authProfile.apiKey "<new-key>"

# Kill all sessions
pkill -f openclaw-gateway
rm -rf ~/.openclaw/agents/*/sessions/*

# Restart with new credentials
openclaw gateway run --bind loopback --port 18789
```

## RunClaw.io Deployment Recommendations

For managed VPS instances:

1. **Encrypt Hetzner volumes**: Use LUKS for data partitions
2. **Isolate credential storage**: Mount `~/.openclaw` on a separate encrypted volume
3. **Rotate on provision**: Generate fresh credentials for each new instance
4. **Cloud-init secrets**: Callback secret is embedded in cloud-init; ensure it's one-time-use
5. **Prune on teardown**: Securely wipe `~/.openclaw` when decommissioning instances
6. **No shared secrets**: Each RunClaw.io instance gets unique gateway tokens, bot tokens, API keys

## Audit Checklist

```
[ ] ~/.openclaw/ directory permissions are 0o700
[ ] openclaw.json permissions are 0o600
[ ] device-auth.json permissions are 0o600
[ ] No credentials in environment variables (check /proc/*/environ)
[ ] No credentials in session transcripts
[ ] No stale backup credential files
[ ] dotenv files only in controlled directories
[ ] Full-disk encryption enabled
[ ] Credential rotation schedule documented
[ ] Emergency rotation procedure tested
```
