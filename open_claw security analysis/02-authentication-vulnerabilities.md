# 02 - Authentication Vulnerabilities

## Overview

OpenClaw implements multiple authentication layers: gateway auth (token/password), device auth (payload-based), Tailscale identity, and per-channel bot token management. Each layer has distinct attack vectors.

## Gateway Authentication (`src/gateway/auth.ts`)

### Architecture

The gateway supports two auth modes:

- **Token mode**: Shared secret compared via `timingSafeEqual`
- **Password mode**: Shared password compared via `timingSafeEqual`

Token resolution order:
1. `gateway.auth.token` in config
2. `OPENCLAW_GATEWAY_TOKEN` environment variable
3. `gateway.auth.password` in config
4. `OPENCLAW_GATEWAY_PASSWORD` environment variable

### Vulnerability: No Auth by Default

**Severity**: Critical

When the gateway is first deployed, no auth token or password may be configured. If the gateway is bound to a non-loopback address (LAN, custom, or auto mode), it is accessible without authentication.

**Attack**: Connect to `ws://<host>:18789` and send RPC commands to control the AI agent.

**Mitigation**:
```yaml
# openclaw.yml
gateway:
  auth:
    mode: token
    token: "<random-64-char-string>"
  bind: loopback
```

Always set auth before changing bind mode. The `openclaw security audit` command flags this as CRITICAL.

### Vulnerability: Weak Token Length

**Severity**: Medium

The audit warns when tokens are shorter than 24 characters. Short tokens are vulnerable to brute-force.

**Attack**: Enumerate short tokens via repeated WebSocket connection attempts.

**Mitigation**:
```bash
# Generate a strong token
openssl rand -hex 32
```

### Vulnerability: Token in Environment Variable

**Severity**: Medium

Environment variables can leak via:
- `/proc/<pid>/environ` on Linux (readable by same-user processes)
- Process listing (`ps aux` with certain configurations)
- Container orchestration logs
- Cloud metadata endpoints

**Attack**: Read `OPENCLAW_GATEWAY_TOKEN` from process environment on shared systems.

**Mitigation**:
- Prefer config file over env vars for secrets
- Ensure config file permissions are `0o600`
- On VPS, run OpenClaw as a dedicated user with restricted access

## Device Authentication (`src/gateway/device-auth.ts`)

### Architecture

Device auth uses a structured payload for WebSocket connections:

```
v1|deviceId|clientId|clientMode|role|scopes|signedAtMs|token|[nonce]
```

Version 2 adds a nonce for replay protection.

### Vulnerability: Replay Attack on v1 Payloads

**Severity**: Medium

Version 1 device auth payloads lack a nonce. A captured payload can be replayed to establish a new connection.

**Attack**:
1. Intercept WebSocket upgrade request (MITM on non-TLS connection)
2. Extract device auth payload from headers
3. Replay the payload to establish unauthorized connection

**Mitigation**:
- Enable TLS on the gateway (`gateway.tls.enabled: true`)
- Use Tailscale or SSH tunnel for transport encryption
- Upgrade to v2 payloads (nonce-based)

### Vulnerability: Device Token Storage

**Severity**: Medium

Device tokens are stored at `~/.openclaw/identity/device-auth.json` with `0o600` permissions. If filesystem permissions are relaxed, any local user can read the token.

**Attack**: Read device-auth.json on a shared system where permissions are misconfigured.

**Mitigation**:
```bash
chmod 600 ~/.openclaw/identity/device-auth.json
chmod 700 ~/.openclaw/identity/
```

## Tailscale Authentication (`src/gateway/auth.ts`, `src/infra/tailscale.ts`)

### Architecture

When Tailscale is enabled, the gateway trusts identity headers from the Tailscale proxy:
- `tailscale-user-login`
- `tailscale-user-name`
- `tailscale-user-profile-pic`

### Vulnerability: Header Injection via Non-Tailscale Proxy

**Severity**: High

If the gateway accepts Tailscale headers but the request doesn't come through the Tailscale proxy, an attacker can inject these headers to impersonate any Tailscale user.

**Attack**:
1. Send request with forged `tailscale-user-login` header
2. Gateway trusts the header if `allowTailscale` is enabled
3. Attacker gains authenticated access as any user

**Mitigation**:
The code validates that Tailscale requests come from loopback + have proxy headers. Ensure:
- Gateway is bound to loopback
- `gateway.trustedProxies` only lists known proxy IPs
- Tailscale headers are stripped by reverse proxy before forwarding

### Vulnerability: Tailscale Funnel Exposure

**Severity**: Critical

Tailscale Funnel exposes the gateway to the public internet. Combined with weak or missing auth, this is a direct path to compromise.

**Attack**: Discover the Funnel URL (predictable `<hostname>.<tailnet>.ts.net` pattern) and connect.

**Mitigation**:
- Use `tailscale.mode: serve` (tailnet-only) instead of `funnel`
- Always require token auth even with Tailscale
- The security audit flags Funnel as CRITICAL

## Control UI Authentication

### Architecture (`src/config/types.gateway.ts`)

The Control UI has its own auth settings:
- `controlUi.allowInsecureAuth`: Allow token auth over HTTP (dangerous)
- `controlUi.dangerouslyDisableDeviceAuth`: Disable device identity checks

### Vulnerability: Insecure Auth Flag

**Severity**: High

`allowInsecureAuth: true` transmits tokens over unencrypted HTTP, making them interceptable.

**Attack**: MITM the HTTP connection, capture auth token, replay for persistent access.

**Mitigation**:
```yaml
gateway:
  controlUi:
    allowInsecureAuth: false  # default
    dangerouslyDisableDeviceAuth: false  # default
```

Never set these flags in production. They exist for local development only.

## Channel Token Security

### Bot Token Handling

Each messaging channel stores tokens differently:

| Channel | Storage Location | Resolution Priority |
|---|---|---|
| Telegram | Config `botToken`, `tokenFile`, or `TELEGRAM_BOT_TOKEN` env | Account-specific > Global > Env |
| Discord | Config `token` or `DISCORD_BOT_TOKEN` env | Config > Env |
| Slack | OAuth flow, stored in auth profiles | OAuth tokens in `~/.openclaw/credentials/` |
| WhatsApp | Session-based, `~/.openclaw/oauth/whatsapp/*/creds.json` | QR code pairing |
| Signal | Phone/captcha-based registration | Local storage |

### Vulnerability: Token File Path Traversal (Telegram)

**Severity**: Medium

The `tokenFile` config option reads a token from an arbitrary filesystem path. If an attacker can modify the config, they could point this to a sensitive file.

**Attack**: Set `tokenFile: /etc/shadow` in config to leak system passwords in Telegram API error messages.

**Mitigation**:
- Restrict config file write access (`chmod 600`)
- Validate `tokenFile` paths against a whitelist of allowed directories
- Run OpenClaw as a non-root user with limited filesystem access

### Vulnerability: WhatsApp Session Persistence

**Severity**: Medium

WhatsApp Web credentials at `~/.openclaw/oauth/whatsapp/*/creds.json` contain session keys that grant persistent WhatsApp access. These are not encrypted.

**Attack**: Copy `creds.json` to another machine and impersonate the WhatsApp session.

**Mitigation**:
- Ensure `~/.openclaw/oauth/` permissions are `0o700`
- Monitor for concurrent session warnings from WhatsApp
- Rotate sessions periodically (re-pair via QR code)

## Hooks Endpoint Authentication

### Architecture (`src/gateway/server-http.ts`)

Hooks endpoints accept tokens via:
1. `Authorization: Bearer <token>` header (preferred)
2. `X-OpenClaw-Token` header
3. `?token=<token>` query parameter (deprecated, logged as warning)

### Vulnerability: Token in Query String

**Severity**: Medium

Query string tokens appear in:
- Server access logs
- Browser history
- Referrer headers
- Proxy/CDN logs

**Attack**: Extract token from Caddy/nginx access logs or browser history.

**Mitigation**:
- Always use the `Authorization` header
- The code warns about query parameter usage; enforce header-only auth
- Configure access logs to strip query parameters

## Penetration Testing Checklist

```
[ ] Attempt gateway WebSocket connection without credentials
[ ] Attempt gateway connection with empty/short token
[ ] Test timing-based token enumeration (should be constant-time)
[ ] Inject Tailscale identity headers from non-Tailscale source
[ ] Attempt device auth payload replay (capture and reuse)
[ ] Check for token exposure in server logs
[ ] Verify config file permissions (should be 0o600)
[ ] Check for tokens in process environment (/proc/*/environ)
[ ] Test hooks endpoint with token in query string vs header
[ ] Verify Control UI auth flags are not set to insecure values
```
