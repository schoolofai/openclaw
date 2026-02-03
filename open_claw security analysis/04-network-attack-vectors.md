# 04 - Network Attack Vectors

## Overview

OpenClaw's gateway exposes WebSocket and HTTP endpoints that, if improperly secured, provide direct control over the AI agent. The network attack surface includes gateway binding, TLS configuration, mDNS discovery, reverse proxy misconfigurations, and transport-layer weaknesses.

## Gateway Binding Modes (`src/gateway/net.ts`)

### Binding Options

| Mode | Address | Exposure | Risk Level |
|---|---|---|---|
| `loopback` (default) | `127.0.0.1` | Local only | Low |
| `tailnet` | Tailscale IP | Tailnet only | Medium |
| `lan` | `0.0.0.0` | All interfaces | High |
| `auto` | Loopback or `0.0.0.0` | Varies | Medium-High |
| `custom` | User-specified | Depends | Varies |

### Attack: Exposed Gateway on Public Interface

**Severity**: Critical

When `bind: lan` or `bind: auto` (fallback to `0.0.0.0`), the gateway is accessible from any network interface.

**Ethical Hacker Approach**:
```bash
# Scan for OpenClaw gateway
nmap -p 18789 <target-ip>

# Attempt WebSocket connection
wscat -c ws://<target-ip>:18789

# If no auth, send RPC to list agents
echo '{"type":"list-agents"}' | wscat -c ws://<target-ip>:18789
```

**Mitigation**:
```yaml
gateway:
  bind: loopback
  port: 18789
  auth:
    mode: token
    token: "<64-char-random-string>"
```

For VPS deployments, always use `loopback` + reverse proxy (Caddy/nginx).

### Attack: Auto Mode Fallback

**Severity**: High

`bind: auto` tries loopback first, but falls back to `0.0.0.0` if loopback is unavailable. In Docker containers without a loopback interface, this silently exposes the gateway to all networks.

**Mitigation**: Never use `auto` in production. Explicitly set `loopback` or `tailnet`.

## WebSocket Security

### Attack: WebSocket Hijacking via MITM

**Severity**: High

Without TLS, WebSocket traffic is unencrypted. On shared networks (WiFi, co-located servers), an attacker can intercept and modify WebSocket frames.

**Ethical Hacker Approach**:
```bash
# ARP spoof to position as MITM
arpspoof -i eth0 -t <target-ip> <gateway-ip>

# Intercept WebSocket traffic
mitmproxy --mode transparent --set websocket=true
```

Captured data includes:
- Auth tokens (if using query parameter auth)
- Device auth payloads
- Full conversation content
- Tool execution commands and results

**Mitigation**:
- Enable TLS on the gateway: `gateway.tls.enabled: true`
- Use Tailscale (WireGuard-encrypted) or SSH tunneling
- For RunClaw.io: Caddy provides automatic TLS termination

### Attack: WebSocket Flood / DoS

**Severity**: Medium

OpenClaw has no built-in rate limiting on WebSocket connections. An attacker can open thousands of connections to exhaust server resources.

**Ethical Hacker Approach**:
```python
import asyncio
import websockets

async def flood():
    tasks = []
    for _ in range(10000):
        tasks.append(websockets.connect(f'ws://{target}:18789'))
    await asyncio.gather(*tasks, return_exceptions=True)

asyncio.run(flood())
```

**Mitigation**:
- Use Cloudflare proxy (absorbs connection floods)
- Configure connection limits in Caddy:
  ```
  {subdomain}.runclaw.io {
      reverse_proxy openclaw:18789 {
          transport http {
              max_conns_per_host 100
          }
      }
  }
  ```
- Set WebSocket `maxPayload` limit (default 25MB in `src/gateway/client.ts`)

### WebSocket Payload Size

The gateway accepts payloads up to **25 MB** (`maxPayload: 25 * 1024 * 1024`). Large payloads can cause memory exhaustion.

**Mitigation**: Reduce `maxPayload` if large messages aren't needed.

## TLS Configuration (`src/infra/tls/gateway.ts`)

### Architecture

- Auto-generates self-signed certificates (RSA 2048-bit, 3650-day expiry)
- Enforces TLS 1.3 minimum (`minVersion: "TLSv1.3"`)
- Supports certificate fingerprint pinning

### Attack: Self-Signed Certificate Trust

**Severity**: Medium

Self-signed certificates require clients to trust them explicitly. If clients skip verification (`NODE_TLS_REJECT_UNAUTHORIZED=0`), MITM attacks become trivial.

**Ethical Hacker Approach**:
```bash
# Check if gateway uses self-signed cert
openssl s_client -connect <target>:18789 2>/dev/null | openssl x509 -text

# If self-signed, clients may skip verification
# Attempt MITM with custom cert
mitmproxy -p 18789 --ssl-insecure
```

**Mitigation**:
- For RunClaw.io: Use Caddy with Let's Encrypt certificates (auto-renewal)
- Pin certificate fingerprints: `gateway.remote.tlsFingerprint`
- Never set `NODE_TLS_REJECT_UNAUTHORIZED=0` in production

### Attack: RSA 2048 Key Strength

**Severity**: Low (current)

RSA 2048-bit keys are considered adequate through ~2030 but are on the weak end for long-lived certificates (3650-day expiry).

**Mitigation**: For long-term deployments, regenerate certificates or switch to ECDSA P-256.

## mDNS Discovery (`src/infra/bonjour.ts`)

### Architecture

OpenClaw broadcasts `_openclaw-gw._tcp` via mDNS on port 5353, advertising its presence on the local network.

### Information Disclosed

| TXT Record | Content | Risk |
|---|---|---|
| `cliPath` | Full filesystem path to OpenClaw binary | Infrastructure disclosure |
| `sshPort` | SSH port number | Attack surface identification |
| `version` | OpenClaw version | Vulnerability matching |
| `hostname` | System hostname | Target identification |

### Attack: LAN Reconnaissance via mDNS

**Severity**: Medium

**Ethical Hacker Approach**:
```bash
# Discover OpenClaw gateways on the LAN
avahi-browse -art | grep openclaw
dns-sd -B _openclaw-gw._tcp

# Extract detailed information
dig @<target-ip> -p 5353 -t ANY _openclaw-gw._tcp.local
```

**Mitigation**:
```yaml
# Use minimal mode (omits sensitive TXT records)
gateway:
  mdns: minimal

# Or disable entirely
# Environment: OPENCLAW_DISABLE_BONJOUR=1
```

For RunClaw.io VPS: always disable mDNS (`OPENCLAW_DISABLE_BONJOUR=1`).

## HTTP Endpoint Exposure (`src/gateway/server-http.ts`)

### Exposed Endpoints

| Endpoint | Auth Required | Purpose |
|---|---|---|
| `/` | Device auth | Control UI |
| `/v1/chat/completions` | Token | OpenAI-compatible API |
| `/v1/responses` | Token | OpenResponses API |
| `/hooks/wake` | Token | Voice wake forwarding |
| `/hooks/agent` | Token | Agent hooks |
| `/hooks/<custom>` | Token | Custom hook mappings |
| `/health` | None | Health check |
| `/models` | Token | Model catalog |
| Media server (port 18794) | None | Media file serving |

### Attack: Unauthenticated Health Endpoint

**Severity**: Low

The `/health` endpoint responds without authentication, confirming the service is running.

**Ethical Hacker Approach**:
```bash
curl -s https://<subdomain>.runclaw.io/health
# Returns 200 if OpenClaw is running
```

**Mitigation**: Acceptable for health monitoring. If stealth is needed, move health checks behind auth.

### Attack: Media Server Exposure

**Severity**: Medium

The media server runs on port 18794 and serves uploaded/downloaded files. While it validates media IDs and prevents path traversal, it may expose sensitive media content.

**Ethical Hacker Approach**:
```bash
# Enumerate media IDs (if predictable)
for id in $(seq 1 1000); do
  curl -s http://<target>:18794/media/$id -o /dev/null -w "%{http_code} $id\n"
done
```

**Mitigation**:
- Media IDs use random identifiers (not sequential)
- TTL-based cleanup (default 2 minutes)
- Ensure port 18794 is not exposed via firewall
- For RunClaw.io: UFW blocks 18794 (only 80, 443, 22 allowed)

## Client IP Resolution and Trusted Proxies

### Architecture (`src/gateway/net.ts`)

The gateway resolves client IPs from:
1. `X-Forwarded-For` header (if from trusted proxy)
2. `X-Real-IP` header (if from trusted proxy)
3. Socket remote address (fallback)

### Attack: IP Spoofing via Untrusted Proxy Headers

**Severity**: Medium

If `gateway.trustedProxies` is not configured, the gateway may trust forged `X-Forwarded-For` headers from any source.

**Ethical Hacker Approach**:
```bash
# Forge client IP to bypass IP-based restrictions
curl -H "X-Forwarded-For: 127.0.0.1" http://<target>:18789/health
```

**Mitigation**:
```yaml
gateway:
  trustedProxies:
    - "127.0.0.1"
    - "172.17.0.1"  # Docker bridge gateway
```

Only list known reverse proxy IPs.

## Reverse Proxy Misconfigurations

### Caddy Configuration Issues (RunClaw.io)

**Missing rate limiting**:
```
# Bad: No rate limiting
subdomain.runclaw.io {
    reverse_proxy openclaw:3000
}

# Good: With rate limiting
subdomain.runclaw.io {
    rate_limit {
        zone dynamic {
            key {remote_host}
            events 100
            window 1m
        }
    }
    reverse_proxy openclaw:3000
}
```

**Missing WebSocket timeout**:
```
# Good: Set WebSocket timeouts
subdomain.runclaw.io {
    reverse_proxy openclaw:3000 {
        transport http {
            read_timeout 300s
            write_timeout 300s
        }
    }
}
```

**Security headers** (included in RunClaw cloud-init):
```
header {
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    X-XSS-Protection "1; mode=block"
    Referrer-Policy "strict-origin-when-cross-origin"
    Content-Security-Policy "default-src 'self'"
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
```

## Port Exposure Summary (RunClaw.io VPS)

| Port | Service | Should be exposed | Firewall rule |
|---|---|---|---|
| 22 | SSH | Yes (key-only) | `ufw allow 22/tcp` |
| 80 | Caddy HTTP | Yes (redirect to HTTPS) | `ufw allow 80/tcp` |
| 443 | Caddy HTTPS | Yes | `ufw allow 443/tcp` |
| 18789 | OpenClaw Gateway | **No** (loopback only) | Blocked by default |
| 18790 | OpenClaw Bridge | **No** | Blocked by default |
| 18793 | Canvas Host | **No** | Blocked by default |
| 18794 | Media Server | **No** | Blocked by default |
| 5353 | mDNS | **No** | Blocked by default |

## Penetration Testing Checklist

```
[ ] Port scan all 65535 TCP ports on VPS
[ ] Attempt WebSocket connection to gateway from external network
[ ] Verify TLS certificate validity and pinning
[ ] Test X-Forwarded-For header spoofing
[ ] Scan for mDNS broadcasts
[ ] Enumerate HTTP endpoints (/, /health, /v1/*, /hooks/*)
[ ] Test WebSocket flood resilience
[ ] Verify media server is not externally accessible
[ ] Check Caddy security headers with securityheaders.com
[ ] Verify HSTS is enforced
[ ] Test HTTP to HTTPS redirect
[ ] Attempt SSL stripping attack
```
