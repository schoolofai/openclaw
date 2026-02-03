# Configuration Baselines

These are defensive defaults. Adjust only with a clear threat model.

## Gateway Auth (Example)

```yaml
gateway:
  bind: "127.0.0.1"
  port: 18789
  auth:
    mode: token
    token: "${OPENCLAW_GATEWAY_TOKEN}"
  trustedProxies:
    - "127.0.0.1"
```

## DM and Group Policies (Example)

```yaml
channels:
  telegram:
    dm:
      policy: pairing
    groupPolicy: allowlist
  discord:
    dm:
      policy: allowlist
    groupPolicy: allowlist
```

## Sandbox Defaults (Example)

```yaml
agents:
  defaults:
    sandbox:
      mode: "non-main"
      scope: "session"
      workspaceAccess: "none"
```

## Tool Policy (Example)

```yaml
tools:
  policy:
    deny:
      - exec
      - browser
  elevated:
    enabled: false
```

## Docker Security (Example)

```bash
docker run --read-only --cap-drop=ALL \
  -v openclaw-data:/app/data \
  openclaw/openclaw:latest
```

## Runtime Baselines

- Node.js version **22.12.0+**
- Regular `openclaw security audit --deep`
- Permissions: `~/.openclaw` → `700`, secrets → `600`
