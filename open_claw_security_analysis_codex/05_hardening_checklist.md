# Hardening Checklist

Use this as a baseline for every deployment.

## OpenClaw Gateway

- Run `openclaw security audit --deep` and resolve all findings
- Bind Gateway to loopback or private network only
- Require `gateway.auth.token` or `gateway.auth.password`
- Configure `gateway.trustedProxies` if behind a reverse proxy
- Keep Control UI in a secure context (HTTPS or localhost)
- Avoid `gateway.controlUi.allowInsecureAuth` in production
- Keep `tools.elevated` disabled unless explicitly required

## Access Control (Channels)

- Default DMs to `pairing` or `allowlist`
- Avoid `open` DMs in production
- Use group allowlists and mention gating for group channels
- Set DM session scope to per-channel-peer when multiple users are allowed

## Tool and Sandbox Policy

- Enable sandboxing for non-main sessions
- Set workspace access to `none` or `ro` unless write is required
- Avoid mounting sensitive host paths into sandbox
- Deny network egress in sandboxes by default

## Secrets and Credentials

- Store secrets in `~/.openclaw/.env` with `600` permissions
- Avoid copying secrets into logs or build artifacts
- Rotate API keys regularly (OpenClaw providers, Runclaw control plane)

## OS and Container Hardening (VPS)

- Disable password auth and root login via SSH
- Enable UFW with only `80`, `443`, and `22`
- Install fail2ban and unattended upgrades
- Run OpenClaw containers as non-root
- Use `--read-only` and `--cap-drop=ALL` where possible

## Monitoring and Recovery

- Collect gateway logs and reverse proxy access logs
- Track instance lifecycle events in Runclaw
- Back up `~/.openclaw` and workspace on a schedule
- Document an incident response runbook
