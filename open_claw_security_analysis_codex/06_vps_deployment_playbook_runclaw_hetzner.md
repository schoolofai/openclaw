# VPS Deployment Playbook (Runclaw + Hetzner)

This playbook aligns with the Runclaw architecture described in `runclaw-spec.md` and focuses on secure deployment of OpenClaw instances on Hetzner-class VPS providers.

## Goals

- Private-by-default Gateway exposure
- Strong secrets and per-instance isolation
- Minimal attack surface on the VPS
- Clear operational routines for patching and audit

## 1) Control Plane Prerequisites

- **Appwrite**
  - Use least-privilege API keys where possible
  - Lock down collection permissions to per-user access
- **Stripe**
  - Verify webhook signatures
  - Store webhook secrets in a secure secret store
- **Hetzner**
  - Use scoped API tokens if supported
  - Log provisioning actions
- **Cloudflare**
  - Use scoped tokens limited to the runclaw.io zone

## 2) VPS Provisioning (Data Plane)

- Use Ubuntu or Debian LTS
- Enable UFW and allow only `80`, `443`, and `22`
- Disable SSH password auth; disable root login
- Install fail2ban and unattended upgrades

## 3) Docker and OpenClaw

- Run OpenClaw in Docker with a non-root user
- Persist `~/.openclaw` and workspace on the host
- Avoid mounting the Docker socket into the container
- Keep container images updated and pinned where possible

## 4) Reverse Proxy (Caddy)

- Terminate TLS at Caddy
- Only proxy to the internal OpenClaw container
- Enable security headers
- Log access separately from application logs

## 5) Gateway Exposure Model

Preferred:

- Bind the Gateway to loopback on the VPS
- Access via SSH tunnel or Tailscale Serve

If public exposure is required:

- Enforce `gateway.auth.token` or `gateway.auth.password`
- Configure `gateway.trustedProxies`
- Restrict ingress to known IPs where possible

## 6) Instance Callback Security

- Use a per-instance callback secret
- Verify instance status before accepting callbacks
- Rate-limit callback endpoint

## 7) Secrets Management

- Store all control plane secrets in a managed secret store
- Avoid embedding secrets in cloud-init logs
- Rotate secrets on a schedule

## 8) Backups and Recovery

- Back up `~/.openclaw` and workspace to encrypted storage
- Test restores on a staging instance
- Track instance_events for operational audit

## 9) Health Checks and Reconciliation

- Use a signed cron secret for all health endpoints
- Retry with backoff; alert on repeated failures
- Reconcile orphaned servers/DNS weekly

## 10) Operational Runbook

- Run `openclaw security audit --deep` after each change
- Rotate gateway tokens if suspicious activity is detected
- Keep a documented escalation path for incident response
