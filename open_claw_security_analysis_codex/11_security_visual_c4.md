# Security Visual (C4 Diagram)

This diagram shows the **secure target state** after applying the deployment playbook and hardening checklist. It emphasizes private-by-default access, authenticated control paths, and least-privilege boundaries.

```mermaid
C4Context
title Runclaw + OpenClaw Secure Architecture (Target State)

Person(user, "End User", "Accesses their OpenClaw instance via HTTPS")
Person(operator, "Runclaw Operator", "Manages control plane and provisioning")

Enterprise_Boundary(runclaw, "Runclaw Control Plane") {
  System(runclaw_web, "Runclaw Web App (Vercel)", "Auth, dashboard, APIs")
  System(appwrite, "Appwrite", "Auth + DB with per-user permissions")
  System(stripe, "Stripe", "Billing + webhook events")
  System_Ext(hetzner, "Hetzner Cloud", "VPS provisioning API")
  System_Ext(cloudflare, "Cloudflare", "DNS + TLS proxy")
}

Enterprise_Boundary(vps, "Customer VPS (OpenClaw Instance)") {
  System(caddy, "Caddy", "TLS termination + reverse proxy")
  System(openclaw, "OpenClaw Gateway", "Agent runtime + tools")
  SystemDb(openclaw_state, "OpenClaw State", "~/.openclaw (locked perms)")
}

Enterprise_Boundary(vps_security, "Security Controls") {
  System_Ext(ufw, "UFW", "Ingress allowlist - Only 22/80/443")
  System_Ext(fail2ban, "Fail2ban", "SSH brute-force protection")
  System_Ext(auto_updates, "Unattended Upgrades", "OS patching")
}

Rel(user, runclaw_web, "Login / manage instance", "HTTPS")
Rel(runclaw_web, appwrite, "Auth + data", "API")
Rel(runclaw_web, stripe, "Subscriptions", "API + webhook")
Rel(runclaw_web, hetzner, "Create/delete VPS", "API")
Rel(runclaw_web, cloudflare, "DNS + TLS", "API")
Rel(user, cloudflare, "Access subdomain", "HTTPS")
Rel(cloudflare, caddy, "Proxy to VPS", "TLS")
Rel(caddy, openclaw, "Reverse proxy", "Local network")
Rel(openclaw, openclaw_state, "Credentials + sessions", "Filesystem")
Rel(operator, runclaw_web, "Audits, rotation, monitoring", "Admin access")
Rel(ufw, caddy, "Enforces ingress rules")
Rel(fail2ban, caddy, "SSH rate limits")
Rel(auto_updates, openclaw, "Security patches")
```

## Key Security Properties Shown

- Gateway is **behind** a reverse proxy and **not directly exposed**
- Control plane and billing are **authenticated** and **separated**
- Instance callbacks and provisioning are **secret-bound**
- Data at rest is protected by **strict filesystem permissions**
- VPS ingress is **restricted** and **rate-limited**
