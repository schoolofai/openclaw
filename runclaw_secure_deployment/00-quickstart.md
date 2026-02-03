# RunClaw.io Security Documentation Suite

**Version:** 1.0 | **Date:** 2026-02-03 | **Classification:** Internal -- Security Sensitive

---

## What is RunClaw.io?

RunClaw.io is a managed hosting platform that provisions and manages OpenClaw (open-source personal AI agent) instances on Hetzner Cloud VPS. The platform stack:

| Layer | Technology |
|-------|-----------|
| Control Plane | Next.js 14 on Vercel |
| Auth / Database | Appwrite Cloud |
| Payments | Stripe (subscriptions + webhooks) |
| VPS Provisioning | Hetzner Cloud API + cloud-init |
| DNS / WAF | Cloudflare |
| Customer VPS | Ubuntu 24.04, Docker Compose (Caddy + OpenClaw) |

Each customer gets a hardened VPS accessible at `username.runclaw.io`.

---

## Documentation Map

This suite contains six documents. Read them in order for a full security picture, or jump to the document relevant to your role.

### 1. Attack Surface Analysis

**File:** [01-attack-surface-analysis.md](./01-attack-surface-analysis.md)

Comprehensive mapping of every entry point an attacker could target. Covers 32 attack surfaces across 8 categories with CVSS severity ratings, attack vectors, impact assessments, and mitigations.

**Categories covered:**
- Control plane (Next.js API routes on Vercel)
- Authentication and session management (Appwrite)
- Payment flow (Stripe webhooks, subscription logic)
- VPS provisioning pipeline (Hetzner API, cloud-init)
- DNS and network layer (Cloudflare, subdomain routing)
- Customer VPS runtime (Docker, Caddy, OpenClaw)
- Data store security (Appwrite collections, permissions)
- Supply chain (dependencies, Docker images, CI/CD)

**Audience:** Security architects, engineering leads, threat modelers.

---

### 2. Infrastructure Security Hardening Guide

**File:** [02-infrastructure-security.md](./02-infrastructure-security.md)

Step-by-step hardening procedures for every infrastructure layer. Includes ready-to-use configuration files, commands, and verification steps.

**Sections:**
1. Hetzner Cloud security (API token management, firewalls, snapshots)
2. VPS OS hardening (kernel parameters, sysctl, automatic updates)
3. SSH hardening (key-only auth, fail2ban, jump hosts)
4. Firewall configuration (UFW rules, Docker iptables, egress filtering)
5. Docker security (userns-remap, seccomp, AppArmor, read-only containers)
6. Caddy reverse proxy hardening (TLS 1.3, security headers, rate limiting)
7. Cloudflare configuration (WAF rules, bot management, origin protection)
8. Monitoring and alerting (Falco, auditd, Prometheus, log aggregation)
9. Backup and recovery (encrypted backups, restore testing, retention)

**Audience:** DevOps engineers, system administrators, infrastructure teams.

---

### 3. Application Security

**File:** [03-application-security.md](./03-application-security.md)

Catalogs 39 application-layer vulnerabilities specific to the RunClaw.io codebase. Each entry shows the vulnerable code pattern (derived from the spec) alongside the fixed pattern.

**Vulnerability classes:**
- Authentication bypass and session management flaws
- Authorization failures (IDOR on instance endpoints)
- Injection attacks (cloud-init template injection, XSS)
- API security (rate limiting, input validation, error leakage)
- Webhook security (Stripe signature verification, replay attacks)
- Secrets management (environment variable handling, rotation)
- Client-side security (CSP, CORS, token storage)
- Race conditions (TOCTOU on subdomain uniqueness, double-spend)

**Audience:** Application developers, code reviewers, security engineers.

---

### 4. Penetration Testing Playbook

**File:** [04-penetration-testing-playbook.md](./04-penetration-testing-playbook.md)

A 10-phase penetration testing methodology tailored to RunClaw.io. Each test includes objectives, prerequisites, exact commands/payloads, expected results for both secure and vulnerable states, and evidence collection procedures.

**Phases:**
1. Reconnaissance and information gathering
2. Authentication testing
3. Authorization and IDOR testing
4. Injection testing (cloud-init, XSS, header injection)
5. Business logic testing (payment bypass, plan downgrade abuse)
6. Infrastructure testing (Hetzner API, Docker escape, network)
7. Cron job and background task testing
8. Data exfiltration testing
9. Denial of service testing
10. Reporting and remediation tracking

**Requires:** Written authorization (Rules of Engagement) before execution.

**Audience:** Penetration testers, red team operators, security auditors.

---

### 5. Secure Deployment Playbook

**File:** [05-secure-deployment-playbook.md](./05-secure-deployment-playbook.md)

Operational runbook for securely deploying and operating RunClaw.io. Copy-paste-ready commands with expected outputs and verification steps for every phase.

**Sections:**
1. Pre-deployment security checklist
2. Hardened cloud-init template
3. Vercel deployment security
4. Appwrite setup security
5. Stripe configuration security
6. Cloudflare setup security
7. Step-by-step deployment procedure
8. Post-deployment verification
9. Operational security procedures (rotation, updates, monitoring)
10. Rollback procedures (emergency shutdown, mass recovery)

**Audience:** DevOps engineers, on-call operators, deployment leads.

---

### 6. Incident Response Plan

**File:** [06-incident-response.md](./06-incident-response.md)

Complete incident response framework with severity classification, runbooks for common scenarios, communication templates, forensics procedures, and drill schedules.

**Sections:**
1. Incident classification (P0 -- P3 severity levels with response times)
2. Incident response playbooks (7 scenarios: Hetzner token compromise, VPS compromise, Stripe webhook tampering, Appwrite breach, mass failure, Cloudflare compromise, DDoS)
3. Communication templates (internal alerts, customer notifications, status page)
4. Forensics procedures (evidence preservation, memory/disk analysis, chain of custody)
5. Recovery procedures (single instance, mass recovery, DNS restoration)
6. Post-incident (review template, blameless retrospective, action tracking)
7. Regular drills (7 drill scenarios with evaluation rubric)

**Audience:** Incident responders, on-call engineers, security leads, management.

---

## Reading Guide by Role

| Role | Start With | Then Read |
|------|-----------|-----------|
| **Security Architect** | 01 Attack Surface | 03 App Security, 02 Infrastructure |
| **Developer** | 03 App Security | 01 Attack Surface, 05 Deployment |
| **DevOps / SRE** | 05 Deployment | 02 Infrastructure, 06 Incident Response |
| **Penetration Tester** | 04 Pentest Playbook | 01 Attack Surface, 03 App Security |
| **On-Call Engineer** | 06 Incident Response | 05 Deployment, 02 Infrastructure |
| **Engineering Manager** | 01 Attack Surface | 06 Incident Response, 05 Deployment |

---

## Critical Findings Summary

The attack surface analysis identified the following top-severity issues that require immediate attention:

| # | Vulnerability | CVSS | Document | Section |
|---|--------------|------|----------|---------|
| 1 | Cloud-init template injection via subdomain | 9.8 | [01](./01-attack-surface-analysis.md) | 4.1 |
| 2 | Docker image supply chain tampering | 9.5 | [01](./01-attack-surface-analysis.md) | 8.1 |
| 3 | API route authentication bypass | 9.1 | [01](./01-attack-surface-analysis.md) | 1.1 |
| 4 | Hetzner API token exposure | 9.0 | [01](./01-attack-surface-analysis.md) | 4.2 |
| 5 | IDOR on instance management endpoints | 8.8 | [01](./01-attack-surface-analysis.md) | 1.2 |
| 6 | Stripe webhook signature bypass | 8.5 | [01](./01-attack-surface-analysis.md) | 3.1 |

**Recommended remediation priority:**

1. **Immediate (before launch):** Fix cloud-init injection, enforce server-side auth on all API routes, lock Docker image digests, implement IDOR protection
2. **Short-term (first week):** Hetzner token rotation, Stripe webhook hardening, rate limiting on all endpoints
3. **Medium-term (first month):** Full infrastructure hardening per doc 02, establish monitoring/alerting, run first penetration test
4. **Long-term (ongoing):** Quarterly pen tests, regular incident drills, continuous dependency scanning

---

## Quick Commands

```bash
# Run security audit checklist
# See: 02-infrastructure-security.md, Appendix B

# Deploy a new hardened instance
# See: 05-secure-deployment-playbook.md, Section 7

# Respond to a security incident
# See: 06-incident-response.md, Section 2

# Execute penetration test
# See: 04-penetration-testing-playbook.md (requires written authorization)
```

---

## Document Maintenance

- **Review cadence:** Quarterly, or after any significant architecture change
- **Owner:** RunClaw Security Team
- **Update process:** All changes require peer review before merge
- **Version control:** Track changes in git; tag releases with date stamps

Each document is self-contained but cross-references others where relevant. Keep all six documents in sync when the platform architecture changes.
