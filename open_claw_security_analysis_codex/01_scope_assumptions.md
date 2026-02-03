# Scope and Assumptions

## Scope

- OpenClaw Gateway and runtime behavior (tools, sandboxing, auth, channel access)
- Runclaw-style control plane components (Vercel/Next.js, Appwrite, Stripe, Hetzner, Cloudflare)
- VPS deployment hardening for OpenClaw instances
- Common operational risks: secrets handling, logging, updates, and incident response

## Assumptions

- You are deploying OpenClaw instances on a VPS (Hetzner-class) with Docker and a reverse proxy (Caddy)
- The OpenClaw Gateway is **not intended for public exposure** and should be protected with auth and/or private network access
- You will use the built-in OpenClaw security audit regularly and treat findings as priority action items

## Ethical Hacker Framing

This documentation describes **likely attacker paths** without providing exploit steps. For each scenario, it focuses on:

- The **preconditions** that enable the breach
- The **impact** if the weakness is present
- The **mitigations** that prevent or contain it

If you intend to run live penetration tests, do so only with explicit authorization and a written scope.

## Not Covered

- Active exploitation instructions
- Breaking into third-party services
- Attacks that rely on credential theft outside your environment

## OpenClaw Security Policy Alignment

OpenClaw’s project security policy notes that public internet exposure and prompt injection are out of scope for disclosure. Operationally, **those risks still matter for you as an operator**, so they are included here as risk scenarios with mitigations.
