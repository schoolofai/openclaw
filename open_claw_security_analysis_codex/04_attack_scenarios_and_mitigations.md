# Attack Scenarios and Mitigations

This section describes **likely breach scenarios** that an ethical hacker would validate in a controlled assessment, without providing exploit steps.

## 1) Public Gateway Exposure Without Strong Auth

**Preconditions**
- Gateway bound to `0.0.0.0` or public interface
- Missing or weak `gateway.auth.*`

**Impact**
- Unauthorized access to Control UI or APIs
- Potential tool execution and data access

**Mitigations**
- Keep Gateway on loopback and access via SSH tunnel or Tailscale
- Require `gateway.auth.token` or `gateway.auth.password`
- Use `gateway.trustedProxies` when behind a reverse proxy

## 2) Open DMs + Tools Enabled

**Preconditions**
- DM policy set to `open` or broad allowlists
- Tools allowed without strict policy or sandboxing

**Impact**
- Untrusted users can trigger tool actions

**Mitigations**
- Use `pairing` or `allowlist` DM policies
- Set group policies to allowlist and restrict mention triggers
- Prefer sandboxing for non-main sessions

## 3) Prompt Injection Leading to Tool Misuse

**Preconditions**
- Tools with broad filesystem/network access
- No sandboxing or tool policy constraints

**Impact**
- Data exfiltration or unsafe commands

**Mitigations**
- Use sandboxing (`agents.defaults.sandbox.mode`)
- Tighten tool allowlists and deny elevated exec
- Restrict workspace mounts to read-only where possible

## 4) Plugin or Extension Supply-Chain Risk

**Preconditions**
- Installing unvetted plugins or dynamic skills
- Overly permissive plugin allowlists

**Impact**
- Arbitrary code execution within Gateway process

**Mitigations**
- Only install trusted, pinned versions
- Review plugin code before enabling
- Use explicit plugin allowlists

## 5) Weak Local File Permissions

**Preconditions**
- `~/.openclaw` and credentials world- or group-readable
- Host users shared or multi-tenant

**Impact**
- Token and session leakage
- Cross-user data access

**Mitigations**
- Run `openclaw security audit --fix`
- Enforce `700` on `~/.openclaw` and `600` on secrets
- Separate OS users for distinct agents

## 6) Reverse Proxy Misconfiguration

**Preconditions**
- Proxy headers accepted from untrusted sources
- Gateway trusts spoofed `X-Forwarded-For`

**Impact**
- Auth bypass or local-client trust escalation

**Mitigations**
- Configure `gateway.trustedProxies`
- Ensure proxy overwrites incoming `X-Forwarded-For`
- Keep Gateway auth enabled

## 7) Exposed Browser/Node Control

**Preconditions**
- Remote browser control exposed outside private network
- Node pairing or device auth disabled

**Impact**
- Remote control of browser/system actions

**Mitigations**
- Keep Control UI in a secure context (HTTPS/localhost)
- Do not disable device auth in production
- Restrict remote control to private network

## 8) Credential Leakage in Logs or Env

**Preconditions**
- Secrets printed to logs or stored in plaintext in build artifacts
- Shared logging or backups without redaction

**Impact**
- Token compromise and account takeover

**Mitigations**
- Use env files with tight permissions
- Enable log redaction in OpenClaw
- Store secrets in a managed vault where possible

## 9) Overly Broad Control Plane Permissions (Runclaw)

**Preconditions**
- Appwrite API key with full permissions used broadly
- Cloud provider tokens with wide scope

**Impact**
- Full infrastructure compromise if leaked

**Mitigations**
- Use least-privilege API keys and rotate regularly
- Separate roles for read vs. write actions
- Restrict tokens to specific zones/servers where supported

## 10) Insecure Instance Callback

**Preconditions**
- Callback secrets reused or too short
- Callback endpoint lacks verification

**Impact**
- Fake “ready” callbacks or status manipulation

**Mitigations**
- Use per-instance strong secrets
- Verify provisioning state before accepting callback
- Rate-limit and log callbacks

## 11) Missing OS Patching / Docker Hardening

**Preconditions**
- Unpatched OS or outdated Node runtime
- Containers run as root or with excessive capabilities

**Impact**
- Known CVE exploitation, container escape risk

**Mitigations**
- Enforce Node 22.12.0+ baseline
- Use non-root containers, `--read-only`, and `--cap-drop=ALL`
- Apply unattended security updates

## 12) Inadequate Auditability

**Preconditions**
- No centralized logs or audit trails
- Sparse or missing security event logs

**Impact**
- Breaches go undetected or uninvestigated

**Mitigations**
- Centralize logs and audit critical changes
- Keep immutable event logs in control plane (instance_events)
