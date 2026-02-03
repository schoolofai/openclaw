# RunClaw.io Incident Response Plan

**Version:** 1.0
**Last Updated:** 2026-02-03
**Owner:** RunClaw Security Team
**Review Cadence:** Quarterly

---

## Table of Contents

1. [Incident Classification](#1-incident-classification)
2. [Incident Response Playbooks](#2-incident-response-playbooks)
3. [Communication Templates](#3-communication-templates)
4. [Forensics Procedures](#4-forensics-procedures)
5. [Recovery Procedures](#5-recovery-procedures)
6. [Post-Incident](#6-post-incident)
7. [Regular Drills](#7-regular-drills)

---

## 1. Incident Classification

### Severity Levels

| Severity | Definition | Examples | Response Time | Escalation |
|----------|-----------|----------|---------------|------------|
| **P0 - Critical** | Active exploitation, mass customer impact, or data breach affecting sensitive information | Hetzner API token compromised, mass VPS compromise, Stripe payment data breach, Appwrite database exfiltration, wildcard DNS hijack | **15 minutes** | Immediate all-hands; CEO + CTO notified |
| **P1 - High** | Single-customer compromise, authentication bypass, or integrity violation with limited blast radius | Single VPS compromised, auth bypass discovered, Stripe webhook tampering, Cloudflare API token leaked, unauthorized admin access | **1 hour** | On-call engineer + security lead |
| **P2 - Medium** | Service degradation, orphaned resources, or single-customer impact without data exposure | Health check failures on multiple instances, orphaned Hetzner servers, Appwrite rate limiting, single customer instance down, DNS propagation issues | **4 hours** | On-call engineer |
| **P3 - Low** | Non-critical information disclosure, cosmetic security issues, or policy violations without active exploitation | Non-sensitive info disclosure in error messages, missing security headers on non-critical endpoints, outdated dependency with no known exploit, cosmetic UI issues exposing internal naming | **24 hours** | Next business day triage |

### Classification Decision Tree

```
Is there active data exfiltration or mass compromise?
  YES --> P0
  NO  --> Is a single customer compromised or is there an auth bypass?
            YES --> P1
            NO  --> Is there service degradation or limited customer impact?
                      YES --> P2
                      NO  --> P3
```

### Escalation Triggers (Upgrade Severity)

- P2 upgrades to P1 if more than 3 customers are affected
- P1 upgrades to P0 if compromise spreads beyond initial scope
- Any severity upgrades to P0 if payment data or credentials are confirmed exposed
- Any severity upgrades to P0 if media/press inquiries are received about the incident

---

## 2. Incident Response Playbooks

### General Response Framework

Every incident follows these phases regardless of type:

1. **Detect** - Identify and confirm the incident
2. **Contain** - Limit the blast radius
3. **Eradicate** - Remove the threat
4. **Recover** - Restore normal operations
5. **Learn** - Post-mortem and improvements

---

### Playbook A: Hetzner API Token Compromised

**Severity:** P0
**On-Call Required:** Yes (immediate)

#### Phase 1: Immediate Containment (0-15 minutes)

1. **Rotate the token in Hetzner console immediately**
   - Log in to https://console.hetzner.cloud
   - Navigate to the project security settings
   - Revoke the compromised API token
   - Generate a new API token with the same permissions
   - Record the old token prefix for log correlation

2. **Audit existing infrastructure**
   ```bash
   # List all servers via new token
   curl -H "Authorization: Bearer $NEW_HETZNER_TOKEN" \
     https://api.hetzner.cloud/v1/servers | jq '.servers[] | {id, name, status, created}'

   # Compare against Appwrite database records
   # Query the instances collection for all active instances
   # Flag any server IDs not present in the database as unauthorized
   ```

3. **Identify unauthorized servers**
   - Cross-reference Hetzner server list with Appwrite `instances` collection
   - Check for servers created after the suspected compromise time
   - Check for servers in unexpected regions or with unexpected configurations
   - Document all unauthorized resources with timestamps

#### Phase 2: Eradication (15-60 minutes)

4. **Delete unauthorized servers**
   ```bash
   # For each unauthorized server ID
   curl -X DELETE \
     -H "Authorization: Bearer $NEW_HETZNER_TOKEN" \
     https://api.hetzner.cloud/v1/servers/$UNAUTHORIZED_SERVER_ID
   ```

5. **Check for unauthorized SSH keys**
   ```bash
   curl -H "Authorization: Bearer $NEW_HETZNER_TOKEN" \
     https://api.hetzner.cloud/v1/ssh_keys | jq '.ssh_keys[] | {id, name, fingerprint, created}'
   ```
   - Remove any SSH keys not recognized by the team

6. **Check for unauthorized firewalls, networks, or volumes**
   ```bash
   # List firewalls
   curl -H "Authorization: Bearer $NEW_HETZNER_TOKEN" \
     https://api.hetzner.cloud/v1/firewalls | jq '.firewalls[] | {id, name, created}'

   # List volumes
   curl -H "Authorization: Bearer $NEW_HETZNER_TOKEN" \
     https://api.hetzner.cloud/v1/volumes | jq '.volumes[] | {id, name, server, created}'
   ```

#### Phase 3: Recovery (1-4 hours)

7. **Deploy the new token to Vercel environment variables**
   ```bash
   # Update via Vercel CLI
   vercel env rm HETZNER_API_TOKEN production
   vercel env add HETZNER_API_TOKEN production
   # Paste the new token when prompted

   # Trigger a redeployment
   vercel --prod
   ```

8. **Verify all provisioning operations work with the new token**
   - Test instance creation (use a test account)
   - Test instance deletion
   - Test health check endpoint
   - Confirm the cron-based health checks resume

#### Phase 4: Investigation

9. **Determine how the token was exposed**
   - Check Vercel deployment logs for accidental token logging
   - Review recent code changes for hardcoded credentials
   - Check Vercel environment variable access logs
   - Review Git history for accidental commits containing the token
   - Check if any third-party integrations had access
   ```bash
   # Search git history for potential token exposure
   git log --all -p -S "HETZNER" --since="30 days ago"
   ```

10. **Audit Hetzner API call logs**
    - Review Hetzner project activity log in the console
    - Identify any API calls made from unexpected IP addresses
    - Document the full timeline of unauthorized access

#### Phase 5: Notification

11. **Notify affected customers if their instances were accessed**
    - Use the Customer Notification (Instance Compromise) template from Section 3
    - Include: what happened, what data may have been exposed, steps taken, steps customer should take

12. **Conduct post-mortem** (see Section 6)

---

### Playbook B: Customer VPS Compromised

**Severity:** P1
**On-Call Required:** Yes (within 1 hour)

#### Phase 1: Immediate Isolation (0-30 minutes)

1. **Isolate the compromised VPS via Hetzner firewall**
   ```bash
   # Create an isolation firewall rule (block all inbound/outbound except SSH from admin IP)
   curl -X POST \
     -H "Authorization: Bearer $HETZNER_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "incident-isolate-'$SERVER_ID'",
       "rules": [
         {
           "direction": "in",
           "protocol": "tcp",
           "port": "22",
           "source_ips": ["ADMIN_IP/32"],
           "description": "SSH from admin only"
         }
       ]
     }' \
     https://api.hetzner.cloud/v1/firewalls

   # Apply firewall to the server
   curl -X POST \
     -H "Authorization: Bearer $HETZNER_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "actions": [{"type": "apply_to_server", "server": '$SERVER_ID'}]
     }' \
     https://api.hetzner.cloud/v1/firewalls/$FIREWALL_ID/actions
   ```

2. **Record the current state before any changes**
   - Note the server status, IP, region, and creation date
   - Record the customer ID and subscription details from Appwrite

#### Phase 2: Evidence Preservation (30-60 minutes)

3. **Create a server snapshot for forensic analysis**
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $HETZNER_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"description": "forensic-snapshot-incident-'$INCIDENT_ID'"}' \
     https://api.hetzner.cloud/v1/servers/$SERVER_ID/actions/create_image
   ```

4. **Collect volatile evidence before shutdown** (if server is still running)
   ```bash
   ssh root@$SERVER_IP << 'EVIDENCE'
   # Capture running processes
   ps auxww > /tmp/forensics_ps.txt
   # Capture network connections
   ss -tulnp > /tmp/forensics_netstat.txt
   # Capture Docker containers
   docker ps -a > /tmp/forensics_docker.txt
   # Capture Docker logs
   docker logs openclaw-instance > /tmp/forensics_docker_logs.txt 2>&1
   # Capture login history
   last -a > /tmp/forensics_last.txt
   # Capture auth logs
   cp /var/log/auth.log /tmp/forensics_auth.log
   # Capture cron
   crontab -l > /tmp/forensics_cron.txt 2>&1
   # Package evidence
   tar czf /tmp/forensics_bundle.tar.gz /tmp/forensics_*.txt /tmp/forensics_*.log
   EVIDENCE

   # Download the evidence bundle
   scp root@$SERVER_IP:/tmp/forensics_bundle.tar.gz ./incident-$INCIDENT_ID/
   ```

#### Phase 3: Assessment (1-2 hours)

5. **Determine if compromise spread to other instances**
   - Check if the compromised instance had any credentials for other systems
   - Review if the Docker container had access to shared resources
   - Check if the attacker established lateral movement paths
   - Query the health check results for anomalies in other instances

6. **Determine the attack vector**
   - Check for known vulnerabilities in the OpenClaw version deployed
   - Review SSH access logs for brute force or unauthorized key usage
   - Check Docker container escape indicators
   - Review application-level logs for injection or exploitation

#### Phase 4: Containment and Rebuild (2-4 hours)

7. **Rebuild the instance from a clean image**
   ```bash
   # Delete the compromised server
   curl -X DELETE \
     -H "Authorization: Bearer $HETZNER_API_TOKEN" \
     https://api.hetzner.cloud/v1/servers/$SERVER_ID

   # Provision a new clean instance using the standard provisioning flow
   # This triggers the normal instance creation with fresh Docker setup
   ```

8. **Restore customer configuration**
   - Pull customer configuration from Appwrite
   - Deploy to the new instance
   - Verify the OpenClaw instance is functional
   - Update the instance record in Appwrite with the new server ID and IP

9. **If the vulnerability is systemic, patch all instances**
   ```bash
   # For each active instance, apply the security patch
   # Use the mass update procedure from Recovery Section 5
   ```

#### Phase 5: Customer Notification

10. **Notify the affected customer**
    - Use the Customer Notification (Instance Compromise) template
    - Advise the customer to rotate any credentials stored in their OpenClaw configuration
    - Provide a timeline of the incident and actions taken

11. **Conduct post-mortem** (see Section 6)

---

### Playbook C: Stripe Webhook Tampering

**Severity:** P1
**On-Call Required:** Yes (within 1 hour)

#### Phase 1: Detection and Confirmation (0-30 minutes)

1. **Identify webhook signature verification failures**
   - Check Vercel function logs for `stripe.webhooks.constructEvent` failures
   - Check Stripe dashboard webhook logs for delivery failures
   ```bash
   # Query Vercel logs for webhook failures
   vercel logs --since 24h | grep -i "webhook.*signature\|stripe.*verification"
   ```

2. **Determine if this is an attack vs. configuration issue**
   - Legitimate Stripe webhooks will have valid signatures
   - Multiple failures from non-Stripe IPs indicate tampering
   - Check source IPs against Stripe's published webhook IP ranges

#### Phase 2: Immediate Containment (30-60 minutes)

3. **Rotate the webhook signing secret in Stripe dashboard**
   - Navigate to Stripe Dashboard > Developers > Webhooks
   - Select the RunClaw webhook endpoint
   - Roll the signing secret (Stripe provides a grace period with both old and new secrets)
   - Record the new signing secret

4. **Deploy the new webhook secret to Vercel**
   ```bash
   vercel env rm STRIPE_WEBHOOK_SECRET production
   vercel env add STRIPE_WEBHOOK_SECRET production
   # Paste the new secret
   vercel --prod
   ```

5. **Verify webhook processing resumes with the new secret**
   - Trigger a test event from Stripe dashboard
   - Confirm the webhook endpoint returns 200

#### Phase 3: Audit (1-4 hours)

6. **Audit the webhook_events collection in Appwrite**
   - Query for events processed during the suspected tampering window
   - Look for unusual patterns:
     - Subscription activations without corresponding Stripe charges
     - Instance provisioning without valid payment
     - Duplicate event IDs
     - Events with unexpected metadata

7. **Verify no unauthorized instance provisioning occurred**
   - Cross-reference recently provisioned instances with legitimate Stripe payments
   - Check for instances created without corresponding `checkout.session.completed` events
   - Verify all active subscriptions have matching Stripe subscription records
   ```bash
   # List recent Stripe subscriptions via API
   curl https://api.stripe.com/v1/subscriptions?limit=100 \
     -u "$STRIPE_SECRET_KEY:" | jq '.data[] | {id, status, created}'
   ```

#### Phase 4: Investigation

8. **Analyze the attack pattern**
   - Were the forged webhooks attempting to provision free instances?
   - Were they attempting to modify existing subscriptions?
   - Were they probing for information disclosure?

9. **Check for payment anomalies**
   - Review Stripe for disputed charges, unusual refunds, or modified subscriptions
   - Verify no customer payment methods were exposed

10. **Conduct post-mortem** (see Section 6)

---

### Playbook D: Appwrite Data Breach

**Severity:** P0
**On-Call Required:** Yes (immediate)

#### Phase 1: Immediate Containment (0-15 minutes)

1. **Rotate the Appwrite API key**
   - Log in to Appwrite Cloud console
   - Navigate to project settings > API Keys
   - Delete the compromised key
   - Generate a new API key with the same scopes
   - Record the old key prefix for log correlation

2. **Deploy the new API key to Vercel immediately**
   ```bash
   vercel env rm APPWRITE_API_KEY production
   vercel env add APPWRITE_API_KEY production
   vercel --prod
   ```

#### Phase 2: Session Revocation (15-30 minutes)

3. **If authentication was compromised, revoke all user sessions**
   - Use the Appwrite Server SDK to delete all sessions
   - This forces all users to re-authenticate
   ```typescript
   // Emergency session revocation
   import { Client, Users } from 'node-appwrite';

   const client = new Client()
     .setEndpoint(process.env.APPWRITE_ENDPOINT)
     .setProject(process.env.APPWRITE_PROJECT_ID)
     .setKey(process.env.NEW_APPWRITE_API_KEY);

   const users = new Users(client);
   const userList = await users.list();
   for (const user of userList.users) {
     await users.deleteSessions(user.$id);
   }
   ```

4. **Reset any compromised user passwords**
   - If specific accounts were targeted, force password resets
   - Notify those users directly via email

#### Phase 3: Audit and Assessment (30 minutes - 4 hours)

5. **Review Appwrite audit logs**
   - Check for unauthorized document reads, writes, or deletions
   - Identify which collections were accessed
   - Determine the time window of unauthorized access
   - Focus on sensitive collections: `users`, `instances`, `subscriptions`

6. **Determine what data was accessed**
   - Customer email addresses and profiles
   - Instance configuration data (server IPs, regions)
   - Subscription and payment references (note: full payment details are in Stripe, not Appwrite)
   - Any API keys or tokens stored in instance documents

7. **Assess the blast radius**
   - How many customer records were accessed?
   - Was any data modified or deleted?
   - Were any instance configurations tampered with?

#### Phase 4: Investigation

8. **Determine how the API key was exposed**
   - Review Vercel deployment logs
   - Check Git history for accidental commits
   - Review access logs for the Appwrite project
   - Check if any third-party service had the key
   - Review server-side code for accidental key exposure in responses

9. **Check for data exfiltration indicators**
   - Unusual API call volume in Appwrite logs
   - Bulk read operations on customer collections
   - Data access patterns inconsistent with normal application behavior

#### Phase 5: Customer Notification

10. **Notify affected customers per breach notification requirements**
    - Use the Customer Notification (Data Breach) template from Section 3
    - Comply with applicable data protection regulations (GDPR 72-hour window)
    - Include: what data was exposed, timeline, actions taken, recommended customer actions
    - Report to relevant data protection authorities if required

11. **Conduct post-mortem** (see Section 6)

---

### Playbook E: Mass Instance Failure

**Severity:** P1 (upgrades to P0 if >50% of instances affected)
**On-Call Required:** Yes (within 1 hour)

#### Phase 1: Detection and Triage (0-30 minutes)

1. **Confirm the health check cron findings**
   ```bash
   # Check recent health check results in Appwrite
   # Query the instances collection for status != 'healthy'
   # Determine the percentage of affected instances
   ```

2. **Determine root cause category**
   - **Hetzner infrastructure outage**: Check https://status.hetzner.com
   - **Network issue**: Check if instances are reachable but Docker is down
   - **Configuration drift**: Check if a recent deployment introduced a bug
   - **Resource exhaustion**: Check if instances are running out of disk/memory
   - **DNS issue**: Check if Cloudflare is routing correctly

3. **Check Hetzner status and regional impact**
   ```bash
   # Test connectivity to sample instances in each region
   for ip in $SAMPLE_IPS; do
     echo "Testing $ip..."
     timeout 5 ssh -o ConnectTimeout=3 root@$ip "docker ps" 2>&1 || echo "UNREACHABLE: $ip"
   done
   ```

#### Phase 2: Communication (30-60 minutes)

4. **Update the status page**
   - Use the Status Page Update template from Section 3
   - Acknowledge the issue and provide initial scope
   - Set expected update interval (every 30 minutes for P0/P1)

5. **Notify affected customers proactively**
   - Bulk notification via email
   - Include: acknowledged issue, current scope, expected resolution timeline

#### Phase 3: Investigation (1-2 hours)

6. **SSH into sample affected instances for diagnostics**
   ```bash
   ssh root@$AFFECTED_IP << 'DIAG'
   echo "=== System Resources ==="
   df -h
   free -m
   uptime

   echo "=== Docker Status ==="
   systemctl status docker
   docker ps -a
   docker logs openclaw-instance --tail 100

   echo "=== Network ==="
   ping -c 3 8.8.8.8
   curl -s -o /dev/null -w "%{http_code}" https://cloud.appwrite.io

   echo "=== System Logs ==="
   journalctl -u docker --since "1 hour ago" --no-pager | tail -50
   DIAG
   ```

7. **Identify the common failure pattern**
   - Is Docker crashing? Check for OOM kills
   - Is the OpenClaw container failing to start? Check image availability
   - Is there a network partition? Check DNS resolution and outbound connectivity

#### Phase 4: Remediation

8. **Apply the fix based on root cause**

   **If Docker crash / OOM:**
   ```bash
   # Restart Docker and the container
   ssh root@$AFFECTED_IP "systemctl restart docker && docker start openclaw-instance"
   ```

   **If configuration issue (rolling fix):**
   ```bash
   # Apply fix to each instance sequentially
   for instance in $AFFECTED_INSTANCES; do
     ssh root@${instance.ip} "docker pull openclaw/openclaw:latest && docker restart openclaw-instance"
     sleep 5  # Stagger restarts
   done
   ```

   **If mass redeployment needed:**
   - Use the Mass Instance Recovery procedure from Section 5
   - Deploy in batches of 10 to avoid overwhelming Hetzner API limits

#### Phase 5: Verification

9. **Confirm all instances are healthy**
   ```bash
   # Trigger an immediate health check cycle
   # Verify all instances report healthy status
   # Monitor for 1 hour to confirm stability
   ```

10. **Update status page with resolution**
11. **Conduct post-mortem** (see Section 6)

---

### Playbook F: Cloudflare Configuration Compromise

**Severity:** P1
**On-Call Required:** Yes (within 1 hour)

#### Phase 1: Detection and Assessment (0-30 minutes)

1. **Check DNS records for unauthorized changes**
   ```bash
   # List all DNS records for the zone
   curl -X GET \
     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     -H "Content-Type: application/json" \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
     | jq '.result[] | {id, name, type, content, modified_on}'
   ```

2. **Compare current records against the expected baseline**
   - Check for added records (potential phishing subdomains)
   - Check for modified A/CNAME records (potential traffic redirection)
   - Check for removed records (potential denial of service)
   - Check for modified MX records (potential email interception)

3. **Review Cloudflare audit logs**
   - Navigate to Cloudflare Dashboard > Audit Log
   - Filter for DNS, SSL, and Firewall changes
   - Identify unauthorized actors and their IP addresses

#### Phase 2: Containment (30-60 minutes)

4. **Revert unauthorized DNS changes**
   ```bash
   # Delete unauthorized records
   curl -X DELETE \
     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$UNAUTHORIZED_RECORD_ID"

   # Restore modified records to correct values
   curl -X PUT \
     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"type": "A", "name": "runclaw.io", "content": "CORRECT_IP", "proxied": true}' \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID"
   ```

5. **Rotate the Cloudflare API token**
   - Revoke the compromised token in Cloudflare Dashboard > My Profile > API Tokens
   - Create a new token with the same permissions
   - Update the token in Vercel environment variables

6. **Enable additional Cloudflare security measures**
   - Enable two-factor authentication if not already active
   - Review and restrict API token permissions to minimum required
   - Enable Cloudflare notifications for all zone changes

#### Phase 3: Verification

7. **Verify all DNS records match expected state**
   ```bash
   # External verification using dig
   dig runclaw.io A +short
   dig www.runclaw.io CNAME +short
   dig _acme-challenge.runclaw.io TXT +short

   # Verify customer instance DNS records
   for subdomain in $CUSTOMER_SUBDOMAINS; do
     dig $subdomain.runclaw.io A +short
   done
   ```

8. **Monitor for recurrence**
   - Set up Cloudflare email alerts for all DNS modifications
   - Monitor for 48 hours post-incident

9. **Conduct post-mortem** (see Section 6)

---

### Playbook G: Denial of Service Attack

**Severity:** P1 (upgrades to P0 if platform is unreachable)
**On-Call Required:** Yes (within 1 hour)

#### Phase 1: Detection (0-15 minutes)

1. **Confirm the attack**
   - Check Cloudflare Analytics for traffic spike
   - Check Vercel function invocation metrics for unusual patterns
   - Verify customer reports align with monitoring data

2. **Classify the attack type**
   - **Volumetric**: High bandwidth consumption (L3/L4)
   - **Application-layer**: HTTP flood targeting API endpoints (L7)
   - **API abuse**: Targeting provisioning endpoints to exhaust Hetzner resources

#### Phase 2: Immediate Mitigation (15-30 minutes)

3. **Enable Cloudflare "Under Attack" mode**
   ```bash
   curl -X PATCH \
     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"value": "under_attack"}' \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/security_level"
   ```

4. **Deploy targeted WAF rules**
   ```bash
   # Block specific attack pattern (example: blocking a User-Agent)
   curl -X POST \
     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "filter": {"expression": "http.user_agent contains \"attack-pattern\""},
       "action": "block",
       "description": "Incident response - DDoS mitigation"
     }' \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/firewall/rules"
   ```

5. **Enable Cloudflare rate limiting on critical endpoints**
   - `/api/webhooks/stripe` - Limit to expected webhook volume
   - `/api/instances/*` - Limit provisioning requests
   - `/api/auth/*` - Limit authentication attempts

#### Phase 3: Analysis (30 minutes - 2 hours)

6. **Identify attack source and pattern**
   - Review Cloudflare Firewall Events
   - Identify top attacking IPs, ASNs, and countries
   - Determine targeted endpoints
   - Check if the attack correlates with any external events

7. **Monitor attack progression**
   - Track requests per second on Cloudflare dashboard
   - Monitor Vercel function health
   - Check if customer instances are affected

#### Phase 4: Sustained Mitigation

8. **Implement geo-blocking if appropriate**
   - Block countries not in the customer base (if attack is geo-concentrated)

9. **Coordinate with Cloudflare support for large attacks**
   - Open a Cloudflare support ticket for attacks exceeding normal mitigation capacity

10. **Disable "Under Attack" mode once attack subsides**
    ```bash
    curl -X PATCH \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"value": "medium"}' \
      "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/security_level"
    ```

#### Phase 5: Prevention

11. **Update permanent WAF rules based on attack patterns**
12. **Review and update rate limiting thresholds**
13. **Conduct post-mortem** (see Section 6)

---

## 3. Communication Templates

### Template A: Customer Notification - Instance Compromise

```
Subject: Security Incident Affecting Your RunClaw Instance

Dear [Customer Name],

We are writing to inform you of a security incident that affected your
RunClaw instance ([instance-id]).

WHAT HAPPENED
On [date] at approximately [time UTC], we detected [brief description of
the compromise]. Our security team immediately began incident response
procedures.

WHAT WE DID
- Isolated the affected instance at [time UTC]
- Preserved evidence for forensic analysis
- Rebuilt your instance from a clean image at [time UTC]
- Patched the vulnerability that enabled the compromise

WHAT DATA MAY HAVE BEEN AFFECTED
- [List specific data types, e.g., "messages processed by your OpenClaw
  instance during the affected time window"]
- [Be specific and honest about what was and was not exposed]

WHAT WE RECOMMEND YOU DO
1. Rotate any API keys or credentials stored in your OpenClaw configuration
2. Review your OpenClaw activity logs for any unusual behavior
3. [Any additional customer-specific recommendations]

Your instance has been fully restored and is operational. We have
implemented additional security measures to prevent similar incidents.

If you have questions or concerns, please contact our security team at
security@runclaw.io.

Sincerely,
RunClaw Security Team
```

### Template B: Customer Notification - Data Breach

```
Subject: Important Security Notice - Data Breach Notification

Dear [Customer Name],

We are writing to notify you of a data breach that may have affected your
personal information stored with RunClaw.

WHAT HAPPENED
On [date], we discovered that [brief factual description]. The breach
occurred between [start date] and [end date].

WHAT INFORMATION WAS INVOLVED
The following types of information may have been accessed:
- [Email address]
- [Account profile information]
- [Instance configuration data]
- [Other specific data types]

The following information was NOT affected:
- Payment card details (stored exclusively by Stripe, our payment processor)
- [Other data confirmed not exposed]

WHAT WE ARE DOING
- [Specific remediation steps taken]
- [Security improvements implemented]
- We have reported this incident to [relevant data protection authority]

WHAT YOU CAN DO
1. Change your RunClaw account password immediately
2. Enable two-factor authentication if not already active
3. Monitor your accounts for unusual activity
4. [Additional recommendations]

CONTACT INFORMATION
For questions about this incident:
- Email: security@runclaw.io
- Response time: within 24 hours

We sincerely apologize for this incident and are committed to protecting
your information.

Sincerely,
[Name], [Title]
RunClaw Security Team
```

### Template C: Internal Escalation

```
Subject: [P0/P1/P2/P3] Security Incident - [Brief Title]

INCIDENT ID: INC-[YYYY-MM-DD]-[sequential number]
SEVERITY: [P0/P1/P2/P3]
DETECTED: [timestamp UTC]
REPORTED BY: [name]
CURRENT STATUS: [Detected | Contained | Investigating | Resolved]

SUMMARY
[2-3 sentence description of the incident]

AFFECTED SYSTEMS
- [ ] Vercel (Next.js application)
- [ ] Appwrite Cloud (database/auth)
- [ ] Hetzner (customer VPS instances)
- [ ] Stripe (payments/billing)
- [ ] Cloudflare (DNS/CDN)
- [ ] Customer instances (count: [N])

IMMEDIATE ACTIONS TAKEN
1. [Action with timestamp]
2. [Action with timestamp]

CURRENT ASSESSMENT
- Blast radius: [description]
- Data exposure: [confirmed/suspected/none]
- Customer impact: [description]

NEXT STEPS
1. [Planned action]
2. [Planned action]

ASSIGNED TO: [name(s)]
NEXT UPDATE: [time UTC]
```

### Template D: Status Page Update

**Investigating:**
```
[Title]: Investigating [component] Issues

We are currently investigating reports of [brief description]. Our
engineering team has been engaged and is actively working to identify the
root cause.

Affected services: [list]
Impact: [description]

Next update in [30 minutes / 1 hour].

Posted: [timestamp UTC]
```

**Identified:**
```
[Title]: [Component] Issue Identified

We have identified the cause of the [component] issues. [Brief
explanation without revealing sensitive security details].

We are implementing a fix and expect resolution by [estimated time UTC].

Affected services: [list]
Impact: [description]

Next update in [30 minutes / 1 hour].

Updated: [timestamp UTC]
```

**Resolved:**
```
[Title]: [Component] Issue Resolved

The [component] issue has been resolved. [Brief explanation of what
happened and what was done].

All services are operating normally. We will publish a full incident
report within [48 hours / 5 business days].

Duration: [start time] to [end time] ([total duration])

Updated: [timestamp UTC]
```

### Template E: Blameless Post-Mortem (see Section 6 for full template)

---

## 4. Forensics Procedures

### 4.1 VPS Forensics

#### Step 1: Preserve the Evidence

```bash
# Create a snapshot BEFORE any investigation changes
curl -X POST \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description": "forensic-snapshot-INC-'$INCIDENT_ID'-'$(date +%Y%m%d%H%M%S)'"}' \
  https://api.hetzner.cloud/v1/servers/$SERVER_ID/actions/create_image

# Record the snapshot ID for chain of custody
echo "Snapshot ID: $SNAPSHOT_ID created at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> chain_of_custody.log
```

#### Step 2: Collect Volatile Data (if server is running)

```bash
ssh root@$SERVER_IP << 'VOLATILE'
mkdir -p /tmp/forensics

# Process information
ps auxww > /tmp/forensics/processes.txt
ls -la /proc/*/exe 2>/dev/null > /tmp/forensics/proc_exe.txt

# Network state
ss -tulnp > /tmp/forensics/network_connections.txt
ip addr > /tmp/forensics/ip_addresses.txt
ip route > /tmp/forensics/routes.txt
iptables -L -n -v > /tmp/forensics/iptables.txt

# User and authentication
last -a > /tmp/forensics/login_history.txt
lastb -a > /tmp/forensics/failed_logins.txt 2>/dev/null
who > /tmp/forensics/current_users.txt
cat /etc/passwd > /tmp/forensics/passwd.txt
cat /etc/shadow > /tmp/forensics/shadow.txt

# File system state
find / -mtime -1 -type f 2>/dev/null > /tmp/forensics/recently_modified.txt
find / -ctime -1 -type f 2>/dev/null > /tmp/forensics/recently_changed.txt
find /tmp -type f -ls > /tmp/forensics/tmp_contents.txt

# Docker state
docker ps -a > /tmp/forensics/docker_containers.txt
docker images > /tmp/forensics/docker_images.txt
docker logs openclaw-instance > /tmp/forensics/docker_app_logs.txt 2>&1
docker inspect openclaw-instance > /tmp/forensics/docker_inspect.json

# System logs
journalctl --since "24 hours ago" --no-pager > /tmp/forensics/journald.txt
cp /var/log/auth.log /tmp/forensics/
cp /var/log/syslog /tmp/forensics/

# Cron and scheduled tasks
crontab -l > /tmp/forensics/root_cron.txt 2>&1
ls -la /etc/cron.d/ > /tmp/forensics/cron_d.txt
cat /etc/crontab > /tmp/forensics/system_cron.txt

# SSH artifacts
ls -la /root/.ssh/ > /tmp/forensics/ssh_dir.txt
cat /root/.ssh/authorized_keys > /tmp/forensics/authorized_keys.txt

# Package and bundle
tar czf /tmp/forensics_bundle.tar.gz -C /tmp forensics/
sha256sum /tmp/forensics_bundle.tar.gz > /tmp/forensics_bundle.sha256
VOLATILE

# Download evidence
scp root@$SERVER_IP:/tmp/forensics_bundle.tar.gz ./incident-$INCIDENT_ID/
scp root@$SERVER_IP:/tmp/forensics_bundle.sha256 ./incident-$INCIDENT_ID/

# Verify integrity
cd ./incident-$INCIDENT_ID/
sha256sum -c forensics_bundle.sha256
```

#### Step 3: Analyze the Snapshot

```bash
# Create a new isolated server from the snapshot for analysis
# This avoids modifying the original evidence
curl -X POST \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "forensics-analysis-'$INCIDENT_ID'",
    "server_type": "cx22",
    "image": '$FORENSIC_SNAPSHOT_ID',
    "location": "nbg1",
    "firewalls": [{"firewall": '$ISOLATION_FIREWALL_ID'}]
  }' \
  https://api.hetzner.cloud/v1/servers
```

### 4.2 Log Collection Matrix

| Source | Log Location | Retention | Collection Method |
|--------|-------------|-----------|-------------------|
| **Vercel** | Vercel Dashboard > Logs | 7 days (free) / 30 days (Pro) | `vercel logs --since 7d > vercel_logs.txt` |
| **Appwrite** | Appwrite Console > Audit | 30 days | Appwrite Console export or API query |
| **Cloudflare** | CF Dashboard > Audit Log | 18 months (Enterprise) | `cf api /audit_logs` or Dashboard CSV export |
| **Hetzner** | Hetzner Console > Activity | 90 days | Hetzner Console manual review |
| **VPS System** | `/var/log/` on each instance | Varies (logrotate) | SSH + `tar` collection |
| **Docker** | `docker logs` on each instance | Container lifetime | SSH + `docker logs` redirect |
| **Stripe** | Stripe Dashboard > Events | 30 days | Stripe Dashboard or API |

### 4.3 Timeline Reconstruction

1. **Establish the earliest known indicator of compromise (IOC)**
   - Correlate timestamps across all log sources (normalize to UTC)
   - Work backwards from the detection point

2. **Build the timeline document**
   ```
   INCIDENT TIMELINE: INC-[ID]
   All times UTC

   [YYYY-MM-DD HH:MM:SS] [Source] [Event Description]
   [YYYY-MM-DD HH:MM:SS] [Source] [Event Description]
   ...

   KEY:
   [!] Malicious activity confirmed
   [?] Suspicious activity under investigation
   [R] Response action taken
   ```

3. **Cross-reference across sources**
   - Match Cloudflare request logs with Vercel function logs
   - Match Hetzner API calls with Appwrite instance records
   - Match Stripe events with provisioning actions
   - Identify gaps in logging coverage

### 4.4 Evidence Preservation - Chain of Custody

Every piece of evidence must be documented:

```
CHAIN OF CUSTODY LOG
Incident: INC-[ID]

| # | Evidence Item | Hash (SHA-256) | Collected By | Date/Time (UTC) | Storage Location | Notes |
|---|--------------|----------------|-------------|-----------------|-----------------|-------|
| 1 | forensics_bundle.tar.gz | [sha256] | [name] | [timestamp] | [path/bucket] | VPS volatile data |
| 2 | Snapshot ID: [id] | N/A (Hetzner) | [name] | [timestamp] | Hetzner Cloud | Server disk snapshot |
| 3 | vercel_logs_export.txt | [sha256] | [name] | [timestamp] | [path/bucket] | Vercel function logs |
| 4 | appwrite_audit_export.json | [sha256] | [name] | [timestamp] | [path/bucket] | Appwrite audit trail |
```

**Rules:**
- Never modify original evidence; work on copies
- Hash all evidence files immediately upon collection
- Record every access to evidence with name and timestamp
- Store evidence in a dedicated, access-controlled location
- Retain evidence for a minimum of 12 months after incident closure

---

## 5. Recovery Procedures

### 5.1 Single Instance Recovery

**When to use:** One customer instance is down or compromised.

1. **Assess current state**
   ```bash
   # Check server status via Hetzner API
   curl -H "Authorization: Bearer $HETZNER_API_TOKEN" \
     https://api.hetzner.cloud/v1/servers/$SERVER_ID | jq '.server | {status, public_net}'
   ```

2. **Attempt restart (if server is reachable)**
   ```bash
   ssh root@$SERVER_IP << 'RESTART'
   docker restart openclaw-instance
   sleep 10
   docker ps | grep openclaw-instance
   docker logs openclaw-instance --tail 20
   RESTART
   ```

3. **If restart fails, rebuild the instance**
   ```bash
   # Delete the old server
   curl -X DELETE \
     -H "Authorization: Bearer $HETZNER_API_TOKEN" \
     https://api.hetzner.cloud/v1/servers/$SERVER_ID

   # Trigger re-provisioning through the application
   # Update the instance record in Appwrite to 'provisioning' status
   # The provisioning system will create a new server with the customer's configuration
   ```

4. **Verify recovery**
   - Confirm Docker container is running
   - Confirm OpenClaw health endpoint responds
   - Update instance record in Appwrite with new server details
   - Notify the customer that their instance is restored

### 5.2 Mass Instance Recovery

**When to use:** Multiple instances need rebuilding (post-compromise, failed update, infrastructure issue).

1. **Prepare the recovery plan**
   - Query Appwrite for all affected instances
   - Categorize by region and severity
   - Determine batch size (recommended: 10 instances per batch to respect Hetzner API limits)

2. **Execute rolling recovery**
   ```bash
   #!/bin/bash
   # mass_recovery.sh
   # Usage: ./mass_recovery.sh affected_instances.json

   BATCH_SIZE=10
   DELAY_BETWEEN_BATCHES=60  # seconds

   instances=$(cat "$1" | jq -r '.[] | @base64')
   batch_count=0

   for instance in $instances; do
     decoded=$(echo "$instance" | base64 -d)
     server_id=$(echo "$decoded" | jq -r '.serverId')
     customer_id=$(echo "$decoded" | jq -r '.customerId')
     config=$(echo "$decoded" | jq -r '.config')

     echo "[$(date -u)] Recovering instance for customer $customer_id (server: $server_id)"

     # Delete old server
     curl -s -X DELETE \
       -H "Authorization: Bearer $HETZNER_API_TOKEN" \
       "https://api.hetzner.cloud/v1/servers/$server_id"

     # Trigger re-provisioning (application-specific)
     # ... provisioning logic ...

     batch_count=$((batch_count + 1))
     if [ $((batch_count % BATCH_SIZE)) -eq 0 ]; then
       echo "[$(date -u)] Batch complete. Waiting ${DELAY_BETWEEN_BATCHES}s..."
       sleep $DELAY_BETWEEN_BATCHES
     fi
   done

   echo "[$(date -u)] Mass recovery complete. Processed $batch_count instances."
   ```

3. **Verify recovery**
   - Run health checks against all recovered instances
   - Compare instance count with Appwrite records
   - Send bulk customer notification about restoration

### 5.3 Database Recovery (Appwrite Backup Restore)

**When to use:** Appwrite data corruption, accidental deletion, or post-breach data integrity issues.

1. **Assess the damage**
   - Determine which collections are affected
   - Determine the last known good state timestamp

2. **Restore from Appwrite Cloud backup**
   - Appwrite Cloud maintains automated backups
   - Contact Appwrite support for point-in-time recovery if needed
   - For self-managed backups, restore from the latest verified backup

3. **Verify data integrity post-restore**
   - Compare instance records with actual Hetzner servers
   - Verify user accounts can authenticate
   - Verify subscription records match Stripe

4. **Reconcile any drift**
   - Instances provisioned between backup and restore need manual reconciliation
   - Cross-reference Stripe payment events to identify missed transactions
   - Manually create records for any legitimate activity during the gap

### 5.4 DNS Recovery

**When to use:** Cloudflare DNS records are corrupted, deleted, or hijacked.

1. **Restore DNS records from documented baseline**
   ```bash
   # Maintain a DNS baseline file: dns_baseline.json
   # This should be updated whenever intentional DNS changes are made

   # Restore from baseline
   for record in $(cat dns_baseline.json | jq -c '.[]'); do
     type=$(echo $record | jq -r '.type')
     name=$(echo $record | jq -r '.name')
     content=$(echo $record | jq -r '.content')
     proxied=$(echo $record | jq -r '.proxied')

     curl -X POST \
       -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
       -H "Content-Type: application/json" \
       -d "{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\",\"proxied\":$proxied}" \
       "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records"
   done
   ```

2. **Verify propagation**
   ```bash
   # Check DNS propagation from multiple resolvers
   for resolver in 1.1.1.1 8.8.8.8 9.9.9.9; do
     echo "Resolver: $resolver"
     dig @$resolver runclaw.io A +short
     dig @$resolver runclaw.io MX +short
   done
   ```

3. **Monitor for 24-48 hours for full global propagation**

### 5.5 Payment System Recovery

**When to use:** Stripe integration issues, webhook failures, or subscription drift.

1. **Verify Stripe webhook is operational**
   - Check Stripe Dashboard > Webhooks for delivery status
   - Send a test webhook event

2. **Reconcile subscriptions**
   ```bash
   # List all active Stripe subscriptions
   curl https://api.stripe.com/v1/subscriptions?status=active&limit=100 \
     -u "$STRIPE_SECRET_KEY:" | jq '.data[] | {id, customer, status}'

   # Compare with Appwrite subscription records
   # Identify mismatches: active in Stripe but not in Appwrite, or vice versa
   ```

3. **Replay missed webhook events**
   - Use Stripe Dashboard to resend failed webhook deliveries
   - Process events in chronological order
   - Verify each event is handled idempotently

4. **Verify provisioning consistency**
   - Every active subscription should have a corresponding healthy instance
   - Every instance should have a corresponding active subscription
   - Cancel/deprovision any orphaned resources

### 5.6 Full Platform Recovery (Nuclear Option)

**When to use:** Catastrophic failure requiring complete platform rebuild. Use only as a last resort.

**Prerequisites:**
- Access to Hetzner console
- Access to Cloudflare console
- Access to Stripe dashboard
- Access to Appwrite Cloud console
- Access to Vercel console
- Latest application code in Git

**Procedure:**

1. **Assess what is salvageable**
   - Check each service independently for data integrity
   - Prioritize: Stripe data (payments) > Appwrite data (users/config) > Hetzner instances

2. **Rebuild the application layer**
   ```bash
   # Redeploy the Next.js application to Vercel
   vercel --prod

   # Verify all environment variables are set
   vercel env ls production
   ```

3. **Restore Appwrite data**
   - Follow the Database Recovery procedure (5.3)

4. **Restore DNS**
   - Follow the DNS Recovery procedure (5.4)

5. **Reconcile Stripe**
   - Follow the Payment System Recovery procedure (5.5)

6. **Rebuild customer instances**
   - Follow the Mass Instance Recovery procedure (5.2)

7. **Verification checklist**
   - [ ] runclaw.io resolves correctly
   - [ ] User authentication works
   - [ ] Stripe checkout flow completes
   - [ ] New instance provisioning works
   - [ ] Existing instances are reachable and healthy
   - [ ] Health check cron is running
   - [ ] Webhooks are processing
   - [ ] All customer notifications sent

---

## 6. Post-Incident

### 6.1 Blameless Post-Mortem Template

```
POST-MORTEM REPORT
==================

Incident ID: INC-[YYYY-MM-DD]-[N]
Severity: [P0/P1/P2/P3]
Date: [YYYY-MM-DD]
Duration: [start time UTC] to [end time UTC] ([total duration])
Author: [name]
Reviewers: [names]

STATUS: [Draft | In Review | Final]

---

1. SUMMARY
   [2-3 sentence plain-language description of what happened]

2. IMPACT
   - Customers affected: [number]
   - Duration of customer impact: [duration]
   - Data exposed: [yes/no, with details]
   - Financial impact: [estimated cost, credits issued]
   - Reputational impact: [assessment]

3. TIMELINE (all times UTC)
   [HH:MM] - [Event]
   [HH:MM] - [Event]
   ...

4. ROOT CAUSE
   [Technical description of the root cause]

5. ROOT CAUSE ANALYSIS (5 Whys)
   Why 1: [Why did the incident occur?]
     Because: [answer]
   Why 2: [Why did that happen?]
     Because: [answer]
   Why 3: [Why did that happen?]
     Because: [answer]
   Why 4: [Why did that happen?]
     Because: [answer]
   Why 5: [Why did that happen?]
     Because: [answer]

   Root cause: [final root cause statement]

6. CONTRIBUTING FACTORS
   - [Factor 1]
   - [Factor 2]
   - [Factor 3]

7. WHAT WENT WELL
   - [Positive aspect of the response]
   - [Positive aspect of the response]

8. WHAT COULD BE IMPROVED
   - [Area for improvement]
   - [Area for improvement]

9. ACTION ITEMS
   | # | Action | Owner | Priority | Due Date | Status |
   |---|--------|-------|----------|----------|--------|
   | 1 | [action] | [name] | [P0-P3] | [date] | [Open/In Progress/Done] |
   | 2 | [action] | [name] | [P0-P3] | [date] | [Open/In Progress/Done] |

10. LESSONS LEARNED
    [Key takeaways that should inform future architecture, process, or
    monitoring decisions]
```

### 6.2 Root Cause Analysis Framework

Use the **5 Whys** method to trace from symptom to root cause:

**Example: Customer VPS Compromised**
1. Why was the VPS compromised? Because an attacker gained SSH access.
2. Why did they gain SSH access? Because the SSH key was not rotated after an employee departure.
3. Why was the key not rotated? Because there is no automated key rotation process.
4. Why is there no automated key rotation? Because key management was not included in the initial architecture.
5. Why was it not included? Because the security architecture review did not cover post-provisioning key lifecycle.

**Root cause:** Missing key lifecycle management in the security architecture.

**Action:** Implement automated SSH key rotation and add key lifecycle to the security architecture review checklist.

### 6.3 Action Item Tracking

All post-mortem action items are tracked in a central register:

| Incident ID | Action Item | Owner | Priority | Due Date | Status | Completed Date |
|-------------|-------------|-------|----------|----------|--------|---------------|
| INC-2026-01-15-1 | Implement API token rotation automation | [name] | P1 | 2026-02-15 | Open | - |
| INC-2026-01-15-1 | Add Hetzner API call alerting | [name] | P2 | 2026-02-28 | Open | - |

**Rules:**
- P0/P1 action items must be completed within 30 days
- P2 action items must be completed within 60 days
- P3 action items must be completed within 90 days
- Action items not completed by due date are escalated to management
- Action items are reviewed weekly in the security standup

### 6.4 Security Improvement Backlog

Maintain a prioritized backlog of security improvements derived from incidents:

**Categories:**
- **Detection** - Improving ability to detect incidents faster
- **Prevention** - Preventing incident classes from occurring
- **Response** - Improving response speed and effectiveness
- **Recovery** - Improving recovery time and reliability

**Prioritization criteria:**
- Frequency of related incidents
- Potential blast radius if unaddressed
- Implementation effort
- Dependency on other improvements

### 6.5 Incident Metrics

Track these metrics across all incidents to measure program effectiveness:

| Metric | Definition | Target |
|--------|-----------|--------|
| **MTTD** (Mean Time to Detect) | Time from incident start to detection | P0: < 15 min, P1: < 1 hr |
| **MTTR** (Mean Time to Respond) | Time from detection to first response action | P0: < 15 min, P1: < 30 min |
| **MTTC** (Mean Time to Contain) | Time from detection to containment | P0: < 1 hr, P1: < 2 hr |
| **MTTRE** (Mean Time to Resolve) | Time from detection to full resolution | P0: < 4 hr, P1: < 8 hr |
| **Incident Count** | Total incidents per quarter by severity | Trending down |
| **Repeat Incidents** | Incidents with same root cause as a prior incident | 0 (goal) |
| **Action Item Completion Rate** | % of action items completed by due date | > 90% |

**Reporting cadence:**
- Weekly: active incident summary
- Monthly: metric trends and action item status
- Quarterly: full incident program review with executive summary

### 6.6 Incident Database Maintenance

All incidents are recorded in a structured incident database with the following fields:

```
{
  "incident_id": "INC-YYYY-MM-DD-N",
  "severity": "P0|P1|P2|P3",
  "title": "Brief descriptive title",
  "status": "Open|Contained|Resolved|Closed",
  "detected_at": "ISO-8601 timestamp",
  "contained_at": "ISO-8601 timestamp",
  "resolved_at": "ISO-8601 timestamp",
  "closed_at": "ISO-8601 timestamp",
  "affected_systems": ["vercel", "appwrite", "hetzner", "stripe", "cloudflare"],
  "affected_customers": ["customer_id_1", "customer_id_2"],
  "root_cause": "Description of root cause",
  "playbook_used": "Playbook identifier",
  "postmortem_url": "Link to post-mortem document",
  "action_items": ["AI-001", "AI-002"],
  "reporter": "Name",
  "incident_commander": "Name"
}
```

**Retention:** All incident records are retained indefinitely. Evidence and forensic artifacts are retained for a minimum of 12 months.

**Review:** The incident database is reviewed quarterly to identify trends, recurring root causes, and gaps in playbook coverage.

---

## 7. Regular Drills

### 7.1 Quarterly Tabletop Exercises

**Frequency:** Every quarter (January, April, July, October)
**Duration:** 90 minutes
**Participants:** All team members with incident response roles

**Format:**
1. **Scenario presentation** (10 min) - Facilitator presents a realistic incident scenario
2. **Initial response** (20 min) - Team walks through detection and initial triage
3. **Escalation and containment** (20 min) - Team discusses containment strategy
4. **Recovery and communication** (20 min) - Team plans recovery and customer communication
5. **Debrief** (20 min) - Discussion of what went well, gaps identified, playbook updates needed

**Quarterly Scenario Rotation:**
- Q1: Credential compromise scenario (API token, SSH key, or webhook secret)
- Q2: Customer data breach scenario (Appwrite or VPS data exposure)
- Q3: Infrastructure attack scenario (DDoS, DNS hijack, or mass instance failure)
- Q4: Supply chain or insider threat scenario

### 7.2 Annual Full Incident Simulation

**Frequency:** Once per year (recommended: September, before Q4 freeze)
**Duration:** 4 hours (half-day)
**Participants:** All team members, including non-technical stakeholders

**Structure:**
1. **Pre-simulation briefing** (30 min) - Rules of engagement, scope, boundaries
2. **Simulation execution** (2 hours) - Live exercise with simulated alerts, realistic data, and time pressure
3. **Cool-down** (30 min) - Stop exercise, collect notes
4. **Debrief and AAR** (1 hour) - After-action review with specific improvement recommendations

**Rules of engagement:**
- Use a dedicated staging environment (never production)
- All actions are logged for post-simulation analysis
- Participants may not consult playbooks for the first 15 minutes (tests recall)
- A designated observer records all decisions, timeline, and communication gaps
- Clear "Exercise, Exercise, Exercise" prefix on all communications to prevent real-world confusion

### 7.3 Drill Scenarios Specific to RunClaw

#### Scenario 1: The Stolen Token
> At 2:00 AM, your monitoring detects that 15 new Hetzner servers have been created in the last 10 minutes. None of these correspond to new customer signups. The Hetzner API token appears to have been compromised. Go.

**Tests:** Playbook A execution, after-hours response, rapid containment.

#### Scenario 2: The Lateral Mover
> A customer reports strange behavior from their OpenClaw instance. Upon investigation, you discover the Docker container has been modified and is making outbound connections to an unknown IP. You suspect the attacker may have access to your provisioning SSH key and could pivot to other customer instances.

**Tests:** Playbook B execution, blast radius assessment, multi-instance containment.

#### Scenario 3: The Free Rider
> Stripe webhook logs show a pattern of `checkout.session.completed` events that don't correspond to actual payments. Someone has been forging webhook events to provision free instances. There are 8 unauthorized instances running.

**Tests:** Playbook C execution, financial impact assessment, Stripe reconciliation.

#### Scenario 4: The Data Harvester
> Appwrite audit logs reveal that an API key was used to bulk-read the entire `users` collection and `instances` collection over the weekend. The reads came from an IP address you don't recognize. 2,400 customer records may have been accessed.

**Tests:** Playbook D execution, breach notification process, regulatory compliance.

#### Scenario 5: The Cascade
> Hetzner status page shows a major outage in the `fsn1` datacenter. 60% of your customer instances are in this region. Customers are reporting outages and your health check cron is firing alerts every minute.

**Tests:** Playbook E execution, customer communication at scale, status page management.

#### Scenario 6: The DNS Hijack
> A customer reports that `runclaw.io` is showing a phishing page. You check and find that multiple DNS records have been changed to point to attacker-controlled IPs. Your Cloudflare audit log shows changes made with your API token from an IP in a country where you have no team members.

**Tests:** Playbook F execution, DNS recovery speed, Cloudflare security hardening.

#### Scenario 7: The Perfect Storm
> Simultaneously: Vercel is returning 500 errors on the checkout page, Stripe webhooks are failing to deliver, and 3 customer instances have gone unhealthy. Is this a coordinated attack or coincidence?

**Tests:** Multi-vector triage, prioritization under pressure, parallel response coordination.

### 7.4 Drill Evaluation Criteria

Each drill is scored on the following criteria:

| Criterion | Weight | Scoring (1-5) |
|-----------|--------|---------------|
| **Detection speed** - How quickly was the simulated incident identified? | 20% | 5=immediate, 1=missed |
| **Correct classification** - Was the severity level assigned correctly? | 10% | 5=correct, 1=off by 2+ levels |
| **Playbook adherence** - Were the documented steps followed? | 15% | 5=followed exactly, 1=improvised entirely |
| **Containment effectiveness** - Was the blast radius limited? | 20% | 5=optimal containment, 1=spread unchecked |
| **Communication quality** - Were stakeholders informed appropriately? | 15% | 5=timely and clear, 1=no communication |
| **Recovery completeness** - Was full service restored? | 10% | 5=full recovery, 1=partial/failed |
| **Documentation** - Was the incident properly documented? | 10% | 5=complete records, 1=no documentation |

**Scoring thresholds:**
- 4.0-5.0: Excellent - team is well prepared
- 3.0-3.9: Good - minor improvements needed
- 2.0-2.9: Needs improvement - significant gaps identified, schedule follow-up drill
- 1.0-1.9: Critical - fundamental process gaps, immediate remediation required

**Post-drill actions:**
- Drill results are recorded and compared against previous drills to track improvement
- Identified gaps are added to the Security Improvement Backlog (Section 6.4)
- Playbooks are updated based on drill findings within 1 week
- Follow-up mini-drills are scheduled for any criterion scoring below 3.0

---

## Appendix A: Contact Information

| Role | Primary Contact | Backup Contact | Notification Method |
|------|----------------|----------------|-------------------|
| Incident Commander | [Name] | [Name] | Phone + Slack |
| Security Lead | [Name] | [Name] | Phone + Slack |
| Infrastructure Lead | [Name] | [Name] | Phone + Slack |
| Customer Communications | [Name] | [Name] | Slack + Email |
| Legal/Compliance | [Name] | [Name] | Phone + Email |

## Appendix B: External Contacts

| Service | Support Channel | SLA |
|---------|----------------|-----|
| Hetzner | https://console.hetzner.cloud/support | Business hours |
| Cloudflare | https://dash.cloudflare.com/support | Plan-dependent |
| Vercel | https://vercel.com/support | Plan-dependent |
| Stripe | https://support.stripe.com | 24/7 for urgent |
| Appwrite Cloud | https://appwrite.io/support | Business hours |

## Appendix C: Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-03 | RunClaw Security Team | Initial document |
