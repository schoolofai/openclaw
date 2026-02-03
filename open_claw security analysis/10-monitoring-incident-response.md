# 10 - Monitoring & Incident Response

## Overview

This document covers operational security monitoring for OpenClaw deployments and provides a structured incident response playbook. Effective monitoring detects attacks early; rapid incident response limits damage.

## Monitoring Architecture

```
[OpenClaw Container]
    |
    +-- Application logs (session transcripts, tool execution)
    +-- Gateway access logs (WebSocket connections, HTTP requests)
    |
[Caddy Container]
    |
    +-- Access logs (HTTP requests, status codes)
    +-- TLS handshake logs
    |
[Host OS]
    |
    +-- SSH auth logs (/var/log/auth.log)
    +-- Fail2ban logs (/var/log/fail2ban.log)
    +-- Docker daemon logs (journalctl -u docker)
    +-- UFW firewall logs (/var/log/ufw.log)
    +-- System logs (journalctl)
    +-- AIDE file integrity (/var/log/aide/)
    |
[External]
    |
    +-- Health check results (RunClaw.io cron)
    +-- Cloudflare analytics (DDoS, WAF events)
    +-- Hetzner monitoring (CPU, disk, network)
```

## Detection Rules

### Critical Alerts (Immediate Response)

| Rule | Detection Method | Severity |
|---|---|---|
| Gateway auth failure spike | >10 failed auth attempts in 5 minutes | Critical |
| Unauthorized tool execution | Tool execution from non-allowlisted sender | Critical |
| Credential file access | `inotifywait` on `~/.openclaw/openclaw.json` | Critical |
| SSH brute-force | Fail2ban trigger (>3 failures) | Critical |
| Container escape indicators | Unexpected processes on host | Critical |
| Outbound connection to unknown IP | UFW deny log entries | High |
| Config file modification | AIDE integrity check failure | High |

### Warning Alerts (Investigate Within 1 Hour)

| Rule | Detection Method | Severity |
|---|---|---|
| Health check failure | 3+ consecutive failures | High |
| Unusual message volume | >100 DMs in 10 minutes | Medium |
| Prompt injection attempt | Pattern match in session transcripts | Medium |
| Disk space > 80% | df monitoring | Medium |
| Memory usage > 90% | Docker stats | Medium |
| Docker container restart | Docker events | Medium |

### Informational (Review Weekly)

| Rule | Detection Method | Severity |
|---|---|---|
| New senders contacting bot | DM pairing requests | Low |
| Security audit findings | `openclaw security audit` | Low |
| Package updates available | apt list --upgradable | Low |
| Certificate expiry < 30 days | Caddy/TLS monitoring | Low |

## Monitoring Implementation

### 1. Gateway Auth Monitoring

```bash
# Monitor gateway logs for auth failures
cat > /opt/openclaw/monitor-auth.sh <<'SCRIPT'
#!/bin/bash
# Count recent auth failures from Docker logs
FAILURES=$(docker logs openclaw --since 5m 2>&1 | grep -c "auth.*fail\|unauthorized\|invalid.*token")

if [ "$FAILURES" -gt 10 ]; then
    echo "[CRITICAL] $(date): $FAILURES gateway auth failures in last 5 minutes" >> /var/log/openclaw-alerts.log
    # Send alert (replace with your notification method)
    curl -s -X POST "https://runclaw.io/api/instances/alert" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"auth_failure_spike\",\"count\":$FAILURES}"
fi
SCRIPT

chmod +x /opt/openclaw/monitor-auth.sh
echo "*/5 * * * * root /opt/openclaw/monitor-auth.sh" > /etc/cron.d/openclaw-monitor-auth
```

### 2. File Integrity Monitoring

```bash
# Install and configure inotifywait for real-time monitoring
apt-get install inotify-tools

cat > /opt/openclaw/watch-credentials.sh <<'SCRIPT'
#!/bin/bash
WATCH_DIR=$(docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}')

inotifywait -m -r -e modify,create,delete,move "$WATCH_DIR" \
    --include '(openclaw\.json|device-auth\.json|auth-profiles\.json|creds\.json)' \
    | while read dir event file; do
    echo "[ALERT] $(date): $event on $dir$file" >> /var/log/openclaw-file-changes.log
done
SCRIPT

# Run as a systemd service
cat > /etc/systemd/system/openclaw-watch.service <<'UNIT'
[Unit]
Description=OpenClaw Credential File Watcher
After=docker.service

[Service]
ExecStart=/opt/openclaw/watch-credentials.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl enable --now openclaw-watch
```

### 3. Prompt Injection Detection

```bash
cat > /opt/openclaw/detect-injection.sh <<'SCRIPT'
#!/bin/bash
VOLUME_PATH=$(docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}')
SESSION_DIR="$VOLUME_PATH/agents/*/sessions"

# Patterns that indicate injection attempts
PATTERNS=(
    "ignore previous instructions"
    "ignore all previous"
    "disregard.*instructions"
    "new.*system.*prompt"
    "you are now"
    "elevated=true"
    "END_EXTERNAL_UNTRUSTED_CONTENT"
    "\\[system\\]"
    "\\[assistant\\]"
)

for pattern in "${PATTERNS[@]}"; do
    MATCHES=$(find $SESSION_DIR -name "*.jsonl" -newer /tmp/last-injection-check -exec grep -li "$pattern" {} \; 2>/dev/null)
    if [ -n "$MATCHES" ]; then
        echo "[WARN] $(date): Potential prompt injection detected: pattern='$pattern' files=$MATCHES" >> /var/log/openclaw-alerts.log
    fi
done

touch /tmp/last-injection-check
SCRIPT

chmod +x /opt/openclaw/detect-injection.sh
echo "*/10 * * * * root /opt/openclaw/detect-injection.sh" > /etc/cron.d/openclaw-detect-injection
```

### 4. Resource Monitoring

```bash
cat > /opt/openclaw/monitor-resources.sh <<'SCRIPT'
#!/bin/bash

# Check disk usage
DISK_USAGE=$(df / --output=pcent | tail -1 | tr -d ' %')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "[WARN] $(date): Disk usage at ${DISK_USAGE}%" >> /var/log/openclaw-alerts.log
fi

# Check Docker container status
CONTAINER_STATUS=$(docker inspect openclaw --format='{{.State.Status}}' 2>/dev/null)
if [ "$CONTAINER_STATUS" != "running" ]; then
    echo "[CRITICAL] $(date): OpenClaw container status: $CONTAINER_STATUS" >> /var/log/openclaw-alerts.log
fi

# Check container restarts
RESTART_COUNT=$(docker inspect openclaw --format='{{.RestartCount}}' 2>/dev/null)
if [ "$RESTART_COUNT" -gt 5 ]; then
    echo "[WARN] $(date): OpenClaw container has restarted $RESTART_COUNT times" >> /var/log/openclaw-alerts.log
fi

# Check memory usage
MEMORY=$(docker stats openclaw --no-stream --format "{{.MemPerc}}" | tr -d '%')
if (( $(echo "$MEMORY > 90" | bc -l) )); then
    echo "[WARN] $(date): OpenClaw memory usage at ${MEMORY}%" >> /var/log/openclaw-alerts.log
fi
SCRIPT

chmod +x /opt/openclaw/monitor-resources.sh
echo "*/5 * * * * root /opt/openclaw/monitor-resources.sh" > /etc/cron.d/openclaw-monitor-resources
```

### 5. Security Audit Automation

```bash
# Weekly security audit
cat > /etc/cron.weekly/openclaw-audit <<'SCRIPT'
#!/bin/bash
REPORT=$(docker exec openclaw openclaw security audit 2>&1)
echo "$REPORT" >> /var/log/openclaw-audit-$(date +%Y%m%d).log

# Check for CRITICAL findings
if echo "$REPORT" | grep -q "CRITICAL"; then
    echo "[CRITICAL] $(date): Security audit found critical issues" >> /var/log/openclaw-alerts.log
    echo "$REPORT" | grep "CRITICAL" >> /var/log/openclaw-alerts.log
fi
SCRIPT

chmod +x /etc/cron.weekly/openclaw-audit
```

## Log Retention Policy

| Log Type | Retention | Rotation |
|---|---|---|
| Caddy access logs | 30 days | 10MB, 5 files |
| OpenClaw session transcripts | 90 days | Manual pruning |
| SSH auth logs | 90 days | System logrotate |
| Fail2ban logs | 90 days | System logrotate |
| UFW firewall logs | 30 days | System logrotate |
| Docker container logs | 7 days | 10MB, 3 files |
| Alert logs | 1 year | Monthly rotation |
| Security audit reports | 1 year | Weekly |

```bash
# Logrotate config for OpenClaw alerts
cat > /etc/logrotate.d/openclaw <<'CONF'
/var/log/openclaw-*.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
CONF
```

## Incident Response Playbook

### Severity Levels

| Level | Description | Response Time | Escalation |
|---|---|---|---|
| P1 - Critical | Active compromise, data exfiltration | Immediate | Operator + RunClaw.io team |
| P2 - High | Attempted breach, credential exposure | < 1 hour | Operator |
| P3 - Medium | Suspicious activity, policy violation | < 4 hours | Operator |
| P4 - Low | Informational, best practice gap | Next business day | Self-service |

### IR Phase 1: Detection and Triage

```
1. IDENTIFY the alert type:
   - Gateway auth failure → Phase 2a
   - Prompt injection → Phase 2b
   - Container compromise → Phase 2c
   - Credential exposure → Phase 2d
   - SSH brute-force → Phase 2e

2. ASSESS scope:
   - Single instance or multiple?
   - Data accessed or just attempted?
   - Ongoing or completed?

3. DOCUMENT:
   - Timestamp of detection
   - Alert source and details
   - Initial assessment
```

### IR Phase 2a: Gateway Auth Compromise

```bash
# 1. CONTAIN: Immediately stop the gateway
docker compose -f /opt/openclaw/docker-compose.yml stop openclaw

# 2. INVESTIGATE: Check recent connections
docker logs openclaw --since 1h 2>&1 | grep -iE "connect|auth|websocket"

# 3. ROTATE: Generate new gateway token
NEW_TOKEN=$(openssl rand -hex 32)
# Update in .env or docker-compose.yml

# 4. REVIEW: Check for unauthorized tool executions
# Search session transcripts for unexpected commands
find $(docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}')/agents/*/sessions \
    -name "*.jsonl" -newer /tmp/incident-start -exec grep -l "exec\|tool_use" {} \;

# 5. RESTART: Start gateway with new token
docker compose -f /opt/openclaw/docker-compose.yml up -d openclaw

# 6. VERIFY: Run security audit
docker exec openclaw openclaw security audit --deep
```

### IR Phase 2b: Prompt Injection Attack

```bash
# 1. CONTAIN: Switch DM policy to disabled
docker exec openclaw openclaw config set channels.defaults.dmPolicy disabled

# 2. INVESTIGATE: Review session transcripts
VOLUME=$(docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}')
grep -rli "ignore.*instructions\|system.*prompt\|elevated" \
    "$VOLUME/agents/*/sessions/"

# 3. ASSESS: Check if any tools were executed as a result
grep -A 5 "tool_use" "$VOLUME/agents/*/sessions/"*.jsonl | tail -50

# 4. BLOCK: Add attacker's sender ID to blocklist
# Identify the sender from session transcripts and block them

# 5. RESTORE: Re-enable DM policy with tighter controls
docker exec openclaw openclaw config set channels.defaults.dmPolicy allowlist
```

### IR Phase 2c: Container Compromise

```bash
# 1. CONTAIN: Stop all containers immediately
docker compose -f /opt/openclaw/docker-compose.yml down

# 2. PRESERVE: Save container state for forensics
docker export openclaw > /opt/forensics/container-$(date +%s).tar
docker logs openclaw > /opt/forensics/container-logs-$(date +%s).txt

# 3. INVESTIGATE: Check host for escape indicators
ps aux | grep -v docker  # Look for unexpected processes
netstat -tlnp  # Check for unexpected listeners
find / -newer /tmp/incident-start -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# 4. REBUILD: Start fresh containers
docker compose -f /opt/openclaw/docker-compose.yml pull
docker compose -f /opt/openclaw/docker-compose.yml up -d

# 5. VERIFY: Full security check
docker exec openclaw openclaw security audit --deep
nmap -sS -p- localhost  # Verify no unexpected ports
```

### IR Phase 2d: Credential Exposure

```bash
# 1. CONTAIN: Stop gateway to prevent further access
docker compose -f /opt/openclaw/docker-compose.yml stop openclaw

# 2. ROTATE ALL CREDENTIALS:

# Gateway token
NEW_GW_TOKEN=$(openssl rand -hex 32)
# Update OPENCLAW_GATEWAY_TOKEN in .env

# LLM API keys (rotate from provider dashboards)
# - OpenAI: https://platform.openai.com/api-keys
# - Anthropic: https://console.anthropic.com/settings/keys

# Bot tokens
# - Telegram: @BotFather > /revoke
# - Discord: Discord Developer Portal > Bot > Reset Token
# - Slack: Rotate OAuth tokens

# SSH keys
ssh-keygen -t ed25519 -f ~/.ssh/runclaw_admin_new
# Update authorized_keys on VPS

# 3. CLEAR: Remove potentially compromised sessions
VOLUME=$(docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}')
rm -rf "$VOLUME/agents/*/sessions/*"

# 4. RESTART: With new credentials
docker compose -f /opt/openclaw/docker-compose.yml up -d

# 5. AUDIT: Verify clean state
docker exec openclaw openclaw security audit --deep
```

### IR Phase 2e: SSH Brute-Force

```bash
# 1. CHECK: Fail2ban status
fail2ban-client status sshd

# 2. VERIFY: No successful unauthorized login
last -20
grep "Accepted" /var/log/auth.log | tail -20

# 3. HARDEN: If not already done
# Change SSH port
# Restrict to key-only auth
# Add additional fail2ban rules

# 4. BLOCK: Persistent attackers at firewall level
ufw deny from <attacker-ip>
```

### IR Phase 3: Recovery

```
1. VERIFY: All rotated credentials are working
2. TEST: Run full security audit (openclaw security audit --deep)
3. MONITOR: Increase monitoring frequency for 72 hours
4. DOCUMENT: Write incident report
5. IMPROVE: Update detection rules based on findings
```

### IR Phase 4: Post-Incident

```
1. REPORT: Document timeline, impact, root cause, remediation
2. REVIEW: Identify gaps in detection and response
3. UPDATE: Modify monitoring rules, hardening configs
4. SHARE: Communicate findings to RunClaw.io team (if applicable)
5. SCHEDULE: Follow-up security audit in 30 days
```

## RunClaw.io Platform-Level Monitoring

For the RunClaw.io platform itself:

```
1. Vercel Cron Health Checks (every 5 minutes)
   - Hits /health on each instance
   - Marks unhealthy after 3 consecutive failures

2. Provision Timeout Monitor (every 10 minutes)
   - Catches stuck provisioning jobs
   - Auto-cleans orphaned Hetzner servers

3. Weekly Reconciliation
   - Finds orphaned VPS instances
   - Cleans up stale DNS records
   - Reports revenue leak prevention

4. Stripe Webhook Monitoring
   - Idempotent processing
   - Failed payment detection
   - Subscription cancellation handling
```

## Audit Checklist

```
[ ] Monitoring scripts installed and running
[ ] Alert notification channel configured
[ ] Log rotation configured for all log types
[ ] AIDE file integrity monitoring initialized
[ ] Credential file watching active
[ ] Prompt injection detection scanning
[ ] Resource monitoring (disk, memory, CPU)
[ ] Weekly security audit automated
[ ] Incident response playbook tested
[ ] Emergency credential rotation procedure tested
[ ] Backup and recovery procedure tested
[ ] Contact list for escalation documented
```
