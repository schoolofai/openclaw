# RunClaw.io Infrastructure Security Hardening Guide

This document provides comprehensive security hardening procedures for RunClaw.io infrastructure. RunClaw.io provisions Hetzner Cloud VPS instances running Ubuntu 24.04 with Docker Compose (Caddy + OpenClaw), managed via cloud-init. DNS is handled by Cloudflare, and the control plane runs on Vercel.

Every section includes specific configuration examples, commands, and rationale. Treat this as a living runbook -- update it as the stack evolves.

---

## Table of Contents

1. [Hetzner Cloud Security](#1-hetzner-cloud-security)
2. [VPS Operating System Hardening](#2-vps-operating-system-hardening)
3. [SSH Hardening (Beyond Basics)](#3-ssh-hardening-beyond-basics)
4. [Firewall Configuration](#4-firewall-configuration)
5. [Docker Security](#5-docker-security)
6. [Caddy Reverse Proxy Hardening](#6-caddy-reverse-proxy-hardening)
7. [Cloudflare Configuration](#7-cloudflare-configuration)
8. [Monitoring and Alerting](#8-monitoring-and-alerting)
9. [Backup and Recovery](#9-backup-and-recovery)

---

## 1. Hetzner Cloud Security

### 1.1 API Token Management

Hetzner API tokens are the keys to the kingdom. A leaked token allows an attacker to create, destroy, or snapshot any server in the project.

**Separate tokens per environment:**

| Environment | Token Name             | Permissions | Rotation Schedule |
|-------------|------------------------|-------------|-------------------|
| Production  | `runclaw-prod-api`     | Read/Write  | Every 90 days     |
| Staging     | `runclaw-staging-api`  | Read/Write  | Every 90 days     |
| CI/CD       | `runclaw-ci-readonly`  | Read Only   | Every 90 days     |
| Monitoring  | `runclaw-mon-readonly` | Read Only   | Every 90 days     |

**Token rotation procedure:**

```bash
#!/bin/bash
# scripts/rotate-hetzner-token.sh
# Run this every 90 days per environment

set -euo pipefail

ENVIRONMENT="${1:?Usage: rotate-hetzner-token.sh <prod|staging>}"
TIMESTAMP=$(date +%Y%m%d)

echo "=== Hetzner API Token Rotation for ${ENVIRONMENT} ==="
echo ""
echo "Steps:"
echo "1. Log in to https://console.hetzner.cloud"
echo "2. Navigate to the '${ENVIRONMENT}' project"
echo "3. Go to Security > API Tokens"
echo "4. Create a new token named: runclaw-${ENVIRONMENT}-api-${TIMESTAMP}"
echo "5. Copy the new token value"
echo "6. Update the Vercel environment variable HETZNER_API_TOKEN_${ENVIRONMENT^^}"
echo "7. Verify provisioning works with the new token"
echo "8. Delete the old token from Hetzner console"
echo "9. Update the rotation log below"
echo ""
echo "Verification command:"
echo "  curl -s -H 'Authorization: Bearer <NEW_TOKEN>' \\"
echo "    https://api.hetzner.cloud/v1/servers | jq '.servers | length'"
```

**Rationale:** Separate tokens limit blast radius. A compromised staging token cannot touch production infrastructure. Read-only tokens for CI and monitoring prevent accidental or malicious mutations.

**Store tokens in Vercel environment variables:**

```
HETZNER_API_TOKEN        # Production (only available in production deployment)
HETZNER_API_TOKEN_STAGING # Staging (only available in preview deployments)
```

Never store Hetzner tokens in version control, `.env` files committed to git, or client-side code.

### 1.2 Server Naming Conventions and Label Security

Server names and labels are visible in the Hetzner console and API responses. Avoid encoding sensitive data in them.

**Naming convention:**

```
Format:  rc-<region>-<random_6hex>
Example: rc-fsn1-a3f2c1
```

```typescript
// lib/hetzner.ts - Secure server name generation
import crypto from 'crypto';

function generateServerName(region: string): string {
  const randomSuffix = crypto.randomBytes(3).toString('hex');
  return `rc-${region}-${randomSuffix}`;
}
```

**Do NOT include in server names or labels:**
- Customer usernames or email addresses
- Subdomain values (maps back to customer identity)
- Stripe customer or subscription IDs
- Internal instance UUIDs from the database

**Safe labels:**

```json
{
  "managed-by": "runclaw",
  "environment": "production",
  "region": "fsn1",
  "plan": "starter",
  "created": "2026-02-03"
}
```

**Rationale:** If an attacker gains read-only API access, server names and labels are the first thing they see. Opaque identifiers prevent customer data leakage.

### 1.3 SSH Key Management

**Admin key requirements:**

```bash
# Generate an Ed25519 admin key (one per admin)
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/runclaw-admin -C "admin@runclaw.io"

# Upload to Hetzner via API
curl -X POST https://api.hetzner.cloud/v1/ssh_keys \
  -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"admin-$(whoami)-$(date +%Y%m)\",
    \"public_key\": \"$(cat ~/.ssh/runclaw-admin.pub)\",
    \"labels\": {
      \"owner\": \"$(whoami)\",
      \"expires\": \"$(date -d '+6 months' +%Y-%m-%d 2>/dev/null || date -v+6m +%Y-%m-%d)\"
    }
  }"
```

**Rotation schedule:**

| Key Type        | Rotation Period | Procedure                            |
|-----------------|-----------------|--------------------------------------|
| Admin SSH keys  | Every 6 months  | Generate new key, add to Hetzner, update cloud-init template, remove old key |
| Per-VPS host keys | On reprovision | Automatically generated by cloud-init |

**Revocation procedure:**

```bash
# List all SSH keys
curl -s -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
  https://api.hetzner.cloud/v1/ssh_keys | jq '.ssh_keys[] | {id, name, labels}'

# Delete a compromised key
curl -X DELETE -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
  https://api.hetzner.cloud/v1/ssh_keys/{KEY_ID}
```

After revoking a key from Hetzner, it is still present on existing VPS instances. You must also remove it from `/root/.ssh/authorized_keys` and `/home/openclaw/.ssh/authorized_keys` on every running VPS, or reprovision the instance.

### 1.4 Hetzner Firewall Rules (Cloud-Level)

Hetzner Cloud Firewalls operate at the hypervisor level, before traffic reaches the VPS. They are the first line of defense.

**Create a firewall for customer VPS instances:**

```bash
# Create the firewall
curl -X POST https://api.hetzner.cloud/v1/firewalls \
  -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "runclaw-customer-vps",
    "labels": { "managed-by": "runclaw" },
    "rules": [
      {
        "direction": "in",
        "protocol": "tcp",
        "port": "80",
        "source_ips": ["0.0.0.0/0", "::/0"],
        "description": "HTTP (Caddy - redirect to HTTPS)"
      },
      {
        "direction": "in",
        "protocol": "tcp",
        "port": "443",
        "source_ips": ["0.0.0.0/0", "::/0"],
        "description": "HTTPS (Caddy TLS termination)"
      },
      {
        "direction": "in",
        "protocol": "tcp",
        "port": "22",
        "source_ips": ["<ADMIN_IP_1>/32", "<ADMIN_IP_2>/32"],
        "description": "SSH admin access (restricted IPs only)"
      },
      {
        "direction": "out",
        "protocol": "tcp",
        "port": "443",
        "destination_ips": ["0.0.0.0/0", "::/0"],
        "description": "HTTPS outbound (APIs, Docker registry)"
      },
      {
        "direction": "out",
        "protocol": "tcp",
        "port": "80",
        "destination_ips": ["0.0.0.0/0", "::/0"],
        "description": "HTTP outbound (package repos, ACME)"
      },
      {
        "direction": "out",
        "protocol": "udp",
        "port": "53",
        "destination_ips": ["0.0.0.0/0", "::/0"],
        "description": "DNS resolution"
      },
      {
        "direction": "out",
        "protocol": "udp",
        "port": "123",
        "destination_ips": ["0.0.0.0/0", "::/0"],
        "description": "NTP time synchronization"
      }
    ]
  }'
```

**Apply the firewall to servers on creation:**

```typescript
// In lib/hetzner.ts createServer function
const res = await fetch(`${HETZNER_API}/servers`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${HETZNER_TOKEN}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    name: generateServerName(location),
    server_type: serverType,
    image: 'ubuntu-24.04',
    location: location,
    user_data: cloudInit,
    ssh_keys: [ADMIN_SSH_KEY_ID],
    firewalls: [{ firewall: HETZNER_FIREWALL_ID }],
    labels: {
      'managed-by': 'runclaw',
      environment: 'production',
      plan: plan
    }
  })
});
```

**Rationale:** Cloud-level firewalls cannot be bypassed by misconfiguration inside the VPS. Even if UFW is disabled or Docker bypasses iptables, the Hetzner firewall blocks unauthorized inbound traffic.

### 1.5 Network Isolation Between Customer VPS Instances

Each customer VPS is a separate Hetzner server with its own public IP address. There is no shared network by default. Enforce this:

**Do NOT use:**
- Hetzner Private Networks (vSwitch) between customer instances
- Hetzner Floating IPs shared across instances
- Hetzner Load Balancers that group customer instances

**Verify isolation:**

```bash
# From any customer VPS, verify it cannot reach other VPS instances on private networks
ip addr show | grep -c "10\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.\|192\.168\."
# Expected output: 0 (no private network interfaces)
```

**Rationale:** Customer VPS instances must be completely isolated from each other. A compromised instance must not be able to reach or scan other customer instances over any network path.

### 1.6 Hetzner Project Separation

**Project structure:**

| Project Name       | Purpose                                    | API Token             |
|--------------------|--------------------------------------------|-----------------------|
| `runclaw-prod`     | Production customer VPS instances          | `runclaw-prod-api`    |
| `runclaw-staging`  | Staging/testing VPS instances              | `runclaw-staging-api` |
| `runclaw-internal` | Internal tooling, monitoring, bastion host | `runclaw-internal-api`|

**Rationale:** Hetzner projects provide hard boundaries. An API token for one project cannot access resources in another. This prevents a staging misconfiguration from affecting production.

### 1.7 Server Snapshot Security

Snapshots contain the full disk image, including secrets stored on the VPS.

**Snapshot policy:**

```bash
# DO NOT create automatic snapshots of customer VPS instances
# Snapshots contain customer credentials and session data

# If a snapshot is needed for debugging, encrypt and delete promptly:
# 1. Create snapshot (manual, one-off)
curl -X POST "https://api.hetzner.cloud/v1/servers/${SERVER_ID}/actions/create_image" \
  -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"type": "snapshot", "description": "debug-20260203-delete-after-48h"}'

# 2. Export and encrypt if needed
# 3. Delete snapshot within 48 hours
curl -X DELETE "https://api.hetzner.cloud/v1/images/${SNAPSHOT_ID}" \
  -H "Authorization: Bearer ${HETZNER_API_TOKEN}"
```

**Automated cleanup of stale snapshots:**

```bash
#!/bin/bash
# scripts/cleanup-stale-snapshots.sh
set -euo pipefail

HETZNER_API_TOKEN="${HETZNER_API_TOKEN:?HETZNER_API_TOKEN must be set}"
MAX_AGE_HOURS=48

echo "Checking for stale snapshots older than ${MAX_AGE_HOURS} hours..."

SNAPSHOTS=$(curl -s -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
  "https://api.hetzner.cloud/v1/images?type=snapshot&sort=created:asc" \
  | jq -r ".images[] | select(.labels.\"managed-by\" == \"runclaw\") | .id")

for SNAPSHOT_ID in ${SNAPSHOTS}; do
  CREATED=$(curl -s -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
    "https://api.hetzner.cloud/v1/images/${SNAPSHOT_ID}" \
    | jq -r '.image.created')

  CREATED_EPOCH=$(date -d "${CREATED}" +%s 2>/dev/null || date -jf "%Y-%m-%dT%H:%M:%S" "${CREATED%%+*}" +%s)
  NOW_EPOCH=$(date +%s)
  AGE_HOURS=$(( (NOW_EPOCH - CREATED_EPOCH) / 3600 ))

  if [ "${AGE_HOURS}" -gt "${MAX_AGE_HOURS}" ]; then
    echo "Deleting stale snapshot ${SNAPSHOT_ID} (age: ${AGE_HOURS}h)"
    curl -X DELETE -H "Authorization: Bearer ${HETZNER_API_TOKEN}" \
      "https://api.hetzner.cloud/v1/images/${SNAPSHOT_ID}"
  fi
done
```

### 1.8 Hetzner API Rate Limiting and Abuse Prevention

Hetzner enforces rate limits of 3600 requests per hour per token. The control plane must respect these.

**Rate limiting in the provisioning code:**

```typescript
// lib/hetzner-rate-limit.ts
const HETZNER_RATE_LIMIT = 3600; // requests per hour
const RATE_LIMIT_WINDOW_MS = 3600 * 1000;

let requestLog: number[] = [];

export async function hetznerFetch(
  url: string,
  options: RequestInit
): Promise<Response> {
  const now = Date.now();

  // Prune old entries
  requestLog = requestLog.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);

  if (requestLog.length >= HETZNER_RATE_LIMIT * 0.9) {
    throw new Error(
      `Hetzner API rate limit approaching: ${requestLog.length}/${HETZNER_RATE_LIMIT} requests in the current window. Aborting to prevent lockout.`
    );
  }

  requestLog.push(now);

  const response = await fetch(url, options);

  // Check rate limit headers
  const remaining = response.headers.get('RateLimit-Remaining');
  if (remaining !== null && parseInt(remaining, 10) < 100) {
    console.warn(
      `Hetzner API rate limit warning: ${remaining} requests remaining`
    );
  }

  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    throw new Error(
      `Hetzner API rate limit exceeded. Retry after ${retryAfter ?? 'unknown'} seconds.`
    );
  }

  return response;
}
```

**Abuse prevention for provisioning endpoint:**

```typescript
// In /api/instances/create - prevent rapid provisioning abuse
const PROVISION_COOLDOWN_MS = 60_000; // 1 minute between provisions per user

const recentProvisions = await databases.listDocuments(
  DATABASE_ID,
  COLLECTIONS.INSTANCE_EVENTS,
  [
    Query.equal('event_type', 'created'),
    Query.greaterThan('created_at',
      new Date(Date.now() - PROVISION_COOLDOWN_MS).toISOString()
    )
  ]
);

if (recentProvisions.total > 0) {
  throw new Error(
    'Provisioning rate limit: please wait at least 60 seconds between instance creation requests.'
  );
}
```

---

## 2. VPS Operating System Hardening

### 2.1 Ubuntu 24.04 CIS Benchmark Compliance Checklist

The following cloud-init runcmd block applies CIS Level 1 hardening on first boot. Each item references the CIS Ubuntu 24.04 LTS Benchmark section.

```yaml
# cloud-init snippet: CIS hardening
runcmd:
  # CIS 1.1.1 - Disable unused filesystems
  - |
    for fs in cramfs freevfat jffs2 hfs hfsplus squashfs udf; do
      echo "install ${fs} /bin/true" >> /etc/modprobe.d/cis-disable-fs.conf
      echo "blacklist ${fs}" >> /etc/modprobe.d/cis-disable-fs.conf
    done

  # CIS 1.4.1 - Ensure permissions on bootloader config
  - chmod 600 /boot/grub/grub.cfg

  # CIS 1.5.1 - Ensure core dumps are restricted
  - |
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-cis.conf
    echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.d/99-cis.conf

  # CIS 1.7.1 - Ensure message of the day is configured
  - echo "Authorized access only. All activity is monitored and logged." > /etc/issue.net
  - echo "" > /etc/motd

  # CIS 3.1 - Network parameters (host)
  - |
    cat >> /etc/sysctl.d/99-cis-network.conf << 'SYSCTL'
    net.ipv4.ip_forward = 1
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    net.ipv4.conf.all.accept_redirects = 0
    net.ipv4.conf.default.accept_redirects = 0
    net.ipv4.conf.all.secure_redirects = 0
    net.ipv4.conf.default.secure_redirects = 0
    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1
    net.ipv4.icmp_echo_ignore_broadcasts = 1
    net.ipv4.icmp_ignore_bogus_error_responses = 1
    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1
    net.ipv4.tcp_syncookies = 1
    net.ipv6.conf.all.accept_ra = 0
    net.ipv6.conf.default.accept_ra = 0
    SYSCTL
    sysctl --system
```

### 2.2 Kernel Hardening (sysctl Parameters)

Beyond CIS baseline, apply additional kernel hardening for a container host:

```bash
# /etc/sysctl.d/99-runclaw-hardening.conf
# Applied via cloud-init write_files

# --- Memory protection ---
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2
# Restrict dmesg access to root
kernel.dmesg_restrict = 1
# Restrict perf_event_paranoid
kernel.perf_event_paranoid = 3
# Restrict eBPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# ASLR full randomization
kernel.randomize_va_space = 2
# Restrict ptrace scope (no cross-process tracing)
kernel.yama.ptrace_scope = 2

# --- Network hardening ---
# SYN flood protection
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
# TCP keepalive (detect dead connections faster)
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5
# Connection tracking limits (for Docker)
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Filesystem ---
# Restrict hardlink/symlink creation
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
# Limit inotify (prevent resource exhaustion)
fs.inotify.max_user_watches = 65536
fs.inotify.max_user_instances = 128
```

**Rationale:** These parameters close common Linux kernel attack vectors: information leaks via `/proc/kallsyms`, ptrace-based process injection, SYN floods, and filesystem race conditions.

### 2.3 AppArmor Profiles for Docker Containers

Ubuntu 24.04 ships with AppArmor enabled by default. Create a custom profile for the OpenClaw container:

```bash
# /etc/apparmor.d/docker-openclaw
# Applied via cloud-init write_files

#include <tunables/global>

profile docker-openclaw flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Network access
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,

  # Node.js runtime
  /usr/local/bin/node ix,
  /app/** r,
  /app/dist/** r,
  /app/node_modules/** r,

  # Writable data directory
  /home/node/.openclaw/** rw,
  /home/node/.openclaw/workspace/** rw,

  # Temp files
  /tmp/** rw,
  /home/node/.cache/** rw,

  # Proc filesystem (Node.js needs some of these)
  @{PROC}/self/fd/ r,
  @{PROC}/self/maps r,
  @{PROC}/self/status r,
  @{PROC}/sys/kernel/random/uuid r,
  @{PROC}/sys/vm/overcommit_memory r,

  # Deny sensitive paths
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny /root/** rw,
  deny /proc/kcore r,
  deny /proc/sysrq-trigger rw,
  deny /sys/firmware/** r,

  # Deny raw disk access
  deny /dev/sd* rw,
  deny /dev/nvme* rw,

  # Deny mount operations
  deny mount,
  deny umount,
  deny pivot_root,
}
```

**Load the profile:**

```yaml
# cloud-init runcmd
runcmd:
  - apparmor_parser -r /etc/apparmor.d/docker-openclaw
```

**Apply to the container in docker-compose.yml:**

```yaml
services:
  openclaw:
    security_opt:
      - apparmor=docker-openclaw
      - no-new-privileges:true
```

### 2.4 Filesystem Permissions and Mount Options

Harden the filesystem via `/etc/fstab` entries and cloud-init:

```yaml
# cloud-init write_files
write_files:
  - path: /etc/fstab.d/runclaw-hardening
    permissions: '0644'
    content: |
      # Harden /tmp - noexec prevents executing binaries from /tmp
      tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0
      # Harden /var/tmp
      tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=256M 0 0
      # Harden /dev/shm (shared memory)
      tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev,size=256M 0 0

runcmd:
  # Apply fstab changes
  - cat /etc/fstab.d/runclaw-hardening >> /etc/fstab
  - mount -o remount /tmp
  - mount -o remount /dev/shm

  # Secure /opt/openclaw
  - chmod 750 /opt/openclaw
  - chown root:docker /opt/openclaw

  # Restrict home directory permissions
  - chmod 700 /home/openclaw

  # Remove world-readable permissions from sensitive config
  - chmod 600 /etc/ssh/sshd_config
  - chmod 600 /etc/shadow
  - chmod 600 /etc/gshadow
```

**Rationale:** `noexec` on `/tmp` prevents a common attack vector where malware is downloaded to `/tmp` and executed. `nosuid` prevents SUID bit exploitation on temporary files.

### 2.5 Audit Logging (auditd)

Install and configure auditd to track security-relevant events:

```yaml
# cloud-init
packages:
  - auditd
  - audispd-plugins

write_files:
  - path: /etc/audit/rules.d/runclaw.rules
    permissions: '0640'
    content: |
      # RunClaw audit rules

      # Delete all existing rules
      -D

      # Set buffer size
      -b 8192

      # Failure mode: log to syslog
      -f 1

      # Monitor Docker daemon
      -w /usr/bin/dockerd -p rwxa -k docker-daemon
      -w /usr/bin/docker -p rwxa -k docker-cli
      -w /var/lib/docker -p rwxa -k docker-data

      # Monitor Docker socket (critical)
      -w /var/run/docker.sock -p rwxa -k docker-socket

      # Monitor container runtime
      -w /usr/bin/containerd -p rwxa -k containerd
      -w /usr/bin/runc -p rwxa -k runc

      # Monitor SSH configuration
      -w /etc/ssh/sshd_config -p rwxa -k sshd-config
      -w /etc/ssh/sshd_config.d -p rwxa -k sshd-config

      # Monitor user authentication
      -w /etc/passwd -p wa -k identity
      -w /etc/group -p wa -k identity
      -w /etc/shadow -p wa -k identity
      -w /var/log/auth.log -p wa -k auth-log

      # Monitor sudo usage
      -w /etc/sudoers -p wa -k sudoers
      -w /etc/sudoers.d -p wa -k sudoers

      # Monitor cron
      -w /etc/crontab -p wa -k cron
      -w /var/spool/cron -p wa -k cron

      # Monitor OpenClaw data directory
      -w /opt/openclaw -p wa -k openclaw-data
      -w /home/openclaw/.openclaw -p wa -k openclaw-config

      # Monitor kernel module loading
      -w /sbin/insmod -p x -k modules
      -w /sbin/modprobe -p x -k modules
      -w /sbin/rmmod -p x -k modules

      # Log all commands executed as root
      -a always,exit -F arch=b64 -F euid=0 -S execve -k root-commands

      # Log unsuccessful file access attempts
      -a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -k access-denied
      -a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -k access-denied

      # Make audit configuration immutable (requires reboot to change)
      -e 2

runcmd:
  - systemctl enable auditd
  - systemctl restart auditd
```

### 2.6 Automatic Security Updates (unattended-upgrades Deep Configuration)

```yaml
# cloud-init write_files
write_files:
  - path: /etc/apt/apt.conf.d/50unattended-upgrades
    permissions: '0644'
    content: |
      Unattended-Upgrade::Allowed-Origins {
          "${distro_id}:${distro_codename}";
          "${distro_id}:${distro_codename}-security";
          "${distro_id}ESMApps:${distro_codename}-apps-security";
          "${distro_id}ESM:${distro_codename}-infra-security";
      };

      // Remove unused kernel packages after upgrade
      Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

      // Remove unused dependencies
      Unattended-Upgrade::Remove-Unused-Dependencies "true";

      // Remove new unused dependencies after upgrade
      Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

      // Do NOT auto-reboot (we handle this via health checks)
      Unattended-Upgrade::Automatic-Reboot "false";

      // If reboot is required, log it so monitoring can detect
      Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

      // Fix interrupted dpkg
      Unattended-Upgrade::AutoFixInterruptedDpkg "true";

      // Split upgrades into minimal steps (safer)
      Unattended-Upgrade::MinimalSteps "true";

      // Mail notifications (optional - if MTA is configured)
      // Unattended-Upgrade::Mail "admin@runclaw.io";
      // Unattended-Upgrade::MailReport "only-on-error";

      // Log to syslog
      Unattended-Upgrade::SyslogEnable "true";
      Unattended-Upgrade::SyslogFacility "daemon";

      // Package blacklist (never auto-update these)
      Unattended-Upgrade::Package-Blacklist {
          "docker-ce";
          "docker-ce-cli";
          "containerd.io";
      };

  - path: /etc/apt/apt.conf.d/20auto-upgrades
    permissions: '0644'
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Download-Upgradeable-Packages "1";
      APT::Periodic::Unattended-Upgrade "1";
      APT::Periodic::AutocleanInterval "7";
```

**Rationale:** Docker packages are blacklisted from auto-updates to prevent unexpected container runtime changes. Docker upgrades must be tested and applied manually. Security patches for the base OS are applied automatically.

### 2.7 Time Synchronization (chrony)

Accurate time is critical for log correlation, TLS certificate validation, and audit trails.

```yaml
# cloud-init
packages:
  - chrony

write_files:
  - path: /etc/chrony/chrony.conf
    permissions: '0644'
    content: |
      # Use Hetzner's NTP servers (low latency)
      server ntp1.hetzner.de iburst
      server ntp2.hetzner.com iburst
      server ntp3.hetzner.net iburst

      # Fallback to public NTP pool
      pool 2.debian.pool.ntp.org iburst

      # Record the rate at which the system clock gains/losses time
      driftfile /var/lib/chrony/chrony.drift

      # Allow the system clock to be stepped in the first three updates
      # if its offset is larger than 1 second
      makestep 1.0 3

      # Enable kernel synchronization of the real-time clock (RTC)
      rtcsync

      # Log statistics
      logdir /var/log/chrony
      log measurements statistics tracking

      # Restrict command access to localhost
      bindcmdaddress 127.0.0.1
      bindcmdaddress ::1

      # Deny NTP client access
      deny all

runcmd:
  - systemctl disable systemd-timesyncd 2>/dev/null || true
  - systemctl enable chrony
  - systemctl start chrony
```

### 2.8 Disable Unnecessary Services and Kernel Modules

```yaml
# cloud-init runcmd
runcmd:
  # Disable unnecessary services
  - systemctl disable --now snapd.service 2>/dev/null || true
  - systemctl disable --now snapd.socket 2>/dev/null || true
  - systemctl disable --now avahi-daemon.service 2>/dev/null || true
  - systemctl disable --now cups.service 2>/dev/null || true
  - systemctl disable --now bluetooth.service 2>/dev/null || true
  - systemctl disable --now ModemManager.service 2>/dev/null || true

  # Disable unnecessary kernel modules
  - |
    cat > /etc/modprobe.d/runclaw-disable.conf << 'EOF'
    # Disable uncommon network protocols
    install dccp /bin/true
    install sctp /bin/true
    install rds /bin/true
    install tipc /bin/true
    # Disable uncommon filesystems
    install cramfs /bin/true
    install freevfat /bin/true
    install jffs2 /bin/true
    install hfs /bin/true
    install hfsplus /bin/true
    install squashfs /bin/true
    install udf /bin/true
    # Disable USB storage (VPS has no USB)
    install usb-storage /bin/true
    # Disable Firewire
    install firewire-core /bin/true
    # Disable Bluetooth
    install bluetooth /bin/true
    install btusb /bin/true
    EOF
```

**Rationale:** Every running service and loaded kernel module is an attack surface. VPS instances do not need Bluetooth, USB storage, CUPS, Avahi, or uncommon network protocols.

---

## 3. SSH Hardening (Beyond Basics)

### 3.1 Ed25519 Keys Only (Disable RSA)

```yaml
# cloud-init write_files
write_files:
  - path: /etc/ssh/sshd_config.d/10-runclaw-hardening.conf
    permissions: '0600'
    content: |
      # === Key Exchange and Ciphers ===
      # Only allow modern, strong algorithms
      KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
      Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
      MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
      HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

      # === Authentication ===
      # Ed25519 keys only (disable RSA host keys)
      HostKey /etc/ssh/ssh_host_ed25519_key
      # Explicitly do NOT list RSA or ECDSA host keys

      PubkeyAuthentication yes
      PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
      PasswordAuthentication no
      PermitEmptyPasswords no
      ChallengeResponseAuthentication no
      KbdInteractiveAuthentication no
      UsePAM yes

      # === Access Control ===
      PermitRootLogin no
      AllowUsers openclaw
      AllowGroups openclaw

      # === Login Limits ===
      MaxAuthTries 2
      LoginGraceTime 20
      MaxSessions 3
      MaxStartups 3:50:10

      # === Features ===
      X11Forwarding no
      AllowAgentForwarding no
      # Allow TCP forwarding for SSH tunnels to gateway
      AllowTcpForwarding yes
      PermitTunnel no
      GatewayPorts no

      # === Logging ===
      LogLevel VERBOSE
      SyslogFacility AUTH

      # === Session ===
      ClientAliveInterval 300
      ClientAliveCountMax 2
      TCPKeepAlive no
      UseDNS no

      # === Banner ===
      Banner /etc/issue.net

runcmd:
  # Remove non-Ed25519 host keys
  - rm -f /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pub
  - rm -f /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ecdsa_key.pub
  - rm -f /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub

  # Regenerate Ed25519 host key if not present
  - |
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
      ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    fi

  # Validate and restart
  - sshd -t && systemctl restart sshd
```

**Rationale:** RSA keys are larger, slower, and require careful parameter choices to remain secure. Ed25519 provides better security with shorter keys and faster operations. The `sntrup761x25519-sha512` key exchange is post-quantum resistant.

### 3.2 Port Randomization

Using a non-standard SSH port reduces noise from automated scanners:

```yaml
# In the same sshd_config.d/10-runclaw-hardening.conf
# Add at the top:

# Use a random high port (generated per-instance by cloud-init)
Port {SSH_PORT}
```

**Generate a random SSH port in cloud-init template:**

```typescript
// lib/cloud-init.ts
function generateSshPort(): number {
  // Random port between 20000-60000
  return 20000 + Math.floor(Math.random() * 40000);
}
```

**Update Hetzner firewall rule to match:**

The Hetzner firewall rule for SSH must use the same random port. Pass it as a label so the control plane can retrieve it for admin access:

```typescript
labels: {
  'managed-by': 'runclaw',
  'ssh-port': String(sshPort)
}
```

**Update UFW in cloud-init:**

```yaml
runcmd:
  - ufw allow {SSH_PORT}/tcp comment 'SSH (randomized port)'
  # Do NOT allow port 22
```

**Rationale:** Port randomization is security through obscurity and is not a substitute for proper authentication. However, it eliminates 99% of automated SSH brute force attempts, reducing log noise and fail2ban load.

### 3.3 AllowUsers/AllowGroups Restrictions

Covered in section 3.1 above. Only the `openclaw` user and group are permitted. The `root` user is denied via `PermitRootLogin no`.

### 3.4 MaxAuthTries, LoginGraceTime Tuning

Covered in section 3.1 above. Settings:

| Parameter       | Value | Rationale                                           |
|-----------------|-------|-----------------------------------------------------|
| MaxAuthTries    | 2     | An attacker gets 2 tries before disconnection       |
| LoginGraceTime  | 20    | 20 seconds to authenticate before connection drops  |
| MaxSessions     | 3     | Limit concurrent sessions per connection            |
| MaxStartups     | 3:50:10 | Start dropping connections at 3 unauthenticated, 50% drop rate, max 10 |

### 3.5 SSH Certificate-Based Authentication (Admin Access)

For admin access to customer VPS instances, use SSH certificates instead of individual authorized_keys:

**Set up a Certificate Authority (CA) on a secure admin machine:**

```bash
# Generate the CA key (do this ONCE, store securely)
ssh-keygen -t ed25519 -f /secure/runclaw-ssh-ca -C "runclaw-ssh-ca"

# The CA public key goes on every VPS
# /etc/ssh/runclaw-ca.pub
```

**Sign an admin key to create a short-lived certificate:**

```bash
# Sign admin's key for 8 hours
ssh-keygen -s /secure/runclaw-ssh-ca \
  -I "admin-$(whoami)-$(date +%Y%m%d%H%M)" \
  -n openclaw \
  -V +8h \
  -z "$(date +%s)" \
  ~/.ssh/runclaw-admin.pub

# This creates ~/.ssh/runclaw-admin-cert.pub
# The certificate is valid for 8 hours only
```

**Configure VPS to trust the CA:**

```yaml
# cloud-init write_files
write_files:
  - path: /etc/ssh/runclaw-ca.pub
    permissions: '0644'
    content: |
      {SSH_CA_PUBLIC_KEY}

# In sshd_config.d/10-runclaw-hardening.conf, add:
# TrustedUserCAKeys /etc/ssh/runclaw-ca.pub
# AuthorizedPrincipalsFile /etc/ssh/authorized_principals
```

```yaml
write_files:
  - path: /etc/ssh/authorized_principals
    permissions: '0644'
    content: |
      openclaw
```

**Rationale:** Certificate-based auth eliminates the need to distribute and manage individual public keys across hundreds of VPS instances. Certificates can be short-lived (8 hours), reducing the window of exposure if an admin key is compromised.

### 3.6 Bastion Host Pattern for Admin Access

Admin access to customer VPS instances should go through a bastion (jump host):

```
Admin Laptop --> Bastion Host (runclaw-internal project) --> Customer VPS
```

**Bastion host setup (in Hetzner `runclaw-internal` project):**

```bash
# Bastion host has:
# - Hardened SSH (same config as customer VPS)
# - No Docker, no customer data
# - Audit logging of all SSH sessions
# - IP allowlist for admin IPs only
# - 2FA (via SSH + TOTP or hardware key)
```

**SSH config for admin laptops:**

```
# ~/.ssh/config
Host runclaw-bastion
    HostName <bastion-ip>
    User admin
    Port <bastion-ssh-port>
    IdentityFile ~/.ssh/runclaw-admin
    CertificateFile ~/.ssh/runclaw-admin-cert.pub

Host runclaw-vps-*
    ProxyJump runclaw-bastion
    User openclaw
    IdentityFile ~/.ssh/runclaw-admin
    CertificateFile ~/.ssh/runclaw-admin-cert.pub
```

**Connect to a customer VPS:**

```bash
# Through the bastion
ssh runclaw-vps-<instance-ip>
```

### 3.7 SSH Audit Logging

Already covered by the auditd rules in section 2.5. Additionally, SSH is configured with `LogLevel VERBOSE` in section 3.1, which logs key fingerprints used for authentication.

**Verify SSH logging:**

```bash
# Check auth log for SSH events
journalctl -u ssh --since "1 hour ago" | grep "Accepted\|Failed\|Invalid"

# Check auditd for SSH config changes
ausearch -k sshd-config --start today
```

---

## 4. Firewall Configuration

### 4.1 UFW Rules (Detailed)

```yaml
# cloud-init runcmd
runcmd:
  # Reset to clean state
  - ufw --force reset

  # Default policies: deny all inbound, allow all outbound
  - ufw default deny incoming
  - ufw default allow outgoing

  # SSH (randomized port, rate limited)
  - ufw limit {SSH_PORT}/tcp comment 'SSH rate-limited'

  # HTTP (Caddy - for Let's Encrypt ACME and HTTP->HTTPS redirect)
  - ufw allow 80/tcp comment 'HTTP (Caddy)'

  # HTTPS (Caddy TLS termination)
  - ufw allow 443/tcp comment 'HTTPS (Caddy)'

  # Deny common attack ports explicitly (for logging)
  - ufw deny 23/tcp comment 'Deny telnet'
  - ufw deny 3389/tcp comment 'Deny RDP'
  - ufw deny 5900/tcp comment 'Deny VNC'

  # Enable UFW
  - ufw --force enable

  # Enable UFW logging
  - ufw logging medium
```

### 4.2 iptables/nftables Rate Limiting Rules

UFW's `limit` only applies to SSH. Add additional rate limiting with nftables:

```yaml
# cloud-init write_files
write_files:
  - path: /etc/nftables.d/runclaw-ratelimit.conf
    permissions: '0644'
    content: |
      # Rate limiting rules for RunClaw VPS
      # Applied after UFW rules via nftables

      table inet runclaw_ratelimit {
        chain input {
          type filter hook input priority 10; policy accept;

          # Rate limit new TCP connections to port 443 (150/minute per source IP)
          tcp dport 443 ct state new limit rate over 150/minute burst 50 packets \
            counter drop comment "HTTPS rate limit"

          # Rate limit new TCP connections to port 80 (50/minute per source IP)
          tcp dport 80 ct state new limit rate over 50/minute burst 20 packets \
            counter drop comment "HTTP rate limit"

          # Rate limit ICMP (prevent ping flood)
          ip protocol icmp limit rate over 10/second burst 20 packets \
            counter drop comment "ICMP rate limit"

          # Log dropped packets (sampled to prevent log flood)
          limit rate 5/minute burst 10 packets \
            log prefix "nft-ratelimit-drop: " level warn
        }
      }

runcmd:
  - nft -f /etc/nftables.d/runclaw-ratelimit.conf
```

### 4.3 Docker and iptables Interaction

**This is critical.** Docker manipulates iptables directly and bypasses UFW by default. A port exposed with `-p 0.0.0.0:3000:3000` in docker-compose is accessible from the internet even if UFW blocks port 3000.

**Mitigation 1: Bind to localhost only in docker-compose.yml:**

```yaml
services:
  openclaw:
    # NEVER use "3000:3000" - this exposes to 0.0.0.0
    # ALWAYS bind to 127.0.0.1
    ports:
      - "127.0.0.1:3000:3000"
```

**Mitigation 2: Disable Docker's iptables manipulation:**

```json
// /etc/docker/daemon.json
{
  "iptables": false
}
```

**WARNING:** Disabling Docker iptables requires manual network configuration. For RunClaw, because Caddy runs in the same Docker Compose stack and uses Docker's internal networking to reach the OpenClaw container, we do NOT disable Docker iptables. Instead, we rely on binding to `127.0.0.1` only.

**Mitigation 3: Restrict Docker's FORWARD chain:**

```yaml
# cloud-init runcmd
runcmd:
  # After Docker is running, restrict the DOCKER-USER chain
  - |
    # Wait for Docker to start
    until systemctl is-active docker >/dev/null 2>&1; do sleep 2; done

    # Drop all external traffic to Docker containers by default
    # Only allow established/related connections and traffic from localhost
    iptables -I DOCKER-USER -i eth0 -j DROP
    iptables -I DOCKER-USER -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -I DOCKER-USER -i eth0 -p tcp --dport 80 -j ACCEPT
    iptables -I DOCKER-USER -i eth0 -p tcp --dport 443 -j ACCEPT

    # Save rules to persist across reboots
    apt-get install -y iptables-persistent
    netfilter-persistent save
```

**Rationale:** The DOCKER-USER chain is processed before Docker's own rules. By default-dropping all external traffic and only allowing ports 80/443, we prevent Docker from accidentally exposing internal services to the internet.

### 4.4 Egress Filtering

Restrict outbound connections to prevent data exfiltration and C2 callbacks:

```yaml
# cloud-init runcmd
runcmd:
  # Restrict outbound to necessary destinations only
  - ufw default deny outgoing

  # DNS
  - ufw allow out 53/udp comment 'DNS'
  - ufw allow out 53/tcp comment 'DNS (TCP fallback)'

  # HTTPS outbound (APIs, Docker Hub, npm registry)
  - ufw allow out 443/tcp comment 'HTTPS outbound'

  # HTTP outbound (package repos, ACME challenges)
  - ufw allow out 80/tcp comment 'HTTP outbound'

  # NTP
  - ufw allow out 123/udp comment 'NTP'

  # SMTP (if email notifications are configured)
  # - ufw allow out 587/tcp comment 'SMTP submission'

  # Block all other outbound traffic
  - ufw --force enable
```

**Rationale:** Default deny outbound prevents a compromised container from connecting to arbitrary external hosts for data exfiltration or command-and-control (C2). Only explicitly allowed protocols/ports are permitted.

### 4.5 Connection Tracking Limits

```bash
# /etc/sysctl.d/99-runclaw-conntrack.conf
# Prevent connection tracking table exhaustion (DoS vector)

# Maximum entries in the conntrack table
net.netfilter.nf_conntrack_max = 131072

# Timeout for established TCP connections (1 hour instead of default 5 days)
net.netfilter.nf_conntrack_tcp_timeout_established = 3600

# Timeout for connections in TIME_WAIT
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# Timeout for connections in CLOSE_WAIT
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30

# Timeout for connections in FIN_WAIT
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

# Timeout for UDP connections
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# Hash table size (automatically set to nf_conntrack_max/4)
# net.netfilter.nf_conntrack_buckets = 32768
```

---

## 5. Docker Security

### 5.1 Docker Daemon Configuration

```yaml
# cloud-init write_files
write_files:
  - path: /etc/docker/daemon.json
    permissions: '0644'
    content: |
      {
        "live-restore": true,
        "userland-proxy": false,
        "no-new-privileges": true,
        "userns-remap": "default",
        "log-driver": "json-file",
        "log-opts": {
          "max-size": "10m",
          "max-file": "3",
          "tag": "{{.Name}}/{{.ID}}"
        },
        "storage-driver": "overlay2",
        "default-ulimits": {
          "nofile": {
            "Name": "nofile",
            "Hard": 65536,
            "Soft": 32768
          },
          "nproc": {
            "Name": "nproc",
            "Hard": 4096,
            "Soft": 2048
          }
        },
        "icc": false,
        "default-address-pools": [
          {
            "base": "172.17.0.0/16",
            "size": 24
          }
        ]
      }
```

**Key settings explained:**

| Setting | Value | Rationale |
|---------|-------|-----------|
| `userns-remap` | `default` | Maps container root to an unprivileged host user. Container root (UID 0) becomes a high-numbered UID on the host. |
| `no-new-privileges` | `true` | Prevents processes from gaining additional privileges via SUID binaries or `execve()`. |
| `icc` | `false` | Disables inter-container communication on the default bridge network. Containers must use explicit links or custom networks. |
| `userland-proxy` | `false` | Uses iptables for port forwarding instead of a userland proxy. Better performance and fewer attack surfaces. |
| `live-restore` | `true` | Keeps containers running when the Docker daemon is restarted (for daemon upgrades). |

### 5.2 Container Resource Limits

```yaml
# docker-compose.yml (production)
services:
  caddy:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
          pids: 100
        reservations:
          memory: 64M
    ulimits:
      nofile:
        soft: 8192
        hard: 16384

  openclaw:
    deploy:
      resources:
        limits:
          cpus: '1.5'
          memory: 3G
          pids: 512
        reservations:
          memory: 512M
    ulimits:
      nofile:
        soft: 32768
        hard: 65536
      nproc:
        soft: 2048
        hard: 4096
```

**PID limit rationale:** A `pids` limit of 512 for OpenClaw prevents fork bombs. If a subprocess spawns uncontrollably, it will be killed rather than consuming all host PIDs.

### 5.3 Read-Only Root Filesystem

```yaml
services:
  caddy:
    image: caddy:2-alpine
    read_only: true
    tmpfs:
      - /tmp:size=64M,mode=1777
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config

  openclaw:
    image: openclaw/openclaw:latest
    read_only: true
    tmpfs:
      - /tmp:size=256M,mode=1777
      - /home/node/.cache:size=512M,mode=700
    volumes:
      - openclaw_data:/app/data:rw
```

**Rationale:** A read-only root filesystem prevents an attacker who gains code execution inside a container from modifying binaries, installing backdoors, or altering configuration. Writable areas are limited to explicit tmpfs mounts and named volumes.

### 5.4 Docker Socket Protection

**Never mount the Docker socket into any container.**

```yaml
# BAD - never do this
services:
  openclaw:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # CRITICAL VULNERABILITY

# GOOD - no socket mount
services:
  openclaw:
    volumes:
      - openclaw_data:/app/data
```

**Verify no socket mount is present:**

```bash
# Check running containers for docker.sock mounts
docker inspect $(docker ps -q) \
  --format '{{.Name}}: {{range .Mounts}}{{if eq .Source "/var/run/docker.sock"}}ALERT: docker.sock mounted!{{end}}{{end}}'
```

**Rationale:** Access to the Docker socket is equivalent to root on the host. Any container with the Docker socket can create privileged containers, mount the host filesystem, and execute arbitrary commands as root.

### 5.5 Image Verification and Signing

Enable Docker Content Trust (DCT) to verify image signatures:

```yaml
# cloud-init runcmd
runcmd:
  # Enable Docker Content Trust globally
  - echo 'DOCKER_CONTENT_TRUST=1' >> /etc/environment

  # Pin image digests in docker-compose.yml for production
  # (see below)
```

**Use pinned image digests in production docker-compose.yml:**

```yaml
services:
  caddy:
    # Pin to a specific verified digest instead of a mutable tag
    image: caddy:2-alpine@sha256:<DIGEST>

  openclaw:
    image: openclaw/openclaw:latest@sha256:<DIGEST>
```

**Update procedure:**

```bash
# Pull and verify new image
DOCKER_CONTENT_TRUST=1 docker pull openclaw/openclaw:latest

# Get the digest
docker inspect openclaw/openclaw:latest --format '{{index .RepoDigests 0}}'

# Update docker-compose.yml with the new digest
```

### 5.6 Container Network Isolation

```yaml
# docker-compose.yml
services:
  caddy:
    networks:
      - frontend
      - backend

  openclaw:
    networks:
      - backend

networks:
  frontend:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: "br-frontend"
    ipam:
      config:
        - subnet: 172.20.0.0/24

  backend:
    driver: bridge
    internal: true  # No external access from this network
    driver_opts:
      com.docker.network.bridge.name: "br-backend"
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

**Network topology:**

```
Internet --> :80/:443 --> Caddy (frontend + backend networks)
                              |
                              +--> [internal bridge] --> OpenClaw (backend network only)
```

**Rationale:** The `internal: true` flag on the backend network prevents the OpenClaw container from making direct outbound connections. All external traffic must go through Caddy. This limits the blast radius of a compromised OpenClaw container.

### 5.7 Docker Logging Driver Configuration

Already configured in section 5.1 daemon.json. Additional per-container logging:

```yaml
services:
  caddy:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
        tag: "caddy/{{.ID}}"

  openclaw:
    logging:
      driver: json-file
      options:
        max-size: "25m"
        max-file: "5"
        tag: "openclaw/{{.ID}}"
```

### 5.8 Seccomp and AppArmor Profiles for Containers

**Custom seccomp profile for OpenClaw:**

```yaml
# cloud-init write_files
write_files:
  - path: /opt/openclaw/seccomp-openclaw.json
    permissions: '0644'
    content: |
      {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "architectures": [
          "SCMP_ARCH_X86_64",
          "SCMP_ARCH_AARCH64"
        ],
        "syscalls": [
          {
            "names": [
              "accept", "accept4", "access", "arch_prctl", "bind",
              "brk", "capget", "capset", "chdir", "chown", "clock_getres",
              "clock_gettime", "clock_nanosleep", "clone", "clone3", "close",
              "connect", "copy_file_range", "dup", "dup2", "dup3",
              "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait",
              "eventfd", "eventfd2", "execve", "execveat", "exit",
              "exit_group", "faccessat", "faccessat2", "fadvise64",
              "fallocate", "fchmod", "fchmodat", "fchown", "fchownat",
              "fcntl", "fdatasync", "flock", "fstat", "fstatfs",
              "fsync", "ftruncate", "futex", "getcwd", "getdents",
              "getdents64", "getegid", "geteuid", "getgid", "getgroups",
              "getpeername", "getpgid", "getpgrp", "getpid", "getppid",
              "getpriority", "getrandom", "getresgid", "getresuid",
              "getrlimit", "getrusage", "getsid", "getsockname",
              "getsockopt", "gettid", "gettimeofday", "getuid",
              "inotify_add_watch", "inotify_init", "inotify_init1",
              "inotify_rm_watch", "ioctl", "kill", "lchown", "lgetxattr",
              "link", "linkat", "listen", "lseek", "lstat",
              "madvise", "membarrier", "memfd_create", "mincore",
              "mkdir", "mkdirat", "mlock", "mlock2", "mmap",
              "mprotect", "mremap", "munlock", "munmap", "nanosleep",
              "newfstatat", "open", "openat", "openat2", "pipe",
              "pipe2", "poll", "ppoll", "prctl", "pread64",
              "preadv", "preadv2", "prlimit64", "pselect6", "pwrite64",
              "pwritev", "pwritev2", "read", "readahead", "readlink",
              "readlinkat", "readv", "recv", "recvfrom", "recvmmsg",
              "recvmsg", "rename", "renameat", "renameat2", "restart_syscall",
              "rmdir", "rseq", "rt_sigaction", "rt_sigpending",
              "rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn",
              "rt_sigsuspend", "rt_sigtimedwait", "sched_getaffinity",
              "sched_getattr", "sched_getparam", "sched_get_priority_max",
              "sched_get_priority_min", "sched_getscheduler",
              "sched_setaffinity", "sched_yield", "seccomp", "select",
              "semget", "semop", "semtimedop", "send", "sendfile",
              "sendmmsg", "sendmsg", "sendto", "set_robust_list",
              "set_tid_address", "setgid", "setgroups", "setitimer",
              "setpgid", "setpriority", "setresgid", "setresuid",
              "setsid", "setsockopt", "setuid", "shutdown", "sigaltstack",
              "socket", "socketpair", "splice", "stat", "statfs",
              "statx", "symlink", "symlinkat", "sysinfo", "tee",
              "tgkill", "time", "timer_create", "timer_delete",
              "timer_getoverrun", "timer_gettime", "timer_settime",
              "timerfd_create", "timerfd_gettime", "timerfd_settime",
              "tkill", "truncate", "umask", "uname", "unlink",
              "unlinkat", "utimensat", "vfork", "wait4", "waitid",
              "write", "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
          }
        ]
      }
```

**Apply in docker-compose.yml:**

```yaml
services:
  openclaw:
    security_opt:
      - no-new-privileges:true
      - seccomp=/opt/openclaw/seccomp-openclaw.json
      - apparmor=docker-openclaw
```

**Rationale:** The seccomp profile uses an allowlist approach. Only system calls that Node.js and OpenClaw actually need are permitted. Dangerous syscalls like `mount`, `ptrace`, `reboot`, `kexec_load`, and `init_module` are blocked by default.

---

## 6. Caddy Reverse Proxy Hardening

### 6.1 TLS Configuration

```
# /opt/openclaw/Caddyfile

{
    # Global options
    email admin@runclaw.io

    # TLS settings
    default_sni {$SUBDOMAIN}.runclaw.io

    # Disable admin API in production
    admin off

    # Logging
    log {
        output file /data/caddy-global.log {
            roll_size 10mb
            roll_keep 5
            roll_keep_for 168h
        }
        format json
        level WARN
    }

    # OCSP stapling is enabled by default in Caddy
    # Prefer server cipher suites
    servers {
        protocols h1 h2
        strict_sni_host on
    }
}

{$SUBDOMAIN}.runclaw.io {
    # TLS configuration
    tls {
        protocols tls1.3
        curves x25519 secp384r1
        alpn h2 http/1.1
    }

    # Reverse proxy to OpenClaw
    reverse_proxy openclaw:3000 {
        # Health check for upstream
        health_uri /health
        health_interval 30s
        health_timeout 5s
        health_status 200

        # Timeouts
        transport http {
            dial_timeout 5s
            response_header_timeout 30s
            read_timeout 120s
            write_timeout 120s
        }

        # Pass real client IP
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    # Security headers
    header {
        # HSTS (2 years, includeSubDomains, preload-ready)
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

        # Prevent MIME type sniffing
        X-Content-Type-Options "nosniff"

        # Clickjacking protection
        X-Frame-Options "DENY"

        # XSS protection (legacy browsers)
        X-XSS-Protection "1; mode=block"

        # Referrer policy
        Referrer-Policy "strict-origin-when-cross-origin"

        # Content Security Policy
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' wss: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

        # Permissions Policy (disable browser features not needed)
        Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"

        # Remove server identification
        -Server
        -X-Powered-By
    }

    # Request size limit (16MB)
    request_body {
        max_size 16MB
    }

    # Access logging
    log {
        output file /data/access.log {
            roll_size 10mb
            roll_keep 10
            roll_keep_for 720h
        }
        format json {
            time_format iso8601
        }
    }

    # Health endpoint (no auth, no logging)
    handle /health {
        respond "OK" 200
    }

    # Error pages (no information disclosure)
    handle_errors {
        respond "{err.status_code} {err.status_text}" {err.status_code}
    }
}
```

### 6.2 Security Headers Details

| Header | Value | Rationale |
|--------|-------|-----------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Forces HTTPS for 2 years. Prevents SSL stripping attacks. |
| `X-Content-Type-Options` | `nosniff` | Prevents browsers from MIME-type guessing. Blocks drive-by downloads. |
| `X-Frame-Options` | `DENY` | Prevents clickjacking by disallowing embedding in iframes. |
| `Content-Security-Policy` | See above | Restricts what resources the browser can load. Prevents XSS and injection. |
| `Permissions-Policy` | Camera, mic, geo all disabled | Prevents malicious scripts from accessing device sensors. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer information leaked to third-party sites. |

### 6.3 Rate Limiting Configuration

```
# Add to the Caddyfile site block

{$SUBDOMAIN}.runclaw.io {
    # Rate limiting
    @api_endpoints {
        path /api/*
    }

    @auth_endpoints {
        path /api/auth/*
        path /login
    }

    # Strict rate limit on auth endpoints (5 requests per minute)
    rate_limit @auth_endpoints {
        zone auth_zone {
            key {remote_host}
            events 5
            window 60s
        }
    }

    # General API rate limit (60 requests per minute)
    rate_limit @api_endpoints {
        zone api_zone {
            key {remote_host}
            events 60
            window 60s
        }
    }

    # Global rate limit (300 requests per minute per IP)
    rate_limit {
        zone global_zone {
            key {remote_host}
            events 300
            window 60s
        }
    }
}
```

### 6.4 Request Size Limits

Already configured in section 6.1 with `max_size 16MB`. For specific endpoints:

```
# Limit file upload endpoints differently
handle /api/upload/* {
    request_body {
        max_size 50MB
    }
    reverse_proxy openclaw:3000
}

# Limit all other endpoints
handle {
    request_body {
        max_size 1MB
    }
    reverse_proxy openclaw:3000
}
```

### 6.5 Caddy Admin API Disabled

Already configured in section 6.1 with `admin off` in the global options block.

**Rationale:** The Caddy admin API (default port 2019) allows runtime configuration changes. In production, configuration is file-based and should not be modifiable at runtime.

---

## 7. Cloudflare Configuration

### 7.1 WAF Rules (OWASP Core Rule Set)

**Enable via Cloudflare API:**

```bash
# Enable Cloudflare WAF managed rules
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/firewall/waf/packages" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "sensitivity": "high",
    "action_mode": "challenge"
  }'
```

**Recommended WAF rule groups to enable:**

| Rule Group | Action | Description |
|------------|--------|-------------|
| OWASP ModSecurity Core Rule Set | Challenge/Block | SQL injection, XSS, path traversal |
| Cloudflare Managed Ruleset | Block | Known attack patterns |
| Cloudflare OWASP Core Ruleset | Challenge | Generic web attacks |

**Custom WAF rules for RunClaw:**

```bash
# Block common vulnerability scanners
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/firewall/rules" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "filter": {
        "expression": "(http.request.uri.path contains \"/wp-admin\") or (http.request.uri.path contains \"/wp-login\") or (http.request.uri.path contains \"/.env\") or (http.request.uri.path contains \"/phpinfo\") or (http.request.uri.path contains \"/xmlrpc.php\") or (http.request.uri.path contains \"/phpmyadmin\")",
        "description": "Block common scan targets"
      },
      "action": "block"
    },
    {
      "filter": {
        "expression": "(http.request.uri.path contains \"/.git\") or (http.request.uri.path contains \"/.svn\") or (http.request.uri.path contains \"/.hg\")",
        "description": "Block version control exposure"
      },
      "action": "block"
    }
  ]'
```

### 7.2 Bot Management

```bash
# Configure Bot Management (requires Cloudflare Pro+)
# Set Super Bot Fight Mode rules

curl -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/bot_management" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "fight_mode": true,
    "enable_js": true,
    "optimize_wordpress": false,
    "sbfm_definitely_automated": "block",
    "sbfm_likely_automated": "managed_challenge",
    "sbfm_verified_bots": "allow",
    "sbfm_static_resource_protection": false
  }'
```

### 7.3 DDoS Protection Settings

```bash
# Enable advanced DDoS protection
curl -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/security_level" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "medium"}'

# Set challenge passage TTL (how long a solved challenge is valid)
curl -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/challenge_ttl" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": 1800}'

# Enable Under Attack Mode programmatically during an incident
# curl -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/security_level" \
#   -H "Authorization: Bearer ${CF_TOKEN}" \
#   -d '{"value": "under_attack"}'
```

### 7.4 SSL/TLS Mode (Full Strict)

```bash
# Set SSL mode to Full (Strict)
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/ssl" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "strict"}'

# Enable TLS 1.3
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/tls_1_3" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "on"}'

# Set minimum TLS version to 1.2
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/min_tls_version" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "1.2"}'

# Enable Automatic HTTPS Rewrites
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/automatic_https_rewrites" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "on"}'

# Enable Always Use HTTPS
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/always_use_https" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"value": "on"}'
```

**Rationale:** Full (Strict) mode validates the origin server's TLS certificate. This prevents MITM attacks between Cloudflare and the Hetzner VPS. Caddy handles the origin certificate via Let's Encrypt.

### 7.5 Page Rules for Security

```bash
# Create page rules
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/pagerules" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "*.runclaw.io/*"}}],
    "actions": [
      {"id": "ssl", "value": "strict"},
      {"id": "always_use_https", "value": "on"},
      {"id": "browser_check", "value": "on"},
      {"id": "security_level", "value": "medium"},
      {"id": "cache_level", "value": "aggressive"}
    ],
    "status": "active",
    "priority": 1
  }'

# Disable caching for API endpoints
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/pagerules" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "*.runclaw.io/api/*"}}],
    "actions": [
      {"id": "cache_level", "value": "bypass"},
      {"id": "security_level", "value": "high"}
    ],
    "status": "active",
    "priority": 2
  }'
```

### 7.6 Firewall Rules (Geo-Blocking, IP Reputation)

```bash
# Block traffic from countries with no expected users (adjust to your user base)
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/firewall/rules" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "filter": {
        "expression": "(ip.geoip.country in {\"CN\" \"RU\" \"KP\" \"IR\"}) and not (cf.client.bot)",
        "description": "Challenge high-risk geolocations"
      },
      "action": "managed_challenge"
    },
    {
      "filter": {
        "expression": "(cf.threat_score gt 30)",
        "description": "Block high threat score IPs"
      },
      "action": "block"
    },
    {
      "filter": {
        "expression": "(cf.threat_score gt 14) and (cf.threat_score le 30)",
        "description": "Challenge medium threat score IPs"
      },
      "action": "managed_challenge"
    }
  ]'
```

### 7.7 Rate Limiting at Edge

```bash
# Rate limit at Cloudflare edge (before traffic reaches origin)
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/rate_limits" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "match": {
      "request": {
        "url_pattern": "*.runclaw.io/api/*",
        "schemes": ["HTTPS"],
        "methods": ["POST", "PUT", "DELETE", "PATCH"]
      }
    },
    "threshold": 30,
    "period": 60,
    "action": {
      "mode": "challenge",
      "timeout": 3600
    },
    "enabled": true,
    "description": "Rate limit API mutations"
  }'

# Strict rate limit on health endpoints to prevent abuse
curl -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/rate_limits" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "match": {
      "request": {
        "url_pattern": "*.runclaw.io/health",
        "schemes": ["HTTPS"]
      }
    },
    "threshold": 10,
    "period": 60,
    "action": {
      "mode": "simulate",
      "timeout": 60
    },
    "enabled": true,
    "description": "Rate limit health checks"
  }'
```

### 7.8 Origin Server Protection

Prevent direct IP access that bypasses Cloudflare:

**Step 1: Restrict Hetzner firewall to Cloudflare IPs only for HTTP/HTTPS:**

```bash
# Fetch current Cloudflare IP ranges
CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4)
CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6)

# Update Hetzner firewall rules to only allow Cloudflare IPs on 80/443
# Build the source_ips array
CF_IPS_JSON=$(echo "${CF_IPV4}" | jq -R -s 'split("\n") | map(select(length > 0))')
CF_IPV6_JSON=$(echo "${CF_IPV6}" | jq -R -s 'split("\n") | map(select(length > 0))')
ALL_CF_IPS=$(echo "${CF_IPS_JSON} ${CF_IPV6_JSON}" | jq -s 'add')

echo "Cloudflare IP ranges for firewall rules:"
echo "${ALL_CF_IPS}" | jq .
```

**Step 2: Configure Caddy to reject non-Cloudflare traffic:**

```
# In Caddyfile - reject direct IP access
:80, :443 {
    @not_cloudflare {
        not remote_ip 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
    }
    respond @not_cloudflare "Access denied" 403
}
```

**Rationale:** If an attacker discovers the origin IP address (via DNS history, certificate transparency logs, etc.), they can bypass all Cloudflare protections. Restricting origin access to Cloudflare IPs only ensures all traffic goes through the WAF.

---

## 8. Monitoring and Alerting

### 8.1 System Metrics Collection

Install node_exporter for Prometheus-compatible metrics:

```yaml
# cloud-init
write_files:
  - path: /opt/monitoring/docker-compose.monitoring.yml
    permissions: '0644'
    content: |
      services:
        node-exporter:
          image: prom/node-exporter:latest
          restart: unless-stopped
          read_only: true
          pid: host
          network_mode: host
          volumes:
            - /proc:/host/proc:ro
            - /sys:/host/sys:ro
            - /:/rootfs:ro
          command:
            - '--path.procfs=/host/proc'
            - '--path.rootfs=/rootfs'
            - '--path.sysfs=/host/sys'
            - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
            - '--web.listen-address=127.0.0.1:9100'
            - '--collector.processes'
            - '--collector.conntrack'
            - '--collector.systemd'
          deploy:
            resources:
              limits:
                cpus: '0.1'
                memory: 128M
          security_opt:
            - no-new-privileges:true

runcmd:
  - cd /opt/monitoring && docker compose -f docker-compose.monitoring.yml up -d
```

**Key metrics to collect:**

| Metric | Alert Threshold | Description |
|--------|----------------|-------------|
| `node_cpu_seconds_total` | > 80% sustained 5min | CPU saturation |
| `node_memory_MemAvailable_bytes` | < 256MB | Memory pressure |
| `node_filesystem_avail_bytes` | < 10% free | Disk filling up |
| `node_netstat_Tcp_CurrEstab` | > 500 | Connection count anomaly |
| `node_load1` | > 2x CPU cores | Load average spike |
| `node_network_receive_bytes_total` | > 100MB/min sustained | Potential data exfiltration or DDoS |

### 8.2 Log Aggregation Strategy

```yaml
# cloud-init write_files
write_files:
  - path: /opt/monitoring/promtail-config.yml
    permissions: '0644'
    content: |
      server:
        http_listen_port: 9080
        grpc_listen_port: 0
        http_listen_address: 127.0.0.1

      positions:
        filename: /tmp/positions.yaml

      clients:
        - url: ${LOKI_PUSH_URL}
          tenant_id: ${INSTANCE_ID}
          basic_auth:
            username: ${LOKI_USERNAME}
            password: ${LOKI_PASSWORD}

      scrape_configs:
        - job_name: system
          static_configs:
            - targets: [localhost]
              labels:
                job: varlogs
                host: ${HOSTNAME}
                __path__: /var/log/{syslog,auth.log,kern.log}

        - job_name: docker
          static_configs:
            - targets: [localhost]
              labels:
                job: docker
                host: ${HOSTNAME}
                __path__: /var/lib/docker/containers/*/*.log

        - job_name: caddy
          static_configs:
            - targets: [localhost]
              labels:
                job: caddy
                host: ${HOSTNAME}
                __path__: /opt/openclaw/caddy_data/access.log

        - job_name: audit
          static_configs:
            - targets: [localhost]
              labels:
                job: audit
                host: ${HOSTNAME}
                __path__: /var/log/audit/audit.log
```

### 8.3 Intrusion Detection (Wazuh Agent)

```yaml
# cloud-init
packages:
  - curl
  - apt-transport-https

runcmd:
  # Install Wazuh agent
  - |
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    apt-get update
    WAZUH_MANAGER='{WAZUH_MANAGER_IP}' apt-get install -y wazuh-agent

  # Configure Wazuh agent
  - |
    cat > /var/ossec/etc/ossec.conf << 'WAZUH_EOF'
    <ossec_config>
      <client>
        <server>
          <address>{WAZUH_MANAGER_IP}</address>
          <port>1514</port>
          <protocol>tcp</protocol>
        </server>
        <enrollment>
          <groups>runclaw-vps</groups>
        </enrollment>
      </client>

      <syscheck>
        <!-- File integrity monitoring -->
        <frequency>3600</frequency>
        <directories check_all="yes" realtime="yes">/etc/ssh</directories>
        <directories check_all="yes" realtime="yes">/etc/docker</directories>
        <directories check_all="yes" realtime="yes">/opt/openclaw</directories>
        <directories check_all="yes" realtime="yes">/etc/crontab</directories>
        <directories check_all="yes" realtime="yes">/etc/cron.d</directories>
        <directories check_all="yes">/usr/bin</directories>
        <directories check_all="yes">/usr/sbin</directories>

        <!-- Ignore dynamic/temp files -->
        <ignore>/etc/mtab</ignore>
        <ignore>/etc/resolv.conf</ignore>
        <ignore type="sregex">.log$</ignore>
      </syscheck>

      <rootcheck>
        <disabled>no</disabled>
        <frequency>43200</frequency>
      </rootcheck>

      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/auth.log</location>
      </localfile>

      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/syslog</location>
      </localfile>

      <localfile>
        <log_format>audit</log_format>
        <location>/var/log/audit/audit.log</location>
      </localfile>
    </ossec_config>
    WAZUH_EOF

  - systemctl enable wazuh-agent
  - systemctl start wazuh-agent
```

### 8.4 File Integrity Monitoring

Wazuh handles FIM (see section 8.3). For standalone FIM without Wazuh, use AIDE:

```yaml
# cloud-init
packages:
  - aide

runcmd:
  # Initialize AIDE database
  - aideinit
  - cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

  # Schedule daily AIDE check
  - |
    cat > /etc/cron.daily/aide-check << 'EOF'
    #!/bin/bash
    /usr/bin/aide --check --config /etc/aide/aide.conf > /var/log/aide/aide-check-$(date +%Y%m%d).log 2>&1
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
      echo "AIDE detected filesystem changes on $(hostname)" | \
        logger -t aide-alert -p security.alert
    fi
    EOF
    chmod 755 /etc/cron.daily/aide-check
    mkdir -p /var/log/aide
```

### 8.5 Container Runtime Security (Falco)

```yaml
# cloud-init write_files
write_files:
  - path: /opt/monitoring/falco-rules-runclaw.yaml
    permissions: '0644'
    content: |
      - rule: RunClaw Container Shell Spawned
        desc: Detect shell spawned inside RunClaw containers
        condition: >
          spawned_process and
          container and
          (proc.name in (bash, sh, dash, zsh, csh)) and
          not proc.pname in (node, npm, pnpm) and
          container.name startswith "openclaw"
        output: >
          Shell spawned in RunClaw container
          (user=%user.name command=%proc.cmdline container=%container.name
           image=%container.image.repository)
        priority: WARNING
        tags: [container, shell, runclaw]

      - rule: RunClaw Unexpected Outbound Connection
        desc: Detect unexpected outbound network connections from OpenClaw container
        condition: >
          outbound and
          container and
          container.name startswith "openclaw" and
          not fd.sport in (80, 443, 53)
        output: >
          Unexpected outbound connection from RunClaw container
          (command=%proc.cmdline connection=%fd.name
           container=%container.name)
        priority: WARNING
        tags: [container, network, runclaw]

      - rule: RunClaw Sensitive File Read
        desc: Detect reads of sensitive files inside container
        condition: >
          open_read and
          container and
          container.name startswith "openclaw" and
          (fd.name startswith /etc/shadow or
           fd.name startswith /etc/passwd or
           fd.name startswith /proc/1/environ)
        output: >
          Sensitive file read in RunClaw container
          (user=%user.name command=%proc.cmdline file=%fd.name
           container=%container.name)
        priority: CRITICAL
        tags: [container, filesystem, runclaw]

runcmd:
  # Install Falco
  - |
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
      gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > \
      /etc/apt/sources.list.d/falcosecurity.list
    apt-get update
    apt-get install -y falco

  # Copy custom rules
  - cp /opt/monitoring/falco-rules-runclaw.yaml /etc/falco/rules.d/

  - systemctl enable falco
  - systemctl start falco
```

### 8.6 Alert Thresholds for Suspicious Activity

```yaml
# Alert configuration (for whatever alerting system is used)
# These can feed into PagerDuty, OpsGenie, Slack, or email

alerts:
  critical:
    - name: container_shell_exec
      description: "Shell executed inside production container"
      source: falco
      action: page_oncall

    - name: ssh_brute_force
      description: "More than 10 failed SSH attempts in 5 minutes"
      source: fail2ban
      action: page_oncall

    - name: docker_socket_access
      description: "Docker socket was accessed unexpectedly"
      source: auditd
      action: page_oncall

    - name: file_integrity_change
      description: "Critical system file modified"
      source: aide/wazuh
      action: page_oncall

  warning:
    - name: high_cpu_usage
      description: "CPU usage above 80% for 5+ minutes"
      source: node_exporter
      threshold: "rate(node_cpu_seconds_total{mode='idle'}[5m]) < 0.2"
      action: slack_alert

    - name: low_disk_space
      description: "Disk usage above 85%"
      source: node_exporter
      threshold: "(node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.15"
      action: slack_alert

    - name: high_memory_usage
      description: "Available memory below 256MB"
      source: node_exporter
      threshold: "node_memory_MemAvailable_bytes < 268435456"
      action: slack_alert

    - name: container_restart
      description: "OpenClaw container restarted"
      source: docker
      action: slack_alert

    - name: unusual_outbound_traffic
      description: "Outbound traffic exceeds 100MB/min"
      source: node_exporter
      threshold: "rate(node_network_transmit_bytes_total[1m]) > 104857600"
      action: slack_alert
```

---

## 9. Backup and Recovery

### 9.1 Automated Backup Strategy

```yaml
# cloud-init write_files
write_files:
  - path: /opt/openclaw/scripts/backup.sh
    permissions: '0750'
    content: |
      #!/bin/bash
      set -euo pipefail

      BACKUP_DIR="/opt/openclaw/backups"
      TIMESTAMP=$(date +%Y%m%d_%H%M%S)
      BACKUP_FILE="${BACKUP_DIR}/openclaw-backup-${TIMESTAMP}.tar.gz"
      ENCRYPTED_FILE="${BACKUP_FILE}.enc"
      BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:?BACKUP_ENCRYPTION_KEY must be set}"
      RETENTION_DAYS=30

      # Create backup directory
      mkdir -p "${BACKUP_DIR}"

      echo "[$(date)] Starting backup..."

      # Stop OpenClaw gracefully to ensure data consistency
      cd /opt/openclaw
      docker compose exec -T openclaw kill -SIGTERM 1 2>/dev/null || true
      sleep 5

      # Create compressed archive of customer data
      tar -czf "${BACKUP_FILE}" \
        -C /opt/openclaw \
        openclaw_data/ \
        2>/dev/null || true

      # Restart OpenClaw
      docker compose up -d openclaw

      # Verify backup file exists and is non-empty
      if [ ! -s "${BACKUP_FILE}" ]; then
        echo "[$(date)] ERROR: Backup file is empty or missing"
        exit 1
      fi

      BACKUP_SIZE=$(stat -c%s "${BACKUP_FILE}" 2>/dev/null || stat -f%z "${BACKUP_FILE}")
      echo "[$(date)] Backup created: ${BACKUP_FILE} (${BACKUP_SIZE} bytes)"

      # Encrypt the backup
      openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "${BACKUP_FILE}" \
        -out "${ENCRYPTED_FILE}" \
        -pass env:BACKUP_ENCRYPTION_KEY

      # Remove unencrypted backup
      rm -f "${BACKUP_FILE}"
      echo "[$(date)] Backup encrypted: ${ENCRYPTED_FILE}"

      # Upload to remote storage (S3-compatible)
      if command -v aws >/dev/null 2>&1; then
        aws s3 cp "${ENCRYPTED_FILE}" \
          "s3://${BACKUP_S3_BUCKET}/backups/$(hostname)/" \
          --storage-class STANDARD_IA
        echo "[$(date)] Backup uploaded to S3"
      fi

      # Clean up old local backups
      find "${BACKUP_DIR}" -name "*.enc" -mtime +${RETENTION_DAYS} -delete
      echo "[$(date)] Old backups cleaned (retention: ${RETENTION_DAYS} days)"

      echo "[$(date)] Backup complete"

  - path: /opt/openclaw/scripts/backup-verify.sh
    permissions: '0750'
    content: |
      #!/bin/bash
      set -euo pipefail

      BACKUP_DIR="/opt/openclaw/backups"
      BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:?BACKUP_ENCRYPTION_KEY must be set}"

      # Find the most recent backup
      LATEST_BACKUP=$(ls -t "${BACKUP_DIR}"/*.enc 2>/dev/null | head -1)

      if [ -z "${LATEST_BACKUP}" ]; then
        echo "ERROR: No backups found in ${BACKUP_DIR}"
        exit 1
      fi

      echo "Verifying backup: ${LATEST_BACKUP}"

      # Decrypt to a temp file
      TEMP_FILE=$(mktemp)
      trap "rm -f ${TEMP_FILE}" EXIT

      openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
        -in "${LATEST_BACKUP}" \
        -out "${TEMP_FILE}" \
        -pass env:BACKUP_ENCRYPTION_KEY

      # Verify the tar archive is valid
      tar -tzf "${TEMP_FILE}" > /dev/null 2>&1
      RETVAL=$?

      if [ ${RETVAL} -eq 0 ]; then
        FILE_COUNT=$(tar -tzf "${TEMP_FILE}" | wc -l)
        echo "PASS: Backup is valid (${FILE_COUNT} files)"
      else
        echo "FAIL: Backup archive is corrupted"
        exit 1
      fi
```

**Schedule automated backups via cron:**

```yaml
# cloud-init runcmd
runcmd:
  - |
    # Daily backup at 3:00 AM UTC
    echo "0 3 * * * root BACKUP_ENCRYPTION_KEY='${BACKUP_ENCRYPTION_KEY}' /opt/openclaw/scripts/backup.sh >> /var/log/openclaw-backup.log 2>&1" \
      > /etc/cron.d/openclaw-backup
    chmod 644 /etc/cron.d/openclaw-backup

    # Weekly backup verification on Sundays at 4:00 AM UTC
    echo "0 4 * * 0 root BACKUP_ENCRYPTION_KEY='${BACKUP_ENCRYPTION_KEY}' /opt/openclaw/scripts/backup-verify.sh >> /var/log/openclaw-backup.log 2>&1" \
      > /etc/cron.d/openclaw-backup-verify
    chmod 644 /etc/cron.d/openclaw-backup-verify
```

### 9.2 Backup Encryption at Rest

All backups are encrypted with AES-256-CBC using PBKDF2 key derivation (100,000 iterations). See section 9.1 for the encryption commands.

**Encryption key management:**

```
BACKUP_ENCRYPTION_KEY is:
- Generated per-instance during provisioning
- 64 hex characters (256 bits of entropy)
- Stored in the control plane database (Appwrite), encrypted at rest
- Passed to the VPS via cloud-init (transmitted over HTTPS)
- Stored in /opt/openclaw/.env on the VPS (permissions 600)
- Rotated every 6 months (requires re-encrypting existing backups)
```

**Generate the backup encryption key during provisioning:**

```typescript
// lib/cloud-init.ts
import crypto from 'crypto';

const backupEncryptionKey = crypto.randomBytes(32).toString('hex');
```

### 9.3 Backup Verification Procedures

The verification script (section 9.1) runs weekly and checks:

1. **Existence**: A backup file exists in the backup directory.
2. **Decryptability**: The encrypted backup can be decrypted with the current key.
3. **Integrity**: The decrypted tar archive is valid and lists files without errors.
4. **File count**: The backup contains a reasonable number of files (logged for trending).

**Full restore test (run quarterly on staging):**

```bash
#!/bin/bash
# scripts/backup-restore-test.sh
# Run on a staging VPS to verify full restore capability
set -euo pipefail

BACKUP_FILE="${1:?Usage: backup-restore-test.sh <encrypted-backup-file>}"
BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:?BACKUP_ENCRYPTION_KEY must be set}"
RESTORE_DIR="/tmp/restore-test-$(date +%s)"

echo "=== Full Restore Test ==="
echo "Backup file: ${BACKUP_FILE}"
echo "Restore directory: ${RESTORE_DIR}"

mkdir -p "${RESTORE_DIR}"

# Decrypt
openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
  -in "${BACKUP_FILE}" \
  -out "${RESTORE_DIR}/backup.tar.gz" \
  -pass env:BACKUP_ENCRYPTION_KEY

# Extract
tar -xzf "${RESTORE_DIR}/backup.tar.gz" -C "${RESTORE_DIR}"

# Verify data integrity
echo "Restored files:"
ls -la "${RESTORE_DIR}/openclaw_data/"

# Start OpenClaw with restored data
echo "Starting OpenClaw with restored data..."
docker run --rm -d \
  --name restore-test \
  -v "${RESTORE_DIR}/openclaw_data:/app/data" \
  -p 127.0.0.1:13000:3000 \
  openclaw/openclaw:latest

# Wait for startup
sleep 10

# Health check
if curl -sf http://127.0.0.1:13000/health > /dev/null 2>&1; then
  echo "PASS: Restored instance is healthy"
else
  echo "FAIL: Restored instance failed health check"
fi

# Cleanup
docker stop restore-test 2>/dev/null || true
rm -rf "${RESTORE_DIR}"

echo "=== Restore Test Complete ==="
```

### 9.4 Recovery Time Objectives

| Scenario | RTO (Recovery Time Objective) | RPO (Recovery Point Objective) | Procedure |
|----------|-------------------------------|--------------------------------|-----------|
| Container crash | 30 seconds | 0 (data on host volume) | Docker `restart: unless-stopped` auto-recovers |
| VPS reboot | 2 minutes | 0 (data on disk) | Docker services start automatically via compose restart policy |
| VPS disk failure | 15 minutes | 24 hours (last daily backup) | Provision new VPS, restore from latest backup |
| Hetzner region outage | 30 minutes | 24 hours | Provision in alternate region, restore from S3 backup |
| Complete data loss | 1 hour | 24 hours | Full reprovision + backup restore from S3 |
| Control plane (Vercel) outage | N/A | N/A | Existing VPS instances continue running. No new provisioning until resolved. |

### 9.5 Disaster Recovery Playbook

**Scenario 1: Single VPS failure**

```
1. Detect failure via health check (5 min interval)
2. Control plane marks instance as "unhealthy"
3. After 3 consecutive failures (15 min), trigger recovery:
   a. Attempt VPS reboot via Hetzner API
      curl -X POST "https://api.hetzner.cloud/v1/servers/${SERVER_ID}/actions/reboot" \
        -H "Authorization: Bearer ${HETZNER_API_TOKEN}"
   b. Wait 2 minutes, check health
   c. If still unhealthy:
      - Provision new VPS in same region
      - Restore from latest backup
      - Update DNS to point to new VPS
      - Delete failed VPS
4. Notify customer via email
```

**Scenario 2: Region-wide Hetzner outage**

```
1. Health checks fail for all instances in affected region
2. Detect via monitoring (multiple simultaneous failures)
3. For each affected instance:
   a. Provision new VPS in alternate region (fsn1 -> nbg1, etc.)
   b. Restore from S3 backup (region-independent)
   c. Update Cloudflare DNS to new VPS IP
   d. Verify health
4. Send status page update
5. When original region recovers:
   a. Delete old VPS instances
   b. Optionally migrate back to original region
```

**Scenario 3: Compromised customer VPS**

```
1. Detect via Falco/Wazuh alert or customer report
2. Immediately:
   a. Remove Cloudflare DNS record (stop traffic)
   b. Take Hetzner snapshot for forensic analysis
   c. Create new Hetzner firewall blocking all traffic
   d. Apply the restrictive firewall to the compromised VPS
3. Forensic analysis:
   a. SSH to VPS via bastion host
   b. Collect logs: docker logs, /var/log/audit, /var/log/auth.log
   c. Check for unauthorized processes: ps auxf, netstat -tlnp
   d. Check for unauthorized files: aide --check
4. Recovery:
   a. Provision fresh VPS
   b. Restore from last known good backup (pre-compromise)
   c. Rotate all customer credentials (API keys, tokens)
   d. Update DNS to new VPS
   e. Delete compromised VPS
5. Post-incident:
   a. Write incident report
   b. Update security rules to prevent recurrence
   c. Notify customer of actions taken
```

**Scenario 4: Backup encryption key loss**

```
This is a critical data loss scenario. Prevention is paramount.

Prevention:
- Backup encryption keys are stored in Appwrite (encrypted at rest)
- Keys are also stored in a separate secure vault (1Password, AWS Secrets Manager)
- Key rotation procedure includes updating both storage locations

If key is lost:
- Data in encrypted backups is unrecoverable
- Customer must start fresh
- This is an acceptable trade-off vs. storing unencrypted backups
```

---

## Appendix A: Complete Cloud-Init Template (Hardened)

This is the full cloud-init template incorporating all security measures from this document. Template variables are enclosed in `{VARIABLE_NAME}`.

```yaml
#cloud-config

package_update: true
package_upgrade: true

packages:
  - docker.io
  - docker-compose-v2
  - ufw
  - fail2ban
  - unattended-upgrades
  - apt-listchanges
  - needrestart
  - auditd
  - audispd-plugins
  - chrony
  - aide
  - iptables-persistent
  - jq

# [Include all write_files from sections 2-5]
# [Include all runcmd from sections 2-5]

# Final runcmd steps:
runcmd:
  # ... (all hardening steps from above sections) ...

  # Start Docker and OpenClaw
  - systemctl enable docker
  - systemctl start docker
  - cd /opt/openclaw && docker compose pull
  - cd /opt/openclaw && docker compose up -d

  # Wait for healthy and callback
  - |
    max_attempts=60
    attempt=0
    until curl -sf http://localhost:3000/health > /dev/null 2>&1; do
      attempt=$((attempt + 1))
      if [ $attempt -ge $max_attempts ]; then
        echo "OpenClaw failed to start after $((max_attempts * 5)) seconds"
        exit 1
      fi
      sleep 5
    done

    curl -X POST https://runclaw.io/api/instances/ready \
      -H "Content-Type: application/json" \
      -d "{
        \"instance_id\": \"{INSTANCE_ID}\",
        \"callback_secret\": \"{CALLBACK_SECRET}\",
        \"openclaw_version\": \"latest\"
      }"
```

---

## Appendix B: Security Audit Checklist

Run this checklist quarterly for each production VPS instance.

```
[ ] SSH: Only Ed25519 keys accepted
[ ] SSH: Root login disabled
[ ] SSH: Password auth disabled
[ ] SSH: LogLevel is VERBOSE
[ ] Firewall: UFW enabled with correct rules
[ ] Firewall: Docker DOCKER-USER chain restricts external access
[ ] Firewall: Hetzner Cloud Firewall applied
[ ] Docker: daemon.json has no-new-privileges, userns-remap
[ ] Docker: No containers mount docker.sock
[ ] Docker: All containers have resource limits
[ ] Docker: icc is false
[ ] OS: Kernel parameters match hardening spec
[ ] OS: AppArmor is enforcing for all containers
[ ] OS: auditd is running with correct rules
[ ] OS: unattended-upgrades is enabled
[ ] OS: chrony is syncing time correctly
[ ] OS: No unnecessary services running
[ ] Caddy: TLS 1.3 only
[ ] Caddy: Security headers present and correct
[ ] Caddy: Admin API is disabled
[ ] Cloudflare: SSL mode is Full (Strict)
[ ] Cloudflare: WAF rules are enabled
[ ] Cloudflare: Origin IP is not exposed
[ ] Backups: Running daily
[ ] Backups: Encrypted at rest
[ ] Backups: Last verification passed
[ ] Monitoring: node_exporter running
[ ] Monitoring: Falco or Wazuh running
[ ] Monitoring: Alert routes configured and tested
```

---

## Appendix C: Incident Response Contact Chain

```
1. Automated alert fires (Falco/Wazuh/Prometheus)
2. Alert sent to on-call via PagerDuty/OpsGenie
3. On-call acknowledges within 5 minutes
4. On-call assesses severity:
   - SEV1 (data breach, full compromise): Escalate immediately, invoke playbook
   - SEV2 (service disruption, partial compromise): Begin investigation
   - SEV3 (suspicious activity, anomaly): Log and investigate during business hours
5. All incidents are documented in incident log
6. Post-incident review within 48 hours for SEV1/SEV2
```
