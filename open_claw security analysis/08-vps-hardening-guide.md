# 08 - VPS Hardening Guide (Hetzner + RunClaw.io)

## Overview

This guide provides a comprehensive hardening playbook for deploying OpenClaw on Hetzner Cloud VPS instances via RunClaw.io. Each section addresses a specific hardening area with commands, configuration, and verification steps.

## Pre-Deployment: Hetzner Account Security

### API Token Management

```bash
# Hetzner API tokens should:
# - Be project-scoped (not account-wide)
# - Have minimal permissions (create/delete servers only)
# - Be rotated quarterly
# - Never be committed to source control
```

**Verification**:
- Check Hetzner Console > Security > API Tokens
- Ensure tokens are project-scoped
- Review token last-used timestamps

### SSH Key Setup

```bash
# Generate a dedicated SSH key for RunClaw VPS management
ssh-keygen -t ed25519 -C "runclaw-admin" -f ~/.ssh/runclaw_admin

# Upload to Hetzner (via API or Console)
# This key gets injected into cloud-init
```

## Phase 1: OS Hardening (Cloud-Init)

### 1.1 Create Non-Root User

```yaml
# cloud-init addition: create dedicated openclaw user
users:
  - name: openclaw
    groups: docker
    shell: /bin/bash
    sudo: false  # No sudo access
    ssh_authorized_keys:
      - "<admin-ssh-public-key>"
```

**Rationale**: OpenClaw should never run as root. The dedicated user limits blast radius.

### 1.2 SSH Hardening

```yaml
# cloud-init runcmd additions
runcmd:
  # Disable password authentication
  - sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  - sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

  # Disable root login
  - sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
  - sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

  # Disable X11 forwarding
  - sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config

  # Set max auth tries
  - echo "MaxAuthTries 3" >> /etc/ssh/sshd_config

  # Set login grace time
  - echo "LoginGraceTime 30" >> /etc/ssh/sshd_config

  # Disable empty passwords
  - echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

  # Use only strong algorithms
  - echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org" >> /etc/ssh/sshd_config
  - echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" >> /etc/ssh/sshd_config
  - echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> /etc/ssh/sshd_config

  # Change SSH port (optional, reduces noise)
  - sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

  - systemctl restart sshd
```

**Verification**:
```bash
# Test SSH hardening
ssh -o PreferredAuthentications=password <vps-ip>  # Should fail
ssh root@<vps-ip>  # Should fail
ssh -p 2222 openclaw@<vps-ip>  # Should succeed with key only
```

### 1.3 Firewall Configuration

```yaml
runcmd:
  # UFW firewall
  - ufw default deny incoming
  - ufw default deny outgoing  # Strict: deny outgoing too

  # Allow inbound
  - ufw allow 80/tcp    # HTTP (Caddy redirect)
  - ufw allow 443/tcp   # HTTPS (Caddy)
  - ufw allow 2222/tcp  # SSH (custom port)

  # Allow outbound (minimal)
  - ufw allow out 443/tcp   # HTTPS (API calls, Docker pulls)
  - ufw allow out 80/tcp    # HTTP (package updates)
  - ufw allow out 53/udp    # DNS
  - ufw allow out 53/tcp    # DNS
  - ufw allow out 123/udp   # NTP

  - ufw --force enable
```

**Strict outbound filtering** prevents reverse shells and data exfiltration. If OpenClaw needs to reach specific services (Telegram API, Discord API, etc.), add them:

```bash
# Allow outbound to Telegram API
ufw allow out to 149.154.160.0/20 port 443/tcp

# Allow outbound to Discord API
ufw allow out to any port 443/tcp proto tcp  # Broad but necessary for multiple APIs
```

### 1.4 Fail2ban Configuration

```yaml
write_files:
  - path: /etc/fail2ban/jail.local
    content: |
      [DEFAULT]
      bantime = 3600
      findtime = 600
      maxretry = 3
      banaction = ufw

      [sshd]
      enabled = true
      port = 2222
      filter = sshd
      logpath = /var/log/auth.log
      maxretry = 3
      bantime = 86400

      [caddy-auth]
      enabled = true
      port = 80,443
      filter = caddy-auth
      logpath = /data/access.log
      maxretry = 10
      bantime = 3600

  - path: /etc/fail2ban/filter.d/caddy-auth.conf
    content: |
      [Definition]
      failregex = ^.*"remote_ip":"<HOST>".*"status":40[13].*$
      ignoreregex =
```

### 1.5 Kernel Hardening

```yaml
write_files:
  - path: /etc/sysctl.d/99-security.conf
    content: |
      # IP spoofing protection
      net.ipv4.conf.all.rp_filter = 1
      net.ipv4.conf.default.rp_filter = 1

      # Disable source routing
      net.ipv4.conf.all.accept_source_route = 0
      net.ipv6.conf.all.accept_source_route = 0

      # Disable ICMP redirects
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv6.conf.all.accept_redirects = 0
      net.ipv4.conf.all.send_redirects = 0

      # Enable SYN flood protection
      net.ipv4.tcp_syncookies = 1

      # Log Martian packets
      net.ipv4.conf.all.log_martians = 1

      # Disable IPv6 if not needed
      net.ipv6.conf.all.disable_ipv6 = 1

      # Restrict /proc access
      kernel.hidepid = 2

      # Disable core dumps
      fs.suid_dumpable = 0

runcmd:
  - sysctl -p /etc/sysctl.d/99-security.conf
```

### 1.6 Automatic Security Updates

```yaml
packages:
  - unattended-upgrades
  - apt-listchanges

write_files:
  - path: /etc/apt/apt.conf.d/50unattended-upgrades
    content: |
      Unattended-Upgrade::Allowed-Origins {
          "${distro_id}:${distro_codename}-security";
      };
      Unattended-Upgrade::AutoFixInterruptedDpkg "true";
      Unattended-Upgrade::MinimalSteps "true";
      Unattended-Upgrade::Remove-Unused-Dependencies "true";
      Unattended-Upgrade::Automatic-Reboot "true";
      Unattended-Upgrade::Automatic-Reboot-Time "04:00";

  - path: /etc/apt/apt.conf.d/20auto-upgrades
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
      APT::Periodic::Download-Upgradeable-Packages "1";
      APT::Periodic::AutocleanInterval "7";
```

## Phase 2: Docker Hardening

### 2.1 Docker Daemon Configuration

```yaml
write_files:
  - path: /etc/docker/daemon.json
    content: |
      {
        "live-restore": true,
        "no-new-privileges": true,
        "userns-remap": "default",
        "log-driver": "json-file",
        "log-opts": {
          "max-size": "10m",
          "max-file": "3"
        },
        "storage-driver": "overlay2",
        "default-ulimits": {
          "nofile": {
            "Name": "nofile",
            "Hard": 65536,
            "Soft": 32768
          }
        }
      }
```

### 2.2 Docker Compose Hardening

```yaml
# /opt/openclaw/docker-compose.yml (hardened)
version: "3.8"

services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - openclaw
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

  openclaw:
    image: openclaw/openclaw:latest
    restart: unless-stopped
    volumes:
      - openclaw_data:/home/node/.openclaw
    environment:
      - NODE_ENV=production
      - OPENCLAW_GATEWAY_BIND=loopback
      - OPENCLAW_GATEWAY_TOKEN=${OPENCLAW_GATEWAY_TOKEN}
    read_only: true
    tmpfs:
      - /tmp
      - /home/node/.cache
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

volumes:
  caddy_data:
  caddy_config:
  openclaw_data:
```

### 2.3 Container Image Verification

```bash
# Pin image digests instead of tags
docker pull openclaw/openclaw:latest
docker inspect openclaw/openclaw:latest --format='{{.RepoDigests}}'

# Use the digest in docker-compose.yml:
# image: openclaw/openclaw@sha256:<digest>

# Scan image for vulnerabilities
docker scout cves openclaw/openclaw:latest
# or
trivy image openclaw/openclaw:latest
```

## Phase 3: Caddy Reverse Proxy Hardening

### 3.1 Caddyfile (Production)

```
{
    email admin@runclaw.io

    # OCSP stapling
    ocsp_stapling on

    # Global rate limiting
    order rate_limit before reverse_proxy
}

{SUBDOMAIN}.runclaw.io {
    # Rate limiting
    rate_limit {
        zone dynamic {
            key {remote_host}
            events 100
            window 1m
        }
    }

    # Security headers
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self' wss: ws:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        X-Permitted-Cross-Domain-Policies "none"
    }

    # Remove server identification
    header -Server

    # Reverse proxy to OpenClaw
    reverse_proxy localhost:18789 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}

        # WebSocket support
        transport http {
            read_timeout 300s
            write_timeout 300s
        }
    }

    # Health endpoint (no auth needed)
    handle /health {
        reverse_proxy localhost:18789
    }

    # Access logging
    log {
        output file /data/access.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
```

## Phase 4: OpenClaw Application Hardening

### 4.1 Gateway Configuration

```bash
# Set strong authentication
GATEWAY_TOKEN=$(openssl rand -hex 32)

cat > /opt/openclaw/.env <<EOF
OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}
OPENCLAW_GATEWAY_BIND=loopback
OPENCLAW_GATEWAY_PORT=18789
OPENCLAW_DISABLE_BONJOUR=1
NODE_ENV=production
EOF

chmod 600 /opt/openclaw/.env
```

### 4.2 Security-First OpenClaw Config

```yaml
# /home/node/.openclaw/openclaw.yml (inside container)
gateway:
  bind: loopback
  port: 18789
  auth:
    mode: token
    # Token set via OPENCLAW_GATEWAY_TOKEN env var
  tls:
    enabled: false  # Caddy handles TLS
  controlUi:
    enabled: true
    allowInsecureAuth: false
    dangerouslyDisableDeviceAuth: false
  trustedProxies:
    - "127.0.0.1"
    - "172.17.0.1"  # Docker bridge

channels:
  defaults:
    dmPolicy: pairing
    groupPolicy: allowlist

agents:
  defaults:
    sandbox:
      mode: all
    tools:
      deny:
        - browser
    maxConcurrent: 2
    subagents:
      maxConcurrent: 4

logging:
  redactSensitive: tools

session:
  dmScope: per-channel-peer
```

### 4.3 File Permissions

```bash
# Run inside the container or on the host volume mount
chmod 700 /home/node/.openclaw
chmod 600 /home/node/.openclaw/openclaw.json
chmod 700 /home/node/.openclaw/credentials
chmod 700 /home/node/.openclaw/identity
chmod 600 /home/node/.openclaw/identity/device-auth.json
```

## Phase 5: Monitoring Setup

### 5.1 Log Aggregation

```yaml
# Add to docker-compose.yml
services:
  log-forwarder:
    image: fluent/fluent-bit:latest
    volumes:
      - /var/log:/var/log:ro
      - /opt/openclaw/logs:/openclaw-logs:ro
    environment:
      - OUTPUT_HOST=<log-aggregation-endpoint>
```

### 5.2 Health Check Monitoring

```bash
# Cron job for local health monitoring
cat > /etc/cron.d/openclaw-health <<'EOF'
*/5 * * * * root curl -sf http://localhost:18789/health > /dev/null || systemctl restart docker
EOF
```

### 5.3 Intrusion Detection

```bash
# Install and configure AIDE (Advanced Intrusion Detection Environment)
apt-get install aide
aide --init
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Weekly integrity check
cat > /etc/cron.weekly/aide-check <<'EOF'
#!/bin/bash
aide --check | mail -s "AIDE Report $(hostname)" admin@runclaw.io
EOF
chmod +x /etc/cron.weekly/aide-check
```

## Phase 6: Backup and Recovery

### 6.1 Automated Backups

```bash
# Backup script
cat > /opt/openclaw/backup.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/opt/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Stop OpenClaw briefly for consistent backup
docker compose -f /opt/openclaw/docker-compose.yml stop openclaw

# Backup data volume
docker run --rm \
  -v openclaw_openclaw_data:/data:ro \
  -v "$BACKUP_DIR":/backup \
  alpine tar czf "/backup/openclaw_${TIMESTAMP}.tar.gz" -C /data .

# Restart OpenClaw
docker compose -f /opt/openclaw/docker-compose.yml start openclaw

# Encrypt backup
gpg --symmetric --cipher-algo AES256 \
  --output "$BACKUP_DIR/openclaw_${TIMESTAMP}.tar.gz.gpg" \
  "$BACKUP_DIR/openclaw_${TIMESTAMP}.tar.gz"

# Remove unencrypted backup
rm "$BACKUP_DIR/openclaw_${TIMESTAMP}.tar.gz"

# Retain last 7 days
find "$BACKUP_DIR" -name "*.gpg" -mtime +7 -delete
SCRIPT

chmod 700 /opt/openclaw/backup.sh

# Schedule daily backups
echo "0 3 * * * root /opt/openclaw/backup.sh" > /etc/cron.d/openclaw-backup
```

## Verification Checklist

After deployment, verify every hardening step:

```bash
# SSH
ssh -o PreferredAuthentications=password root@<vps-ip>  # Expect: fail
sshd -T | grep -E "passwordauth|permitroot|maxauth"

# Firewall
ufw status verbose
nmap -sS -p- <vps-ip>  # Only 80, 443, 2222

# Docker
docker inspect openclaw --format='{{.Config.User}}'  # node
docker inspect openclaw --format='{{.HostConfig.Privileged}}'  # false
docker inspect openclaw --format='{{json .HostConfig.CapDrop}}'  # ALL

# OpenClaw
curl -s https://<subdomain>.runclaw.io/health  # 200
wscat -c ws://<vps-ip>:18789  # Fail (loopback only)

# Security headers
curl -sI https://<subdomain>.runclaw.io | grep -i strict-transport

# Security audit
docker exec openclaw openclaw security audit --deep

# Kernel hardening
sysctl net.ipv4.conf.all.rp_filter  # 1
sysctl kernel.hidepid  # 2
```
