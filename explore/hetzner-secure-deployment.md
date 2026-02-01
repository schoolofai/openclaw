# Secure OpenClaw Deployment on Hetzner VPS

This guide provides a security-hardened deployment of OpenClaw Gateway on a Hetzner VPS. It builds on the standard Hetzner deployment guide with additional security measures appropriate for production use.

## Table of Contents

1. [Security Overview](#security-overview)
2. [Prerequisites](#prerequisites)
3. [VPS Provisioning](#vps-provisioning)
4. [Initial Server Hardening](#initial-server-hardening)
5. [Docker Installation](#docker-installation)
6. [OpenClaw Secure Deployment](#openclaw-secure-deployment)
7. [Network Security](#network-security)
8. [Access Methods](#access-methods)
9. [Monitoring & Alerting](#monitoring--alerting)
10. [Maintenance & Updates](#maintenance--updates)
11. [Incident Response](#incident-response)
12. [Security Checklist](#security-checklist)

---

## Security Overview

### Threat Model for VPS Deployment

When running OpenClaw on a remote VPS, the attack surface includes:

| Threat | Impact | Mitigation |
|--------|--------|------------|
| SSH brute force | Server compromise | Key-only auth, fail2ban |
| Network scanning | Service discovery | Firewall, minimal ports |
| Gateway exposure | Unauthorized AI access | Token auth, SSH tunnel |
| Container escape | Host compromise | Rootless Docker, AppArmor |
| Credential theft | Data breach | Encrypted secrets, permissions |
| Supply chain | Malicious dependencies | Pinned versions, audited images |

### Security Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         INTERNET                                  │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Hetzner Cloud   │
                    │     Firewall      │
                    │   (Port 22 only)  │
                    └─────────┬─────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────┐
│                        HETZNER VPS                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    UFW Firewall                             │  │
│  │            SSH (22) + Loopback (18789)                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                   Docker (Rootless)                         │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │              OpenClaw Gateway                         │  │  │
│  │  │        (127.0.0.1:18789 + Token Auth)                │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              Persistent Storage (Host)                      │  │
│  │   ~/.openclaw (700) + ~/.openclaw/workspace (700)          │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   SSH Tunnel      │
                    │   (Your Laptop)   │
                    └───────────────────┘
```

---

## Prerequisites

### Required

- Hetzner Cloud account
- SSH key pair (Ed25519 preferred)
- Basic Linux administration knowledge
- Strong password manager for secrets

### Recommended

- Tailscale account (for easier secure access)
- Separate API keys for production
- Backup strategy for credentials

---

## VPS Provisioning

### 1. Create SSH Key (if needed)

On your local machine:

```bash
# Generate Ed25519 key (more secure than RSA)
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/hetzner_openclaw -C "openclaw@hetzner"

# Display public key to add to Hetzner
cat ~/.ssh/hetzner_openclaw.pub
```

### 2. Provision VPS in Hetzner Cloud Console

1. **Location:** Choose region closest to you
2. **Image:** Ubuntu 24.04 LTS (latest LTS)
3. **Type:** CX22 minimum (2 vCPU, 4GB RAM) - adjust based on usage
4. **SSH Keys:** Add your public key
5. **Firewall:** Create new firewall (see below)
6. **Name:** `openclaw-gateway`

### 3. Configure Hetzner Cloud Firewall

Create firewall rules **before** provisioning:

**Inbound Rules:**
| Protocol | Port | Source | Description |
|----------|------|--------|-------------|
| TCP | 22 | Your IP/32 or 0.0.0.0/0 | SSH access |

**Outbound Rules:**
| Protocol | Port | Destination | Description |
|----------|------|-------------|-------------|
| TCP | 443 | 0.0.0.0/0 | HTTPS (APIs, Docker Hub) |
| TCP | 80 | 0.0.0.0/0 | HTTP (package updates) |
| UDP | 53 | 0.0.0.0/0 | DNS |

**Do NOT expose port 18789** in Hetzner firewall - access via SSH tunnel only.

---

## Initial Server Hardening

### 1. Initial Connection

```bash
# Connect as root initially
ssh -i ~/.ssh/hetzner_openclaw root@YOUR_VPS_IP
```

### 2. System Updates

```bash
# Update system packages
apt-get update && apt-get upgrade -y

# Install security essentials
apt-get install -y \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  needrestart
```

### 3. Create Non-Root User

```bash
# Create dedicated user for OpenClaw
useradd -m -s /bin/bash -G sudo openclaw

# Set secure password (store in password manager)
passwd openclaw

# Copy SSH key for new user
mkdir -p /home/openclaw/.ssh
cp /root/.ssh/authorized_keys /home/openclaw/.ssh/
chown -R openclaw:openclaw /home/openclaw/.ssh
chmod 700 /home/openclaw/.ssh
chmod 600 /home/openclaw/.ssh/authorized_keys
```

### 4. SSH Hardening

Edit `/etc/ssh/sshd_config`:

```bash
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
# Disable password authentication
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes

# Use strong key exchange and ciphers
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Limit authentication attempts
MaxAuthTries 3
LoginGraceTime 30

# Disable unused features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding yes  # Required for SSH tunnels

# Only allow specific user
AllowUsers openclaw
EOF

# Validate and restart SSH
sshd -t && systemctl restart sshd
```

**Test new SSH configuration before disconnecting:**

```bash
# In a NEW terminal
ssh -i ~/.ssh/hetzner_openclaw openclaw@YOUR_VPS_IP
```

### 5. Configure UFW Firewall

```bash
# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (adjust port if changed)
ufw allow 22/tcp comment 'SSH'

# Enable firewall
ufw enable

# Verify status
ufw status verbose
```

### 6. Configure fail2ban

```bash
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
EOF

systemctl enable fail2ban
systemctl restart fail2ban
```

### 7. Enable Automatic Security Updates

```bash
# Configure unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# Enable automatic updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

systemctl enable unattended-upgrades
```

---

## Docker Installation

### 1. Install Docker (Official Repository)

Switch to the `openclaw` user:

```bash
su - openclaw
```

Install Docker:

```bash
# Add Docker's official GPG key
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker openclaw

# Apply group membership (or logout/login)
newgrp docker
```

### 2. Harden Docker Daemon

```bash
sudo mkdir -p /etc/docker

sudo cat > /etc/docker/daemon.json << 'EOF'
{
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

sudo systemctl restart docker
```

### 3. Verify Installation

```bash
docker --version
docker compose version
docker run --rm hello-world
```

---

## OpenClaw Secure Deployment

### 1. Clone Repository

```bash
cd ~
git clone https://github.com/openclaw/openclaw.git
cd openclaw
```

### 2. Create Secure Directory Structure

```bash
# Create directories with secure permissions
mkdir -p ~/.openclaw
mkdir -p ~/.openclaw/workspace
mkdir -p ~/.openclaw/credentials
mkdir -p ~/.openclaw/agents

# Set ownership (uid 1000 = node user in container)
sudo chown -R 1000:1000 ~/.openclaw

# Set secure permissions
chmod 700 ~/.openclaw
chmod 700 ~/.openclaw/workspace
chmod 700 ~/.openclaw/credentials
chmod 700 ~/.openclaw/agents
```

### 3. Generate Secure Secrets

```bash
# Generate gateway token (64 hex chars)
GATEWAY_TOKEN=$(openssl rand -hex 32)
echo "Gateway Token: $GATEWAY_TOKEN"
echo "SAVE THIS IN YOUR PASSWORD MANAGER"

# Generate keyring password
KEYRING_PASSWORD=$(openssl rand -hex 32)
echo "Keyring Password: $KEYRING_PASSWORD"
echo "SAVE THIS IN YOUR PASSWORD MANAGER"
```

### 4. Create Environment File

```bash
cat > ~/openclaw/.env << EOF
# OpenClaw Docker Configuration
OPENCLAW_IMAGE=openclaw:latest

# Gateway Authentication (REQUIRED - DO NOT EXPOSE WITHOUT THIS)
OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}

# Gateway Binding (ALWAYS use loopback for security)
OPENCLAW_GATEWAY_BIND=loopback
OPENCLAW_GATEWAY_PORT=18789

# Host directories (mapped to container)
OPENCLAW_CONFIG_DIR=/home/openclaw/.openclaw
OPENCLAW_WORKSPACE_DIR=/home/openclaw/.openclaw/workspace

# Keyring password for encrypted credentials
GOG_KEYRING_PASSWORD=${KEYRING_PASSWORD}

# Container paths
XDG_CONFIG_HOME=/home/node/.openclaw
EOF

# Secure the .env file
chmod 600 ~/openclaw/.env
```

### 5. Create Secure Docker Compose

```bash
cat > ~/openclaw/docker-compose.secure.yml << 'EOF'
services:
  openclaw-gateway:
    image: ${OPENCLAW_IMAGE}
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped

    # Security: run as non-root
    user: "1000:1000"

    # Security: drop capabilities
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

    # Security: read-only root filesystem (except tmpfs)
    read_only: true
    tmpfs:
      - /tmp:size=100M,mode=1777
      - /home/node/.cache:size=500M,mode=700

    # Security: no privilege escalation
    security_opt:
      - no-new-privileges:true

    env_file:
      - .env

    environment:
      - HOME=/home/node
      - NODE_ENV=production
      - TERM=xterm-256color
      - OPENCLAW_GATEWAY_BIND=${OPENCLAW_GATEWAY_BIND}
      - OPENCLAW_GATEWAY_PORT=${OPENCLAW_GATEWAY_PORT}
      - OPENCLAW_GATEWAY_TOKEN=${OPENCLAW_GATEWAY_TOKEN}
      - GOG_KEYRING_PASSWORD=${GOG_KEYRING_PASSWORD}
      - XDG_CONFIG_HOME=${XDG_CONFIG_HOME}

    volumes:
      # Persistent state (host directories)
      - ${OPENCLAW_CONFIG_DIR}:/home/node/.openclaw:rw
      - ${OPENCLAW_WORKSPACE_DIR}:/home/node/.openclaw/workspace:rw

    ports:
      # CRITICAL: Bind to localhost ONLY
      # Access via SSH tunnel, NOT direct exposure
      - "127.0.0.1:${OPENCLAW_GATEWAY_PORT}:18789"

    # Health check
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://127.0.0.1:18789/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 3G
        reservations:
          memory: 1G

    command:
      [
        "node",
        "dist/index.js",
        "gateway",
        "--bind",
        "${OPENCLAW_GATEWAY_BIND}",
        "--port",
        "${OPENCLAW_GATEWAY_PORT}",
      ]
EOF
```

### 6. Create Secure Dockerfile

```bash
cat > ~/openclaw/Dockerfile.secure << 'EOF'
# Build stage
FROM node:22-bookworm-slim AS builder

WORKDIR /app

# Install build dependencies
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY ui/package.json ./ui/package.json
COPY scripts ./scripts

RUN corepack enable pnpm
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build
RUN pnpm ui:install
RUN pnpm ui:build

# Production stage
FROM node:22-bookworm-slim AS production

# Security: create non-root user
RUN groupadd -g 1000 node || true && \
    useradd -u 1000 -g node -m node || true

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Optional: Install additional binaries (example)
# RUN curl -L https://example.com/binary.tar.gz | tar -xz -C /usr/local/bin

WORKDIR /app

# Copy built application
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/package.json ./
COPY --from=builder --chown=node:node /app/ui/dist ./ui/dist

# Security: switch to non-root user
USER node

ENV NODE_ENV=production

CMD ["node", "dist/index.js"]
EOF
```

### 7. Create OpenClaw Configuration

```bash
cat > ~/.openclaw/openclaw.json << 'EOF'
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token"
    }
  },
  "discovery": {
    "mdns": { "mode": "off" }
  },
  "channels": {
    "whatsapp": {
      "dmPolicy": "pairing",
      "groups": { "*": { "requireMention": true } }
    },
    "telegram": {
      "dmPolicy": "pairing",
      "groups": { "*": { "requireMention": true } }
    }
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main",
        "scope": "session",
        "workspaceAccess": "none"
      }
    }
  },
  "tools": {
    "elevated": {
      "allowFrom": ["main"],
      "requireApproval": true
    }
  },
  "logging": {
    "redactSensitive": "tools",
    "file": "/home/node/.openclaw/logs/openclaw.log"
  }
}
EOF

# Secure permissions
chmod 600 ~/.openclaw/openclaw.json
```

### 8. Build and Deploy

```bash
cd ~/openclaw

# Build the secure image
docker compose -f docker-compose.secure.yml build

# Start the gateway
docker compose -f docker-compose.secure.yml up -d

# Verify deployment
docker compose -f docker-compose.secure.yml ps
docker compose -f docker-compose.secure.yml logs -f
```

---

## Network Security

### Verify No External Exposure

```bash
# Check listening ports
ss -tlnp | grep 18789
# Should show: 127.0.0.1:18789 (NOT 0.0.0.0:18789)

# Test from VPS
curl -s http://127.0.0.1:18789/health

# This should FAIL from external
# curl http://YOUR_VPS_IP:18789/health
```

### Additional Firewall Rules (Optional)

```bash
# Rate limit SSH connections
sudo ufw limit ssh comment 'SSH rate limit'

# Block known bad actors (optional, use ip blocklists)
# sudo ufw deny from BAD_IP_RANGE
```

---

## Access Methods

### Method 1: SSH Tunnel (Recommended)

From your local machine:

```bash
# Create tunnel
ssh -N -L 18789:127.0.0.1:18789 -i ~/.ssh/hetzner_openclaw openclaw@YOUR_VPS_IP

# In another terminal, access the UI
open http://127.0.0.1:18789/

# Enter your gateway token when prompted
```

**Persistent tunnel with autossh:**

```bash
# Install autossh
# macOS: brew install autossh
# Linux: apt install autossh

# Create persistent tunnel
autossh -M 0 -f -N \
  -o "ServerAliveInterval=30" \
  -o "ServerAliveCountMax=3" \
  -L 18789:127.0.0.1:18789 \
  -i ~/.ssh/hetzner_openclaw \
  openclaw@YOUR_VPS_IP
```

### Method 2: Tailscale (Alternative)

If you prefer Tailscale for access:

**On VPS:**

```bash
# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Authenticate
sudo tailscale up

# Get Tailscale IP
tailscale ip -4
```

**Update docker-compose.secure.yml:**

```yaml
ports:
  # Bind to Tailscale IP instead
  - "100.x.x.x:18789:18789"
```

**On your laptop:**

```bash
# Connect via Tailscale IP
open http://100.x.x.x:18789/
```

---

## Monitoring & Alerting

### 1. Container Health Monitoring

```bash
# Create monitoring script
cat > ~/openclaw/monitor.sh << 'EOF'
#!/bin/bash

CONTAINER_NAME="openclaw-openclaw-gateway-1"

# Check if container is running
if ! docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" -q | grep -q .; then
    echo "ALERT: OpenClaw container is not running!"
    # Add notification command here (email, Slack, etc.)
    exit 1
fi

# Check health status
HEALTH=$(docker inspect --format='{{.State.Health.Status}}' $CONTAINER_NAME 2>/dev/null)
if [ "$HEALTH" != "healthy" ]; then
    echo "ALERT: OpenClaw container is unhealthy: $HEALTH"
    exit 1
fi

echo "OK: OpenClaw is healthy"
EOF

chmod +x ~/openclaw/monitor.sh
```

### 2. Setup Cron Monitoring

```bash
# Add to crontab
crontab -e

# Add line:
*/5 * * * * /home/openclaw/openclaw/monitor.sh >> /home/openclaw/openclaw/monitor.log 2>&1
```

### 3. Log Rotation

```bash
cat > /etc/logrotate.d/openclaw << 'EOF'
/home/openclaw/.openclaw/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 600 1000 1000
}
EOF
```

---

## Maintenance & Updates

### Updating OpenClaw

```bash
cd ~/openclaw

# Pull latest code
git pull origin main

# Rebuild image
docker compose -f docker-compose.secure.yml build --no-cache

# Restart with new image
docker compose -f docker-compose.secure.yml down
docker compose -f docker-compose.secure.yml up -d

# Verify health
docker compose -f docker-compose.secure.yml logs -f
```

### Backup Credentials

```bash
# Create backup (run on VPS)
tar -czvf ~/openclaw-backup-$(date +%Y%m%d).tar.gz \
  ~/.openclaw/openclaw.json \
  ~/.openclaw/credentials \
  ~/.openclaw/agents/*/agent/*.json \
  ~/.openclaw/nodes

# Transfer to local machine
scp -i ~/.ssh/hetzner_openclaw \
  openclaw@YOUR_VPS_IP:~/openclaw-backup-*.tar.gz \
  ~/backups/

# Encrypt backup (optional but recommended)
gpg --symmetric --cipher-algo AES256 ~/backups/openclaw-backup-*.tar.gz
```

### Security Audit

Run regularly:

```bash
# SSH into VPS
ssh -i ~/.ssh/hetzner_openclaw openclaw@YOUR_VPS_IP

# Run OpenClaw security audit
docker compose -f ~/openclaw/docker-compose.secure.yml exec openclaw-gateway \
  node dist/index.js security audit --deep

# Check system security
sudo lynis audit system  # Install: apt install lynis
```

---

## Incident Response

### Suspected Compromise Procedure

1. **Isolate:**
   ```bash
   # Stop the gateway immediately
   docker compose -f ~/openclaw/docker-compose.secure.yml down

   # Block all incoming traffic except your IP
   sudo ufw default deny incoming
   sudo ufw allow from YOUR_IP to any port 22
   ```

2. **Preserve Evidence:**
   ```bash
   # Save container logs
   docker logs openclaw-openclaw-gateway-1 > ~/incident-logs-$(date +%s).txt 2>&1

   # Save auth logs
   sudo cp /var/log/auth.log ~/incident-auth-$(date +%s).log

   # Save session transcripts
   cp -r ~/.openclaw/agents/*/sessions ~/incident-sessions-$(date +%s)/
   ```

3. **Rotate All Credentials:**
   ```bash
   # Generate new gateway token
   NEW_TOKEN=$(openssl rand -hex 32)

   # Update .env file
   sed -i "s/OPENCLAW_GATEWAY_TOKEN=.*/OPENCLAW_GATEWAY_TOKEN=${NEW_TOKEN}/" ~/openclaw/.env

   # Rotate model API keys via Anthropic/OpenAI console
   # Update in auth-profiles.json
   ```

4. **Rebuild Clean:**
   ```bash
   # Remove potentially compromised image
   docker image rm openclaw:latest

   # Rebuild from verified source
   git fetch origin
   git reset --hard origin/main
   docker compose -f docker-compose.secure.yml build --no-cache
   ```

5. **Restore Service:**
   ```bash
   # Re-enable firewall
   sudo ufw default deny incoming
   sudo ufw allow 22/tcp
   sudo ufw enable

   # Start gateway
   docker compose -f docker-compose.secure.yml up -d
   ```

---

## Security Checklist

### Initial Setup

- [ ] SSH key-only authentication enabled
- [ ] Root login disabled
- [ ] Non-root user created for OpenClaw
- [ ] UFW firewall enabled (port 22 only)
- [ ] fail2ban configured
- [ ] Automatic security updates enabled
- [ ] Docker installed with hardened daemon config

### OpenClaw Configuration

- [ ] Gateway bound to loopback only (127.0.0.1)
- [ ] Strong gateway token generated (32+ bytes)
- [ ] Token stored in password manager
- [ ] mDNS discovery disabled
- [ ] DM pairing enabled (not open)
- [ ] Group mention gating enabled
- [ ] Sandbox mode enabled for non-main sessions
- [ ] Log redaction enabled
- [ ] File permissions set (700/600)

### Network Security

- [ ] Hetzner Cloud Firewall configured
- [ ] Port 18789 NOT exposed externally
- [ ] SSH tunnel or Tailscale configured for access
- [ ] No sensitive ports exposed

### Operational Security

- [ ] Backup strategy implemented
- [ ] Monitoring script deployed
- [ ] Log rotation configured
- [ ] Incident response plan documented
- [ ] Regular security audits scheduled

### Ongoing Maintenance

- [ ] Weekly: Check container health and logs
- [ ] Monthly: Review and rotate credentials
- [ ] Monthly: Apply security updates
- [ ] Quarterly: Run full security audit
- [ ] Quarterly: Test incident response procedure

---

## Additional Resources

- [OpenClaw Security Architecture](./security-architecture.md)
- [Gateway Security Documentation](https://docs.openclaw.ai/gateway/security)
- [Hetzner Cloud Firewall Documentation](https://docs.hetzner.com/cloud/firewalls)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [SSH Hardening Guide](https://www.ssh.com/academy/ssh/sshd_config)
