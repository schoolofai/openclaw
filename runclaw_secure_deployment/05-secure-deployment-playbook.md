# RunClaw.io Secure Deployment Playbook

Operational guide for securely deploying OpenClaw instances via RunClaw.io. This document provides exact commands, expected outputs, and verification steps for every phase of deployment and operations.

**Platform stack:** Hetzner Cloud VPS, Ubuntu 24.04, Docker Compose (Caddy + OpenClaw), cloud-init provisioning, Cloudflare DNS, Appwrite Cloud, Stripe, Next.js 14 on Vercel.

---

## Table of Contents

1. [Pre-Deployment Security Checklist](#1-pre-deployment-security-checklist)
2. [Hardened Cloud-Init Template](#2-hardened-cloud-init-template)
3. [Vercel Deployment Security](#3-vercel-deployment-security)
4. [Appwrite Setup Security](#4-appwrite-setup-security)
5. [Stripe Configuration Security](#5-stripe-configuration-security)
6. [Cloudflare Setup Security](#6-cloudflare-setup-security)
7. [Deployment Procedure (Step-by-Step)](#7-deployment-procedure-step-by-step)
8. [Post-Deployment Verification](#8-post-deployment-verification)
9. [Operational Security Procedures](#9-operational-security-procedures)
10. [Rollback Procedures](#10-rollback-procedures)

---

## 1. Pre-Deployment Security Checklist

Complete every item before proceeding to deployment. Do not skip any line.

### API Tokens and Keys

- [ ] **Hetzner API token** generated with minimum permissions (server create, delete, list only). Verify at `https://console.hetzner.cloud/projects/<project>/security/tokens`.
- [ ] **Cloudflare API token** scoped to `Zone:DNS:Edit` for the `runclaw.io` zone only. Create at `https://dash.cloudflare.com/profile/api-tokens` using the "Edit zone DNS" template.
- [ ] **Appwrite API key** scoped to required collections only (databases.read, databases.write, users.read). Generate under Appwrite Console > Project Settings > API Keys.
- [ ] **Stripe webhook secret** (`whsec_...`) configured and verified with test event.
- [ ] **CRON_SECRET** generated: `openssl rand -hex 32` (64 character hex string).
- [ ] **SSH admin keys** generated as Ed25519 and registered with Hetzner project:

```bash
# Generate key
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/runclaw_admin -C "admin@runclaw.io"

# Display public key for Hetzner registration
cat ~/.ssh/runclaw_admin.pub
```

### Secret Storage Verification

- [ ] All secrets stored in Vercel environment variables (not in code, not in `.env` files committed to git).
- [ ] `.env.local` listed in `.gitignore`. Verify:

```bash
grep -q '.env.local' .gitignore && echo "PASS: .env.local is gitignored" || echo "FAIL: add .env.local to .gitignore"
```

- [ ] No secrets present in any committed file:

```bash
# Scan for potential secret patterns in committed files
git log --all -p | grep -iE '(sk_live|whsec_|HETZNER_API_TOKEN|CLOUDFLARE_API_TOKEN|APPWRITE_API_KEY)' && echo "FAIL: secrets found in git history" || echo "PASS: no secrets in git history"
```

### Docker Image Verification

- [ ] Docker images verified. Pin to digest in production cloud-init:

```bash
# Get current digest for caddy:2-alpine
docker pull caddy:2-alpine
docker inspect --format='{{index .RepoDigests 0}}' caddy:2-alpine
# Expected output: caddy@sha256:<64-char-hex>

# Get current digest for openclaw/openclaw:latest
docker pull openclaw/openclaw:latest
docker inspect --format='{{index .RepoDigests 0}}' openclaw/openclaw:latest
# Expected output: openclaw/openclaw@sha256:<64-char-hex>
```

- [ ] Record both digests. Update the cloud-init template `IMAGE_DIGEST_CADDY` and `IMAGE_DIGEST_OPENCLAW` variables before deployment.

### Network and DNS Pre-checks

- [ ] Cloudflare zone ID for `runclaw.io` recorded.
- [ ] Wildcard SSL certificate enabled (Cloudflare handles this automatically with proxy enabled).
- [ ] Verify Cloudflare SSL mode is set to Full (Strict).

---

## 2. Hardened Cloud-Init Template

This is the production-ready cloud-init template. It is generated server-side by the control plane and injected into the Hetzner API `user_data` field. Template variables are enclosed in `%%VAR%%` delimiters and are substituted using a safe templating function that validates and escapes all inputs.

### Template Generation (TypeScript)

```typescript
// lib/cloud-init.ts

const RESERVED_CHARS_RE = /[`$\\!"'{}]/g;

/**
 * Safely escape a value for embedding in a YAML heredoc / shell context.
 * Throws on invalid input rather than silently producing broken YAML.
 */
function escapeForYaml(value: string, fieldName: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`cloud-init template: ${fieldName} must be a non-empty string`);
  }
  if (value.length > 255) {
    throw new Error(`cloud-init template: ${fieldName} exceeds 255 characters`);
  }
  // For subdomain: only allow lowercase alphanumeric and hyphens
  if (fieldName === 'subdomain' && !/^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/.test(value)) {
    throw new Error(`cloud-init template: invalid subdomain format: ${value}`);
  }
  // For secrets: only allow hex characters
  if (fieldName === 'callbackSecret' && !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`cloud-init template: callbackSecret must be 64 hex chars`);
  }
  if (fieldName === 'instanceId' && !/^[a-zA-Z0-9_-]{1,36}$/.test(value)) {
    throw new Error(`cloud-init template: invalid instanceId format`);
  }
  return value.replace(RESERVED_CHARS_RE, '');
}

export function generateCloudInit(
  subdomain: string,
  callbackSecret: string,
  instanceId: string,
  caddyImageDigest: string,
  openclawImageDigest: string
): string {
  const safeSubdomain = escapeForYaml(subdomain, 'subdomain');
  const safeSecret = escapeForYaml(callbackSecret, 'callbackSecret');
  const safeInstanceId = escapeForYaml(instanceId, 'instanceId');

  // The template below uses the safe values directly.
  // No string interpolation of user input into shell commands.
  return CLOUD_INIT_TEMPLATE
    .replaceAll('%%SUBDOMAIN%%', safeSubdomain)
    .replaceAll('%%CALLBACK_SECRET%%', safeSecret)
    .replaceAll('%%INSTANCE_ID%%', safeInstanceId)
    .replaceAll('%%CADDY_IMAGE%%', caddyImageDigest)
    .replaceAll('%%OPENCLAW_IMAGE%%', openclawImageDigest);
}
```

### Production Cloud-Init YAML

```yaml
#cloud-config

# =============================================================================
# RunClaw.io - Hardened VPS Provisioning Template
# Ubuntu 24.04 LTS + Docker Compose (Caddy + OpenClaw)
# =============================================================================

# --- System packages ---
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
  - apparmor
  - apparmor-utils
  - logrotate
  - curl
  - jq

# --- User setup ---
users:
  - name: openclaw
    groups: docker, sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys: []

# --- Sysctl hardening ---
write_files:
  # Kernel network hardening
  - path: /etc/sysctl.d/99-runclaw-hardening.conf
    permissions: '0644'
    content: |
      # IP spoofing protection
      net.ipv4.conf.all.rp_filter = 1
      net.ipv4.conf.default.rp_filter = 1

      # Disable source routing
      net.ipv4.conf.all.accept_source_route = 0
      net.ipv4.conf.default.accept_source_route = 0
      net.ipv6.conf.all.accept_source_route = 0
      net.ipv6.conf.default.accept_source_route = 0

      # Disable ICMP redirects
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv4.conf.default.accept_redirects = 0
      net.ipv4.conf.all.send_redirects = 0
      net.ipv4.conf.default.send_redirects = 0
      net.ipv6.conf.all.accept_redirects = 0
      net.ipv6.conf.default.accept_redirects = 0

      # SYN flood protection
      net.ipv4.tcp_syncookies = 1
      net.ipv4.tcp_max_syn_backlog = 2048
      net.ipv4.tcp_synack_retries = 2
      net.ipv4.tcp_syn_retries = 5

      # Ignore ICMP broadcasts
      net.ipv4.icmp_echo_ignore_broadcasts = 1

      # Log martians
      net.ipv4.conf.all.log_martians = 1
      net.ipv4.conf.default.log_martians = 1

      # Disable IPv6 router advertisements
      net.ipv6.conf.all.accept_ra = 0
      net.ipv6.conf.default.accept_ra = 0

      # Memory protections
      kernel.randomize_va_space = 2
      kernel.kptr_restrict = 2

      # Restrict dmesg access
      kernel.dmesg_restrict = 1

      # Restrict kernel profiling
      kernel.perf_event_paranoid = 3

      # Protect hard/soft links
      fs.protected_hardlinks = 1
      fs.protected_symlinks = 1

      # Restrict ptrace scope
      kernel.yama.ptrace_scope = 2

  # Docker daemon hardened configuration
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
          "max-file": "3"
        },
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
        "storage-driver": "overlay2"
      }

  # AppArmor Docker profile
  - path: /etc/apparmor.d/docker-openclaw
    permissions: '0644'
    content: |
      #include <tunables/global>

      profile docker-openclaw flags=(attach_disconnected,mediate_deleted) {
        #include <abstractions/base>
        #include <abstractions/nameservice>

        # Allow network access
        network inet tcp,
        network inet udp,
        network inet6 tcp,
        network inet6 udp,

        # Allow reading common system files
        /etc/hosts r,
        /etc/resolv.conf r,
        /etc/nsswitch.conf r,
        /etc/ssl/certs/** r,
        /usr/share/ca-certificates/** r,

        # Allow node process execution
        /usr/local/bin/node ix,
        /app/** r,
        /app/dist/** r,
        /app/node_modules/** r,

        # Allow data volume writes
        /app/data/** rw,
        /tmp/** rw,

        # Deny dangerous operations
        deny /proc/*/mem rw,
        deny /sys/** w,
        deny /dev/** w,

        # Allow stdout/stderr
        /dev/null rw,
        /dev/stdout rw,
        /dev/stderr rw,
      }

  # Docker Compose configuration
  - path: /opt/openclaw/docker-compose.yml
    permissions: '0644'
    content: |
      services:
        caddy:
          image: %%CADDY_IMAGE%%
          restart: unless-stopped
          ports:
            - "80:80"
            - "443:443"
          volumes:
            - ./Caddyfile:/etc/caddy/Caddyfile:ro
            - caddy_data:/data
            - caddy_config:/config
          depends_on:
            openclaw:
              condition: service_healthy
          deploy:
            resources:
              limits:
                cpus: '0.5'
                memory: 256M
              reservations:
                memory: 64M
          security_opt:
            - no-new-privileges:true
          cap_drop:
            - ALL
          cap_add:
            - NET_BIND_SERVICE
          read_only: true
          tmpfs:
            - /tmp:size=50M,mode=1777
          healthcheck:
            test: ["CMD", "caddy", "version"]
            interval: 30s
            timeout: 5s
            retries: 3
            start_period: 10s

        openclaw:
          image: %%OPENCLAW_IMAGE%%
          restart: unless-stopped
          volumes:
            - openclaw_data:/app/data
          environment:
            - NODE_ENV=production
          deploy:
            resources:
              limits:
                cpus: '1.5'
                memory: 3G
              reservations:
                cpus: '0.25'
                memory: 512M
          security_opt:
            - no-new-privileges:true
          cap_drop:
            - ALL
          read_only: true
          tmpfs:
            - /tmp:size=200M,mode=1777
            - /home/node/.cache:size=500M,mode=700
          healthcheck:
            test: ["CMD", "curl", "-sf", "http://127.0.0.1:3000/health"]
            interval: 30s
            timeout: 10s
            retries: 3
            start_period: 45s

      volumes:
        caddy_data:
        caddy_config:
        openclaw_data:

  # Caddy reverse proxy configuration with full security headers
  - path: /opt/openclaw/Caddyfile
    permissions: '0644'
    content: |
      {
        # Global options
        email admin@runclaw.io
        default_sni %%SUBDOMAIN%%.runclaw.io

        servers {
          protocols h1 h2 h3
        }
      }

      %%SUBDOMAIN%%.runclaw.io {
        # TLS configuration - TLS 1.3 only
        tls {
          protocols tls1.3
        }

        # Reverse proxy to OpenClaw
        reverse_proxy openclaw:3000 {
          header_up X-Forwarded-Proto {scheme}
          header_up X-Real-IP {remote_host}
          health_uri /health
          health_interval 30s
          health_timeout 5s
        }

        # Security headers
        header {
          X-Content-Type-Options "nosniff"
          X-Frame-Options "DENY"
          X-XSS-Protection "0"
          Referrer-Policy "strict-origin-when-cross-origin"
          Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none'"
          Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
          Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
          X-Permitted-Cross-Domain-Policies "none"
          Cross-Origin-Opener-Policy "same-origin"
          Cross-Origin-Resource-Policy "same-origin"
          Cross-Origin-Embedder-Policy "require-corp"
          -Server
          -X-Powered-By
        }

        # Health check endpoint (no information leakage)
        handle /health {
          respond "ok" 200
        }

        # Block sensitive paths
        @blocked path /. /wp-admin* /wp-login* /xmlrpc* /admin* /.env* /.git*
        handle @blocked {
          respond "Not Found" 404
        }

        # Rate limiting
        rate_limit {
          zone dynamic_zone {
            key {remote_host}
            events 100
            window 1m
          }
        }

        # Access logging
        log {
          output file /data/access.log {
            roll_size 10mb
            roll_keep 5
            roll_keep_for 168h
          }
          format json
          level INFO
        }
      }

  # Fail2ban - aggressive SSH and HTTP rules
  - path: /etc/fail2ban/jail.local
    permissions: '0644'
    content: |
      [DEFAULT]
      bantime = 3600
      findtime = 600
      maxretry = 3
      banaction = ufw
      ignoreip = 127.0.0.1/8 ::1

      [sshd]
      enabled = true
      port = 22
      filter = sshd
      logpath = /var/log/auth.log
      maxretry = 3
      bantime = 86400
      findtime = 600

      [sshd-ddos]
      enabled = true
      port = 22
      filter = sshd-ddos
      logpath = /var/log/auth.log
      maxretry = 6
      bantime = 172800
      findtime = 600

  # Fail2ban HTTP abuse filter
  - path: /etc/fail2ban/filter.d/caddy-abuse.conf
    permissions: '0644'
    content: |
      [Definition]
      failregex = ^.*"remote_ip":"<HOST>".*"status":(401|403|404|429).*$
      ignoreregex =

  # Fail2ban HTTP abuse jail
  - path: /etc/fail2ban/jail.d/caddy-abuse.conf
    permissions: '0644'
    content: |
      [caddy-abuse]
      enabled = true
      port = http,https
      filter = caddy-abuse
      logpath = /var/lib/docker/volumes/*caddy_data/_data/access.log
      maxretry = 20
      findtime = 120
      bantime = 3600

  # Audit rules for security monitoring
  - path: /etc/audit/rules.d/runclaw.rules
    permissions: '0640'
    content: |
      # Delete all existing rules
      -D

      # Buffer size
      -b 8192

      # Failure mode (1 = printk, 2 = panic)
      -f 1

      # Monitor SSH key changes
      -w /etc/ssh/sshd_config -p wa -k sshd_config
      -w /home/openclaw/.ssh -p wa -k ssh_keys

      # Monitor Docker configuration
      -w /etc/docker -p wa -k docker_config
      -w /opt/openclaw -p wa -k openclaw_config

      # Monitor user/group changes
      -w /etc/passwd -p wa -k identity
      -w /etc/group -p wa -k identity
      -w /etc/shadow -p wa -k identity

      # Monitor sudo usage
      -w /var/log/auth.log -p wa -k auth_log

      # Monitor cron changes
      -w /etc/crontab -p wa -k cron
      -w /etc/cron.d -p wa -k cron

      # Make the configuration immutable (reboot required to change)
      -e 2

  # Log rotation for all custom logs
  - path: /etc/logrotate.d/runclaw
    permissions: '0644'
    content: |
      /var/log/runclaw/*.log {
        daily
        rotate 14
        compress
        delaycompress
        missingok
        notifempty
        create 640 openclaw openclaw
        sharedscripts
        postrotate
          /usr/bin/docker compose -f /opt/openclaw/docker-compose.yml restart caddy 2>/dev/null || true
        endscript
      }

  # Swap and OOM configuration
  - path: /etc/sysctl.d/99-runclaw-memory.conf
    permissions: '0644'
    content: |
      # Prefer killing processes over OOM
      vm.panic_on_oom = 0
      vm.oom_kill_allocating_task = 1

      # Reduce swappiness (prefer RAM)
      vm.swappiness = 10

      # Overcommit: heuristic (don't overcommit aggressively)
      vm.overcommit_memory = 0

  # Unattended upgrades configuration
  - path: /etc/apt/apt.conf.d/50unattended-upgrades
    permissions: '0644'
    content: |
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

  - path: /etc/apt/apt.conf.d/20auto-upgrades
    permissions: '0644'
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
      APT::Periodic::AutocleanInterval "7";

# =============================================================================
# COMMANDS
# =============================================================================
runcmd:
  # ---- Apply sysctl hardening ----
  - sysctl --system

  # ---- Firewall: ingress ----
  - ufw default deny incoming
  - ufw default deny outgoing
  - ufw allow in 80/tcp comment 'HTTP'
  - ufw allow in 443/tcp comment 'HTTPS'
  - ufw allow in 22/tcp comment 'SSH'

  # ---- Firewall: egress (only allow necessary outbound) ----
  - ufw allow out 53/udp comment 'DNS'
  - ufw allow out 53/tcp comment 'DNS TCP'
  - ufw allow out 80/tcp comment 'HTTP outbound (apt, ACME)'
  - ufw allow out 443/tcp comment 'HTTPS outbound (APIs, Docker Hub, callback)'
  - ufw allow out 123/udp comment 'NTP'
  - ufw --force enable

  # ---- SSH hardening ----
  - |
    cat > /etc/ssh/sshd_config.d/runclaw-hardening.conf << 'SSHEOF'
    PasswordAuthentication no
    PermitRootLogin no
    PubkeyAuthentication yes
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    MaxAuthTries 3
    LoginGraceTime 30
    X11Forwarding no
    AllowAgentForwarding no
    AllowTcpForwarding no
    ClientAliveInterval 300
    ClientAliveCountMax 2
    MaxSessions 2
    AllowUsers openclaw
    SSHEOF
    sshd -t && systemctl restart sshd

  # ---- Enable services ----
  - systemctl enable fail2ban && systemctl start fail2ban
  - systemctl enable unattended-upgrades && systemctl start unattended-upgrades
  - systemctl enable auditd && systemctl start auditd
  - systemctl enable docker && systemctl start docker

  # ---- Load AppArmor profile ----
  - apparmor_parser -r /etc/apparmor.d/docker-openclaw

  # ---- Configure swap (1GB) ----
  - |
    if [ ! -f /swapfile ]; then
      fallocate -l 1G /swapfile
      chmod 600 /swapfile
      mkswap /swapfile
      swapon /swapfile
      echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

  # ---- Create log directory ----
  - mkdir -p /var/log/runclaw
  - chown openclaw:openclaw /var/log/runclaw
  - chmod 750 /var/log/runclaw

  # ---- Pull and start containers ----
  - cd /opt/openclaw && docker compose pull
  - cd /opt/openclaw && docker compose up -d

  # ---- Wait for healthy state and callback with retry ----
  - |
    CALLBACK_URL="https://runclaw.io/api/instances/ready"
    INSTANCE_ID="%%INSTANCE_ID%%"
    CALLBACK_SECRET="%%CALLBACK_SECRET%%"
    LOG_FILE="/var/log/runclaw/provision.log"
    MAX_HEALTH_ATTEMPTS=60
    MAX_CALLBACK_ATTEMPTS=5

    log() {
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $1" >> "$LOG_FILE"
    }

    log "Provisioning started for instance $INSTANCE_ID"

    # Wait for OpenClaw to become healthy
    attempt=0
    until curl -sf http://127.0.0.1:3000/health > /dev/null 2>&1; do
      attempt=$((attempt + 1))
      if [ $attempt -ge $MAX_HEALTH_ATTEMPTS ]; then
        log "FATAL: OpenClaw failed to start after $MAX_HEALTH_ATTEMPTS attempts (300s)"
        exit 1
      fi
      log "Waiting for OpenClaw health check... attempt $attempt/$MAX_HEALTH_ATTEMPTS"
      sleep 5
    done

    log "OpenClaw is healthy after $attempt health check attempts"

    # Get OpenClaw version
    OPENCLAW_VERSION=$(curl -sf http://127.0.0.1:3000/health | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
    log "OpenClaw version: $OPENCLAW_VERSION"

    # Callback with retry logic and exponential backoff
    callback_attempt=0
    callback_success=false
    while [ $callback_attempt -lt $MAX_CALLBACK_ATTEMPTS ] && [ "$callback_success" = "false" ]; do
      callback_attempt=$((callback_attempt + 1))
      backoff=$((2 ** (callback_attempt - 1)))

      log "Callback attempt $callback_attempt/$MAX_CALLBACK_ATTEMPTS"

      HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 30 \
        -X POST "$CALLBACK_URL" \
        -H "Content-Type: application/json" \
        -d "{\"instance_id\":\"$INSTANCE_ID\",\"callback_secret\":\"$CALLBACK_SECRET\",\"openclaw_version\":\"$OPENCLAW_VERSION\"}" \
        2>> "$LOG_FILE")

      if [ "$HTTP_CODE" = "200" ]; then
        callback_success=true
        log "Callback succeeded with HTTP $HTTP_CODE"
      else
        log "Callback failed with HTTP $HTTP_CODE, retrying in ${backoff}s"
        sleep $backoff
      fi
    done

    if [ "$callback_success" = "false" ]; then
      log "FATAL: All $MAX_CALLBACK_ATTEMPTS callback attempts failed"
      # Do not exit 1 here - the instance is running, just the callback failed.
      # The provision-timeout cron will catch this.
    fi

    log "Provisioning complete"

# ---- Final reboot to apply all kernel settings ----
power_state:
  mode: reboot
  delay: "+1"
  message: "Rebooting to apply security hardening"
  timeout: 120
  condition: true
```

---

## 3. Vercel Deployment Security

### 3.1 Environment Variable Management

Set environment variables via the Vercel CLI or dashboard. Never commit them to source.

```bash
# Install Vercel CLI
npm i -g vercel

# Login
vercel login

# Set production environment variables
vercel env add APPWRITE_ENDPOINT production
# Enter: https://cloud.appwrite.io/v1

vercel env add APPWRITE_PROJECT_ID production
# Enter: <your-project-id>

vercel env add APPWRITE_DATABASE_ID production
# Enter: main

vercel env add APPWRITE_API_KEY production
# Enter: <your-api-key>

vercel env add NEXT_PUBLIC_APPWRITE_ENDPOINT production
# Enter: https://cloud.appwrite.io/v1

vercel env add NEXT_PUBLIC_APPWRITE_PROJECT_ID production
# Enter: <your-project-id>

vercel env add NEXT_PUBLIC_APPWRITE_DATABASE_ID production
# Enter: main

vercel env add STRIPE_SECRET_KEY production
# Enter: sk_live_...

vercel env add STRIPE_WEBHOOK_SECRET production
# Enter: whsec_...

vercel env add NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY production
# Enter: pk_live_...

vercel env add HETZNER_API_TOKEN production
# Enter: <token>

vercel env add CLOUDFLARE_API_TOKEN production
# Enter: <token>

vercel env add CLOUDFLARE_ZONE_ID production
# Enter: <zone-id>

vercel env add CRON_SECRET production
# Enter: <64-char-hex from openssl rand -hex 32>

vercel env add NEXT_PUBLIC_APP_URL production
# Enter: https://runclaw.io
```

**Verify no secrets leak into preview deployments:**

```bash
# List env vars for preview environment -- should be empty or contain
# only NEXT_PUBLIC_ vars with non-sensitive values
vercel env ls preview
```

If any sensitive variables appear in `preview`, remove them:

```bash
vercel env rm STRIPE_SECRET_KEY preview
vercel env rm APPWRITE_API_KEY preview
vercel env rm HETZNER_API_TOKEN preview
vercel env rm CLOUDFLARE_API_TOKEN preview
vercel env rm CRON_SECRET preview
```

### 3.2 Vercel Project Settings

```bash
# Set framework preset
vercel project set framework nextjs

# Set build command (ensure no secret injection during build)
vercel project set buildCommand "next build"

# Set output directory
vercel project set outputDirectory ".next"

# Set Node.js version
vercel project set nodeVersion "22.x"
```

### 3.3 Vercel Edge Middleware for Security Headers

Create `middleware.ts` at the project root:

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // Security headers
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '0');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://js.stripe.com; " +
    "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; " +
    "connect-src 'self' https://cloud.appwrite.io https://api.stripe.com; " +
    "frame-src https://js.stripe.com https://hooks.stripe.com; " +
    "frame-ancestors 'none';"
  );
  response.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(self)'
  );
  response.headers.set(
    'Strict-Transport-Security',
    'max-age=63072000; includeSubDomains; preload'
  );

  // Block sensitive paths
  const blockedPaths = ['/.env', '/.git', '/wp-admin', '/xmlrpc.php'];
  if (blockedPaths.some((p) => request.nextUrl.pathname.startsWith(p))) {
    return new NextResponse('Not Found', { status: 404 });
  }

  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

### 3.4 Serverless Function Timeout Configuration

In `vercel.json`:

```json
{
  "functions": {
    "app/api/instances/create/route.ts": {
      "maxDuration": 30
    },
    "app/api/instances/delete/route.ts": {
      "maxDuration": 15
    },
    "app/api/instances/ready/route.ts": {
      "maxDuration": 5
    },
    "app/api/instances/list/route.ts": {
      "maxDuration": 5
    },
    "app/api/stripe/webhook/route.ts": {
      "maxDuration": 15
    },
    "app/api/stripe/portal/route.ts": {
      "maxDuration": 5
    },
    "app/api/cron/health/route.ts": {
      "maxDuration": 60
    },
    "app/api/cron/reconcile/route.ts": {
      "maxDuration": 120
    },
    "app/api/cron/provision-timeout/route.ts": {
      "maxDuration": 30
    }
  },
  "crons": [
    { "path": "/api/cron/health", "schedule": "*/5 * * * *" },
    { "path": "/api/cron/provision-timeout", "schedule": "*/10 * * * *" },
    { "path": "/api/cron/reconcile", "schedule": "0 3 * * 0" }
  ]
}
```

### 3.5 Custom Domain SSL

```bash
# Add custom domain
vercel domains add runclaw.io

# Verify DNS is pointed to Vercel
vercel domains inspect runclaw.io

# Expected output:
# Domain: runclaw.io
# Status: Valid Configuration
# SSL: Automatic (Let's Encrypt)
```

### 3.6 Log Drain for Security Monitoring

```bash
# Set up log drain to a SIEM (example: Datadog)
vercel integrations add datadog

# Or use a generic HTTP log drain
vercel log-drains add \
  --url "https://your-siem.example.com/api/v1/logs" \
  --type json \
  --sources static,lambda,edge
```

---

## 4. Appwrite Setup Security

### 4.1 Project Creation

1. Navigate to `https://cloud.appwrite.io`.
2. Create project with name `runclaw`.
3. Record the **Project ID** (displayed on project settings page).
4. Set project region to `fra` (Frankfurt) for EU data residency (closest to Hetzner fsn1).

### 4.2 Database and Collections

Create the database and all four collections using the Appwrite CLI:

```bash
# Install Appwrite CLI
npm install -g appwrite-cli

# Login
appwrite login

# Set project
appwrite client --projectId <your-project-id>

# Create database
appwrite databases create --databaseId main --name "RunClaw Main"

# Create users collection
appwrite databases createCollection \
  --databaseId main \
  --collectionId users \
  --name "Users" \
  --documentSecurity true

# Create users collection attributes
appwrite databases createStringAttribute --databaseId main --collectionId users --key email --size 255 --required true
appwrite databases createStringAttribute --databaseId main --collectionId users --key stripe_customer_id --size 255 --required false
appwrite databases createDatetimeAttribute --databaseId main --collectionId users --key created_at --required true
appwrite databases createDatetimeAttribute --databaseId main --collectionId users --key updated_at --required true

# Create users indexes
appwrite databases createIndex --databaseId main --collectionId users --key email_unique --type unique --attributes email
appwrite databases createIndex --databaseId main --collectionId users --key stripe_customer_unique --type unique --attributes stripe_customer_id

# Create instances collection
appwrite databases createCollection \
  --databaseId main \
  --collectionId instances \
  --name "Instances" \
  --documentSecurity true

# Create instances attributes
appwrite databases createStringAttribute --databaseId main --collectionId instances --key user_id --size 36 --required true
appwrite databases createStringAttribute --databaseId main --collectionId instances --key subdomain --size 63 --required true
appwrite databases createIntegerAttribute --databaseId main --collectionId instances --key hetzner_server_id --required false
appwrite databases createStringAttribute --databaseId main --collectionId instances --key ip_address --size 45 --required false
appwrite databases createStringAttribute --databaseId main --collectionId instances --key region --size 10 --required true --default "fsn1"
appwrite databases createStringAttribute --databaseId main --collectionId instances --key server_type --size 10 --required true --default "cx22"
appwrite databases createEnumAttribute --databaseId main --collectionId instances --key status --elements provisioning,running,unhealthy,stopped,failed,deleting --required true --default provisioning
appwrite databases createStringAttribute --databaseId main --collectionId instances --key status_message --size 500 --required false
appwrite databases createStringAttribute --databaseId main --collectionId instances --key stripe_subscription_id --size 255 --required false
appwrite databases createEnumAttribute --databaseId main --collectionId instances --key plan --elements starter,pro,dedicated --required true --default starter
appwrite databases createDatetimeAttribute --databaseId main --collectionId instances --key provision_started_at --required true
appwrite databases createDatetimeAttribute --databaseId main --collectionId instances --key provision_completed_at --required false
appwrite databases createStringAttribute --databaseId main --collectionId instances --key callback_secret --size 64 --required true
appwrite databases createDatetimeAttribute --databaseId main --collectionId instances --key last_health_check_at --required false
appwrite databases createDatetimeAttribute --databaseId main --collectionId instances --key created_at --required true
appwrite databases createDatetimeAttribute --databaseId main --collectionId instances --key updated_at --required true

# Create instances indexes
appwrite databases createIndex --databaseId main --collectionId instances --key subdomain_unique --type unique --attributes subdomain
appwrite databases createIndex --databaseId main --collectionId instances --key user_id_idx --type key --attributes user_id
appwrite databases createIndex --databaseId main --collectionId instances --key status_idx --type key --attributes status
appwrite databases createIndex --databaseId main --collectionId instances --key stripe_sub_idx --type key --attributes stripe_subscription_id

# Create webhook_events collection
appwrite databases createCollection \
  --databaseId main \
  --collectionId webhook_events \
  --name "Webhook Events" \
  --documentSecurity false

# Create webhook_events attributes
appwrite databases createStringAttribute --databaseId main --collectionId webhook_events --key stripe_event_id --size 255 --required true
appwrite databases createStringAttribute --databaseId main --collectionId webhook_events --key event_type --size 100 --required true
appwrite databases createDatetimeAttribute --databaseId main --collectionId webhook_events --key processed_at --required true
appwrite databases createStringAttribute --databaseId main --collectionId webhook_events --key payload --size 16000 --required false
appwrite databases createBooleanAttribute --databaseId main --collectionId webhook_events --key success --required true --default false
appwrite databases createStringAttribute --databaseId main --collectionId webhook_events --key error_message --size 1000 --required false
appwrite databases createDatetimeAttribute --databaseId main --collectionId webhook_events --key created_at --required true

# Create webhook_events indexes
appwrite databases createIndex --databaseId main --collectionId webhook_events --key stripe_event_unique --type unique --attributes stripe_event_id

# Create instance_events collection
appwrite databases createCollection \
  --databaseId main \
  --collectionId instance_events \
  --name "Instance Events" \
  --documentSecurity false

# Create instance_events attributes
appwrite databases createStringAttribute --databaseId main --collectionId instance_events --key instance_id --size 36 --required true
appwrite databases createStringAttribute --databaseId main --collectionId instance_events --key event_type --size 50 --required true
appwrite databases createStringAttribute --databaseId main --collectionId instance_events --key details --size 5000 --required false
appwrite databases createDatetimeAttribute --databaseId main --collectionId instance_events --key created_at --required true

# Create instance_events indexes
appwrite databases createIndex --databaseId main --collectionId instance_events --key instance_id_idx --type key --attributes instance_id
appwrite databases createIndex --databaseId main --collectionId instance_events --key created_at_idx --type key --attributes created_at
```

### 4.3 API Key with Minimal Scopes

In Appwrite Console > Project Settings > API Keys > Create API Key:

- **Name:** `runclaw-server`
- **Scopes (select only these):**
  - `databases.read` -- read documents from all collections
  - `databases.write` -- create/update/delete documents
  - `users.read` -- verify user sessions server-side
- **Expiration:** Set to 90 days and schedule rotation.

**Do not select:** `collections.read`, `collections.write`, `attributes.*`, `indexes.*`, `teams.*`, `functions.*`, `health.*`, `storage.*`.

Record the API key value and store it as `APPWRITE_API_KEY` in Vercel.

### 4.4 Auth Settings

In Appwrite Console > Auth > Settings:

- **Password length:** Minimum 12 characters.
- **Password history:** Enable (prevent reuse of last 5 passwords).
- **Session limits:** Maximum 5 active sessions per user.
- **Session duration:** 30 days.
- **Allowed OAuth providers:** Disable all (email/password only for v1).
- **Personal data deletion:** Enable.

### 4.5 Rate Limiting

Appwrite Cloud has built-in rate limiting. Verify defaults:

- Authentication endpoints: 10 requests per minute per IP.
- General API: 60 requests per minute per IP.
- Document writes: 120 requests per minute per API key.

For additional protection, the Vercel Edge middleware provides rate limiting at the application layer.

### 4.6 Audit Log Monitoring

```bash
# Query recent Appwrite audit logs via API
curl -X GET "https://cloud.appwrite.io/v1/databases/main/logs" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" | jq '.logs[-10:]'
```

Set up a weekly review of audit logs. Look for:
- Unusual document deletion patterns.
- Requests from unexpected IP addresses.
- Failed authentication attempts.
- API key usage outside expected hours.

---

## 5. Stripe Configuration Security

### 5.1 Webhook Endpoint Setup

In the Stripe Dashboard at `https://dashboard.stripe.com/webhooks`:

1. Click **Add endpoint**.
2. **Endpoint URL:** `https://runclaw.io/api/stripe/webhook`
3. **Listen to:** Events on your account.
4. **Select events (minimal set only):**
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`
   - `invoice.payment_succeeded`
5. Click **Add endpoint**.
6. Copy the **Signing secret** (`whsec_...`).
7. Store as `STRIPE_WEBHOOK_SECRET` in Vercel.

### 5.2 Webhook Signature Verification Test

```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Login
stripe login

# Forward webhooks to local dev server for testing
stripe listen --forward-to localhost:3000/api/stripe/webhook

# In another terminal, trigger a test event
stripe trigger customer.subscription.deleted

# Expected output in the stripe listen terminal:
#   --> customer.subscription.deleted [evt_...]
#   <-- [200] POST http://localhost:3000/api/stripe/webhook
```

**Verification in code:**

```typescript
// Verify that signature verification rejects tampered payloads
const tamperedBody = body + 'tampered';
try {
  stripe.webhooks.constructEvent(tamperedBody, signature, webhookSecret);
  throw new Error('TEST FAILED: tampered payload was accepted');
} catch (err) {
  if (err instanceof Stripe.errors.StripeSignatureVerificationError) {
    console.log('TEST PASSED: tampered payload correctly rejected');
  }
}
```

### 5.3 Products and Prices

```bash
# Create Starter product and price
stripe products create \
  --name "RunClaw Starter" \
  --metadata[plan]=starter \
  --metadata[server_type]=cx22

stripe prices create \
  --product <starter-product-id> \
  --unit-amount 1500 \
  --currency usd \
  --recurring[interval]=month

# Create Pro product and price
stripe products create \
  --name "RunClaw Pro" \
  --metadata[plan]=pro \
  --metadata[server_type]=cx32

stripe prices create \
  --product <pro-product-id> \
  --unit-amount 2900 \
  --currency usd \
  --recurring[interval]=month

# Create Dedicated product and price
stripe products create \
  --name "RunClaw Dedicated" \
  --metadata[plan]=dedicated \
  --metadata[server_type]=cx42

stripe prices create \
  --product <dedicated-product-id> \
  --unit-amount 4900 \
  --currency usd \
  --recurring[interval]=month
```

**Record all product and price IDs for use in the application.**

### 5.4 Customer Portal Configuration

In Stripe Dashboard > Settings > Billing > Customer Portal:

- **Allow customers to:** Update payment methods, view invoices.
- **Allow customers to:** Cancel subscriptions (with proration).
- **Do NOT allow:** Switching plans (handle this through the RunClaw dashboard to trigger VPS resize).
- **Redirect URL:** `https://runclaw.io/dashboard`

### 5.5 Pre-Go-Live Stripe Checklist

- [ ] All products created in **test mode** first.
- [ ] Full flow tested with Stripe test cards (`4242424242424242`).
- [ ] Webhook signature verification confirmed working.
- [ ] All test events processed correctly (check `webhook_events` collection).
- [ ] Switch to **live mode** and recreate products/prices.
- [ ] Update all price IDs in the application.
- [ ] Configure live webhook endpoint.
- [ ] Verify live webhook receives events.

---

## 6. Cloudflare Setup Security

### 6.1 Zone Configuration

1. Add `runclaw.io` zone to Cloudflare.
2. Update registrar nameservers to Cloudflare's assigned nameservers.
3. Wait for zone activation (check via `dig NS runclaw.io`).

```bash
# Verify zone is active
curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=runclaw.io" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result[0].status'
# Expected: "active"
```

### 6.2 SSL/TLS Mode

In Cloudflare Dashboard > SSL/TLS:

- **Encryption mode:** Full (Strict).
- **Always Use HTTPS:** On.
- **Automatic HTTPS Rewrites:** On.
- **Minimum TLS Version:** TLS 1.2.
- **TLS 1.3:** On.
- **Opportunistic Encryption:** On.

```bash
# Verify via API
curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/ssl" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"strict"}' | jq '.success'
# Expected: true

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/always_use_https" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"on"}' | jq '.success'
# Expected: true

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/min_tls_version" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"1.2"}' | jq '.success'
# Expected: true

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/tls_1_3" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"on"}' | jq '.success'
# Expected: true
```

### 6.3 WAF Rules

In Cloudflare Dashboard > Security > WAF:

**Managed rules -- enable:**
- Cloudflare Managed Ruleset (default action: Block).
- Cloudflare OWASP Core Ruleset (Paranoia Level 2).

**Custom rules for RunClaw:**

```bash
# Block common attack paths
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/firewall/rules" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '[{
    "filter": {
      "expression": "(http.request.uri.path contains \"/wp-admin\") or (http.request.uri.path contains \"/wp-login\") or (http.request.uri.path contains \"/xmlrpc\") or (http.request.uri.path contains \"/.env\") or (http.request.uri.path contains \"/.git\") or (http.request.uri.path contains \"/phpmyadmin\")",
      "paused": false
    },
    "action": "block",
    "description": "Block common attack paths"
  }]' | jq '.success'
```

### 6.4 Bot Fight Mode

In Cloudflare Dashboard > Security > Bots:

- **Bot Fight Mode:** On.
- **Super Bot Fight Mode (if available on plan):** Definitely automated = Block. Likely automated = Managed Challenge.

### 6.5 Rate Limiting Rules

```bash
# Rate limit API endpoints (per customer subdomain)
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/rate_limits" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "match": {
      "request": {
        "url_pattern": "*.runclaw.io/*",
        "schemes": ["HTTPS"],
        "methods": ["_ALL_"]
      },
      "response": {}
    },
    "threshold": 300,
    "period": 60,
    "action": {
      "mode": "challenge",
      "timeout": 3600
    },
    "enabled": true,
    "description": "Rate limit all customer subdomains"
  }' | jq '.success'
```

### 6.6 Origin Protection

```bash
# Create firewall rule to only allow Cloudflare IPs to reach origins
# This is done at the Hetzner Cloud Firewall level:
# Only allow inbound TCP 80/443 from Cloudflare IP ranges

# Get current Cloudflare IP ranges
curl -s https://api.cloudflare.com/client/v4/ips | jq '.result.ipv4_cidrs, .result.ipv6_cidrs'

# Use these CIDRs in your Hetzner Cloud Firewall rules
# so that only Cloudflare can reach ports 80/443 on customer VPSes.
```

### 6.7 DNS Record Automation Security

The Cloudflare API token used for DNS automation must be scoped strictly:

- **Permissions:** Zone:DNS:Edit
- **Zone Resources:** Include specific zone: `runclaw.io`
- **Client IP Address Filtering:** Restrict to Vercel's egress IP ranges (if available) or leave unrestricted since the token is server-side only.
- **TTL:** Set to 1 year, rotate annually.

Verify token permissions:

```bash
curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result.status'
# Expected: "active"
```

---

## 7. Deployment Procedure (Step-by-Step)

### Step 1: Initial Vercel Deployment

```bash
# Clone the RunClaw repository
git clone https://github.com/your-org/runclaw.git
cd runclaw

# Install dependencies
pnpm install

# Run local build to verify before deploying
pnpm build

# Expected output:
#   Route (app)                              Size     First Load JS
#   ...
#   + First Load JS shared by all            XX kB
#   Build completed successfully

# Deploy to Vercel
vercel --prod

# Expected output:
#   Vercel CLI XX.X.X
#   Deploying runclaw to production
#   ...
#   Production: https://runclaw.io [XX.XXs]

# Verify deployment
curl -s -o /dev/null -w "%{http_code}" https://runclaw.io
# Expected: 200
```

### Step 2: Appwrite Project and Collections Setup

Execute all commands from Section 4.2 above. After completion, verify:

```bash
# Verify collections exist
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" | jq '.collections[].name'

# Expected output:
# "Users"
# "Instances"
# "Webhook Events"
# "Instance Events"

# Verify indexes on instances collection
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/indexes" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" | jq '.indexes[].key'

# Expected output:
# "subdomain_unique"
# "user_id_idx"
# "status_idx"
# "stripe_sub_idx"
```

### Step 3: Stripe Products and Webhook Configuration

1. Create products and prices using the commands in Section 5.3.
2. Configure webhook endpoint as described in Section 5.1.
3. Verify with Stripe CLI:

```bash
# Start webhook forwarding (local dev only)
stripe listen --forward-to localhost:3000/api/stripe/webhook

# Trigger test event
stripe trigger checkout.session.completed

# Check the webhook_events collection for the processed event
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/webhook_events/documents" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" | jq '.documents | length'

# Expected: 1 (or however many test events you sent)
```

### Step 4: Cloudflare Zone and Wildcard DNS Setup

```bash
# Verify zone is active (from Step 6.1)
curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=runclaw.io" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result[0].status'
# Expected: "active"

# Create A record for root domain (pointing to Vercel)
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "type": "A",
    "name": "runclaw.io",
    "content": "76.76.21.21",
    "ttl": 1,
    "proxied": true
  }' | jq '.success'
# Expected: true
# Note: 76.76.21.21 is Vercel's IP. Adjust if Vercel provides different IPs.

# Create CNAME for www
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "type": "CNAME",
    "name": "www",
    "content": "runclaw.io",
    "ttl": 1,
    "proxied": true
  }' | jq '.success'
# Expected: true

# Verify SSL settings are applied (from Step 6.2)
curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/ssl" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result.value'
# Expected: "strict"
```

### Step 5: First Test Instance Provisioning

```bash
# Create a test user account via the RunClaw signup page
# Navigate to: https://runclaw.io/signup
# Use a test email and password

# After signup, create a test Stripe subscription:
stripe subscriptions create \
  --customer <test-customer-id> \
  --items[0][price]=<starter-price-id>

# Trigger instance creation via the API (or through the dashboard)
curl -s -X POST "https://runclaw.io/api/instances/create" \
  -H "Content-Type: application/json" \
  -H "Cookie: a_session_<project-id>=<session-cookie>" \
  -d '{
    "subdomain": "test001",
    "plan": "starter",
    "region": "fsn1"
  }'

# Expected response:
# {
#   "success": true,
#   "instance": {
#     "id": "<instance-id>",
#     "subdomain": "test001",
#     "status": "provisioning",
#     "url": "https://test001.runclaw.io",
#     "estimated_ready": "2026-02-03T12:03:00.000Z"
#   }
# }
```

### Step 6: Verification of Full Flow

Wait approximately 3 minutes for provisioning, then verify:

```bash
# Check instance status in Appwrite
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/<instance-id>" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" | jq '{status: .status, ip: .ip_address, hetzner_id: .hetzner_server_id}'

# Expected: { "status": "running", "ip": "XXX.XXX.XXX.XXX", "hetzner_id": XXXXXXX }

# Verify Hetzner server exists
curl -s -X GET "https://api.hetzner.cloud/v1/servers?name=claw-test001" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq '.servers[0].status'
# Expected: "running"

# Verify DNS record exists
curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?name=test001.runclaw.io" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | jq '.result[0].content'
# Expected: "XXX.XXX.XXX.XXX" (the VPS IP)

# Verify the instance is accessible via HTTPS
curl -s -o /dev/null -w "%{http_code}" https://test001.runclaw.io/health
# Expected: 200

# Verify security headers
curl -sI https://test001.runclaw.io/ | grep -E "^(X-Content-Type|X-Frame|Strict-Transport|Content-Security|Referrer-Policy)"
# Expected:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
# Content-Security-Policy: default-src 'self'; ...
# Referrer-Policy: strict-origin-when-cross-origin

# Clean up: delete the test instance
curl -s -X POST "https://runclaw.io/api/instances/delete" \
  -H "Content-Type: application/json" \
  -H "Cookie: a_session_<project-id>=<session-cookie>" \
  -d '{"instance_id": "<instance-id>"}'
# Expected: { "success": true, "message": "Instance scheduled for deletion" }
```

### Step 7: Production Go-Live Checklist

- [ ] All test instances deleted and verified.
- [ ] Stripe switched from test mode to live mode.
- [ ] Live webhook endpoint configured with live signing secret.
- [ ] All Vercel environment variables updated with live credentials.
- [ ] Redeploy to Vercel after env var updates: `vercel --prod`
- [ ] DNS propagation complete (check `dig test.runclaw.io` from multiple locations).
- [ ] Cloudflare WAF and rate limiting rules verified active.
- [ ] Health check cron verified running (check Vercel cron logs).
- [ ] Provision-timeout cron verified running.
- [ ] Reconciliation cron verified running.
- [ ] Monitoring and alerting active (see Section 8).
- [ ] Backup procedures documented and tested.
- [ ] Incident response contacts documented.

---

## 8. Post-Deployment Verification

### 8.1 Security Scan Checklist

| Scan Type | Tool | Command / URL | Frequency |
|-----------|------|---------------|-----------|
| SSL/TLS | SSL Labs | `https://www.ssllabs.com/ssltest/analyze.html?d=runclaw.io` | After deployment, monthly |
| Security headers | SecurityHeaders.com | `https://securityheaders.com/?q=runclaw.io` | After deployment, monthly |
| DNS security | DNS Viz | `https://dnsviz.net/d/runclaw.io` | After deployment |
| Port scan | nmap | `nmap -sV -p- test001.runclaw.io` | After first VPS provision |
| Web vulnerability | OWASP ZAP | `zap-cli quick-scan https://runclaw.io` | Monthly |
| Dependency audit | npm audit | `pnpm audit --production` | Before each deployment |
| Container scan | Trivy | `trivy image openclaw/openclaw:latest` | Before each deployment |

```bash
# SSL Labs scan (programmatic)
curl -s "https://api.ssllabs.com/api/v3/analyze?host=runclaw.io&startNew=on" | jq '.status'
# Wait for completion, then:
curl -s "https://api.ssllabs.com/api/v3/analyze?host=runclaw.io" | jq '.endpoints[0].grade'
# Expected: "A" or "A+"

# Port scan a test VPS
nmap -sV -p- --open <vps-ip>
# Expected: Only ports 22, 80, 443 should be open

# Dependency audit
cd /path/to/runclaw
pnpm audit --production
# Expected: 0 vulnerabilities (or only low-severity advisories with no fix available)

# Container image scan
trivy image openclaw/openclaw:latest --severity HIGH,CRITICAL
# Expected: 0 HIGH or CRITICAL vulnerabilities
```

### 8.2 Penetration Test Schedule

| Test Type | Scope | Frequency | Provider |
|-----------|-------|-----------|----------|
| Automated web scan | `runclaw.io` control plane | Monthly | OWASP ZAP (automated) |
| Automated infra scan | Sample VPS | Monthly | OpenVAS (automated) |
| Manual pen test | Full stack | Annually | Third-party security firm |
| Bug bounty | Public-facing surfaces | Ongoing | Self-managed or HackerOne |

### 8.3 Monitoring Setup Verification

```bash
# Verify Vercel cron jobs are executing
# Check Vercel Dashboard > Project > Cron Jobs
# Or via Vercel API:
vercel logs --output json | grep "api/cron" | head -5

# Trigger each cron manually to verify:
curl -s -H "Authorization: Bearer $CRON_SECRET" https://runclaw.io/api/cron/health | jq '.'
# Expected: { "checked": N, "healthy": N, "unhealthy": 0 }

curl -s -H "Authorization: Bearer $CRON_SECRET" https://runclaw.io/api/cron/provision-timeout | jq '.'
# Expected: { "timedOut": 0 }

curl -s -H "Authorization: Bearer $CRON_SECRET" https://runclaw.io/api/cron/reconcile | jq '.'
# Expected: { "hetznerServersDeleted": 0, "dnsRecordsDeleted": 0, "instancesMarkedFailed": 0, "errors": [] }
```

### 8.4 Alert Testing

Trigger each alert type to verify delivery:

```bash
# 1. Provision timeout alert
#    Create an instance but block the callback URL at the VPS level.
#    Wait 10 minutes for the provision-timeout cron to fire.
#    Verify the instance is marked "failed" in Appwrite.

# 2. Health check failure alert
#    SSH into a test VPS and stop the OpenClaw container:
#    docker compose -f /opt/openclaw/docker-compose.yml stop openclaw
#    Wait 15 minutes (3 consecutive health check failures).
#    Verify the instance is marked "unhealthy" in Appwrite.

# 3. Payment failure alert
#    Use Stripe test card 4000000000000341 (attaches but fails on charge).
#    Verify invoice.payment_failed event is processed.

# 4. Webhook processing error
#    Temporarily break the webhook handler, send a test event via Stripe CLI.
#    Verify the error is logged in webhook_events with success=false.
```

### 8.5 Backup Verification

```bash
# Verify Appwrite data can be exported
# Appwrite Cloud provides automated backups, but verify access:
appwrite databases listDocuments --databaseId main --collectionId instances --queries '[]' | jq '.total'
# Expected: Number matches expected instance count

# Verify Vercel deployment can be rolled back
vercel ls
# Expected: List of recent deployments with URLs

# Verify Hetzner snapshots (if configured)
curl -s -X GET "https://api.hetzner.cloud/v1/images?type=snapshot" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq '.images | length'
```

### 8.6 Incident Response Drill Schedule

| Drill | Frequency | Duration | Participants |
|-------|-----------|----------|--------------|
| VPS goes down (single instance) | Monthly | 30 min | On-call engineer |
| Control plane outage (Vercel) | Quarterly | 1 hour | Full team |
| Credential compromise | Quarterly | 2 hours | Full team + security |
| Mass instance failure | Semi-annually | 2 hours | Full team |
| Full disaster recovery | Annually | 4 hours | Full team |

---

## 9. Operational Security Procedures

### 9.1 API Key Rotation Schedule

| Key | Rotation Period | Procedure |
|-----|----------------|-----------|
| Hetzner API token | 90 days | Generate new token in Hetzner Console, update Vercel env, verify, delete old token |
| Cloudflare API token | 90 days | Generate new token in Cloudflare Dashboard, update Vercel env, verify, delete old token |
| Appwrite API key | 90 days | Generate new key in Appwrite Console, update Vercel env, verify, delete old key |
| Stripe webhook secret | On endpoint change only | Create new endpoint, update Vercel env, verify, delete old endpoint |
| CRON_SECRET | 90 days | Generate new secret, update Vercel env, redeploy |

**Rotation procedure (example: Hetzner API token):**

```bash
# Step 1: Generate new token in Hetzner Console
# https://console.hetzner.cloud/projects/<project>/security/tokens
# Name it with a date: "runclaw-YYYY-MM-DD"
# Copy the new token

# Step 2: Update Vercel environment variable
vercel env rm HETZNER_API_TOKEN production
vercel env add HETZNER_API_TOKEN production
# Paste new token

# Step 3: Redeploy to pick up new variable
vercel --prod

# Step 4: Verify new token works
curl -s -X GET "https://api.hetzner.cloud/v1/servers" \
  -H "Authorization: Bearer <new-token>" | jq '.servers | length'
# Expected: number >= 0 (no error)

# Step 5: Delete old token in Hetzner Console
# Only after verifying the new token works in production

# Step 6: Document rotation in ops log
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Rotated Hetzner API token" >> /path/to/ops-log.txt
```

### 9.2 SSH Key Rotation

```bash
# Step 1: Generate new Ed25519 key
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/runclaw_admin_new -C "admin@runclaw.io-$(date +%Y%m)"

# Step 2: Add new public key to Hetzner project
# https://console.hetzner.cloud/projects/<project>/security/sshkeys

# Step 3: Add new key to all existing VPSes
# For each running instance, SSH in with the old key and add the new key:
for ip in $(curl -s -X GET "https://api.hetzner.cloud/v1/servers" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq -r '.servers[].public_net.ipv4.ip'); do
  ssh -i ~/.ssh/runclaw_admin openclaw@$ip \
    "echo '$(cat ~/.ssh/runclaw_admin_new.pub)' >> ~/.ssh/authorized_keys"
done

# Step 4: Test new key against each VPS
for ip in $(curl -s -X GET "https://api.hetzner.cloud/v1/servers" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq -r '.servers[].public_net.ipv4.ip'); do
  ssh -i ~/.ssh/runclaw_admin_new openclaw@$ip "echo OK"
done
# Expected: "OK" for each VPS

# Step 5: Remove old key from all VPSes
for ip in $(curl -s -X GET "https://api.hetzner.cloud/v1/servers" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq -r '.servers[].public_net.ipv4.ip'); do
  ssh -i ~/.ssh/runclaw_admin_new openclaw@$ip \
    "sed -i '/runclaw_admin/d' ~/.ssh/authorized_keys"
done

# Step 6: Rename new key to replace old
mv ~/.ssh/runclaw_admin ~/.ssh/runclaw_admin_old
mv ~/.ssh/runclaw_admin_new ~/.ssh/runclaw_admin
mv ~/.ssh/runclaw_admin_new.pub ~/.ssh/runclaw_admin.pub

# Step 7: Remove old key from Hetzner project (Console)
# Step 8: Securely delete old key file after 7-day grace period
# shred -u ~/.ssh/runclaw_admin_old
```

### 9.3 Certificate Renewal Verification

Caddy handles certificate renewal automatically via ACME. Verify:

```bash
# Check certificate expiry for a customer subdomain
echo | openssl s_client -connect test001.runclaw.io:443 -servername test001.runclaw.io 2>/dev/null | openssl x509 -noout -dates
# Expected:
# notBefore=...
# notAfter=... (should be > 30 days from now)

# Check certificate expiry for the control plane
echo | openssl s_client -connect runclaw.io:443 -servername runclaw.io 2>/dev/null | openssl x509 -noout -dates
# Expected: notAfter > 30 days from now
```

Set up a cron job or monitoring alert for certificates expiring within 14 days.

### 9.4 Dependency Update Policy

| Severity | SLA | Procedure |
|----------|-----|-----------|
| Critical (RCE, auth bypass) | 24 hours | Emergency patch, immediate redeploy |
| High (data exposure, privilege escalation) | 72 hours | Priority patch, test, deploy |
| Medium (DoS, information disclosure) | 1 week | Standard patch cycle |
| Low (minor issues) | Next release cycle | Bundle with regular updates |

```bash
# Check for vulnerabilities
pnpm audit --production

# Update a specific critical dependency
pnpm update <package-name>@latest

# Rebuild and test
pnpm build
pnpm test

# Deploy
vercel --prod
```

### 9.5 Customer VPS Update Procedure (Rolling Updates)

For updating OpenClaw on all customer VPSes:

```bash
#!/bin/bash
# scripts/rolling-update.sh
# Usage: ./scripts/rolling-update.sh <new-openclaw-image-digest>

NEW_IMAGE="$1"
if [ -z "$NEW_IMAGE" ]; then
  echo "Usage: $0 <new-openclaw-image-digest>"
  exit 1
fi

HETZNER_TOKEN="$HETZNER_API_TOKEN"
BATCH_SIZE=5
PAUSE_BETWEEN_BATCHES=60

# Get all running instances
SERVERS=$(curl -s -X GET "https://api.hetzner.cloud/v1/servers?label_selector=service=runclaw" \
  -H "Authorization: Bearer $HETZNER_TOKEN" | jq -r '.servers[] | "\(.id) \(.public_net.ipv4.ip) \(.name)"')

TOTAL=$(echo "$SERVERS" | wc -l)
UPDATED=0
FAILED=0

echo "Rolling update: $TOTAL servers, batch size $BATCH_SIZE"

while IFS= read -r line; do
  SERVER_ID=$(echo "$line" | awk '{print $1}')
  SERVER_IP=$(echo "$line" | awk '{print $2}')
  SERVER_NAME=$(echo "$line" | awk '{print $3}')

  echo "Updating $SERVER_NAME ($SERVER_IP)..."

  # Update docker-compose.yml with new image
  ssh -i ~/.ssh/runclaw_admin -o ConnectTimeout=10 openclaw@"$SERVER_IP" \
    "cd /opt/openclaw && \
     sed -i 's|image: openclaw/openclaw:.*|image: $NEW_IMAGE|' docker-compose.yml && \
     docker compose pull openclaw && \
     docker compose up -d openclaw && \
     sleep 10 && \
     curl -sf http://127.0.0.1:3000/health > /dev/null" 2>/dev/null

  if [ $? -eq 0 ]; then
    UPDATED=$((UPDATED + 1))
    echo "  OK: $SERVER_NAME updated successfully"
  else
    FAILED=$((FAILED + 1))
    echo "  FAIL: $SERVER_NAME update failed"
  fi

  # Pause between batches
  if [ $((UPDATED % BATCH_SIZE)) -eq 0 ] && [ $UPDATED -gt 0 ]; then
    echo "Batch complete. Pausing ${PAUSE_BETWEEN_BATCHES}s..."
    sleep $PAUSE_BETWEEN_BATCHES
  fi
done <<< "$SERVERS"

echo ""
echo "Rolling update complete: $UPDATED updated, $FAILED failed out of $TOTAL"
```

---

## 10. Rollback Procedures

### 10.1 Rollback a Bad Vercel Deployment

```bash
# List recent deployments
vercel ls
# Expected output:
#   Age     Status    URL
#   2m      Ready     runclaw-xxxx.vercel.app  (current production)
#   1d      Ready     runclaw-yyyy.vercel.app  (previous)
#   2d      Ready     runclaw-zzzz.vercel.app

# Identify the last known good deployment URL
GOOD_DEPLOYMENT="runclaw-yyyy.vercel.app"

# Promote the good deployment to production
vercel promote $GOOD_DEPLOYMENT

# Expected output:
#   Success! runclaw-yyyy.vercel.app promoted to production

# Verify rollback
curl -s -o /dev/null -w "%{http_code}" https://runclaw.io
# Expected: 200

# Verify the correct deployment is serving
curl -sI https://runclaw.io | grep "x-vercel-id"
# Should correspond to the good deployment
```

### 10.2 Rollback a Bad Cloud-Init Template

A bad cloud-init template affects only newly provisioned VPSes, not existing ones. Existing instances are unaffected.

```bash
# Step 1: Immediately revert the cloud-init template in code
git log --oneline -5  # Find the commit that introduced the bad template
git revert <bad-commit-hash>

# Step 2: Rebuild and redeploy the control plane
pnpm build
vercel --prod

# Step 3: Identify instances provisioned with the bad template
# Check instance_events for recent provisioning_failed or provisioning_completed events
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" \
  --data-urlencode 'queries[]={"method":"greaterThan","attribute":"created_at","values":["<bad-deploy-timestamp>"]}' | jq '.documents[] | {id: .$id, subdomain: .subdomain, status: .status}'

# Step 4: For each affected instance, delete and re-provision
# The user can delete and recreate from the dashboard, or an admin can:
for INSTANCE_ID in <list-of-affected-instance-ids>; do
  # Delete the bad VPS
  HETZNER_ID=$(curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INSTANCE_ID" \
    -H "X-Appwrite-Project: <project-id>" \
    -H "X-Appwrite-Key: <api-key>" | jq -r '.hetzner_server_id')

  curl -s -X DELETE "https://api.hetzner.cloud/v1/servers/$HETZNER_ID" \
    -H "Authorization: Bearer $HETZNER_API_TOKEN"

  # Mark instance as failed so user can re-provision
  curl -s -X PATCH "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INSTANCE_ID" \
    -H "X-Appwrite-Project: <project-id>" \
    -H "X-Appwrite-Key: <api-key>" \
    -H "Content-Type: application/json" \
    -d '{"status":"failed","status_message":"Re-provisioning required due to configuration update. Please delete and recreate your instance."}'
done
```

### 10.3 Recover a Failed VPS Provisioning

```bash
# Step 1: Check what went wrong
INSTANCE_ID="<instance-id>"

# Check instance status
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INSTANCE_ID" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" | jq '{status: .status, message: .status_message, hetzner_id: .hetzner_server_id, ip: .ip_address}'

# Step 2: If the Hetzner server exists, SSH in and check logs
ssh -i ~/.ssh/runclaw_admin openclaw@<vps-ip> "cat /var/log/runclaw/provision.log"
ssh -i ~/.ssh/runclaw_admin openclaw@<vps-ip> "docker compose -f /opt/openclaw/docker-compose.yml logs"
ssh -i ~/.ssh/runclaw_admin openclaw@<vps-ip> "cat /var/log/cloud-init-output.log | tail -100"

# Step 3: If recoverable, fix the issue and trigger the callback manually
ssh -i ~/.ssh/runclaw_admin openclaw@<vps-ip> \
  "curl -X POST https://runclaw.io/api/instances/ready \
   -H 'Content-Type: application/json' \
   -d '{\"instance_id\":\"$INSTANCE_ID\",\"callback_secret\":\"<secret>\",\"openclaw_version\":\"latest\"}'"

# Step 4: If not recoverable, clean up
# Delete Hetzner server
HETZNER_ID=$(curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INSTANCE_ID" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" | jq -r '.hetzner_server_id')

curl -s -X DELETE "https://api.hetzner.cloud/v1/servers/$HETZNER_ID" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN"

# Delete DNS record
SUBDOMAIN=$(curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INSTANCE_ID" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" | jq -r '.subdomain')

DNS_RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?name=$SUBDOMAIN.runclaw.io" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq -r '.result[0].id')

curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$DNS_RECORD_ID" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"

# Mark instance as failed
curl -s -X PATCH "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INSTANCE_ID" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"status":"failed","status_message":"Provisioning failed. Please delete and try again."}'
```

### 10.4 Handle Mass Instance Failures

If multiple instances go down simultaneously (e.g., Hetzner region outage):

```bash
#!/bin/bash
# scripts/mass-recovery.sh
# Run this from the operator's machine

echo "=== Mass Instance Recovery ==="
echo "Started at $(date -u)"

# Step 1: Get all affected instances
AFFECTED=$(curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" \
  --data-urlencode 'queries[]={"method":"equal","attribute":"status","values":["unhealthy"]}' | jq -r '.documents[] | "\(.$id) \(.subdomain) \(.ip_address) \(.hetzner_server_id)"')

TOTAL=$(echo "$AFFECTED" | wc -l)
echo "Affected instances: $TOTAL"

# Step 2: Check each instance and attempt recovery
RECOVERED=0
NEED_REPROVISION=0

while IFS= read -r line; do
  INST_ID=$(echo "$line" | awk '{print $1}')
  SUBDOMAIN=$(echo "$line" | awk '{print $2}')
  IP=$(echo "$line" | awk '{print $3}')
  HETZNER_ID=$(echo "$line" | awk '{print $4}')

  echo "Checking $SUBDOMAIN ($IP)..."

  # Try to restart Docker on the VPS
  ssh -i ~/.ssh/runclaw_admin -o ConnectTimeout=5 openclaw@"$IP" \
    "docker compose -f /opt/openclaw/docker-compose.yml restart" 2>/dev/null

  if [ $? -eq 0 ]; then
    sleep 15
    # Check health
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://$IP:80/health" 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
      RECOVERED=$((RECOVERED + 1))
      echo "  RECOVERED: $SUBDOMAIN"
      # Update status to running
      curl -s -X PATCH "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INST_ID" \
        -H "X-Appwrite-Project: <project-id>" \
        -H "X-Appwrite-Key: <api-key>" \
        -H "Content-Type: application/json" \
        -d "{\"status\":\"running\",\"last_health_check_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > /dev/null
      continue
    fi
  fi

  NEED_REPROVISION=$((NEED_REPROVISION + 1))
  echo "  NEEDS REPROVISION: $SUBDOMAIN"
done <<< "$AFFECTED"

echo ""
echo "=== Summary ==="
echo "Total affected: $TOTAL"
echo "Recovered: $RECOVERED"
echo "Need re-provisioning: $NEED_REPROVISION"
echo "Completed at $(date -u)"
```

### 10.5 Emergency Shutdown Procedure

Use this to immediately shut down all customer instances (e.g., during a security incident):

```bash
#!/bin/bash
# scripts/emergency-shutdown.sh
# WARNING: This shuts down ALL customer instances.

echo "!!! EMERGENCY SHUTDOWN !!!"
echo "This will shut down ALL customer VPS instances."
read -p "Type 'CONFIRM SHUTDOWN' to proceed: " CONFIRM
if [ "$CONFIRM" != "CONFIRM SHUTDOWN" ]; then
  echo "Aborted."
  exit 1
fi

echo "Starting emergency shutdown at $(date -u)"

# Step 1: Get all Hetzner servers with runclaw label
SERVERS=$(curl -s -X GET "https://api.hetzner.cloud/v1/servers?label_selector=service=runclaw" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq -r '.servers[] | "\(.id) \(.name)"')

# Step 2: Power off each server (not delete -- preserve data)
while IFS= read -r line; do
  SERVER_ID=$(echo "$line" | awk '{print $1}')
  SERVER_NAME=$(echo "$line" | awk '{print $2}')

  echo "Powering off $SERVER_NAME (ID: $SERVER_ID)..."
  curl -s -X POST "https://api.hetzner.cloud/v1/servers/$SERVER_ID/actions/poweroff" \
    -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq '.action.status'
done <<< "$SERVERS"

# Step 3: Mark all instances as stopped in the database
curl -s -X GET "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents" \
  -H "X-Appwrite-Project: <project-id>" \
  -H "X-Appwrite-Key: <api-key>" \
  -H "Content-Type: application/json" \
  --data-urlencode 'queries[]={"method":"equal","attribute":"status","values":["running","unhealthy"]}' | \
  jq -r '.documents[].$id' | while read INST_ID; do
    curl -s -X PATCH "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents/$INST_ID" \
      -H "X-Appwrite-Project: <project-id>" \
      -H "X-Appwrite-Key: <api-key>" \
      -H "Content-Type: application/json" \
      -d '{"status":"stopped","status_message":"Emergency maintenance. Your instance will be restored shortly."}' > /dev/null
    echo "Marked $INST_ID as stopped"
  done

echo ""
echo "Emergency shutdown complete at $(date -u)"
echo "To restore: use scripts/mass-recovery.sh after resolving the incident"
```

**To restore after emergency shutdown:**

```bash
# Power on all servers
curl -s -X GET "https://api.hetzner.cloud/v1/servers?label_selector=service=runclaw" \
  -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq -r '.servers[].id' | while read SERVER_ID; do
    curl -s -X POST "https://api.hetzner.cloud/v1/servers/$SERVER_ID/actions/poweron" \
      -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq '.action.status'
    echo "Powered on server $SERVER_ID"
  done

# Wait for servers to boot
echo "Waiting 120 seconds for servers to boot..."
sleep 120

# Run mass recovery to verify health and update statuses
./scripts/mass-recovery.sh
```

---

## Appendix A: Environment Variable Reference

| Variable | Location | Sensitive | Description |
|----------|----------|-----------|-------------|
| `NEXT_PUBLIC_APPWRITE_ENDPOINT` | Vercel (prod) | No | Appwrite API endpoint |
| `NEXT_PUBLIC_APPWRITE_PROJECT_ID` | Vercel (prod) | No | Appwrite project ID |
| `NEXT_PUBLIC_APPWRITE_DATABASE_ID` | Vercel (prod) | No | Appwrite database ID |
| `APPWRITE_ENDPOINT` | Vercel (prod only) | No | Server-side Appwrite endpoint |
| `APPWRITE_PROJECT_ID` | Vercel (prod only) | No | Server-side Appwrite project ID |
| `APPWRITE_DATABASE_ID` | Vercel (prod only) | No | Server-side Appwrite database ID |
| `APPWRITE_API_KEY` | Vercel (prod only) | **Yes** | Server-side API key |
| `STRIPE_SECRET_KEY` | Vercel (prod only) | **Yes** | Stripe secret key |
| `STRIPE_WEBHOOK_SECRET` | Vercel (prod only) | **Yes** | Stripe webhook signing secret |
| `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` | Vercel (prod) | No | Stripe publishable key |
| `HETZNER_API_TOKEN` | Vercel (prod only) | **Yes** | Hetzner Cloud API token |
| `CLOUDFLARE_API_TOKEN` | Vercel (prod only) | **Yes** | Cloudflare API token |
| `CLOUDFLARE_ZONE_ID` | Vercel (prod only) | No | Cloudflare zone ID for runclaw.io |
| `CRON_SECRET` | Vercel (prod only) | **Yes** | Authentication for cron endpoints |
| `NEXT_PUBLIC_APP_URL` | Vercel (prod) | No | Application URL |

## Appendix B: Contact and Escalation

| Situation | Action | Contact |
|-----------|--------|---------|
| Single instance failure | Check logs, attempt recovery | On-call engineer |
| Multiple instance failures | Run mass recovery script | On-call engineer + team lead |
| Control plane outage | Rollback Vercel deployment | On-call engineer |
| Security incident | Execute emergency shutdown, rotate credentials | Security lead + full team |
| Hetzner region outage | Monitor Hetzner status page, communicate to affected users | Team lead + support |
| Stripe billing issues | Check Stripe dashboard, verify webhook processing | Billing admin |

## Appendix C: Useful Commands Quick Reference

```bash
# === Hetzner ===
# List all RunClaw servers
curl -s "https://api.hetzner.cloud/v1/servers?label_selector=service=runclaw" -H "Authorization: Bearer $HETZNER_API_TOKEN" | jq '.servers[] | {id, name, status, ip: .public_net.ipv4.ip}'

# === Cloudflare ===
# List all DNS records for runclaw.io
curl -s "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq '.result[] | {name, type, content}'

# === Appwrite ===
# Count instances by status
for status in provisioning running unhealthy stopped failed deleting; do
  COUNT=$(curl -s "https://cloud.appwrite.io/v1/databases/main/collections/instances/documents" \
    -H "X-Appwrite-Project: <project-id>" -H "X-Appwrite-Key: <api-key>" \
    --data-urlencode "queries[]={\"method\":\"equal\",\"attribute\":\"status\",\"values\":[\"$status\"]}" | jq '.total')
  echo "$status: $COUNT"
done

# === VPS Access ===
# SSH into a customer VPS by subdomain
ssh -i ~/.ssh/runclaw_admin openclaw@$(dig +short <subdomain>.runclaw.io A)

# Check VPS Docker status
ssh -i ~/.ssh/runclaw_admin openclaw@<ip> "docker compose -f /opt/openclaw/docker-compose.yml ps"

# View VPS provisioning logs
ssh -i ~/.ssh/runclaw_admin openclaw@<ip> "cat /var/log/runclaw/provision.log"

# View VPS security logs
ssh -i ~/.ssh/runclaw_admin openclaw@<ip> "sudo journalctl -u fail2ban --since '1 hour ago'"
ssh -i ~/.ssh/runclaw_admin openclaw@<ip> "sudo ausearch -ts recent"
```
