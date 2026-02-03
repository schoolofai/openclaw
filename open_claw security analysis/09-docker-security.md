# 09 - Docker Security

## Overview

OpenClaw runs inside Docker containers on RunClaw.io VPS instances. Container security is a critical layer in the defense-in-depth strategy. This document covers container isolation, image security, runtime hardening, and escape prevention.

## OpenClaw Container Architecture

```
Host OS (Ubuntu 24.04)
  |
  +-- Docker Engine
       |
       +-- openclaw container (node user, uid 1000)
       |     +-- Gateway (WebSocket + HTTP) on 127.0.0.1:18789
       |     +-- Media server on 127.0.0.1:18794
       |     +-- AI Agent (tool execution)
       |     +-- Volume: openclaw_data -> /home/node/.openclaw
       |
       +-- caddy container (non-root)
             +-- Reverse proxy on 0.0.0.0:80,443
             +-- Volume: caddy_data, caddy_config
             +-- Volume: Caddyfile (read-only)
```

## Dockerfile Security Analysis

### Current Dockerfile Strengths

From `Dockerfile` in the OpenClaw repository:

| Feature | Implementation | Risk Reduction |
|---|---|---|
| Non-root user | `USER node` (uid 1000) | Prevents privilege escalation |
| Production mode | `NODE_ENV=production` | Disables dev-only features |
| Loopback binding | Default `127.0.0.1` | Prevents external access |
| Token auth required | Configurable, not hardcoded | Prevents unauthorized access |

### Improvement Recommendations

```dockerfile
# Enhanced Dockerfile additions

# 1. Use specific image digest instead of tag
FROM node:22-bookworm@sha256:<pinned-digest>

# 2. Create dedicated user with specific UID/GID
RUN groupadd -g 1000 openclaw && \
    useradd -u 1000 -g openclaw -m -s /bin/bash openclaw

# 3. Remove unnecessary packages
RUN apt-get purge -y --auto-remove \
    curl wget git && \
    rm -rf /var/lib/apt/lists/*

# 4. Set read-only filesystem marker
ENV OPENCLAW_READONLY_FS=1

# 5. Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:18789/health').then(r => process.exit(r.ok ? 0 : 1))"

# 6. Drop all capabilities
# (Done at docker-compose level)
```

## Container Runtime Security

### 1. Capability Dropping

```yaml
# docker-compose.yml
services:
  openclaw:
    cap_drop:
      - ALL
    # Only add back what's strictly needed:
    # cap_add:
    #   - NET_BIND_SERVICE  # Only if binding to ports < 1024
```

**OpenClaw does NOT need**:
- `SYS_ADMIN` - No filesystem mounting
- `NET_RAW` - No raw socket access
- `SYS_PTRACE` - No debugging
- `MKNOD` - No device creation
- `AUDIT_WRITE` - No audit log writing

### 2. Security Options

```yaml
services:
  openclaw:
    security_opt:
      - no-new-privileges:true  # Prevent privilege escalation via setuid
      - seccomp:default         # Use default seccomp profile (or custom)
    # Optional: AppArmor profile
    # security_opt:
    #   - apparmor:openclaw-profile
```

### 3. Read-Only Filesystem

```yaml
services:
  openclaw:
    read_only: true
    tmpfs:
      - /tmp:size=100M
      - /home/node/.cache:size=200M
    volumes:
      - openclaw_data:/home/node/.openclaw  # Writable data only here
```

### 4. Resource Limits

```yaml
services:
  openclaw:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
          pids: 256
        reservations:
          cpus: '0.5'
          memory: 512M
    ulimits:
      nofile:
        soft: 32768
        hard: 65536
      nproc:
        soft: 256
        hard: 512
```

### 5. Network Isolation

```yaml
services:
  openclaw:
    networks:
      - internal  # Internal only, no direct internet access

  caddy:
    networks:
      - internal
      - external  # Internet-facing
    ports:
      - "80:80"
      - "443:443"

networks:
  internal:
    internal: true  # No external connectivity
  external:
    driver: bridge
```

**Impact**: OpenClaw container cannot reach the internet directly. All traffic goes through Caddy. This prevents reverse shells and data exfiltration via direct connections.

**Caveat**: OpenClaw needs outbound access for LLM APIs and messaging platforms. For strict deployments, use a forward proxy:

```yaml
services:
  squid:
    image: sameersbn/squid
    volumes:
      - ./squid.conf:/etc/squid/squid.conf:ro
    networks:
      - internal
      - external
```

## Container Escape Prevention

### Attack: Docker Socket Mount

**Risk**: If `/var/run/docker.sock` is mounted into the container, an attacker can create new containers with host access.

**Verification**:
```bash
docker inspect openclaw --format='{{json .HostConfig.Binds}}' | grep -i docker
# Should return empty/no docker.sock
```

**Mitigation**: Never mount the Docker socket. The OpenClaw docker-compose.yml does not mount it by default.

### Attack: Privileged Mode

**Risk**: Privileged containers have full access to host devices and capabilities.

**Verification**:
```bash
docker inspect openclaw --format='{{.HostConfig.Privileged}}'
# Must be: false
```

### Attack: Host PID/Network Namespace

**Risk**: `--pid=host` or `--network=host` breaks container isolation.

**Verification**:
```bash
docker inspect openclaw --format='{{.HostConfig.PidMode}}'   # Should be ""
docker inspect openclaw --format='{{.HostConfig.NetworkMode}}'  # Should be bridge/custom
```

### Attack: Writable Host Paths

**Risk**: Volume mounts with write access to sensitive host paths.

**Verification**:
```bash
docker inspect openclaw --format='{{json .HostConfig.Binds}}'
# Audit each mount point
# No mounts to /, /etc, /usr, /var/run, /root
```

### Attack: Kernel Exploitation

**Risk**: Container shares the host kernel. Kernel vulnerabilities can lead to escape.

**Mitigation**:
- Keep host kernel updated (unattended-upgrades)
- Use seccomp profiles to restrict syscalls
- Consider gVisor for stronger isolation:
  ```yaml
  services:
    openclaw:
      runtime: runsc  # gVisor runtime
  ```

## Image Supply Chain Security

### Image Verification

```bash
# Pull with digest pinning
docker pull openclaw/openclaw@sha256:<known-good-digest>

# Verify image layers
docker history openclaw/openclaw:latest --no-trunc

# Scan for CVEs
trivy image openclaw/openclaw:latest
docker scout cves openclaw/openclaw:latest

# Check for hardcoded secrets in image
docker history openclaw/openclaw:latest --no-trunc | grep -iE "token|key|password|secret"
```

### Image Update Strategy

```bash
# Automated image updates with Watchtower (caution: verify images first)
# Only for trusted registries with signed images

# Manual update procedure:
docker compose pull
docker compose up -d --force-recreate

# Verify after update
docker exec openclaw openclaw --version
docker exec openclaw openclaw security audit
```

## Volume Security

### Data Volume Permissions

```bash
# On the host, verify volume permissions
docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}'
ls -la $(docker volume inspect openclaw_openclaw_data --format='{{.Mountpoint}}')

# Inside the container
docker exec openclaw ls -la /home/node/.openclaw
# All files should be owned by node:node (1000:1000)
```

### Volume Encryption

```bash
# For sensitive deployments, use LUKS encryption on the volume backing store

# Create encrypted partition
cryptsetup luksFormat /dev/sdX
cryptsetup open /dev/sdX encrypted-data

# Create filesystem
mkfs.ext4 /dev/mapper/encrypted-data

# Mount for Docker
mount /dev/mapper/encrypted-data /var/lib/docker/volumes/openclaw_openclaw_data/_data
```

### Volume Backup Security

```bash
# Encrypted backups (see VPS Hardening Guide)
docker run --rm \
  -v openclaw_openclaw_data:/data:ro \
  -v /opt/backups:/backup \
  alpine sh -c "tar czf - -C /data . | gpg --symmetric --cipher-algo AES256 -o /backup/openclaw-$(date +%s).tar.gz.gpg"
```

## Docker Logging Security

### Log Configuration

```json
// /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "compress": "true"
  }
}
```

### Log Access Control

```bash
# Docker logs are stored at /var/lib/docker/containers/<id>/<id>-json.log
# Ensure only root can access
chmod 700 /var/lib/docker/containers
```

### Sensitive Data in Logs

```bash
# Check for leaked credentials in container logs
docker logs openclaw 2>&1 | grep -iE "token|key|password|secret" | head -20

# OpenClaw should redact sensitive data when logging.redactSensitive is enabled
```

## Docker Daemon Hardening

### Restrict Docker API

```bash
# Docker daemon should NOT expose TCP socket
# Verify:
cat /etc/docker/daemon.json | grep -i host
# Should NOT contain "tcp://0.0.0.0:2375" or similar

# If remote Docker API is needed, use TLS mutual auth:
# dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376
```

### Docker User Namespace Remapping

```json
// /etc/docker/daemon.json
{
  "userns-remap": "default"
}
```

This maps container root (uid 0) to an unprivileged host user, preventing container root from being host root.

## Monitoring Container Security

### Runtime Monitoring

```bash
# Check running container security posture
docker inspect openclaw --format='
  User: {{.Config.User}}
  Privileged: {{.HostConfig.Privileged}}
  ReadOnly: {{.HostConfig.ReadonlyRootfs}}
  SecurityOpt: {{json .HostConfig.SecurityOpt}}
  CapDrop: {{json .HostConfig.CapDrop}}
  CapAdd: {{json .HostConfig.CapAdd}}
  PidMode: {{.HostConfig.PidMode}}
  NetworkMode: {{.HostConfig.NetworkMode}}
'
```

### Container Drift Detection

```bash
# Check for unexpected changes in running container
docker diff openclaw
# Should show minimal changes (only in tmpfs and data volume)
# Any changes to /usr, /bin, /etc = suspicious
```

## Audit Checklist

```
[ ] Container runs as non-root user (node, uid 1000)
[ ] Privileged mode is false
[ ] All capabilities dropped
[ ] Read-only filesystem enabled (with tmpfs for temp)
[ ] No Docker socket mounted
[ ] No host PID/network namespace
[ ] Resource limits configured (CPU, memory, PIDs)
[ ] Network isolation (internal network for inter-container)
[ ] Volume mounts are minimal and don't include sensitive host paths
[ ] Image digest is pinned (not just :latest tag)
[ ] Image scanned for CVEs
[ ] No hardcoded secrets in image
[ ] Docker daemon not exposing TCP socket
[ ] Log rotation configured
[ ] User namespace remapping enabled
[ ] seccomp profile applied
```
