# Appendix: OpenClaw Security References

These project docs and commands underpin the guidance in this folder.

## Key Docs (Project)

- `SECURITY.md`
- `docs/gateway/security/index.md`
- `docs/gateway/authentication.md`
- `docs/gateway/sandboxing.md`
- `docs/cli/security.md`
- `docs/install/docker.md`
- `docs/platforms/hetzner.md`
- `docs/vps.md`

## Key Commands

```bash
openclaw security audit
openclaw security audit --deep
openclaw security audit --fix
```

## Sensitive Data Locations (OpenClaw)

- `~/.openclaw/credentials/*`
- `~/.openclaw/agents/<agentId>/agent/auth-profiles.json`
- `~/.openclaw/agents/<agentId>/sessions/*.jsonl`
