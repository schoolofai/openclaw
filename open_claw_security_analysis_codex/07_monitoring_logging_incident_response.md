# Monitoring, Logging, and Incident Response

## Logging Strategy

- **Gateway logs**: capture auth failures, tool invocations, and errors
- **Reverse proxy logs**: track ingress patterns and anomalies
- **Runclaw control plane logs**: provisioning, webhook processing, reconciliation

## Recommended Signals

- Spike in failed auth attempts
- Unexpected tool execution on main session
- Multiple pairing requests from unknown senders
- Health check flapping or repeated callback failures
- Webhook verification failures

## Minimal Audit Trail

- Instance lifecycle events stored in Appwrite
- Gateway session logs stored under `~/.openclaw/agents/<agentId>/sessions/*.jsonl`
- Access logs at the proxy

## Alerting

- Notify on repeated health check failures
- Alert on provisioning timeouts
- Alert on gateway auth failures beyond a threshold

## Incident Response (IR) Runbook

1. **Contain**
   - Disable public ingress
   - Rotate gateway auth tokens
   - Revoke suspicious API keys

2. **Eradicate**
   - Rebuild affected VPS from a known-good image
   - Reinstall OpenClaw with clean state

3. **Recover**
   - Restore `~/.openclaw` from verified backups
   - Re-enable services with reduced access

4. **Lessons Learned**
   - Update hardening checklist
   - Add missing alerts and audit logs
