# Tutorial 06: Routing and Session Keys

## Overview

Routing determines which agent handles each incoming message and how sessions are isolated. This tutorial explains session keys, agent routing, and binding configuration.

## Routing Flow

```
Inbound Message
      │
      ▼
┌─────────────────┐
│ Extract Context │
│ - channel       │
│ - accountId     │
│ - peer          │
│ - guildId       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Resolve Route   │
│ - Check bindings│
│ - Match rules   │
│ - Pick agent    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Build Session   │
│ Key             │
│ - agentId       │
│ - channel       │
│ - peer          │
│ - dmScope       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Get/Create      │
│ Session         │
└─────────────────┘
```

## Session Keys

### Session Key Structure: `src/routing/session-key.ts`

Session keys uniquely identify a conversation context:

```typescript
// src/routing/session-key.ts

export const DEFAULT_ACCOUNT_ID = "default";
export const DEFAULT_MAIN_KEY = "main";
export const DEFAULT_AGENT_ID = "default";

// Build a session key for agent + peer interaction
export function buildAgentPeerSessionKey(params: {
  agentId: string;
  mainKey: string;
  channel: string;
  accountId?: string | null;
  peerKind: "dm" | "group" | "channel";
  peerId: string | null;
  dmScope?: "main" | "per-peer" | "per-channel-peer" | "per-account-channel-peer";
  identityLinks?: Record<string, string[]>;
}): string {
  const {
    agentId,
    mainKey,
    channel,
    accountId,
    peerKind,
    peerId,
    dmScope = "main",
    identityLinks,
  } = params;

  // Sanitize components
  const sanitizedAgent = sanitizeAgentId(agentId);
  const sanitizedChannel = channel.toLowerCase();
  const sanitizedAccount = accountId?.trim() || DEFAULT_ACCOUNT_ID;

  // Apply identity links (link multiple peer IDs to same session)
  const resolvedPeerId = resolveIdentityLink(peerId, identityLinks);

  // Build key based on dmScope
  switch (dmScope) {
    case "main":
      // Single session per agent
      return `${sanitizedAgent}::${mainKey}`;

    case "per-peer":
      // Session per peer (across all channels)
      return `${sanitizedAgent}::${peerKind}::${resolvedPeerId}`;

    case "per-channel-peer":
      // Session per channel + peer
      return `${sanitizedAgent}::${sanitizedChannel}::${peerKind}::${resolvedPeerId}`;

    case "per-account-channel-peer":
      // Session per account + channel + peer (most isolated)
      return `${sanitizedAgent}::${sanitizedAccount}::${sanitizedChannel}::${peerKind}::${resolvedPeerId}`;
  }
}

// Build main session key (no peer isolation)
export function buildAgentMainSessionKey(params: {
  agentId: string;
  mainKey: string;
}): string {
  return `${sanitizeAgentId(params.agentId)}::${params.mainKey}`;
}

// Sanitize agent ID for use in session keys
export function sanitizeAgentId(id: string): string {
  return (id ?? DEFAULT_AGENT_ID)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

// Normalize agent ID (case-insensitive comparison)
export function normalizeAgentId(id: string): string {
  return sanitizeAgentId(id);
}
```

### DM Scope Options

The `dmScope` setting controls session isolation:

| Scope | Description | Use Case |
|-------|-------------|----------|
| `main` | Single session per agent | Personal assistant |
| `per-peer` | Session per user | Multi-user bot |
| `per-channel-peer` | Session per channel+user | Channel-specific contexts |
| `per-account-channel-peer` | Fully isolated sessions | Enterprise/multi-tenant |

## Agent Routing

### Route Resolution: `src/routing/resolve-route.ts`

```typescript
// src/routing/resolve-route.ts

export type RoutePeerKind = "dm" | "group" | "channel";

export type RoutePeer = {
  kind: RoutePeerKind;
  id: string;
};

export type ResolveAgentRouteInput = {
  cfg: OpenClawConfig;
  channel: string;
  accountId?: string | null;
  peer?: RoutePeer | null;
  parentPeer?: RoutePeer | null;  // For threads
  guildId?: string | null;         // Discord guilds
  teamId?: string | null;          // MS Teams
};

export type ResolvedAgentRoute = {
  agentId: string;
  channel: string;
  accountId: string;
  sessionKey: string;
  mainSessionKey: string;
  matchedBy:
    | "binding.peer"
    | "binding.peer.parent"
    | "binding.guild"
    | "binding.team"
    | "binding.account"
    | "binding.channel"
    | "default";
};

export function resolveAgentRoute(input: ResolveAgentRouteInput): ResolvedAgentRoute {
  const channel = normalizeToken(input.channel);
  const accountId = normalizeAccountId(input.accountId);
  const peer = input.peer ? { kind: input.peer.kind, id: normalizeId(input.peer.id) } : null;
  const guildId = normalizeId(input.guildId);
  const teamId = normalizeId(input.teamId);

  // Get bindings that match this channel and account
  const bindings = listBindings(input.cfg).filter((binding) => {
    if (!binding || typeof binding !== "object") return false;
    if (!matchesChannel(binding.match, channel)) return false;
    return matchesAccountId(binding.match?.accountId, accountId);
  });

  const dmScope = input.cfg.session?.dmScope ?? "main";
  const identityLinks = input.cfg.session?.identityLinks;

  // Helper to build result
  const choose = (agentId: string, matchedBy: ResolvedAgentRoute["matchedBy"]) => {
    const resolvedAgentId = pickFirstExistingAgentId(input.cfg, agentId);
    const sessionKey = buildAgentSessionKey({
      agentId: resolvedAgentId,
      channel,
      accountId,
      peer,
      dmScope,
      identityLinks,
    }).toLowerCase();
    const mainSessionKey = buildAgentMainSessionKey({
      agentId: resolvedAgentId,
      mainKey: DEFAULT_MAIN_KEY,
    }).toLowerCase();

    return {
      agentId: resolvedAgentId,
      channel,
      accountId,
      sessionKey,
      mainSessionKey,
      matchedBy,
    };
  };

  // Priority 1: Direct peer match
  if (peer) {
    const peerMatch = bindings.find((b) => matchesPeer(b.match, peer));
    if (peerMatch) {
      return choose(peerMatch.agentId, "binding.peer");
    }
  }

  // Priority 2: Parent peer match (for threads)
  const parentPeer = input.parentPeer
    ? { kind: input.parentPeer.kind, id: normalizeId(input.parentPeer.id) }
    : null;
  if (parentPeer?.id) {
    const parentMatch = bindings.find((b) => matchesPeer(b.match, parentPeer));
    if (parentMatch) {
      return choose(parentMatch.agentId, "binding.peer.parent");
    }
  }

  // Priority 3: Guild match (Discord)
  if (guildId) {
    const guildMatch = bindings.find((b) => matchesGuild(b.match, guildId));
    if (guildMatch) {
      return choose(guildMatch.agentId, "binding.guild");
    }
  }

  // Priority 4: Team match (MS Teams)
  if (teamId) {
    const teamMatch = bindings.find((b) => matchesTeam(b.match, teamId));
    if (teamMatch) {
      return choose(teamMatch.agentId, "binding.team");
    }
  }

  // Priority 5: Account match
  const accountMatch = bindings.find(
    (b) =>
      b.match?.accountId?.trim() !== "*" &&
      !b.match?.peer &&
      !b.match?.guildId &&
      !b.match?.teamId
  );
  if (accountMatch) {
    return choose(accountMatch.agentId, "binding.account");
  }

  // Priority 6: Channel wildcard match
  const channelMatch = bindings.find(
    (b) =>
      b.match?.accountId?.trim() === "*" &&
      !b.match?.peer &&
      !b.match?.guildId &&
      !b.match?.teamId
  );
  if (channelMatch) {
    return choose(channelMatch.agentId, "binding.channel");
  }

  // Default: use default agent
  return choose(resolveDefaultAgentId(input.cfg), "default");
}
```

### Match Helpers

```typescript
// Normalize functions
function normalizeToken(value: string | undefined | null): string {
  return (value ?? "").trim().toLowerCase();
}

function normalizeId(value: string | undefined | null): string {
  return (value ?? "").trim();
}

function normalizeAccountId(value: string | undefined | null): string {
  const trimmed = (value ?? "").trim();
  return trimmed ? trimmed : DEFAULT_ACCOUNT_ID;
}

// Match functions
function matchesChannel(match: { channel?: string } | undefined, channel: string): boolean {
  const key = normalizeToken(match?.channel);
  return key && key === channel;
}

function matchesPeer(match: { peer?: { kind?: string; id?: string } } | undefined, peer: RoutePeer): boolean {
  const m = match?.peer;
  if (!m) return false;

  const kind = normalizeToken(m.kind);
  const id = normalizeId(m.id);

  return kind === peer.kind && id === peer.id;
}

function matchesGuild(match: { guildId?: string } | undefined, guildId: string): boolean {
  const id = normalizeId(match?.guildId);
  return id && id === guildId;
}

function matchesAccountId(match: string | undefined, actual: string): boolean {
  const trimmed = (match ?? "").trim();
  if (!trimmed) return actual === DEFAULT_ACCOUNT_ID;
  if (trimmed === "*") return true;
  return trimmed === actual;
}
```

## Bindings Configuration

### Bindings: `src/routing/bindings.ts`

```typescript
// src/routing/bindings.ts

export type Binding = {
  agentId: string;
  match: {
    channel: string;
    accountId?: string;
    peer?: { kind: "dm" | "group"; id: string };
    guildId?: string;
    teamId?: string;
  };
};

// List all bindings from config
export function listBindings(cfg: OpenClawConfig): Binding[] {
  const bindings = cfg.agents?.bindings;
  if (!Array.isArray(bindings)) {
    return [];
  }
  return bindings.filter((b) => b && typeof b === "object" && b.agentId && b.match);
}
```

### Example Bindings Configuration

```json
{
  "agents": {
    "default": "assistant",
    "list": [
      { "id": "assistant", "name": "General Assistant" },
      { "id": "coder", "name": "Coding Assistant" },
      { "id": "support", "name": "Support Agent" }
    ],
    "bindings": [
      {
        "agentId": "coder",
        "match": {
          "channel": "discord",
          "guildId": "123456789"
        }
      },
      {
        "agentId": "support",
        "match": {
          "channel": "slack",
          "accountId": "*"
        }
      },
      {
        "agentId": "coder",
        "match": {
          "channel": "telegram",
          "peer": {
            "kind": "dm",
            "id": "user123"
          }
        }
      }
    ]
  }
}
```

## Routing Priority

The routing system uses this priority order:

```
1. binding.peer          - Exact peer ID match
2. binding.peer.parent   - Parent peer (thread) match
3. binding.guild         - Discord guild match
4. binding.team          - MS Teams team match
5. binding.account       - Account match (specific)
6. binding.channel       - Channel wildcard match (accountId: "*")
7. default               - Default agent
```

## Identity Links

Identity links allow mapping multiple peer IDs to the same session:

```json
{
  "session": {
    "dmScope": "per-peer",
    "identityLinks": {
      "primary-user": ["+1234567890", "user@telegram", "user#discord"]
    }
  }
}
```

```typescript
// src/routing/session-key.ts

function resolveIdentityLink(
  peerId: string | null,
  links?: Record<string, string[]>
): string | null {
  if (!peerId || !links) return peerId;

  // Find if this peer is linked to another identity
  for (const [primary, aliases] of Object.entries(links)) {
    if (aliases.includes(peerId) || primary === peerId) {
      return primary;
    }
  }

  return peerId;
}
```

## Session Key Examples

### Scenario 1: Personal Assistant (main scope)

```
Agent: assistant
Config: dmScope = "main"

WhatsApp message from +1234567890
  → Session key: "assistant::main"

Telegram message from @user123
  → Session key: "assistant::main"

(Same session for all messages)
```

### Scenario 2: Multi-User Bot (per-peer scope)

```
Agent: assistant
Config: dmScope = "per-peer"

WhatsApp DM from +1234567890
  → Session key: "assistant::dm::+1234567890"

WhatsApp DM from +0987654321
  → Session key: "assistant::dm::+0987654321"

Discord DM from user#1234
  → Session key: "assistant::dm::user#1234"
```

### Scenario 3: Channel-Specific (per-channel-peer scope)

```
Agent: assistant
Config: dmScope = "per-channel-peer"

WhatsApp DM from +1234567890
  → Session key: "assistant::whatsapp::dm::+1234567890"

Telegram DM from same user (linked)
  → Session key: "assistant::telegram::dm::+1234567890"
```

## Gateway Session Resolution

### Gateway Session Key: `src/gateway/server-session-key.ts`

```typescript
// src/gateway/server-session-key.ts

export async function resolveSessionKeyForRun(params: {
  config: OpenClawConfig;
  channel: ChannelId;
  accountId?: string;
  peer: { kind: "dm" | "group"; id: string; name?: string };
  guildId?: string;
  teamId?: string;
  parentPeer?: { kind: string; id: string } | null;
}): Promise<ResolvedAgentRoute> {
  const { config, channel, accountId, peer, guildId, teamId, parentPeer } = params;

  return resolveAgentRoute({
    cfg: config,
    channel,
    accountId,
    peer,
    parentPeer,
    guildId,
    teamId,
  });
}
```

## Debugging Routes

To debug routing, enable verbose logging:

```bash
openclaw status --verbose
```

Or check the matchedBy field in responses:

```typescript
const route = resolveAgentRoute(input);
console.log(`Routed to ${route.agentId} via ${route.matchedBy}`);
console.log(`Session key: ${route.sessionKey}`);
```

## Exploration Exercises

1. **Check current routing**: Look at your config bindings and trace which agent handles different messages.

2. **Add a binding**: Configure a specific agent for a Discord guild.

3. **Test dmScope**: Change the dmScope setting and observe how session keys change.

4. **Set up identity links**: Link your phone number across channels.

5. **Trace routing**: Add console.log statements to `resolveAgentRoute` to see the matching process.

## Next Steps

In the next tutorial, we'll explore the [Infrastructure Layer](./07-infrastructure.md) - outbound delivery, media pipeline, and safety gates.
