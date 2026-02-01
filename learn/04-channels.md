# Tutorial 04: Messaging Channels

## Overview

Channels are the messaging platform integrations that allow OpenClaw to communicate through various services like WhatsApp, Telegram, Discord, and more. This tutorial explains the channel abstraction layer and how to work with channels.

## Channel Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Channel Plugin System                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Telegram │  │ WhatsApp │  │ Discord  │  │  Slack   │  │  Signal  │  │
│  │  Plugin  │  │  Plugin  │  │  Plugin  │  │  Plugin  │  │  Plugin  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │             │             │             │         │
│       ▼             ▼             ▼             ▼             ▼         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Channel Plugin Interface                       │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │  │
│  │  │  Setup   │ │ Messaging│ │ Outbound │ │  Status  │ ...        │  │
│  │  │ Adapter  │ │ Adapter  │ │ Adapter  │ │ Adapter  │            │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Core Channels

### Channel Registry: `src/channels/registry.ts`

```typescript
// src/channels/registry.ts

// Ordered list of core chat channels
export const CHAT_CHANNEL_ORDER = [
  "telegram",
  "whatsapp",
  "discord",
  "googlechat",
  "slack",
  "signal",
  "imessage",
] as const;

export type ChatChannelId = (typeof CHAT_CHANNEL_ORDER)[number];

// Default channel for new setups
export const DEFAULT_CHAT_CHANNEL: ChatChannelId = "whatsapp";

// Channel metadata for UI and docs
const CHAT_CHANNEL_META: Record<ChatChannelId, ChannelMeta> = {
  telegram: {
    id: "telegram",
    label: "Telegram",
    selectionLabel: "Telegram (Bot API)",
    detailLabel: "Telegram Bot",
    docsPath: "/channels/telegram",
    docsLabel: "telegram",
    blurb: "simplest way to get started - register a bot with @BotFather",
    systemImage: "paperplane",
  },
  whatsapp: {
    id: "whatsapp",
    label: "WhatsApp",
    selectionLabel: "WhatsApp (QR link)",
    detailLabel: "WhatsApp Web",
    docsPath: "/channels/whatsapp",
    docsLabel: "whatsapp",
    blurb: "works with your own number; recommend a separate phone + eSIM",
    systemImage: "message",
  },
  discord: {
    id: "discord",
    label: "Discord",
    selectionLabel: "Discord (Bot API)",
    detailLabel: "Discord Bot",
    docsPath: "/channels/discord",
    docsLabel: "discord",
    blurb: "very well supported right now",
    systemImage: "bubble.left.and.bubble.right",
  },
  // ... more channels
};

// Channel ID aliases (e.g., "imsg" -> "imessage")
export const CHAT_CHANNEL_ALIASES: Record<string, ChatChannelId> = {
  imsg: "imessage",
  "google-chat": "googlechat",
  gchat: "googlechat",
};

// Normalize channel ID from user input
export function normalizeChatChannelId(raw?: string | null): ChatChannelId | null {
  const normalized = raw?.trim().toLowerCase();
  if (!normalized) return null;

  const resolved = CHAT_CHANNEL_ALIASES[normalized] ?? normalized;
  return CHAT_CHANNEL_ORDER.includes(resolved) ? resolved : null;
}
```

## Channel Plugin Interface

### Plugin Type: `src/channels/plugins/types.plugin.ts`

```typescript
// src/channels/plugins/types.plugin.ts

export type ChannelPlugin<ResolvedAccount = any> = {
  // Unique channel identifier
  id: ChannelId;

  // Display metadata
  meta: ChannelMeta;

  // Feature capabilities
  capabilities: ChannelCapabilities;

  // Default settings
  defaults?: {
    queue?: { debounceMs?: number };
  };

  // Config reload triggers
  reload?: {
    configPrefixes: string[];
    noopPrefixes?: string[];
  };

  // CLI onboarding wizard hooks
  onboarding?: ChannelOnboardingAdapter;

  // Required adapters
  config: ChannelConfigAdapter<ResolvedAccount>;
  configSchema?: ChannelConfigSchema;

  // Optional adapters
  setup?: ChannelSetupAdapter;
  pairing?: ChannelPairingAdapter;
  security?: ChannelSecurityAdapter<ResolvedAccount>;
  groups?: ChannelGroupAdapter;
  mentions?: ChannelMentionAdapter;
  outbound?: ChannelOutboundAdapter;
  status?: ChannelStatusAdapter<ResolvedAccount>;
  gateway?: ChannelGatewayAdapter<ResolvedAccount>;
  auth?: ChannelAuthAdapter;
  elevated?: ChannelElevatedAdapter;
  commands?: ChannelCommandAdapter;
  streaming?: ChannelStreamingAdapter;
  threading?: ChannelThreadingAdapter;
  messaging?: ChannelMessagingAdapter;
  agentPrompt?: ChannelAgentPromptAdapter;
  directory?: ChannelDirectoryAdapter;
  resolver?: ChannelResolverAdapter;
  actions?: ChannelMessageActionAdapter;
  heartbeat?: ChannelHeartbeatAdapter;

  // Channel-owned agent tools (login flows, etc.)
  agentTools?: ChannelAgentToolFactory | ChannelAgentTool[];
};
```

### Channel Capabilities

```typescript
// src/channels/plugins/types.core.ts

export type ChannelCapabilities = {
  // Message features
  text: boolean;
  media: boolean;
  reactions: boolean;
  polls: boolean;
  stickers: boolean;
  voice: boolean;

  // Threading
  threads: boolean;
  replies: boolean;

  // Group features
  groups: boolean;
  mentions: boolean;

  // Advanced
  streaming: boolean;
  editing: boolean;
  deletion: boolean;

  // Limits
  maxTextLength?: number;
  maxMediaSize?: number;
};
```

## Adapter Interfaces

### Setup Adapter

Handles initial channel configuration:

```typescript
// src/channels/plugins/types.adapters.ts

export type ChannelSetupAdapter = {
  // Validate setup prerequisites
  validatePrerequisites?: () => Promise<{ valid: boolean; issues: string[] }>;

  // Interactive setup flow
  runSetupWizard?: (config: OpenClawConfig) => Promise<SetupResult>;

  // QR-based login (WhatsApp, etc.)
  loginWithQr?: {
    start: () => Promise<ChannelLoginWithQrStartResult>;
    wait: (handle: string) => Promise<ChannelLoginWithQrWaitResult>;
    cancel: (handle: string) => Promise<void>;
  };

  // Token-based login (Telegram, Discord, etc.)
  loginWithToken?: (token: string) => Promise<{ success: boolean; error?: string }>;
};
```

### Messaging Adapter

Handles message sending and receiving:

```typescript
export type ChannelMessagingAdapter = {
  // Start monitoring for messages
  startMonitor: (opts: {
    config: OpenClawConfig;
    onMessage: (message: InboundMessage) => void;
    onError?: (error: Error) => void;
  }) => Promise<MonitorHandle>;

  // Stop monitoring
  stopMonitor: (handle: MonitorHandle) => Promise<void>;

  // Check if monitor is running
  isMonitoring: (handle: MonitorHandle) => boolean;
};
```

### Outbound Adapter

Handles sending messages:

```typescript
export type ChannelOutboundAdapter = {
  // Send text message
  sendText: (params: {
    to: string;
    text: string;
    replyToId?: string;
    threadId?: string;
  }) => Promise<{ messageId: string }>;

  // Send media
  sendMedia: (params: {
    to: string;
    caption: string;
    mediaUrl: string;
    mediaType?: "image" | "video" | "audio" | "document";
  }) => Promise<{ messageId: string }>;

  // Send reaction
  sendReaction?: (params: {
    messageId: string;
    emoji: string;
  }) => Promise<void>;

  // Create poll
  sendPoll?: (params: {
    to: string;
    question: string;
    options: string[];
  }) => Promise<{ pollId: string }>;
};
```

### Status Adapter

Provides channel health information:

```typescript
export type ChannelStatusAdapter<T = unknown> = {
  // Check if channel is connected
  isConnected: (account: T) => Promise<boolean>;

  // Probe channel health
  probe: (account: T) => Promise<{
    connected: boolean;
    latency?: number;
    issues?: ChannelStatusIssue[];
  }>;

  // Get channel-specific status info
  getStatusInfo?: (account: T) => Promise<Record<string, unknown>>;
};
```

## Channel Implementations

### Telegram: `src/telegram/`

```typescript
// src/telegram/bot.ts
import { Bot } from "grammy";

export async function createTelegramBot(token: string): Promise<Bot> {
  const bot = new Bot(token);

  // Register message handler
  bot.on("message", async (ctx) => {
    const message = normalizeTelegramMessage(ctx.message);
    await handleInboundMessage(message);
  });

  // Start long polling
  await bot.start();

  return bot;
}

// src/telegram/send.ts
export async function sendMessageTelegram(
  bot: Bot,
  chatId: string,
  text: string,
  opts?: { replyToMessageId?: number; parseMode?: "HTML" | "Markdown" }
): Promise<{ messageId: number }> {
  const result = await bot.api.sendMessage(chatId, text, {
    reply_to_message_id: opts?.replyToMessageId,
    parse_mode: opts?.parseMode,
  });

  return { messageId: result.message_id };
}
```

### WhatsApp: `src/web/` (Baileys)

```typescript
// src/web/monitor.ts
import { makeWASocket, useMultiFileAuthState } from "@whiskeysockets/baileys";

export async function createWhatsAppConnection(sessionPath: string) {
  const { state, saveCreds } = await useMultiFileAuthState(sessionPath);

  const socket = makeWASocket({
    auth: state,
    printQRInTerminal: true,
  });

  // Handle auth state updates
  socket.ev.on("creds.update", saveCreds);

  // Handle messages
  socket.ev.on("messages.upsert", async ({ messages }) => {
    for (const message of messages) {
      if (!message.key.fromMe) {
        const normalized = normalizeWhatsAppMessage(message);
        await handleInboundMessage(normalized);
      }
    }
  });

  return socket;
}

// src/web/outbound.ts
export async function sendMessageWhatsApp(
  socket: WASocket,
  jid: string,
  text: string,
  opts?: { quotedId?: string }
): Promise<{ messageId: string }> {
  const result = await socket.sendMessage(jid, { text }, {
    quoted: opts?.quotedId ? { key: { id: opts.quotedId } } : undefined,
  });

  return { messageId: result.key.id };
}
```

### Discord: `src/discord/`

```typescript
// src/discord/monitor.ts
import { Client, GatewayIntentBits } from "discord.js";

export async function createDiscordClient(token: string): Promise<Client> {
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.DirectMessages,
      GatewayIntentBits.MessageContent,
    ],
  });

  client.on("messageCreate", async (message) => {
    if (message.author.bot) return;

    const normalized = normalizeDiscordMessage(message);
    await handleInboundMessage(normalized);
  });

  await client.login(token);
  return client;
}

// src/discord/send.ts
export async function sendMessageDiscord(
  client: Client,
  channelId: string,
  text: string,
  opts?: { replyToId?: string }
): Promise<{ messageId: string }> {
  const channel = await client.channels.fetch(channelId);
  if (!channel?.isTextBased()) {
    throw new Error("Invalid channel");
  }

  const result = await channel.send({
    content: text,
    reply: opts?.replyToId ? { messageReference: opts.replyToId } : undefined,
  });

  return { messageId: result.id };
}
```

### Slack: `src/slack/`

```typescript
// src/slack/monitor.ts
import { App } from "@slack/bolt";

export async function createSlackApp(
  token: string,
  appToken: string
): Promise<App> {
  const app = new App({
    token,
    appToken,
    socketMode: true,
  });

  app.message(async ({ message, say }) => {
    if (message.subtype) return; // Ignore system messages

    const normalized = normalizeSlackMessage(message);
    await handleInboundMessage(normalized);
  });

  await app.start();
  return app;
}

// src/slack/send.ts
export async function sendMessageSlack(
  app: App,
  channel: string,
  text: string,
  opts?: { threadTs?: string }
): Promise<{ messageId: string; ts: string }> {
  const result = await app.client.chat.postMessage({
    channel,
    text,
    thread_ts: opts?.threadTs,
  });

  return {
    messageId: result.ts!,
    ts: result.ts!,
  };
}
```

## Extension Channels

Extension channels live in `extensions/` and follow the same plugin interface:

```
extensions/
├── msteams/           # Microsoft Teams
├── matrix/            # Matrix protocol
├── mattermost/        # Mattermost
├── line/              # LINE messaging
├── zalo/              # Zalo (Vietnam)
├── zalouser/          # Zalo personal accounts
└── bluebubbles/       # iMessage via BlueBubbles
```

### Example Extension: Matrix

```typescript
// extensions/matrix/src/plugin.ts
import type { ChannelPlugin } from "openclaw/plugin-sdk";

export const matrixPlugin: ChannelPlugin = {
  id: "matrix",

  meta: {
    label: "Matrix",
    selectionLabel: "Matrix (Protocol)",
    detailLabel: "Matrix",
    docsPath: "/channels/matrix",
    docsLabel: "matrix",
    blurb: "Decentralized chat protocol",
    systemImage: "network",
  },

  capabilities: {
    text: true,
    media: true,
    reactions: true,
    polls: false,
    threads: true,
    replies: true,
    groups: true,
    mentions: true,
    streaming: false,
    editing: true,
    deletion: true,
  },

  config: {
    resolveAccount: (config) => {
      const matrixConfig = config.matrix;
      if (!matrixConfig?.homeserver || !matrixConfig?.accessToken) {
        return null;
      }
      return {
        homeserver: matrixConfig.homeserver,
        accessToken: matrixConfig.accessToken,
        userId: matrixConfig.userId,
      };
    },
  },

  messaging: {
    startMonitor: async (opts) => {
      // Implementation...
    },
    stopMonitor: async (handle) => {
      // Implementation...
    },
    isMonitoring: (handle) => handle.running,
  },

  outbound: {
    sendText: async (params) => {
      // Implementation...
    },
    sendMedia: async (params) => {
      // Implementation...
    },
  },

  status: {
    isConnected: async (account) => {
      // Implementation...
    },
    probe: async (account) => {
      // Implementation...
    },
  },
};
```

## Message Normalization

All channels normalize messages to a common format:

```typescript
// src/channels/types.ts

export type InboundMessage = {
  // Source identification
  channel: ChannelId;
  accountId: string;

  // Peer (sender) information
  peer: {
    kind: "dm" | "group" | "channel";
    id: string;
    name?: string;
    isBot?: boolean;
  };

  // Message content
  messageId: string;
  text: string;
  timestamp: number;

  // Optional fields
  media?: MediaAttachment[];
  replyToId?: string;
  threadId?: string;
  mentions?: string[];
  isEdited?: boolean;

  // Platform-specific metadata
  raw?: unknown;
};

export type MediaAttachment = {
  type: "image" | "video" | "audio" | "document" | "sticker";
  url?: string;
  mimeType?: string;
  size?: number;
  filename?: string;
  thumbnail?: string;
};
```

## Channel Security

### Allowlists: `src/channels/allowlists/`

```typescript
// src/channels/allowlists/types.ts

export type AllowlistEntry = {
  id: string;           // User/group ID
  name?: string;        // Display name
  addedAt: number;      // Timestamp
  addedBy?: string;     // Who added it
};

export type ChannelAllowlist = {
  enabled: boolean;
  entries: AllowlistEntry[];
};

// src/channels/allowlists/check.ts
export function checkAllowlist(
  allowlist: ChannelAllowlist,
  peerId: string
): boolean {
  if (!allowlist.enabled) {
    return true; // Allowlist disabled, allow all
  }

  return allowlist.entries.some((entry) => entry.id === peerId);
}
```

### DM Policies

```typescript
// src/channels/plugins/types.core.ts

export type ChannelSecurityDmPolicy =
  | "allow"       // Allow all DMs
  | "allowlist"   // Only allowed users
  | "deny";       // Deny all DMs

export type ChannelSecurityContext = {
  channel: ChannelId;
  peer: { kind: "dm" | "group"; id: string };
  config: OpenClawConfig;
};

// Check if message should be processed
export async function checkInboundSecurity(
  ctx: ChannelSecurityContext
): Promise<boolean> {
  const plugin = getChannelPlugin(ctx.channel);
  if (!plugin?.security) {
    return true; // No security adapter, allow
  }

  const policy = await plugin.security.getDmPolicy(ctx);

  switch (policy) {
    case "allow":
      return true;
    case "deny":
      return false;
    case "allowlist":
      return checkAllowlist(ctx.config, ctx.channel, ctx.peer.id);
  }
}
```

## Threading Support

### Threading Adapter

```typescript
// src/channels/plugins/types.core.ts

export type ChannelThreadingContext = {
  messageId: string;
  threadId?: string;
  parentPeer?: { kind: string; id: string };
};

export type ChannelThreadingAdapter = {
  // Check if channel supports threading
  supportsThreading: () => boolean;

  // Get thread context for a message
  getThreadContext: (
    message: InboundMessage
  ) => ChannelThreadingContext | null;

  // Create a new thread
  createThread?: (params: {
    channelId: string;
    messageId: string;
    name?: string;
  }) => Promise<{ threadId: string }>;

  // Reply in thread
  replyInThread?: (params: {
    threadId: string;
    text: string;
  }) => Promise<{ messageId: string }>;
};
```

## Channel Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Setup     │────▶│  Configure  │────▶│   Start     │
│   (Token)   │     │  (Config)   │     │  (Monitor)  │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                              ▼
                    ┌─────────────┐     ┌─────────────┐
                    │    Stop     │◀────│   Running   │
                    │  (Cleanup)  │     │ (Messages)  │
                    └─────────────┘     └─────────────┘
```

## Exploration Exercises

1. **List channels**: Run `openclaw channels list` to see configured channels.

2. **Add a channel**: Use `openclaw channels add telegram` to walk through Telegram setup.

3. **Check status**: Run `openclaw channels status --probe` to test channel connectivity.

4. **Explore a plugin**: Read through `src/telegram/` to understand a complete channel implementation.

5. **Create a mock channel**: Create a simple test channel that echoes messages back.

## Next Steps

In the next tutorial, we'll explore the [Agent System](./05-agent-system.md) - how AI agents process messages and execute tools.
