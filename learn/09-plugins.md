# Tutorial 09: Plugin System

## Overview

OpenClaw has a powerful plugin system that allows extending functionality with custom channels, services, and tools. This tutorial explains how plugins work and how to create your own.

## Plugin Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Plugin System                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Plugin Registry                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │   │
│  │  │  Channels   │  │  Services   │  │   Tools     │              │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                │                                        │
│       ┌────────────────────────┼────────────────────────┐              │
│       ▼                        ▼                        ▼              │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐            │
│  │   msteams   │      │memory-lance │      │ llm-task    │            │
│  │   matrix    │      │             │      │             │            │
│  │   line      │      │             │      │             │            │
│  └─────────────┘      └─────────────┘      └─────────────┘            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Plugin Types

### 1. Channel Plugins

Add support for new messaging platforms:

```typescript
// extensions/my-channel/src/plugin.ts
import type { ChannelPlugin } from "openclaw/plugin-sdk";

export const myChannelPlugin: ChannelPlugin = {
  id: "my-channel",
  meta: {
    label: "My Channel",
    selectionLabel: "My Channel (API)",
    detailLabel: "My Channel",
    docsPath: "/channels/my-channel",
    docsLabel: "my-channel",
    blurb: "Connect to My Channel service",
    systemImage: "message",
  },
  capabilities: {
    text: true,
    media: true,
    reactions: false,
    polls: false,
    threads: false,
    groups: true,
  },
  // ... adapters
};
```

### 2. Service Plugins

Add backend services like memory or processing:

```typescript
// extensions/my-service/src/plugin.ts
export const myServicePlugin: ServicePlugin = {
  id: "my-service",
  name: "My Service",

  async initialize(config: PluginConfig) {
    // Setup service
  },

  async shutdown() {
    // Cleanup
  },

  getService() {
    return {
      doSomething: async () => { /* ... */ },
    };
  },
};
```

### 3. Tool Plugins

Add custom agent tools:

```typescript
// extensions/my-tool/src/plugin.ts
export const myToolPlugin: ToolPlugin = {
  id: "my-tool",
  tools: [
    {
      name: "my_tool.action",
      description: "Perform a custom action",
      parameters: {
        type: "object",
        properties: {
          input: { type: "string" },
        },
        required: ["input"],
      },
      async execute(params, ctx) {
        return { result: `Processed: ${params.input}` };
      },
    },
  ],
};
```

## Plugin Registry

### Registry: `src/plugins/registry.ts`

```typescript
// src/plugins/registry.ts

export type PluginEntry = {
  id: string;
  type: "channel" | "service" | "tool";
  plugin: ChannelPlugin | ServicePlugin | ToolPlugin;
  loaded: boolean;
};

class PluginRegistry {
  private plugins = new Map<string, PluginEntry>();

  register(entry: PluginEntry) {
    if (this.plugins.has(entry.id)) {
      throw new Error(`Plugin already registered: ${entry.id}`);
    }
    this.plugins.set(entry.id, entry);
  }

  get(id: string): PluginEntry | undefined {
    return this.plugins.get(id);
  }

  list(type?: PluginEntry["type"]): PluginEntry[] {
    const all = Array.from(this.plugins.values());
    if (type) {
      return all.filter((p) => p.type === type);
    }
    return all;
  }

  getChannels(): ChannelPlugin[] {
    return this.list("channel").map((e) => e.plugin as ChannelPlugin);
  }

  getServices(): ServicePlugin[] {
    return this.list("service").map((e) => e.plugin as ServicePlugin);
  }

  getTools(): ToolPlugin[] {
    return this.list("tool").map((e) => e.plugin as ToolPlugin);
  }
}

export const pluginRegistry = new PluginRegistry();
```

### Runtime: `src/plugins/runtime/index.ts`

```typescript
// src/plugins/runtime/index.ts

let activeRegistry: PluginRegistry | null = null;

export function setActivePluginRegistry(registry: PluginRegistry) {
  activeRegistry = registry;
}

export function getActivePluginRegistry(): PluginRegistry | null {
  return activeRegistry;
}

export function requireActivePluginRegistry(): PluginRegistry {
  if (!activeRegistry) {
    throw new Error("Plugin registry not initialized");
  }
  return activeRegistry;
}
```

## Creating a Channel Plugin

### Step 1: Create Plugin Package

```bash
mkdir -p extensions/my-channel
cd extensions/my-channel
npm init -y
```

### Step 2: Setup Package.json

```json
{
  "name": "@openclaw/plugin-my-channel",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "type": "module",
  "dependencies": {
    "my-channel-sdk": "^1.0.0"
  },
  "devDependencies": {
    "openclaw": "workspace:*",
    "typescript": "^5.0.0"
  },
  "peerDependencies": {
    "openclaw": "*"
  }
}
```

### Step 3: Implement Plugin

```typescript
// extensions/my-channel/src/index.ts

import type { ChannelPlugin } from "openclaw/plugin-sdk";
import { MyChannelClient } from "my-channel-sdk";

export const plugin: ChannelPlugin = {
  id: "my-channel",

  meta: {
    label: "My Channel",
    selectionLabel: "My Channel (Bot API)",
    detailLabel: "My Channel Bot",
    docsPath: "/channels/my-channel",
    docsLabel: "my-channel",
    blurb: "Connect to My Channel messaging service",
    systemImage: "message",
  },

  capabilities: {
    text: true,
    media: true,
    reactions: true,
    polls: false,
    stickers: false,
    voice: false,
    threads: false,
    replies: true,
    groups: true,
    mentions: true,
    streaming: false,
    editing: true,
    deletion: true,
    maxTextLength: 4096,
  },

  config: {
    resolveAccount(config) {
      const channelConfig = config.myChannel;
      if (!channelConfig?.token) {
        return null;
      }
      return {
        token: channelConfig.token,
        webhookUrl: channelConfig.webhookUrl,
      };
    },

    isConfigured(config) {
      return !!config.myChannel?.token;
    },
  },

  setup: {
    async loginWithToken(token: string) {
      try {
        const client = new MyChannelClient(token);
        const me = await client.getMe();
        return {
          success: true,
          account: { id: me.id, name: me.name },
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },

  messaging: {
    async startMonitor(opts) {
      const { config, onMessage, onError } = opts;
      const account = plugin.config.resolveAccount(config);

      if (!account) {
        throw new Error("My Channel not configured");
      }

      const client = new MyChannelClient(account.token);

      // Setup message handler
      client.on("message", (msg) => {
        onMessage({
          channel: "my-channel",
          accountId: "default",
          messageId: msg.id,
          text: msg.text,
          peer: {
            kind: msg.isGroup ? "group" : "dm",
            id: msg.chat.id,
            name: msg.chat.name,
          },
          timestamp: msg.timestamp,
        });
      });

      client.on("error", (error) => {
        onError?.(error);
      });

      // Start polling/webhook
      await client.start();

      return {
        id: randomUUID(),
        running: true,
        stop: async () => {
          await client.stop();
        },
      };
    },

    stopMonitor: async (handle) => {
      await handle.stop();
    },

    isMonitoring: (handle) => handle.running,
  },

  outbound: {
    async sendText(params) {
      const { to, text, replyToId } = params;
      const client = await getClient();

      const result = await client.sendMessage(to, {
        text,
        replyTo: replyToId,
      });

      return { messageId: result.id };
    },

    async sendMedia(params) {
      const { to, caption, mediaUrl, mediaType } = params;
      const client = await getClient();

      const result = await client.sendMedia(to, {
        url: mediaUrl,
        type: mediaType,
        caption,
      });

      return { messageId: result.id };
    },
  },

  status: {
    async isConnected(account) {
      try {
        const client = new MyChannelClient(account.token);
        await client.getMe();
        return true;
      } catch {
        return false;
      }
    },

    async probe(account) {
      const start = Date.now();
      try {
        const client = new MyChannelClient(account.token);
        await client.getMe();
        return {
          connected: true,
          latency: Date.now() - start,
        };
      } catch (error) {
        return {
          connected: false,
          issues: [{ severity: "error", message: error.message }],
        };
      }
    },
  },
};

// Helper to get configured client
async function getClient(): Promise<MyChannelClient> {
  const config = await loadConfig();
  const account = plugin.config.resolveAccount(config);
  if (!account) {
    throw new Error("My Channel not configured");
  }
  return new MyChannelClient(account.token);
}

export default plugin;
```

### Step 4: Add Config Schema

```typescript
// extensions/my-channel/src/config-schema.ts

import { z } from "zod";

export const myChannelConfigSchema = z.object({
  myChannel: z.object({
    token: z.string().optional(),
    webhookUrl: z.string().url().optional(),
    allowedUsers: z.array(z.string()).optional(),
  }).optional(),
});

export const configUiHints = {
  "myChannel.token": {
    label: "Bot Token",
    help: "Your My Channel bot token",
    sensitive: true,
  },
  "myChannel.webhookUrl": {
    label: "Webhook URL",
    help: "Optional webhook URL for receiving messages",
    advanced: true,
  },
};
```

## Plugin Loading

### Gateway Plugin Loader: `src/gateway/server-plugins.ts`

```typescript
// src/gateway/server-plugins.ts

export async function loadGatewayPlugins(opts: {
  config: OpenClawConfig;
  logger: Logger;
}): Promise<PluginServicesHandle> {
  const { config, logger } = opts;

  // Get enabled plugins from config
  const enabledPlugins = config.plugins?.enabled ?? [];

  // Load each plugin
  for (const pluginId of enabledPlugins) {
    try {
      logger.info(`Loading plugin: ${pluginId}`);
      const plugin = await importPlugin(pluginId);

      // Register with registry
      pluginRegistry.register({
        id: pluginId,
        type: detectPluginType(plugin),
        plugin,
        loaded: true,
      });

      // Initialize if service plugin
      if (isServicePlugin(plugin)) {
        await plugin.initialize(config);
      }

      logger.info(`Loaded plugin: ${pluginId}`);
    } catch (error) {
      logger.error(`Failed to load plugin ${pluginId}:`, error);
    }
  }

  return {
    shutdown: async () => {
      // Shutdown all service plugins
      for (const entry of pluginRegistry.list("service")) {
        const plugin = entry.plugin as ServicePlugin;
        await plugin.shutdown?.();
      }
    },
  };
}

async function importPlugin(id: string): Promise<unknown> {
  // Try built-in extension
  const builtinPath = `../../extensions/${id}/dist/index.js`;
  try {
    const module = await import(builtinPath);
    return module.default ?? module.plugin;
  } catch {
    // Not a built-in
  }

  // Try npm package
  const packageName = id.startsWith("@") ? id : `@openclaw/plugin-${id}`;
  const module = await import(packageName);
  return module.default ?? module.plugin;
}
```

## Plugin SDK

### Public API: `src/plugin-sdk/index.ts`

```typescript
// src/plugin-sdk/index.ts

// Re-export types for plugin developers
export type {
  ChannelPlugin,
  ChannelCapabilities,
  ChannelMeta,
  ChannelSetupAdapter,
  ChannelMessagingAdapter,
  ChannelOutboundAdapter,
  ChannelStatusAdapter,
} from "../channels/plugins/types.js";

export type {
  InboundMessage,
  OutboundDeliveryResult,
} from "../channels/types.js";

export type {
  OpenClawConfig,
} from "../config/types.js";

export type {
  AgentTool,
  ToolContext,
  ToolResult,
} from "../agents/tools/types.js";

// Utility functions
export { loadConfig, writeConfigFile } from "../config/config.js";
export { getActivePluginRegistry } from "../plugins/runtime/index.js";
```

## Plugin Configuration

### Config in config.json

```json
{
  "plugins": {
    "enabled": ["msteams", "matrix", "memory-lancedb"],
    "config": {
      "memory-lancedb": {
        "dbPath": "~/.openclaw/memory.lance"
      }
    }
  },

  "msteams": {
    "appId": "your-app-id",
    "appPassword": "your-app-password"
  },

  "matrix": {
    "homeserver": "https://matrix.org",
    "accessToken": "your-token"
  }
}
```

## Extension Directory Structure

```
extensions/
├── msteams/
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts          # Main plugin export
│       ├── monitor.ts        # Message monitoring
│       ├── send.ts           # Message sending
│       └── config-schema.ts  # Config validation
│
├── matrix/
│   ├── package.json
│   └── src/
│       ├── index.ts
│       ├── client.ts
│       └── ...
│
├── memory-lancedb/
│   ├── package.json
│   └── src/
│       ├── index.ts
│       ├── store.ts
│       └── search.ts
│
└── llm-task/
    ├── package.json
    └── src/
        ├── index.ts
        └── task-runner.ts
```

## Plugin Best Practices

### 1. Handle Errors Gracefully

```typescript
async startMonitor(opts) {
  try {
    // ... setup
  } catch (error) {
    opts.onError?.(error);
    throw error;
  }
}
```

### 2. Support Graceful Shutdown

```typescript
async shutdown() {
  // Close connections
  await this.client.disconnect();

  // Clear timers
  clearInterval(this.heartbeatTimer);

  // Release resources
  this.resources.clear();
}
```

### 3. Use Proper Logging

```typescript
import { createSubsystemLogger } from "openclaw/logging";

const log = createSubsystemLogger("my-plugin");

log.info("Plugin initialized");
log.error("Connection failed", { error });
```

### 4. Validate Configuration

```typescript
config: {
  resolveAccount(config) {
    const cfg = config.myChannel;
    if (!cfg?.token) {
      return null;
    }

    // Validate token format
    if (!cfg.token.match(/^[A-Za-z0-9_-]+$/)) {
      throw new Error("Invalid token format");
    }

    return { token: cfg.token };
  },
}
```

## Exploration Exercises

1. **List plugins**: Run `openclaw plugins list` to see available plugins.

2. **Install a plugin**: Install an extension plugin like `msteams` or `matrix`.

3. **Create a simple plugin**: Build a plugin that adds a custom agent tool.

4. **Read extension code**: Explore `extensions/msteams` to see a real channel plugin.

5. **Test your plugin**: Write tests for your plugin using Vitest.

## Next Steps

In the final tutorial, we'll explore [Advanced Topics](./10-advanced.md) - hooks, cron jobs, memory systems, and more.
