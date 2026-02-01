# Tutorial 08: Configuration System

## Overview

OpenClaw uses a comprehensive configuration system that supports JSON5 (with comments), Zod validation, and runtime overrides. This tutorial explains how configuration works.

## Configuration Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Configuration System                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐                    ┌─────────────────┐             │
│  │  config.json    │───Load & Parse────▶│  Validation     │             │
│  │  (JSON5)        │                    │  (Zod Schema)   │             │
│  └─────────────────┘                    └────────┬────────┘             │
│                                                  │                       │
│  ┌─────────────────┐                    ┌────────▼────────┐             │
│  │  Environment    │───Merge Overrides─▶│  OpenClawConfig │             │
│  │  Variables      │                    │  (Runtime)      │             │
│  └─────────────────┘                    └────────┬────────┘             │
│                                                  │                       │
│  ┌─────────────────┐                    ┌────────▼────────┐             │
│  │  CLI Arguments  │───Apply Options───▶│  Final Config   │             │
│  │  (--key=value)  │                    │                 │             │
│  └─────────────────┘                    └─────────────────┘             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Configuration Files

### Paths: `src/config/paths.ts`

```typescript
// src/config/paths.ts

import { homedir } from "node:os";
import { join } from "node:path";

// Base OpenClaw directory
export const OPENCLAW_DIR = join(homedir(), ".openclaw");

// Configuration file
export const CONFIG_PATH = join(OPENCLAW_DIR, "config.json");

// Sessions storage
export const SESSIONS_PATH = join(OPENCLAW_DIR, "sessions");

// Credentials storage
export const CREDENTIALS_PATH = join(OPENCLAW_DIR, "credentials");

// State directory
export const STATE_PATH = join(OPENCLAW_DIR, "state");

// Agents directory
export const AGENTS_PATH = join(OPENCLAW_DIR, "agents");

// Media storage
export const MEDIA_PATH = join(OPENCLAW_DIR, "media");

// Logs directory
export const LOGS_PATH = join(OPENCLAW_DIR, "logs");

// Resolve state directory with optional subpath
export function resolveStateDir(subpath?: string): string {
  if (subpath) {
    return join(STATE_PATH, subpath);
  }
  return STATE_PATH;
}

// Check if running in Nix mode (config in different location)
export function isNixMode(): boolean {
  return !!process.env.OPENCLAW_NIX_MODE;
}
```

## Configuration Loading

### Load Config: `src/config/io.ts`

```typescript
// src/config/io.ts

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import JSON5 from "json5";
import { CONFIG_PATH, OPENCLAW_DIR } from "./paths.js";
import { validateConfigObject } from "./validation.js";

// Load configuration from file
export async function loadConfig(): Promise<OpenClawConfig> {
  // Ensure directory exists
  if (!existsSync(OPENCLAW_DIR)) {
    mkdirSync(OPENCLAW_DIR, { recursive: true });
  }

  // Check if config file exists
  if (!existsSync(CONFIG_PATH)) {
    return getDefaultConfig();
  }

  // Read and parse config file
  const content = readFileSync(CONFIG_PATH, "utf-8");
  const parsed = parseConfigJson5(content);

  // Validate config
  const validation = validateConfigObject(parsed);
  if (!validation.success) {
    console.warn("Config validation warnings:", validation.errors);
  }

  // Apply runtime overrides
  const withOverrides = applyRuntimeOverrides(parsed);

  return withOverrides;
}

// Parse JSON5 (allows comments and trailing commas)
export function parseConfigJson5(content: string): unknown {
  try {
    return JSON5.parse(content);
  } catch (error) {
    throw new Error(`Failed to parse config: ${error.message}`);
  }
}

// Write config to file
export async function writeConfigFile(
  config: OpenClawConfig
): Promise<void> {
  const content = JSON.stringify(config, null, 2);
  writeFileSync(CONFIG_PATH, content, "utf-8");
}

// Read raw config file for hash comparison
export function readConfigFileSnapshot(): string | null {
  if (!existsSync(CONFIG_PATH)) {
    return null;
  }
  return readFileSync(CONFIG_PATH, "utf-8");
}

// Compute config hash for change detection
export function resolveConfigSnapshotHash(content: string): string {
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

// Create IO functions (for dependency injection)
export function createConfigIO() {
  return {
    load: loadConfig,
    write: writeConfigFile,
    readSnapshot: readConfigFileSnapshot,
  };
}
```

## Configuration Types

### Base Types: `src/config/types.ts`

```typescript
// src/config/types.ts

// Re-export all config types
export * from "./types.base.js";
export * from "./types.agents.js";
export * from "./types.channels.js";
export * from "./types.gateway.js";
export * from "./types.models.js";
export * from "./types.hooks.js";
export * from "./types.plugins.js";
export * from "./types.session.js";
export * from "./types.sandbox.js";
```

### Base Config: `src/config/types.base.ts`

```typescript
// src/config/types.base.ts

export type OpenClawConfig = {
  // Agent configuration
  agents?: AgentsConfig;

  // Model configuration
  models?: ModelsConfig;

  // Session configuration
  session?: SessionConfig;

  // Gateway configuration
  gateway?: GatewayConfig;

  // Channel-specific configuration
  telegram?: TelegramConfig;
  whatsapp?: WhatsAppConfig;
  discord?: DiscordConfig;
  slack?: SlackConfig;
  signal?: SignalConfig;
  imessage?: IMessageConfig;

  // Hooks configuration
  hooks?: HooksConfig;

  // Plugin configuration
  plugins?: PluginsConfig;

  // Sandbox configuration
  sandbox?: SandboxConfig;

  // Browser configuration
  browser?: BrowserConfig;
};
```

### Agents Config: `src/config/types.agents.ts`

```typescript
// src/config/types.agents.ts

export type AgentsConfig = {
  // Default agent ID
  default?: string;

  // List of agents
  list?: AgentConfig[];

  // Agent routing bindings
  bindings?: AgentBinding[];
};

export type AgentConfig = {
  // Unique identifier
  id: string;

  // Display name
  name?: string;

  // Model to use (e.g., "claude-opus-4-5-20251101")
  model?: string;

  // System prompt
  systemPrompt?: string;

  // Additional instructions
  instructions?: string;

  // Allowed tools
  tools?: string[];

  // Denied tools
  denyTools?: string[];

  // Tools requiring approval
  requireApproval?: string[];

  // Thinking level
  thinking?: ThinkingLevel;

  // Workspace directory
  workspace?: string;
};

export type AgentBinding = {
  agentId: string;
  match: {
    channel: string;
    accountId?: string;
    peer?: { kind: "dm" | "group"; id: string };
    guildId?: string;
    teamId?: string;
  };
};
```

### Gateway Config: `src/config/types.gateway.ts`

```typescript
// src/config/types.gateway.ts

export type GatewayBindMode = "loopback" | "lan" | "tailnet" | "auto";

export type GatewayConfig = {
  // Bind mode
  mode?: "local" | "hosted";

  // Port number
  port?: number;

  // Bind address mode
  bind?: GatewayBindMode;

  // Authentication
  auth?: GatewayAuthConfig;

  // Control UI settings
  controlUi?: {
    enabled?: boolean;
  };

  // HTTP endpoint settings
  http?: {
    endpoints?: {
      chatCompletions?: { enabled?: boolean };
      responses?: { enabled?: boolean };
    };
  };

  // TLS configuration
  tls?: {
    enabled?: boolean;
    cert?: string;
    key?: string;
  };

  // Tailscale exposure
  tailscale?: GatewayTailscaleConfig;
};

export type GatewayAuthConfig = {
  // Enable authentication
  enabled?: boolean;

  // Auth method
  method?: "bearer" | "basic";

  // Bearer token
  token?: string;

  // Basic auth credentials
  username?: string;
  password?: string;
};

export type GatewayTailscaleConfig = {
  // Enable Tailscale exposure
  enabled?: boolean;

  // Use Serve (local) or Funnel (public)
  mode?: "serve" | "funnel";

  // Hostname
  hostname?: string;
};
```

### Models Config: `src/config/types.models.ts`

```typescript
// src/config/types.models.ts

export type ModelsConfig = {
  // Default model
  default?: string;

  // Thinking level
  thinking?: ThinkingLevel;

  // Provider authentication
  auth?: Record<string, ModelAuthConfig>;

  // Fallback chain
  fallbacks?: string[];

  // Model aliases
  aliases?: Record<string, string>;
};

export type ModelAuthConfig = {
  // API key
  apiKey?: string;

  // OAuth token
  oauthToken?: string;

  // OAuth refresh token
  refreshToken?: string;

  // Token expiry
  expiresAt?: number;
};

export type ThinkingLevel =
  | "off"
  | "minimal"
  | "low"
  | "medium"
  | "high"
  | "xhigh";
```

### Session Config: `src/config/types.session.ts`

```typescript
// src/config/types.session.ts

export type SessionConfig = {
  // DM session scope
  dmScope?: "main" | "per-peer" | "per-channel-peer" | "per-account-channel-peer";

  // Identity links (map multiple IDs to same session)
  identityLinks?: Record<string, string[]>;

  // Session timeout (ms)
  timeoutMs?: number;

  // Max messages to retain
  maxMessages?: number;

  // Transcript mirroring
  mirrorTranscript?: boolean;
};
```

## Schema Validation

### Zod Schema: `src/config/zod-schema.ts`

```typescript
// src/config/zod-schema.ts

import { z } from "zod";

// Agent config schema
const AgentConfigSchema = z.object({
  id: z.string().min(1),
  name: z.string().optional(),
  model: z.string().optional(),
  systemPrompt: z.string().optional(),
  instructions: z.string().optional(),
  tools: z.array(z.string()).optional(),
  denyTools: z.array(z.string()).optional(),
  requireApproval: z.array(z.string()).optional(),
  thinking: z.enum(["off", "minimal", "low", "medium", "high", "xhigh"]).optional(),
  workspace: z.string().optional(),
});

// Agent binding schema
const AgentBindingSchema = z.object({
  agentId: z.string(),
  match: z.object({
    channel: z.string(),
    accountId: z.string().optional(),
    peer: z.object({
      kind: z.enum(["dm", "group"]),
      id: z.string(),
    }).optional(),
    guildId: z.string().optional(),
    teamId: z.string().optional(),
  }),
});

// Gateway config schema
const GatewayConfigSchema = z.object({
  mode: z.enum(["local", "hosted"]).optional(),
  port: z.number().int().positive().optional(),
  bind: z.enum(["loopback", "lan", "tailnet", "auto"]).optional(),
  auth: z.object({
    enabled: z.boolean().optional(),
    method: z.enum(["bearer", "basic"]).optional(),
    token: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
  }).optional(),
  controlUi: z.object({
    enabled: z.boolean().optional(),
  }).optional(),
  tls: z.object({
    enabled: z.boolean().optional(),
    cert: z.string().optional(),
    key: z.string().optional(),
  }).optional(),
}).optional();

// Full config schema
export const OpenClawSchema = z.object({
  agents: z.object({
    default: z.string().optional(),
    list: z.array(AgentConfigSchema).optional(),
    bindings: z.array(AgentBindingSchema).optional(),
  }).optional(),
  models: z.object({
    default: z.string().optional(),
    thinking: z.enum(["off", "minimal", "low", "medium", "high", "xhigh"]).optional(),
    auth: z.record(z.object({
      apiKey: z.string().optional(),
      oauthToken: z.string().optional(),
    })).optional(),
    fallbacks: z.array(z.string()).optional(),
  }).optional(),
  session: z.object({
    dmScope: z.enum(["main", "per-peer", "per-channel-peer", "per-account-channel-peer"]).optional(),
    identityLinks: z.record(z.array(z.string())).optional(),
    timeoutMs: z.number().positive().optional(),
    maxMessages: z.number().positive().optional(),
  }).optional(),
  gateway: GatewayConfigSchema,
  // Channel configs...
  telegram: z.object({
    token: z.string().optional(),
    allowedUsers: z.array(z.string()).optional(),
  }).optional(),
  whatsapp: z.object({
    sessionPath: z.string().optional(),
  }).optional(),
  // More channel schemas...
}).passthrough(); // Allow additional properties for plugins
```

### Validation: `src/config/validation.ts`

```typescript
// src/config/validation.ts

import { OpenClawSchema } from "./zod-schema.js";

export type ValidationResult = {
  success: boolean;
  data?: OpenClawConfig;
  errors?: ValidationError[];
};

export type ValidationError = {
  path: string[];
  message: string;
};

export function validateConfigObject(config: unknown): ValidationResult {
  const result = OpenClawSchema.safeParse(config);

  if (result.success) {
    return {
      success: true,
      data: result.data as OpenClawConfig,
    };
  }

  return {
    success: false,
    errors: result.error.errors.map((e) => ({
      path: e.path.map(String),
      message: e.message,
    })),
  };
}

// Validate with plugin schemas merged
export function validateConfigObjectWithPlugins(
  config: unknown,
  pluginSchemas: z.ZodType[]
): ValidationResult {
  // Merge plugin schemas with base schema
  let schema = OpenClawSchema;

  for (const pluginSchema of pluginSchemas) {
    schema = schema.merge(pluginSchema);
  }

  return validateConfigObject(config);
}
```

## Runtime Overrides

### Overrides: `src/config/runtime-overrides.ts`

```typescript
// src/config/runtime-overrides.ts

export function applyRuntimeOverrides(config: OpenClawConfig): OpenClawConfig {
  const overridden = { ...config };

  // Apply environment variable overrides
  applyEnvOverrides(overridden);

  // Apply CLI argument overrides (if available)
  applyCLIOverrides(overridden);

  return overridden;
}

function applyEnvOverrides(config: OpenClawConfig) {
  // Gateway port
  if (process.env.OPENCLAW_GATEWAY_PORT) {
    config.gateway = config.gateway ?? {};
    config.gateway.port = parseInt(process.env.OPENCLAW_GATEWAY_PORT);
  }

  // Default model
  if (process.env.OPENCLAW_DEFAULT_MODEL) {
    config.models = config.models ?? {};
    config.models.default = process.env.OPENCLAW_DEFAULT_MODEL;
  }

  // API keys
  if (process.env.ANTHROPIC_API_KEY) {
    config.models = config.models ?? {};
    config.models.auth = config.models.auth ?? {};
    config.models.auth.anthropic = {
      ...config.models.auth.anthropic,
      apiKey: process.env.ANTHROPIC_API_KEY,
    };
  }

  if (process.env.OPENAI_API_KEY) {
    config.models = config.models ?? {};
    config.models.auth = config.models.auth ?? {};
    config.models.auth.openai = {
      ...config.models.auth.openai,
      apiKey: process.env.OPENAI_API_KEY,
    };
  }

  // Telegram token
  if (process.env.TELEGRAM_BOT_TOKEN) {
    config.telegram = config.telegram ?? {};
    config.telegram.token = process.env.TELEGRAM_BOT_TOKEN;
  }

  // Discord token
  if (process.env.DISCORD_BOT_TOKEN) {
    config.discord = config.discord ?? {};
    config.discord.token = process.env.DISCORD_BOT_TOKEN;
  }
}

function applyCLIOverrides(config: OpenClawConfig) {
  // Check for --config-override flags in process.argv
  const overrides = extractConfigOverrides(process.argv);

  for (const [key, value] of Object.entries(overrides)) {
    setNestedValue(config, key, value);
  }
}

function setNestedValue(obj: any, path: string, value: unknown) {
  const parts = path.split(".");
  let current = obj;

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!(part in current)) {
      current[part] = {};
    }
    current = current[part];
  }

  current[parts[parts.length - 1]] = value;
}
```

## Default Configuration

```typescript
// src/config/defaults.ts

export function getDefaultConfig(): OpenClawConfig {
  return {
    agents: {
      default: "assistant",
      list: [
        {
          id: "assistant",
          name: "Assistant",
          model: "claude-opus-4-5-20251101",
          systemPrompt: "You are a helpful AI assistant.",
          thinking: "low",
        },
      ],
    },
    models: {
      default: "claude-opus-4-5-20251101",
      thinking: "low",
    },
    session: {
      dmScope: "main",
    },
    gateway: {
      mode: "local",
      port: 18789,
      bind: "loopback",
      controlUi: {
        enabled: true,
      },
    },
  };
}
```

## Example Configuration

```json5
// ~/.openclaw/config.json
{
  // Agent configuration
  "agents": {
    "default": "assistant",
    "list": [
      {
        "id": "assistant",
        "name": "General Assistant",
        "model": "claude-opus-4-5-20251101",
        "systemPrompt": "You are a helpful AI assistant.",
        "thinking": "low"
      },
      {
        "id": "coder",
        "name": "Coding Assistant",
        "model": "claude-sonnet-4-20250514",
        "systemPrompt": "You are an expert programmer.",
        "tools": ["system.run", "browser.snapshot"],
        "requireApproval": ["system.run"]
      }
    ],
    "bindings": [
      {
        "agentId": "coder",
        "match": {
          "channel": "discord",
          "guildId": "123456789"
        }
      }
    ]
  },

  // Model configuration
  "models": {
    "default": "claude-opus-4-5-20251101",
    "thinking": "low",
    "auth": {
      "anthropic": {
        "apiKey": "${ANTHROPIC_API_KEY}"
      }
    }
  },

  // Session configuration
  "session": {
    "dmScope": "per-peer"
  },

  // Gateway configuration
  "gateway": {
    "mode": "local",
    "port": 18789,
    "bind": "loopback",
    "controlUi": {
      "enabled": true
    }
  },

  // Telegram configuration
  "telegram": {
    "token": "your-bot-token"
  },

  // Discord configuration
  "discord": {
    "token": "your-bot-token"
  }
}
```

## CLI Config Commands

```bash
# Get a config value
openclaw config get models.default

# Set a config value
openclaw config set models.default anthropic/claude-sonnet-4-20250514

# Get full config
openclaw config get --json

# List all config keys
openclaw config list
```

## Exploration Exercises

1. **View your config**: Run `openclaw config get --json` to see your current configuration.

2. **Modify a setting**: Use `openclaw config set` to change the default model.

3. **Validate config**: Intentionally add an invalid value and see the validation error.

4. **Test overrides**: Set an environment variable and verify it overrides the config file.

5. **Explore the schema**: Read `src/config/zod-schema.ts` to understand all configurable options.

## Next Steps

In the next tutorial, we'll explore the [Plugin System](./09-plugins.md) - how to extend OpenClaw with custom channels and services.
