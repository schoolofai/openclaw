# Tutorial 01: Introduction to OpenClaw

## Overview

OpenClaw is a self-hosted AI assistant platform that bridges multiple messaging channels with AI capabilities. Think of it as your personal AI that lives on your machine and can communicate through WhatsApp, Telegram, Discord, and many other platforms.

## Core Concepts

### 1. Gateway
The Gateway is the central control plane - a WebSocket server that coordinates everything. It:
- Manages connections to messaging channels
- Routes incoming messages to the appropriate AI agent
- Handles outbound message delivery
- Serves web interfaces (Control UI, WebChat)

### 2. Channels
Channels are messaging platform integrations. Each channel:
- Connects to a messaging service (WhatsApp, Telegram, etc.)
- Normalizes incoming messages into a common format
- Formats outgoing messages for the platform

### 3. Agents
Agents are AI assistants that process messages and generate responses. They:
- Have isolated sessions per conversation
- Use configurable AI models (Claude, GPT, etc.)
- Can execute tools (shell commands, browser control, etc.)

### 4. Sessions
Sessions track conversation state. Each session has:
- A unique session key (agent + channel + peer)
- Message history
- Tool execution context

## Project Directory Structure

```
openclaw/
├── src/                      # Main source code
│   ├── cli/                  # CLI framework and command building
│   │   ├── program/          # Commander.js program setup
│   │   ├── deps.ts           # Dependency injection
│   │   └── prompt.ts         # Interactive prompts
│   │
│   ├── commands/             # CLI command implementations
│   │   ├── agent.ts          # Agent execution commands
│   │   ├── channels.ts       # Channel management
│   │   ├── gateway.ts        # Gateway server command
│   │   ├── message.ts        # Message sending commands
│   │   └── onboard.ts        # Setup wizard
│   │
│   ├── gateway/              # WebSocket control plane
│   │   ├── server.impl.ts    # Main server implementation
│   │   ├── server-channels.ts# Channel lifecycle
│   │   ├── server-chat.ts    # Inbound message handling
│   │   ├── server-methods.js # WebSocket RPC handlers
│   │   └── protocol/         # Message schemas
│   │
│   ├── channels/             # Channel abstraction layer
│   │   ├── registry.ts       # Channel metadata
│   │   ├── plugins/          # Plugin adapter interfaces
│   │   └── allowlists/       # DM security
│   │
│   ├── agents/               # AI agent runtime
│   │   ├── pi-embedded.ts    # Embedded Pi agent
│   │   ├── model-selection.ts# Model configuration
│   │   └── tools/            # Agent tools
│   │
│   ├── routing/              # Message routing
│   │   ├── session-key.ts    # Session key generation
│   │   ├── resolve-route.ts  # Agent routing logic
│   │   └── bindings.ts       # Binding configuration
│   │
│   ├── infra/                # Infrastructure layer
│   │   ├── outbound/         # Message delivery
│   │   ├── exec-approvals.ts # Safety gates
│   │   └── heartbeat-*.ts    # Keep-alive system
│   │
│   ├── media/                # Media handling pipeline
│   ├── config/               # Configuration system
│   ├── plugins/              # Plugin system
│   ├── plugin-sdk/           # Public plugin API
│   │
│   ├── telegram/             # Telegram channel
│   ├── discord/              # Discord channel
│   ├── slack/                # Slack channel
│   ├── signal/               # Signal channel
│   ├── imessage/             # iMessage channel
│   └── web/                  # WhatsApp web channel
│
├── extensions/               # Plugin ecosystem
│   ├── msteams/              # Microsoft Teams
│   ├── matrix/               # Matrix protocol
│   ├── mattermost/           # Mattermost
│   ├── line/                 # LINE messaging
│   └── ...                   # Other extensions
│
├── apps/                     # Native applications
│   ├── macos/                # SwiftUI macOS app
│   ├── ios/                  # iOS app
│   └── android/              # Android app
│
├── ui/                       # Web UI (Control UI/WebChat)
├── docs/                     # Documentation (Mintlify)
└── scripts/                  # Build & automation
```

## Entry Point Flow

Let's trace how OpenClaw boots up:

### Step 1: Shell Entry (`openclaw.mjs`)
```javascript
#!/usr/bin/env node
// This is the npm bin entry that invokes the compiled CLI
import('./dist/entry.js')
```

### Step 2: CLI Entry (`src/entry.ts`)

```typescript
// src/entry.ts - Main entry point
process.title = "openclaw";
installProcessWarningFilter();
normalizeEnv();

// Handle experimental warnings by respawning if needed
if (!ensureExperimentalWarningSuppressed()) {
  // Parse CLI profile (--profile flag)
  const parsed = parseCliProfileArgs(process.argv);

  if (parsed.profile) {
    applyCliProfileEnv({ profile: parsed.profile });
    process.argv = parsed.argv;
  }

  // Import and run the CLI
  import("./cli/run-main.js")
    .then(({ runCli }) => runCli(process.argv))
    .catch((error) => {
      console.error("[openclaw] Failed to start CLI:", error);
      process.exitCode = 1;
    });
}
```

Key things happening here:
1. Set process title for visibility in task managers
2. Filter Node.js experimental warnings
3. Normalize environment variables
4. Handle CLI profile switching
5. Dynamically import and run the CLI

### Step 3: Program Building (`src/cli/program/build-program.ts`)

```typescript
// src/cli/program/build-program.ts
import { Command } from "commander";
import { registerProgramCommands } from "./command-registry.js";
import { createProgramContext } from "./context.js";
import { configureProgramHelp } from "./help.js";
import { registerPreActionHooks } from "./preaction.js";

export function buildProgram() {
  const program = new Command();
  const ctx = createProgramContext();
  const argv = process.argv;

  configureProgramHelp(program, ctx);
  registerPreActionHooks(program, ctx.programVersion);
  registerProgramCommands(program, ctx, argv);

  return program;
}
```

This creates the Commander.js program with:
- Program context (version, channel options)
- Help formatting
- Pre-action hooks (version checking)
- All registered commands

## Key Patterns

### 1. Dependency Injection

OpenClaw uses a lightweight DI pattern for testability:

```typescript
// src/cli/deps.ts
export type CliDeps = {
  loadConfig: typeof loadConfig;
  writeConfig: typeof writeConfigFile;
  // ... other dependencies
};

export function createDefaultDeps(): CliDeps {
  return {
    loadConfig,
    writeConfig: writeConfigFile,
    // ...
  };
}
```

Commands receive dependencies through this pattern, making them easy to test with mocks.

### 2. Lazy Loading

Commands and heavy modules are loaded lazily to improve startup time:

```typescript
// Only import when needed
const { startGatewayServer } = await import("../gateway/server.impl.js");
```

### 3. Configuration-Driven

Almost everything is configurable through `~/.openclaw/config.json`:
- Channel credentials
- Model selection
- Agent bindings
- Gateway settings

### 4. Event-Driven Architecture

The Gateway uses events for loose coupling:
- Agent events (message received, tool executed)
- Channel events (connected, disconnected)
- System events (health changes, config updates)

## Running the Project

### Development Mode
```bash
# Install dependencies
pnpm install

# Run CLI in development
pnpm openclaw status

# Run with verbose logging
pnpm openclaw gateway run --verbose
```

### Testing
```bash
# Run all tests
pnpm test

# Run with coverage
pnpm test:coverage
```

### Building
```bash
# Type-check and compile
pnpm build

# Lint code
pnpm lint
```

## Exploration Exercises

1. **Trace the boot sequence**: Start from `openclaw.mjs` and follow the imports to understand how the CLI initializes.

2. **Find all commands**: Look at `src/cli/program/command-registry.ts` to see all registered commands.

3. **Explore the config**: Read `src/config/types.ts` to understand the configuration schema.

4. **Check the channels**: Look at `src/channels/registry.ts` to see all supported channels.

## Next Steps

In the next tutorial, we'll dive deep into the [CLI Architecture](./02-cli-architecture.md) to understand how commands are registered and executed.
