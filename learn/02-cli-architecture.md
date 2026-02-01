# Tutorial 02: CLI Architecture

## Overview

OpenClaw's CLI is built on [Commander.js](https://github.com/tj/commander.js/), a popular Node.js command-line interface framework. This tutorial explains how commands are structured, registered, and executed.

## The CLI Pipeline

```
User Input                 Commander.js              Command Handler
    │                          │                          │
    ▼                          ▼                          ▼
┌─────────┐    ┌──────────────────────────┐    ┌─────────────────┐
│ openclaw│───▶│  buildProgram()          │───▶│ Action Function │
│ status  │    │  - registerCommands()    │    │ - Execute logic │
│ --json  │    │  - parseArgs()           │    │ - Return result │
└─────────┘    └──────────────────────────┘    └─────────────────┘
```

## Entry Points

### Primary Entry: `src/entry.ts`

The entry point handles:
1. Process setup (title, warning filters)
2. Environment normalization
3. CLI profile handling
4. Dynamic CLI loading

```typescript
// src/entry.ts - Key sections

// 1. Set process title
process.title = "openclaw";

// 2. Filter experimental warnings
installProcessWarningFilter();

// 3. Normalize environment variables
normalizeEnv();

// 4. Handle --no-color flag
if (process.argv.includes("--no-color")) {
  process.env.NO_COLOR = "1";
  process.env.FORCE_COLOR = "0";
}

// 5. Suppress experimental warnings by respawning if needed
if (!ensureExperimentalWarningSuppressed()) {
  // 6. Parse CLI profile
  const parsed = parseCliProfileArgs(process.argv);

  if (parsed.profile) {
    applyCliProfileEnv({ profile: parsed.profile });
    process.argv = parsed.argv;
  }

  // 7. Run the CLI
  import("./cli/run-main.js")
    .then(({ runCli }) => runCli(process.argv));
}
```

### CLI Runner: `src/cli/run-main.ts`

```typescript
// src/cli/run-main.ts
import { buildProgram } from "./program/build-program.js";

export async function runCli(argv: string[]) {
  const program = buildProgram();
  await program.parseAsync(argv);
}
```

## Program Building

### Build Program: `src/cli/program/build-program.ts`

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

  // Configure help output formatting
  configureProgramHelp(program, ctx);

  // Add pre-action hooks (version checking, etc.)
  registerPreActionHooks(program, ctx.programVersion);

  // Register all commands
  registerProgramCommands(program, ctx, argv);

  return program;
}
```

### Program Context: `src/cli/program/context.ts`

The context provides shared data for all commands:

```typescript
// src/cli/program/context.ts
export type ProgramContext = {
  programVersion: string;
  agentChannelOptions: ChannelOption[];
};

export function createProgramContext(): ProgramContext {
  const pkg = readPackageJson();
  return {
    programVersion: pkg.version,
    agentChannelOptions: buildAgentChannelOptions(),
  };
}
```

## Command Registration

### Command Registry: `src/cli/program/command-registry.ts`

All commands are registered through a central registry:

```typescript
// src/cli/program/command-registry.ts
import type { Command } from "commander";
import type { ProgramContext } from "./context.js";

type CommandRegisterParams = {
  program: Command;
  ctx: ProgramContext;
  argv: string[];
};

type RouteSpec = {
  match: (path: string[]) => boolean;
  loadPlugins?: boolean;
  run: (argv: string[]) => Promise<boolean>;
};

export type CommandRegistration = {
  id: string;
  register: (params: CommandRegisterParams) => void;
  routes?: RouteSpec[];
};

// The command registry - all commands are listed here
export const commandRegistry: CommandRegistration[] = [
  {
    id: "setup",
    register: ({ program }) => registerSetupCommand(program),
  },
  {
    id: "onboard",
    register: ({ program }) => registerOnboardCommand(program),
  },
  {
    id: "configure",
    register: ({ program }) => registerConfigureCommand(program),
  },
  {
    id: "config",
    register: ({ program }) => registerConfigCli(program),
  },
  {
    id: "maintenance",
    register: ({ program }) => registerMaintenanceCommands(program),
  },
  {
    id: "message",
    register: ({ program, ctx }) => registerMessageCommands(program, ctx),
  },
  {
    id: "memory",
    register: ({ program }) => registerMemoryCli(program),
    routes: [routeMemoryStatus],
  },
  {
    id: "agent",
    register: ({ program, ctx }) =>
      registerAgentCommands(program, {
        agentChannelOptions: ctx.agentChannelOptions
      }),
    routes: [routeAgentsList],
  },
  {
    id: "subclis",
    register: ({ program, argv }) => registerSubCliCommands(program, argv),
  },
  {
    id: "status-health-sessions",
    register: ({ program }) => registerStatusHealthSessionsCommands(program),
    routes: [routeHealth, routeStatus, routeSessions],
  },
  {
    id: "browser",
    register: ({ program }) => registerBrowserCli(program),
  },
];

// Register all commands with the program
export function registerProgramCommands(
  program: Command,
  ctx: ProgramContext,
  argv: string[] = process.argv,
) {
  for (const entry of commandRegistry) {
    entry.register({ program, ctx, argv });
  }
}
```

### Fast Routes

Some commands have "fast routes" that bypass full Commander parsing for speed:

```typescript
// Fast route for health command
const routeHealth: RouteSpec = {
  match: (path) => path[0] === "health",
  loadPlugins: true,
  run: async (argv) => {
    const json = hasFlag(argv, "--json");
    const verbose = getVerboseFlag(argv, { includeDebug: true });
    const timeoutMs = getPositiveIntFlagValue(argv, "--timeout");

    if (timeoutMs === null) {
      return false; // Fall back to Commander
    }

    await healthCommand({ json, timeoutMs, verbose }, defaultRuntime);
    return true;
  },
};

// Check for fast routes before Commander parsing
export function findRoutedCommand(path: string[]): RouteSpec | null {
  for (const entry of commandRegistry) {
    if (!entry.routes) continue;

    for (const route of entry.routes) {
      if (route.match(path)) {
        return route;
      }
    }
  }
  return null;
}
```

## Command Implementation Patterns

### Simple Command: Status

```typescript
// src/cli/program/register.status-health-sessions.ts
export function registerStatusHealthSessionsCommands(program: Command) {
  program
    .command("status")
    .description("Show system status")
    .option("--json", "Output as JSON")
    .option("--deep", "Run deep health checks")
    .option("--all", "Show all status info")
    .option("--usage", "Include usage statistics")
    .option("--timeout <ms>", "Timeout in milliseconds")
    .option("-v, --verbose", "Verbose output")
    .action(async (opts) => {
      await statusCommand({
        json: opts.json,
        deep: opts.deep,
        all: opts.all,
        usage: opts.usage,
        timeoutMs: opts.timeout ? parseInt(opts.timeout) : undefined,
        verbose: opts.verbose,
      }, defaultRuntime);
    });
}
```

### Command with Subcommands: Message

```typescript
// src/cli/program/register.message.ts
export function registerMessageCommands(
  program: Command,
  ctx: ProgramContext
) {
  const messageCmd = program
    .command("message")
    .description("Send and manage messages");

  // Subcommand: send
  messageCmd
    .command("send")
    .description("Send a message")
    .requiredOption("-t, --target <target>", "Target (phone/username/channel)")
    .requiredOption("-m, --message <text>", "Message content")
    .option("-c, --channel <channel>", "Channel to use")
    .option("--media <url>", "Media attachment URL")
    .action(async (opts) => {
      await sendMessage(opts);
    });

  // Subcommand: broadcast
  messageCmd
    .command("broadcast")
    .description("Broadcast to multiple targets")
    .requiredOption("-m, --message <text>", "Message content")
    .requiredOption("--targets <list>", "Comma-separated targets")
    .action(async (opts) => {
      await broadcastMessage(opts);
    });

  // More subcommands...
}
```

### Command with Lazy Loading: Gateway

```typescript
// src/cli/program/register.subclis.ts
export function registerSubCliCommands(program: Command, argv: string[]) {
  // Gateway CLI - lazy loaded
  program
    .command("gateway")
    .description("Gateway server management")
    .action(async () => {
      // Lazy load the gateway CLI module
      const { registerGatewayCli } = await import("../gateway-cli.js");
      const gatewayCli = new Command("gateway");
      registerGatewayCli(gatewayCli);
      await gatewayCli.parseAsync(argv.slice(2));
    });

  // Daemon CLI - lazy loaded
  program
    .command("daemon")
    .description("Daemon service management")
    .action(async () => {
      const { registerDaemonCli } = await import("../daemon-cli.js");
      const daemonCli = new Command("daemon");
      registerDaemonCli(daemonCli);
      await daemonCli.parseAsync(argv.slice(2));
    });
}
```

## Argument Parsing Utilities

### `src/cli/argv.ts`

```typescript
// src/cli/argv.ts - Argument parsing helpers

// Check if a flag is present
export function hasFlag(argv: string[], flag: string): boolean {
  return argv.includes(flag);
}

// Get a flag's value
export function getFlagValue(
  argv: string[],
  flag: string
): string | undefined | null {
  const index = argv.indexOf(flag);
  if (index === -1) return undefined;

  const next = argv[index + 1];
  if (!next || next.startsWith("-")) return null; // Invalid

  return next;
}

// Get verbose flag with debug support
export function getVerboseFlag(
  argv: string[],
  opts?: { includeDebug?: boolean }
): boolean {
  if (hasFlag(argv, "-v") || hasFlag(argv, "--verbose")) {
    return true;
  }
  if (opts?.includeDebug && hasFlag(argv, "--debug")) {
    return true;
  }
  return false;
}

// Get positive integer flag value
export function getPositiveIntFlagValue(
  argv: string[],
  flag: string
): number | undefined | null {
  const value = getFlagValue(argv, flag);
  if (value === undefined) return undefined;
  if (value === null) return null;

  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed <= 0) return null;

  return parsed;
}
```

## Interactive Prompts

### `src/cli/prompt.ts`

OpenClaw uses `@clack/prompts` for interactive CLI prompts:

```typescript
// src/cli/prompt.ts
import * as p from "@clack/prompts";

export async function promptText(message: string): Promise<string> {
  const result = await p.text({
    message,
    validate: (value) => {
      if (!value.trim()) return "Value is required";
    },
  });

  if (p.isCancel(result)) {
    process.exit(0);
  }

  return result;
}

export async function promptSelect<T>(
  message: string,
  options: { value: T; label: string }[]
): Promise<T> {
  const result = await p.select({
    message,
    options,
  });

  if (p.isCancel(result)) {
    process.exit(0);
  }

  return result as T;
}

export async function promptConfirm(message: string): Promise<boolean> {
  const result = await p.confirm({ message });

  if (p.isCancel(result)) {
    process.exit(0);
  }

  return result;
}
```

## Progress Indicators

### `src/cli/progress.ts`

```typescript
// src/cli/progress.ts
import { spinner } from "@clack/prompts";
import { createProgress } from "osc-progress";

// Simple spinner
export async function withSpinner<T>(
  message: string,
  fn: () => Promise<T>
): Promise<T> {
  const s = spinner();
  s.start(message);

  try {
    const result = await fn();
    s.stop("Done");
    return result;
  } catch (error) {
    s.stop("Failed");
    throw error;
  }
}

// Progress bar for longer operations
export function createProgressBar(total: number) {
  return createProgress({
    total,
    format: "[:bar] :percent :current/:total",
    width: 40,
  });
}
```

## Dependency Injection

### `src/cli/deps.ts`

Commands use dependency injection for testability:

```typescript
// src/cli/deps.ts
import { loadConfig, writeConfigFile } from "../config/config.js";
import { sendMessage } from "../infra/outbound/deliver.js";

export type CliDeps = {
  loadConfig: typeof loadConfig;
  writeConfig: typeof writeConfigFile;
  sendMessage: typeof sendMessage;
  // ... more dependencies
};

export function createDefaultDeps(): CliDeps {
  return {
    loadConfig,
    writeConfig: writeConfigFile,
    sendMessage,
  };
}

// Usage in a command:
export async function myCommand(
  opts: MyCommandOptions,
  deps = createDefaultDeps()
) {
  const config = await deps.loadConfig();
  // Use config...
}
```

## Pre-Action Hooks

### `src/cli/program/preaction.js`

```typescript
// src/cli/program/preaction.js
export function registerPreActionHooks(program: Command, version: string) {
  program.hook("preAction", async (thisCommand, actionCommand) => {
    // Check for version updates
    const updateInfo = await checkForUpdates(version);
    if (updateInfo.updateAvailable) {
      console.log(`Update available: ${updateInfo.latestVersion}`);
    }

    // Validate Node.js version
    if (!isNodeVersionSupported()) {
      console.warn("Warning: Node.js 22+ recommended");
    }
  });
}
```

## Command Categories

Commands are organized into logical groups:

| Category | Commands | Purpose |
|----------|----------|---------|
| Setup | `onboard`, `setup`, `configure` | Initial configuration |
| Status | `status`, `health`, `sessions` | System information |
| Message | `message send`, `message broadcast` | Direct messaging |
| Agent | `agent`, `agents list` | AI agent control |
| Gateway | `gateway run`, `gateway stop` | Server management |
| Config | `config get`, `config set` | Configuration |
| Memory | `memory status`, `memory search` | Memory system |
| Maintenance | `doctor`, `reset`, `uninstall` | Troubleshooting |

## Exploration Exercises

1. **Add a new command**: Create a simple command that prints "Hello, World!" and register it in the command registry.

2. **Trace command execution**: Add console.log statements to trace the path from `openclaw status` input to the status command action.

3. **Explore options**: Look at how the `--json` flag is handled across different commands.

4. **Test argument parsing**: Write a test for the `getFlagValue` function with various edge cases.

## Next Steps

In the next tutorial, we'll explore the [Gateway Server](./03-gateway.md) - the heart of OpenClaw's control plane.
