# Tutorial 10: Advanced Topics

## Overview

This final tutorial covers advanced OpenClaw features including hooks, cron jobs, memory systems, browser control, and debugging techniques.

## Hooks System

### What are Hooks?

Hooks are webhooks that fire on specific events, allowing external integrations and custom processing.

### Hook Types

```typescript
// src/config/types.hooks.ts

export type HooksConfig = {
  // Message hooks
  onMessageReceived?: WebhookConfig[];
  onMessageSent?: WebhookConfig[];

  // Media hooks
  onMediaReceived?: WebhookConfig[];

  // Agent hooks
  onAgentStart?: WebhookConfig[];
  onAgentComplete?: WebhookConfig[];
  onToolExecuted?: WebhookConfig[];

  // System hooks
  onGatewayStart?: WebhookConfig[];
  onHealthChange?: WebhookConfig[];
};

export type WebhookConfig = {
  url: string;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
};
```

### Hook Configuration

```json
{
  "hooks": {
    "onMessageReceived": [
      {
        "url": "https://my-server.com/webhook/message",
        "method": "POST",
        "headers": {
          "Authorization": "Bearer secret"
        },
        "timeout": 5000
      }
    ],
    "onMediaReceived": [
      {
        "url": "https://my-server.com/webhook/media",
        "method": "POST"
      }
    ],
    "onToolExecuted": [
      {
        "url": "https://my-server.com/webhook/audit",
        "method": "POST"
      }
    ]
  }
}
```

### Hook Execution: `src/hooks/runner.ts`

```typescript
// src/hooks/runner.ts

export async function executeHooks(
  hookType: keyof HooksConfig,
  payload: unknown,
  config: OpenClawConfig
): Promise<void> {
  const hooks = config.hooks?.[hookType];
  if (!hooks || hooks.length === 0) {
    return;
  }

  // Execute hooks in parallel
  await Promise.allSettled(
    hooks.map((hook) => executeHook(hook, payload))
  );
}

async function executeHook(
  hook: WebhookConfig,
  payload: unknown
): Promise<void> {
  const { url, method = "POST", headers = {}, timeout = 5000, retries = 2 } = hook;

  await withRetry(
    async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          method,
          headers: {
            "Content-Type": "application/json",
            ...headers,
          },
          body: method !== "GET" ? JSON.stringify(payload) : undefined,
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Hook failed: ${response.status}`);
        }
      } finally {
        clearTimeout(timeoutId);
      }
    },
    { maxRetries: retries }
  );
}
```

### Hook Payloads

```typescript
// Message received payload
{
  "event": "message.received",
  "timestamp": 1699000000000,
  "message": {
    "channel": "telegram",
    "messageId": "123",
    "text": "Hello!",
    "peer": {
      "kind": "dm",
      "id": "user123",
      "name": "John"
    }
  }
}

// Tool executed payload
{
  "event": "tool.executed",
  "timestamp": 1699000000000,
  "tool": "system.run",
  "params": { "command": "ls -la" },
  "result": { "stdout": "...", "exitCode": 0 },
  "agentId": "assistant",
  "sessionKey": "assistant::main"
}
```

## Cron Jobs

### Cron Configuration

```json
{
  "cron": {
    "jobs": [
      {
        "id": "daily-summary",
        "schedule": "0 9 * * *",
        "action": {
          "type": "agent",
          "agentId": "assistant",
          "message": "Give me a summary of yesterday's tasks"
        }
      },
      {
        "id": "health-check",
        "schedule": "*/5 * * * *",
        "action": {
          "type": "webhook",
          "url": "https://my-server.com/health"
        }
      }
    ]
  }
}
```

### Cron Service: `src/gateway/server-cron.ts`

```typescript
// src/gateway/server-cron.ts

import { CronJob } from "cron";

export type CronJobConfig = {
  id: string;
  schedule: string;
  action: CronAction;
  enabled?: boolean;
};

export type CronAction =
  | { type: "agent"; agentId: string; message: string; target?: string }
  | { type: "webhook"; url: string; method?: string; body?: unknown }
  | { type: "command"; command: string };

export function buildGatewayCronService(opts: {
  config: OpenClawConfig;
  logger: Logger;
  runtimeState: GatewayRuntimeState;
}) {
  const { config, logger, runtimeState } = opts;
  const jobs = new Map<string, CronJob>();

  // Load jobs from config
  const jobConfigs = config.cron?.jobs ?? [];

  for (const jobConfig of jobConfigs) {
    if (jobConfig.enabled === false) continue;

    const job = new CronJob(
      jobConfig.schedule,
      async () => {
        logger.info(`Running cron job: ${jobConfig.id}`);
        await executeCronAction(jobConfig.action, runtimeState);
      },
      null,
      true, // Start immediately
      config.cron?.timezone ?? "UTC"
    );

    jobs.set(jobConfig.id, job);
  }

  return {
    addJob(config: CronJobConfig) {
      const job = new CronJob(
        config.schedule,
        async () => {
          await executeCronAction(config.action, runtimeState);
        },
        null,
        true
      );
      jobs.set(config.id, job);
    },

    removeJob(id: string) {
      const job = jobs.get(id);
      if (job) {
        job.stop();
        jobs.delete(id);
      }
    },

    listJobs() {
      return Array.from(jobs.entries()).map(([id, job]) => ({
        id,
        running: job.running,
        nextRun: job.nextDate()?.toISO(),
      }));
    },

    stopAll() {
      for (const job of jobs.values()) {
        job.stop();
      }
      jobs.clear();
    },
  };
}

async function executeCronAction(
  action: CronAction,
  runtimeState: GatewayRuntimeState
) {
  switch (action.type) {
    case "agent":
      await runAgentTurn({
        message: action.message,
        agentId: action.agentId,
        sessionKey: `${action.agentId}::cron`,
        // ...
      });
      break;

    case "webhook":
      await fetch(action.url, {
        method: action.method ?? "POST",
        body: action.body ? JSON.stringify(action.body) : undefined,
      });
      break;

    case "command":
      await execCommand(action.command);
      break;
  }
}
```

## Memory System

### Memory Configuration

```json
{
  "memory": {
    "enabled": true,
    "backend": "lancedb",
    "config": {
      "dbPath": "~/.openclaw/memory.lance",
      "embeddingModel": "text-embedding-3-small"
    }
  }
}
```

### Memory Interface

```typescript
// src/memory/types.ts

export type MemoryEntry = {
  id: string;
  content: string;
  embedding?: number[];
  metadata: {
    agentId: string;
    sessionKey: string;
    timestamp: number;
    source: "user" | "assistant" | "tool";
    tags?: string[];
  };
};

export type MemorySearchResult = {
  entry: MemoryEntry;
  score: number;
};

export type MemoryBackend = {
  store(entry: MemoryEntry): Promise<void>;
  search(query: string, opts?: { limit?: number; agentId?: string }): Promise<MemorySearchResult[]>;
  delete(id: string): Promise<void>;
  clear(agentId?: string): Promise<void>;
};
```

### Memory Tools

```typescript
// src/agents/tools/memory-tool.ts

export const memorySearchTool: AgentTool = {
  name: "memory.search",
  description: "Search your memory for relevant information",
  parameters: {
    type: "object",
    properties: {
      query: {
        type: "string",
        description: "Search query",
      },
      limit: {
        type: "number",
        description: "Max results (default 5)",
      },
    },
    required: ["query"],
  },

  async execute(params, ctx) {
    const { query, limit = 5 } = params;
    const memory = await getMemoryBackend();

    const results = await memory.search(query, {
      limit,
      agentId: ctx.agentId,
    });

    return {
      results: results.map((r) => ({
        content: r.entry.content,
        score: r.score,
        timestamp: r.entry.metadata.timestamp,
      })),
    };
  },
};

export const memoryStoreTool: AgentTool = {
  name: "memory.store",
  description: "Store important information in memory",
  parameters: {
    type: "object",
    properties: {
      content: {
        type: "string",
        description: "Information to remember",
      },
      tags: {
        type: "array",
        items: { type: "string" },
        description: "Optional tags for categorization",
      },
    },
    required: ["content"],
  },

  async execute(params, ctx) {
    const { content, tags } = params;
    const memory = await getMemoryBackend();

    const entry: MemoryEntry = {
      id: randomUUID(),
      content,
      metadata: {
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
        timestamp: Date.now(),
        source: "assistant",
        tags,
      },
    };

    await memory.store(entry);

    return { success: true, id: entry.id };
  },
};
```

## Browser Control

### Browser Configuration

```json
{
  "browser": {
    "enabled": true,
    "headless": true,
    "viewport": {
      "width": 1280,
      "height": 720
    },
    "timeout": 30000
  }
}
```

### Browser Tools: `src/agents/tools/browser-tools.ts`

```typescript
// src/agents/tools/browser-tools.ts

export const browserTools: AgentTool[] = [
  {
    name: "browser.navigate",
    description: "Navigate to a URL",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to navigate to" },
      },
      required: ["url"],
    },
    async execute({ url }, ctx) {
      const browser = await ctx.getBrowser();
      await browser.page.goto(url, { waitUntil: "networkidle" });
      return { success: true, url: browser.page.url() };
    },
  },

  {
    name: "browser.snapshot",
    description: "Take a screenshot of the current page",
    parameters: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector (optional)" },
        fullPage: { type: "boolean", description: "Capture full page" },
      },
    },
    async execute(params, ctx) {
      const browser = await ctx.getBrowser();
      const screenshot = await browser.page.screenshot({
        fullPage: params.fullPage,
        element: params.selector,
        encoding: "base64",
      });
      return {
        image: { type: "image", data: screenshot, mimeType: "image/png" },
      };
    },
  },

  {
    name: "browser.click",
    description: "Click an element on the page",
    parameters: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector" },
      },
      required: ["selector"],
    },
    async execute({ selector }, ctx) {
      const browser = await ctx.getBrowser();
      await browser.page.click(selector);
      return { success: true };
    },
  },

  {
    name: "browser.type",
    description: "Type text into an input field",
    parameters: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector" },
        text: { type: "string", description: "Text to type" },
      },
      required: ["selector", "text"],
    },
    async execute({ selector, text }, ctx) {
      const browser = await ctx.getBrowser();
      await browser.page.fill(selector, text);
      return { success: true };
    },
  },

  {
    name: "browser.evaluate",
    description: "Run JavaScript in the browser",
    parameters: {
      type: "object",
      properties: {
        script: { type: "string", description: "JavaScript to run" },
      },
      required: ["script"],
    },
    async execute({ script }, ctx) {
      const browser = await ctx.getBrowser();
      const result = await browser.page.evaluate(script);
      return { result };
    },
  },
];
```

## Sandbox Execution

### Sandbox Configuration

```json
{
  "sandbox": {
    "enabled": true,
    "type": "docker",
    "image": "node:22-slim",
    "timeout": 60000,
    "memory": "512m",
    "networkAccess": false
  }
}
```

### Sandbox Runner

```typescript
// src/sandbox/runner.ts

export type SandboxConfig = {
  type: "docker" | "firecracker" | "process";
  image?: string;
  timeout: number;
  memory?: string;
  networkAccess: boolean;
};

export async function runInSandbox(
  code: string,
  config: SandboxConfig
): Promise<SandboxResult> {
  switch (config.type) {
    case "docker":
      return runInDocker(code, config);
    case "process":
      return runInProcess(code, config);
    default:
      throw new Error(`Unknown sandbox type: ${config.type}`);
  }
}

async function runInDocker(
  code: string,
  config: SandboxConfig
): Promise<SandboxResult> {
  const { image = "node:22-slim", timeout, memory, networkAccess } = config;

  const args = [
    "run",
    "--rm",
    "-i",
    `--memory=${memory ?? "256m"}`,
    `--network=${networkAccess ? "bridge" : "none"}`,
    image,
    "node",
    "-e",
    code,
  ];

  return execWithTimeout("docker", args, timeout);
}
```

## Debugging Techniques

### Enable Verbose Logging

```bash
# CLI verbose mode
openclaw gateway run --verbose

# Debug mode
DEBUG=openclaw:* openclaw gateway run

# Specific subsystem
DEBUG=openclaw:gateway openclaw gateway run
```

### Logging Subsystems

```typescript
// src/logging/subsystem.ts

export function createSubsystemLogger(subsystem: string) {
  return {
    info: (msg: string, data?: object) => {
      console.log(`[${subsystem}] ${msg}`, data ?? "");
    },
    warn: (msg: string, data?: object) => {
      console.warn(`[${subsystem}] ${msg}`, data ?? "");
    },
    error: (msg: string, data?: object) => {
      console.error(`[${subsystem}] ${msg}`, data ?? "");
    },
    debug: (msg: string, data?: object) => {
      if (process.env.DEBUG?.includes(subsystem)) {
        console.debug(`[${subsystem}] ${msg}`, data ?? "");
      }
    },
    child: (name: string) => createSubsystemLogger(`${subsystem}:${name}`),
  };
}
```

### Doctor Command

```bash
# Run diagnostics
openclaw doctor

# Check specific issues
openclaw doctor --check-config
openclaw doctor --check-channels
openclaw doctor --check-auth
```

### Health Check

```bash
# Basic health
openclaw health

# Deep probe (tests connections)
openclaw health --deep

# JSON output for scripting
openclaw health --json
```

## Performance Tuning

### Gateway Tuning

```json
{
  "gateway": {
    "concurrency": {
      "maxAgentTurns": 10,
      "maxChannelRequests": 50
    },
    "queue": {
      "debounceMs": 500,
      "maxQueueSize": 100
    }
  }
}
```

### Session Tuning

```json
{
  "session": {
    "maxMessages": 50,
    "summarizeAfter": 30,
    "timeoutMs": 3600000
  }
}
```

### Memory Tuning

```bash
# Increase Node.js heap
NODE_OPTIONS="--max-old-space-size=4096" openclaw gateway run
```

## Security Best Practices

### 1. Use Allowlists

```json
{
  "telegram": {
    "allowedUsers": ["user123", "user456"]
  },
  "discord": {
    "allowedGuilds": ["guild123"]
  }
}
```

### 2. Require Tool Approvals

```json
{
  "agents": {
    "list": [{
      "id": "assistant",
      "requireApproval": ["system.run", "browser.evaluate"]
    }]
  }
}
```

### 3. Use Gateway Auth

```json
{
  "gateway": {
    "auth": {
      "enabled": true,
      "method": "bearer",
      "token": "${GATEWAY_TOKEN}"
    }
  }
}
```

### 4. Bind to Loopback

```json
{
  "gateway": {
    "bind": "loopback"
  }
}
```

## Monitoring

### Metrics Endpoint

```bash
# Get metrics
curl http://localhost:18789/metrics
```

### System Events

```typescript
// Subscribe to system events
subscribeToSystemEvents((event) => {
  console.log("System event:", event);
});
```

### WebSocket Events

```javascript
// Connect to gateway
const ws = new WebSocket("ws://localhost:18789");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.event) {
    console.log("Gateway event:", data.event, data.data);
  }
};
```

## Exploration Exercises

1. **Set up a hook**: Configure a webhook for message events.

2. **Create a cron job**: Schedule a daily summary message.

3. **Test memory**: Use memory tools to store and retrieve information.

4. **Browser automation**: Write an agent that navigates a website and extracts data.

5. **Debug a problem**: Use verbose logging to trace an issue.

## Conclusion

Congratulations! You've completed the OpenClaw tutorial series. You now have a comprehensive understanding of:

- Project structure and entry points
- CLI architecture and command registration
- Gateway server and WebSocket protocol
- Messaging channels and plugins
- Agent system and tool execution
- Routing and session management
- Infrastructure services
- Configuration system
- Plugin development
- Advanced features

## Next Steps

- Explore the codebase and read real implementations
- Contribute to OpenClaw by fixing bugs or adding features
- Build your own plugins and extensions
- Join the community and share your experiences

Happy coding!
