# Tutorial 05: Agent System

## Overview

The Agent System is the AI brain of OpenClaw. It manages AI models, sessions, tools, and the execution of agent turns. This tutorial covers how agents process messages and generate responses.

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Agent System                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐   │
│  │  Model Selection│     │   Agent Runtime │     │  Tool Execution │   │
│  │  & Auth         │────▶│   (Pi Embedded) │────▶│  & Approvals    │   │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘   │
│                                │                                        │
│                                ▼                                        │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐   │
│  │ System Prompt   │     │    Sessions     │     │    Response     │   │
│  │ Builder         │────▶│   Management    │────▶│    Delivery     │   │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Agent Configuration

### Agent List: `config.json`

```json
{
  "agents": {
    "default": "assistant",
    "list": [
      {
        "id": "assistant",
        "name": "Assistant",
        "model": "claude-opus-4-5-20251101",
        "systemPrompt": "You are a helpful assistant."
      },
      {
        "id": "coder",
        "name": "Coding Assistant",
        "model": "claude-sonnet-4-20250514",
        "systemPrompt": "You are an expert programmer.",
        "tools": ["system.run", "browser.snapshot"]
      }
    ]
  }
}
```

### Agent Scope: `src/agents/agent-scope.ts`

```typescript
// src/agents/agent-scope.ts

import { homedir } from "node:os";
import { join } from "node:path";

// Base directory for all agents
export const AGENTS_BASE_DIR = join(homedir(), ".openclaw", "agents");

// Resolve agent workspace directory
export function resolveAgentWorkspaceDir(agentId: string): string {
  const sanitized = sanitizeAgentId(agentId);
  return join(AGENTS_BASE_DIR, sanitized);
}

// Sanitize agent ID for filesystem use
export function sanitizeAgentId(id: string): string {
  return id
    .toLowerCase()
    .replace(/[^a-z0-9-_]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

// Resolve default agent from config
export function resolveDefaultAgentId(config: OpenClawConfig): string {
  const defaultId = config.agents?.default;
  if (defaultId) {
    return defaultId;
  }

  const firstAgent = config.agents?.list?.[0];
  if (firstAgent?.id) {
    return firstAgent.id;
  }

  return "default";
}
```

## Model Selection

### Model Selection: `src/agents/model-selection.ts`

```typescript
// src/agents/model-selection.ts

export type ModelSelection = {
  provider: "anthropic" | "openai" | "google" | "github-copilot" | string;
  model: string;
  thinking?: ThinkingLevel;
};

export type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh";

// Resolve model for an agent
export function resolveAgentModel(
  config: OpenClawConfig,
  agentId: string
): ModelSelection {
  // 1. Check agent-specific model
  const agent = findAgent(config, agentId);
  if (agent?.model) {
    return parseModelString(agent.model);
  }

  // 2. Check global default
  if (config.models?.default) {
    return parseModelString(config.models.default);
  }

  // 3. Fallback to Claude
  return {
    provider: "anthropic",
    model: "claude-opus-4-5-20251101",
    thinking: "low",
  };
}

// Parse model string (e.g., "anthropic/claude-opus-4-5-20251101")
export function parseModelString(modelStr: string): ModelSelection {
  const [provider, model] = modelStr.includes("/")
    ? modelStr.split("/", 2)
    : ["anthropic", modelStr];

  return { provider, model };
}

// List available models
export function listAvailableModels(): ModelInfo[] {
  return [
    // Anthropic
    { provider: "anthropic", id: "claude-opus-4-5-20251101", name: "Claude Opus 4.5" },
    { provider: "anthropic", id: "claude-sonnet-4-20250514", name: "Claude Sonnet 4" },

    // OpenAI
    { provider: "openai", id: "gpt-4o", name: "GPT-4o" },
    { provider: "openai", id: "gpt-4o-mini", name: "GPT-4o Mini" },

    // Google
    { provider: "google", id: "gemini-2.0-flash", name: "Gemini 2.0 Flash" },

    // More models...
  ];
}
```

### Model Authentication: `src/agents/model-auth.ts`

```typescript
// src/agents/model-auth.ts

export type AuthProfile = {
  provider: string;
  apiKey?: string;
  oauthToken?: string;
  expiresAt?: number;
};

// Resolve auth for a provider
export async function resolveModelAuth(
  provider: string,
  config: OpenClawConfig
): Promise<AuthProfile | null> {
  // 1. Check environment variables
  const envKey = getEnvKeyForProvider(provider);
  if (envKey) {
    return { provider, apiKey: envKey };
  }

  // 2. Check config
  const configAuth = config.models?.auth?.[provider];
  if (configAuth?.apiKey) {
    return { provider, apiKey: configAuth.apiKey };
  }

  // 3. Check credentials file
  const credPath = join(CREDENTIALS_PATH, `${provider}.json`);
  if (existsSync(credPath)) {
    const creds = JSON.parse(readFileSync(credPath, "utf-8"));
    return { provider, ...creds };
  }

  return null;
}

function getEnvKeyForProvider(provider: string): string | undefined {
  switch (provider) {
    case "anthropic":
      return process.env.ANTHROPIC_API_KEY;
    case "openai":
      return process.env.OPENAI_API_KEY;
    case "google":
      return process.env.GOOGLE_API_KEY;
    default:
      return undefined;
  }
}
```

## Agent Runtime

### Pi Embedded: `src/agents/pi-embedded.ts`

OpenClaw uses an embedded AI agent runtime:

```typescript
// src/agents/pi-embedded.ts

import { PiAgent } from "@mariozechner/pi-agent-core";
import { createAnthropicProvider } from "@mariozechner/pi-ai";

export type AgentTurnOptions = {
  message: string;
  sessionKey: string;
  agentId: string;
  model: ModelSelection;
  auth: AuthProfile;
  tools?: AgentTool[];
  thinking?: ThinkingLevel;
  onStream?: (chunk: StreamChunk) => void;
};

export async function runAgentTurn(opts: AgentTurnOptions): Promise<AgentResponse> {
  const { message, sessionKey, agentId, model, auth, tools, thinking, onStream } = opts;

  // 1. Create AI provider
  const provider = createProvider(model, auth);

  // 2. Load session
  const session = await loadSession(sessionKey);

  // 3. Build system prompt
  const systemPrompt = await buildSystemPrompt(agentId, session);

  // 4. Create agent
  const agent = new PiAgent({
    provider,
    systemPrompt,
    tools: tools ?? getDefaultTools(agentId),
    thinking: thinking ?? "low",
  });

  // 5. Add message to session
  session.addMessage({ role: "user", content: message });

  // 6. Run agent turn
  const response = await agent.run({
    messages: session.getMessages(),
    onStream: (chunk) => {
      if (onStream) {
        onStream(chunk);
      }
    },
  });

  // 7. Add response to session
  session.addMessage({ role: "assistant", content: response.content });

  // 8. Save session
  await saveSession(sessionKey, session);

  return {
    content: response.content,
    toolCalls: response.toolCalls,
    thinking: response.thinking,
    usage: response.usage,
  };
}
```

### Agent Runner: `src/agents/pi-embedded-runner.ts`

```typescript
// src/agents/pi-embedded-runner.ts

export type AgentRunContext = {
  agentId: string;
  sessionKey: string;
  channel: ChannelId;
  peer: { kind: string; id: string };
  config: OpenClawConfig;
};

export async function executeAgentRun(
  message: string,
  ctx: AgentRunContext
): Promise<string> {
  // 1. Resolve model and auth
  const model = resolveAgentModel(ctx.config, ctx.agentId);
  const auth = await resolveModelAuth(model.provider, ctx.config);

  if (!auth) {
    throw new Error(`No auth configured for provider: ${model.provider}`);
  }

  // 2. Resolve tools
  const tools = await resolveAgentTools(ctx.agentId, ctx.config);

  // 3. Get thinking level
  const thinking = resolveThinkingLevel(ctx.agentId, ctx.config);

  // 4. Run agent turn
  const response = await runAgentTurn({
    message,
    sessionKey: ctx.sessionKey,
    agentId: ctx.agentId,
    model,
    auth,
    tools,
    thinking,
  });

  return response.content;
}
```

## System Prompts

### System Prompt Builder: `src/agents/system-prompt.ts`

```typescript
// src/agents/system-prompt.ts

export type SystemPromptContext = {
  agentId: string;
  agentConfig: AgentConfig;
  session: Session;
  channel?: ChannelId;
  datetime: string;
  timezone: string;
};

export async function buildSystemPrompt(
  ctx: SystemPromptContext
): Promise<string> {
  const parts: string[] = [];

  // 1. Base identity
  const identity = ctx.agentConfig.systemPrompt ?? getDefaultSystemPrompt();
  parts.push(identity);

  // 2. Date/time context
  parts.push(`Current date and time: ${ctx.datetime} (${ctx.timezone})`);

  // 3. Channel context
  if (ctx.channel) {
    parts.push(buildChannelContext(ctx.channel));
  }

  // 4. Session context
  if (ctx.session.metadata) {
    parts.push(buildSessionContext(ctx.session));
  }

  // 5. Custom instructions from config
  if (ctx.agentConfig.instructions) {
    parts.push(ctx.agentConfig.instructions);
  }

  // 6. Skill prompts (if any)
  const skillPrompts = await loadSkillPrompts(ctx.agentId);
  if (skillPrompts.length > 0) {
    parts.push("## Available Skills");
    parts.push(...skillPrompts);
  }

  return parts.join("\n\n");
}

function getDefaultSystemPrompt(): string {
  return `You are a helpful AI assistant running on OpenClaw.
You can help with various tasks including:
- Answering questions
- Writing and editing text
- Analyzing information
- Running commands (with approval)

Be concise and helpful in your responses.`;
}
```

## Tools

### Tool Policy: `src/agents/tool-policy.ts`

```typescript
// src/agents/tool-policy.ts

export type ToolPolicy = {
  // Allowed tools (empty = all allowed)
  allow?: string[];

  // Denied tools (overrides allow)
  deny?: string[];

  // Require approval for these tools
  requireApproval?: string[];
};

export function resolveToolPolicy(
  agentId: string,
  config: OpenClawConfig
): ToolPolicy {
  const agent = findAgent(config, agentId);

  return {
    allow: agent?.tools ?? [],
    deny: agent?.denyTools ?? [],
    requireApproval: agent?.requireApproval ?? ["system.run"],
  };
}

export function isToolAllowed(
  toolName: string,
  policy: ToolPolicy
): boolean {
  // Check deny list first
  if (policy.deny?.includes(toolName)) {
    return false;
  }

  // If allow list is empty, all tools allowed
  if (!policy.allow || policy.allow.length === 0) {
    return true;
  }

  // Check allow list
  return policy.allow.includes(toolName);
}

export function requiresApproval(
  toolName: string,
  policy: ToolPolicy
): boolean {
  return policy.requireApproval?.includes(toolName) ?? false;
}
```

### Bash Tools: `src/agents/bash-tools.ts`

```typescript
// src/agents/bash-tools.ts

export const bashTool: AgentTool = {
  name: "system.run",
  description: "Execute a shell command",
  parameters: {
    type: "object",
    properties: {
      command: {
        type: "string",
        description: "The command to execute",
      },
      workingDir: {
        type: "string",
        description: "Working directory (optional)",
      },
      timeout: {
        type: "number",
        description: "Timeout in milliseconds (optional)",
      },
    },
    required: ["command"],
  },

  async execute(params: {
    command: string;
    workingDir?: string;
    timeout?: number;
  }, ctx: ToolContext): Promise<ToolResult> {
    const { command, workingDir, timeout = 30000 } = params;

    // Check if approval is required
    if (ctx.requiresApproval) {
      const approved = await ctx.requestApproval({
        tool: "system.run",
        description: `Execute: ${command}`,
      });

      if (!approved) {
        return { error: "Command execution not approved" };
      }
    }

    try {
      const result = await execCommand(command, {
        cwd: workingDir,
        timeout,
      });

      return {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
      };
    } catch (error) {
      return { error: error.message };
    }
  },
};
```

### Browser Tools: `src/agents/tools/browser-tools.ts`

```typescript
// src/agents/tools/browser-tools.ts

export const browserSnapshotTool: AgentTool = {
  name: "browser.snapshot",
  description: "Take a screenshot of the current browser page",
  parameters: {
    type: "object",
    properties: {
      selector: {
        type: "string",
        description: "CSS selector to capture (optional)",
      },
    },
  },

  async execute(params: { selector?: string }, ctx: ToolContext): Promise<ToolResult> {
    const browser = await ctx.getBrowserContext();
    if (!browser) {
      return { error: "Browser not available" };
    }

    const page = await browser.getCurrentPage();
    const screenshot = await page.screenshot({
      selector: params.selector,
      encoding: "base64",
    });

    return {
      image: {
        data: screenshot,
        mimeType: "image/png",
      },
    };
  },
};

export const browserNavigateTool: AgentTool = {
  name: "browser.navigate",
  description: "Navigate to a URL",
  parameters: {
    type: "object",
    properties: {
      url: { type: "string", description: "URL to navigate to" },
    },
    required: ["url"],
  },

  async execute(params: { url: string }, ctx: ToolContext): Promise<ToolResult> {
    const browser = await ctx.getBrowserContext();
    if (!browser) {
      return { error: "Browser not available" };
    }

    const page = await browser.getCurrentPage();
    await page.goto(params.url);

    return { success: true, url: page.url() };
  },
};
```

## Sessions

### Session Management: `src/agents/session.ts`

```typescript
// src/agents/session.ts

export type SessionMessage = {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp?: number;
  toolCalls?: ToolCall[];
};

export type Session = {
  key: string;
  agentId: string;
  messages: SessionMessage[];
  metadata: SessionMetadata;
  createdAt: number;
  updatedAt: number;
};

export type SessionMetadata = {
  channel?: ChannelId;
  peer?: { kind: string; id: string; name?: string };
  lastModel?: string;
  totalTokens?: number;
};

// Session storage path
function getSessionPath(sessionKey: string): string {
  const hash = createHash("sha256")
    .update(sessionKey)
    .digest("hex")
    .slice(0, 16);
  return join(SESSIONS_PATH, `${hash}.json`);
}

// Load session from disk
export async function loadSession(sessionKey: string): Promise<Session> {
  const path = getSessionPath(sessionKey);

  if (existsSync(path)) {
    const data = JSON.parse(readFileSync(path, "utf-8"));
    return data as Session;
  }

  // Create new session
  return {
    key: sessionKey,
    agentId: extractAgentId(sessionKey),
    messages: [],
    metadata: {},
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

// Save session to disk
export async function saveSession(
  sessionKey: string,
  session: Session
): Promise<void> {
  const path = getSessionPath(sessionKey);
  session.updatedAt = Date.now();
  writeFileSync(path, JSON.stringify(session, null, 2));
}

// Clear session messages
export async function clearSession(sessionKey: string): Promise<void> {
  const session = await loadSession(sessionKey);
  session.messages = [];
  await saveSession(sessionKey, session);
}
```

### Session Store: `src/commands/agent/session-store.ts`

```typescript
// src/commands/agent/session-store.ts

export class SessionStore {
  private sessions = new Map<string, Session>();
  private maxSessions = 1000;

  async get(key: string): Promise<Session> {
    // Check memory cache
    if (this.sessions.has(key)) {
      return this.sessions.get(key)!;
    }

    // Load from disk
    const session = await loadSession(key);
    this.sessions.set(key, session);

    // Evict old sessions if needed
    this.evictIfNeeded();

    return session;
  }

  async save(session: Session): Promise<void> {
    this.sessions.set(session.key, session);
    await saveSession(session.key, session);
  }

  private evictIfNeeded() {
    if (this.sessions.size <= this.maxSessions) {
      return;
    }

    // Remove oldest sessions
    const sorted = Array.from(this.sessions.entries())
      .sort((a, b) => a[1].updatedAt - b[1].updatedAt);

    const toRemove = sorted.slice(0, sorted.length - this.maxSessions);
    for (const [key] of toRemove) {
      this.sessions.delete(key);
    }
  }
}
```

## Thinking Levels

OpenClaw supports configurable "thinking" levels for agent responses:

```typescript
// src/agents/thinking.ts

export type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh";

export function resolveThinkingLevel(
  agentId: string,
  config: OpenClawConfig
): ThinkingLevel {
  // Check agent-specific setting
  const agent = findAgent(config, agentId);
  if (agent?.thinking) {
    return agent.thinking;
  }

  // Check global default
  if (config.models?.thinking) {
    return config.models.thinking;
  }

  // Default
  return "low";
}

// Map thinking level to provider-specific settings
export function thinkingToProviderConfig(
  level: ThinkingLevel,
  provider: string
): Record<string, unknown> {
  switch (provider) {
    case "anthropic":
      return {
        thinking: {
          type: "enabled",
          budget_tokens: getThinkingBudget(level),
        },
      };

    case "openai":
      return {
        reasoning_effort: level === "off" ? "low" : level,
      };

    default:
      return {};
  }
}

function getThinkingBudget(level: ThinkingLevel): number {
  switch (level) {
    case "off": return 0;
    case "minimal": return 1024;
    case "low": return 4096;
    case "medium": return 8192;
    case "high": return 16384;
    case "xhigh": return 32768;
  }
}
```

## Multi-Agent Coordination

### Subagent Registry: `src/agents/subagent-registry.ts`

```typescript
// src/agents/subagent-registry.ts

export type SubagentEntry = {
  agentId: string;
  parentId: string;
  sessionKey: string;
  createdAt: number;
};

// Global registry for coordinating multiple agents
class SubagentRegistry {
  private entries = new Map<string, SubagentEntry>();

  register(entry: SubagentEntry): void {
    this.entries.set(entry.agentId, entry);
  }

  unregister(agentId: string): void {
    this.entries.delete(agentId);
  }

  getByParent(parentId: string): SubagentEntry[] {
    return Array.from(this.entries.values())
      .filter((e) => e.parentId === parentId);
  }

  getAll(): SubagentEntry[] {
    return Array.from(this.entries.values());
  }
}

export const subagentRegistry = new SubagentRegistry();

// Initialize registry on gateway start
export function initSubagentRegistry(): void {
  subagentRegistry.clear();
}
```

## Exploration Exercises

1. **Run an agent**: Use `openclaw agent --message "Hello"` to run an agent turn.

2. **Check sessions**: Run `openclaw sessions` to see active sessions.

3. **Configure a model**: Set a different model with `openclaw config set models.default anthropic/claude-sonnet-4-20250514`.

4. **Explore tools**: Look at `src/agents/tools/` to see available agent tools.

5. **Trace an agent turn**: Add logging to trace the flow through `runAgentTurn`.

## Next Steps

In the next tutorial, we'll explore [Routing](./06-routing.md) - how messages are routed to the correct agent and session.
