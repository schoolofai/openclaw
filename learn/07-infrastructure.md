# Tutorial 07: Infrastructure Layer

## Overview

The Infrastructure layer provides core services for message delivery, media handling, safety gates, and system events. This tutorial covers the key infrastructure components.

## Infrastructure Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Infrastructure Layer                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │    Outbound     │  │     Media       │  │     Safety      │         │
│  │    Delivery     │  │    Pipeline     │  │     Gates       │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                    │                   │
│  ┌────────┴────────┐  ┌────────┴────────┐  ┌────────┴────────┐         │
│  │ - Chunking      │  │ - Fetch         │  │ - Exec Approval │         │
│  │ - Formatting    │  │ - Store         │  │ - Tool Policy   │         │
│  │ - Retry         │  │ - Transcode     │  │ - Rate Limit    │         │
│  │ - Rate Limit    │  │ - Serve         │  │                 │         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │    Heartbeat    │  │    Events       │  │    Utilities    │         │
│  │    System       │  │    System       │  │                 │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                    │                   │
│  ┌────────┴────────┐  ┌────────┴────────┐  ┌────────┴────────┐         │
│  │ - Keep-alive    │  │ - Agent events  │  │ - Retry/Backoff │         │
│  │ - Health probe  │  │ - System events │  │ - Port mgmt     │         │
│  │ - Visibility    │  │ - Diagnostics   │  │ - Process exec  │         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Outbound Delivery

### Delivery System: `src/infra/outbound/deliver.ts`

```typescript
// src/infra/outbound/deliver.ts

export type OutboundDeliveryResult = {
  channel: OutboundChannel;
  messageId: string;
  chatId?: string;
  channelId?: string;
  timestamp?: number;
  meta?: Record<string, unknown>;
};

// Main delivery function
export async function deliverOutbound(params: {
  cfg: OpenClawConfig;
  channel: OutboundChannel;
  to: string;
  payloads: ReplyPayload[];
  replyToId?: string;
  threadId?: string;
  sessionKey?: string;
  abortSignal?: AbortSignal;
}): Promise<OutboundDeliveryResult[]> {
  const { cfg, channel, to, payloads, replyToId, threadId, abortSignal } = params;

  // 1. Normalize payloads
  const normalized = normalizeReplyPayloadsForDelivery(payloads);

  // 2. Create channel handler
  const handler = await createChannelHandler({
    cfg,
    channel,
    to,
    replyToId,
    threadId,
  });

  const results: OutboundDeliveryResult[] = [];

  // 3. Deliver each payload
  for (const payload of normalized) {
    throwIfAborted(abortSignal);

    if (payload.media) {
      // Send media
      const result = await handler.sendMedia(payload.text ?? "", payload.media);
      results.push(result);
    } else if (payload.text) {
      // Chunk and send text
      const chunks = chunkText(payload.text, handler);
      for (const chunk of chunks) {
        const result = await handler.sendText(chunk);
        results.push(result);
      }
    }
  }

  // 4. Append to session transcript if configured
  if (params.sessionKey) {
    await appendAssistantMessageToSessionTranscript(params.sessionKey, payloads);
  }

  return results;
}
```

### Text Chunking: `src/auto-reply/chunk.ts`

```typescript
// src/auto-reply/chunk.ts

export type ChunkMode = "text" | "markdown" | "paragraph";

// Resolve chunk limit for channel
export function resolveTextChunkLimit(channel: OutboundChannel): number {
  switch (channel) {
    case "whatsapp": return 4096;
    case "telegram": return 4096;
    case "discord": return 2000;
    case "slack": return 4000;
    case "signal": return 2000;
    default: return 2000;
  }
}

// Chunk text into smaller pieces
export function chunkText(text: string, limit: number): string[] {
  if (text.length <= limit) {
    return [text];
  }

  const chunks: string[] = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= limit) {
      chunks.push(remaining);
      break;
    }

    // Find a good break point
    let breakPoint = findBreakPoint(remaining, limit);
    chunks.push(remaining.slice(0, breakPoint));
    remaining = remaining.slice(breakPoint).trimStart();
  }

  return chunks;
}

function findBreakPoint(text: string, limit: number): number {
  // Try to break at paragraph
  const paragraphBreak = text.lastIndexOf("\n\n", limit);
  if (paragraphBreak > limit * 0.5) {
    return paragraphBreak + 2;
  }

  // Try to break at newline
  const newlineBreak = text.lastIndexOf("\n", limit);
  if (newlineBreak > limit * 0.5) {
    return newlineBreak + 1;
  }

  // Try to break at sentence
  const sentenceBreak = text.lastIndexOf(". ", limit);
  if (sentenceBreak > limit * 0.5) {
    return sentenceBreak + 2;
  }

  // Try to break at word
  const wordBreak = text.lastIndexOf(" ", limit);
  if (wordBreak > limit * 0.5) {
    return wordBreak + 1;
  }

  // Force break at limit
  return limit;
}

// Chunk markdown preserving code blocks
export function chunkMarkdownText(text: string, limit: number): string[] {
  // Handle code blocks specially
  const codeBlockRegex = /```[\s\S]*?```/g;
  const codeBlocks = text.match(codeBlockRegex) || [];

  // If no code blocks, use regular chunking
  if (codeBlocks.length === 0) {
    return chunkText(text, limit);
  }

  // Complex markdown chunking logic
  // ... preserves code blocks intact
}
```

### Outbound Policy: `src/infra/outbound/outbound-policy.ts`

```typescript
// src/infra/outbound/outbound-policy.ts

export type OutboundPolicy = "fire-and-forget" | "retry" | "retry-on-error";

export type RetryConfig = {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number;
};

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  backoffFactor: 2,
};

export async function deliverWithPolicy<T>(
  fn: () => Promise<T>,
  policy: OutboundPolicy,
  retryConfig: RetryConfig = DEFAULT_RETRY_CONFIG
): Promise<T> {
  if (policy === "fire-and-forget") {
    return fn();
  }

  let lastError: Error | null = null;
  let delay = retryConfig.baseDelayMs;

  for (let attempt = 0; attempt <= retryConfig.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (policy === "retry-on-error" && !isRetryableError(error)) {
        throw error;
      }

      if (attempt < retryConfig.maxRetries) {
        await sleep(delay);
        delay = Math.min(delay * retryConfig.backoffFactor, retryConfig.maxDelayMs);
      }
    }
  }

  throw lastError;
}

function isRetryableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;

  // Network errors are retryable
  if (error.message.includes("ECONNRESET")) return true;
  if (error.message.includes("ETIMEDOUT")) return true;
  if (error.message.includes("ENOTFOUND")) return true;

  // Rate limit errors are retryable
  if (error.message.includes("rate limit")) return true;

  return false;
}
```

## Media Pipeline

### Media Store: `src/media/store.ts`

```typescript
// src/media/store.ts

import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const MEDIA_STORE_DIR = join(homedir(), ".openclaw", "media");

export type StoredMedia = {
  id: string;
  path: string;
  mimeType: string;
  size: number;
  createdAt: number;
};

// Store media file
export function storeMedia(
  buffer: Buffer,
  mimeType: string
): StoredMedia {
  ensureMediaDir();

  const id = randomUUID();
  const ext = getExtensionForMime(mimeType);
  const filename = `${id}${ext}`;
  const path = join(MEDIA_STORE_DIR, filename);

  writeFileSync(path, buffer);

  return {
    id,
    path,
    mimeType,
    size: buffer.length,
    createdAt: Date.now(),
  };
}

// Retrieve media file
export function retrieveMedia(id: string): Buffer | null {
  const files = readdirSync(MEDIA_STORE_DIR);
  const match = files.find((f) => f.startsWith(id));

  if (!match) return null;

  return readFileSync(join(MEDIA_STORE_DIR, match));
}

// Get media metadata
export function getMediaMetadata(id: string): StoredMedia | null {
  const files = readdirSync(MEDIA_STORE_DIR);
  const match = files.find((f) => f.startsWith(id));

  if (!match) return null;

  const path = join(MEDIA_STORE_DIR, match);
  const stats = statSync(path);

  return {
    id,
    path,
    mimeType: getMimeForExtension(extname(match)),
    size: stats.size,
    createdAt: stats.birthtimeMs,
  };
}

function ensureMediaDir() {
  if (!existsSync(MEDIA_STORE_DIR)) {
    mkdirSync(MEDIA_STORE_DIR, { recursive: true });
  }
}
```

### Media Fetch: `src/media/fetch.ts`

```typescript
// src/media/fetch.ts

export type FetchedMedia = {
  buffer: Buffer;
  mimeType: string;
  size: number;
  url: string;
};

// Fetch media from URL
export async function fetchMedia(
  url: string,
  opts?: { maxSize?: number; timeout?: number }
): Promise<FetchedMedia> {
  const { maxSize = 50 * 1024 * 1024, timeout = 60000 } = opts ?? {};

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "OpenClaw/1.0",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch media: ${response.status}`);
    }

    // Check content length
    const contentLength = parseInt(response.headers.get("content-length") ?? "0");
    if (contentLength > maxSize) {
      throw new Error(`Media too large: ${contentLength} bytes`);
    }

    const buffer = Buffer.from(await response.arrayBuffer());

    // Verify actual size
    if (buffer.length > maxSize) {
      throw new Error(`Media too large: ${buffer.length} bytes`);
    }

    const mimeType = response.headers.get("content-type") ?? "application/octet-stream";

    return {
      buffer,
      mimeType,
      size: buffer.length,
      url,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
```

### Media Server: `src/media/server.ts`

```typescript
// src/media/server.ts

import express from "express";

export function createMediaServer(): express.Router {
  const router = express.Router();

  // Serve stored media
  router.get("/:id", (req, res) => {
    const { id } = req.params;
    const meta = getMediaMetadata(id);

    if (!meta) {
      return res.status(404).send("Not found");
    }

    const buffer = retrieveMedia(id);
    if (!buffer) {
      return res.status(404).send("Not found");
    }

    res.set("Content-Type", meta.mimeType);
    res.set("Content-Length", String(meta.size));
    res.send(buffer);
  });

  // Upload media
  router.post("/upload", express.raw({ limit: "50mb" }), (req, res) => {
    const mimeType = req.headers["content-type"] ?? "application/octet-stream";
    const stored = storeMedia(req.body, mimeType);

    res.json({
      id: stored.id,
      url: `/media/${stored.id}`,
      size: stored.size,
    });
  });

  return router;
}
```

## Execution Approvals

### Approval System: `src/infra/exec-approvals.ts`

```typescript
// src/infra/exec-approvals.ts

export type ApprovalRequest = {
  id: string;
  tool: string;
  description: string;
  details?: Record<string, unknown>;
  agentId: string;
  sessionKey: string;
  createdAt: number;
  timeoutMs: number;
};

export type ApprovalResult = {
  approved: boolean;
  timedOut?: boolean;
  respondedAt?: number;
  respondedBy?: string;
};

// Create approval request
export function createApprovalRequest(params: {
  tool: string;
  description: string;
  details?: Record<string, unknown>;
  agentId: string;
  sessionKey: string;
  timeoutMs?: number;
}): ApprovalRequest {
  return {
    id: randomUUID(),
    tool: params.tool,
    description: params.description,
    details: params.details,
    agentId: params.agentId,
    sessionKey: params.sessionKey,
    createdAt: Date.now(),
    timeoutMs: params.timeoutMs ?? 60000,
  };
}

// Format approval for display
export function formatApprovalPrompt(request: ApprovalRequest): string {
  return `
Approval requested for: ${request.tool}
Description: ${request.description}

Agent: ${request.agentId}
Session: ${request.sessionKey}

Approve? (y/n)
  `.trim();
}
```

### Approval Forwarder: `src/infra/exec-approval-forwarder.ts`

```typescript
// src/infra/exec-approval-forwarder.ts

export type ApprovalForwarder = {
  requestApproval: (request: ApprovalRequest) => Promise<ApprovalResult>;
  registerListener: (listener: ApprovalListener) => () => void;
};

export function createExecApprovalForwarder(): ApprovalForwarder {
  const listeners = new Set<ApprovalListener>();
  const pending = new Map<string, {
    resolve: (result: ApprovalResult) => void;
    timeoutId: NodeJS.Timeout;
  }>();

  return {
    async requestApproval(request: ApprovalRequest): Promise<ApprovalResult> {
      // Notify all listeners
      for (const listener of listeners) {
        listener.onApprovalRequested(request);
      }

      // Wait for response
      return new Promise((resolve) => {
        const timeoutId = setTimeout(() => {
          pending.delete(request.id);
          resolve({ approved: false, timedOut: true });
        }, request.timeoutMs);

        pending.set(request.id, { resolve, timeoutId });
      });
    },

    registerListener(listener: ApprovalListener): () => void {
      listeners.add(listener);

      return () => {
        listeners.delete(listener);
      };
    },

    respond(requestId: string, approved: boolean) {
      const entry = pending.get(requestId);
      if (entry) {
        clearTimeout(entry.timeoutId);
        pending.delete(requestId);
        entry.resolve({
          approved,
          respondedAt: Date.now(),
        });
      }
    },
  };
}
```

## Heartbeat System

### Heartbeat Runner: `src/infra/heartbeat-runner.ts`

```typescript
// src/infra/heartbeat-runner.ts

export type HeartbeatConfig = {
  intervalMs: number;
  timeoutMs: number;
  onBeat?: () => void;
  onMissed?: () => void;
};

const DEFAULT_HEARTBEAT_INTERVAL = 30000; // 30 seconds

export function startHeartbeatRunner(
  runtimeState: GatewayRuntimeState,
  config: HeartbeatConfig = {}
): () => void {
  const {
    intervalMs = DEFAULT_HEARTBEAT_INTERVAL,
    timeoutMs = intervalMs * 2,
    onBeat,
    onMissed,
  } = config;

  let lastBeat = Date.now();
  let missedCount = 0;

  const intervalId = setInterval(async () => {
    try {
      // Probe channels
      await probeChannelHealth(runtimeState);

      // Check node health
      pruneStaleNodes(runtimeState.nodeRegistry, timeoutMs);

      // Update health snapshot
      await refreshGatewayHealthSnapshot(runtimeState);

      // Record beat
      lastBeat = Date.now();
      missedCount = 0;
      onBeat?.();

      // Emit heartbeat event
      onHeartbeatEvent({
        timestamp: lastBeat,
        healthy: true,
      });
    } catch (error) {
      missedCount++;

      if (missedCount >= 3) {
        onMissed?.();
        onHeartbeatEvent({
          timestamp: Date.now(),
          healthy: false,
          error: error.message,
        });
      }
    }
  }, intervalMs);

  // Return cleanup function
  return () => {
    clearInterval(intervalId);
  };
}

function pruneStaleNodes(registry: NodeRegistry, timeoutMs: number) {
  const now = Date.now();
  const stale = registry.list().filter(
    (node) => now - node.lastHeartbeat > timeoutMs
  );

  for (const node of stale) {
    registry.unregister(node.id);
  }
}
```

## Event System

### Agent Events: `src/infra/agent-events.ts`

```typescript
// src/infra/agent-events.ts

export type AgentEvent =
  | { type: "message.received"; message: InboundMessage }
  | { type: "message.sent"; result: OutboundDeliveryResult }
  | { type: "tool.started"; tool: string; params: unknown }
  | { type: "tool.completed"; tool: string; result: unknown }
  | { type: "tool.failed"; tool: string; error: string }
  | { type: "thinking"; content: string }
  | { type: "session.created"; sessionKey: string }
  | { type: "session.cleared"; sessionKey: string };

type AgentEventListener = (event: AgentEvent) => void;

const listeners = new Set<AgentEventListener>();

export function onAgentEvent(event: AgentEvent) {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch (error) {
      console.error("Agent event listener error:", error);
    }
  }
}

export function subscribeToAgentEvents(listener: AgentEventListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function clearAgentRunContext() {
  // Clear any agent-specific context
}
```

### System Events: `src/infra/system-events.ts`

```typescript
// src/infra/system-events.ts

export type SystemEvent =
  | { type: "gateway.started"; port: number }
  | { type: "gateway.stopped"; reason: string }
  | { type: "channel.connected"; channel: ChannelId }
  | { type: "channel.disconnected"; channel: ChannelId; error?: string }
  | { type: "config.changed"; key?: string }
  | { type: "health.changed"; healthy: boolean };

const eventQueue: SystemEvent[] = [];
const maxQueueSize = 1000;

export function enqueueSystemEvent(event: SystemEvent) {
  eventQueue.push(event);

  // Trim queue if too large
  if (eventQueue.length > maxQueueSize) {
    eventQueue.splice(0, eventQueue.length - maxQueueSize);
  }

  // Emit to listeners
  emitSystemEvent(event);
}

export function getRecentSystemEvents(limit = 100): SystemEvent[] {
  return eventQueue.slice(-limit);
}
```

## Utilities

### Retry Logic: `src/infra/retry.ts`

```typescript
// src/infra/retry.ts

export type RetryOptions = {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number;
  shouldRetry?: (error: unknown, attempt: number) => boolean;
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
};

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  backoffFactor: 2,
};

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  let lastError: Error | null = null;
  let delay = opts.baseDelayMs;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      // Check if we should retry
      if (opts.shouldRetry && !opts.shouldRetry(error, attempt)) {
        throw error;
      }

      // Last attempt, throw
      if (attempt === opts.maxRetries) {
        throw error;
      }

      // Notify retry
      opts.onRetry?.(error, attempt, delay);

      // Wait before retry
      await sleep(delay);

      // Calculate next delay with exponential backoff
      delay = Math.min(delay * opts.backoffFactor, opts.maxDelayMs);
    }
  }

  throw lastError;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

### Port Management: `src/infra/ports.ts`

```typescript
// src/infra/ports.ts

import { createServer } from "node:net";

// Check if a port is available
export async function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();

    server.once("error", () => {
      resolve(false);
    });

    server.once("listening", () => {
      server.close();
      resolve(true);
    });

    server.listen(port, "127.0.0.1");
  });
}

// Find an available port starting from a given port
export async function findAvailablePort(
  startPort: number,
  maxAttempts = 100
): Promise<number> {
  for (let i = 0; i < maxAttempts; i++) {
    const port = startPort + i;
    if (await isPortAvailable(port)) {
      return port;
    }
  }

  throw new Error(`No available port found starting from ${startPort}`);
}

// Get the default gateway port
export function getDefaultGatewayPort(): number {
  return parseInt(process.env.OPENCLAW_GATEWAY_PORT ?? "18789");
}
```

## Exploration Exercises

1. **Trace outbound delivery**: Add logging to follow a message from agent response to channel delivery.

2. **Test media upload**: Use the media server to upload and retrieve an image.

3. **Implement approval**: Trigger an approval request and respond to it.

4. **Monitor heartbeat**: Watch the heartbeat logs and observe health probes.

5. **Test retry logic**: Create a flaky function and verify retry behavior.

## Next Steps

In the next tutorial, we'll explore the [Configuration System](./08-configuration.md) - how OpenClaw loads and validates configuration.
