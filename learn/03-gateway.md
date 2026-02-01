# Tutorial 03: Gateway Server Architecture

## Overview

The Gateway is the central control plane of OpenClaw - a WebSocket server that coordinates all messaging, agents, and clients. Think of it as the "brain" that everything connects to.

## Gateway Architecture

```
                            ┌─────────────────────────────────────┐
                            │         Gateway Server              │
                            │         (Port 18789)                │
                            ├─────────────────────────────────────┤
                            │                                     │
  Channels ─────────────────┤►  Channel Manager                   │
  (Telegram, WhatsApp, etc.)│      ├── Monitor connections        │
                            │      └── Route inbound messages     │
                            │                                     │
  CLI/Apps ─────────────────┤►  WebSocket RPC                     │
  (CLI, macOS, iOS)         │      ├── Method handlers            │
                            │      └── Event streaming            │
                            │                                     │
  Web Browser ──────────────┤►  HTTP Endpoints                    │
                            │      ├── Control UI                 │
                            │      ├── WebChat                    │
                            │      └── OpenAI-compatible API      │
                            │                                     │
                            │   Core Services                     │
                            │      ├── Agent Runtime              │
                            │      ├── Cron Service               │
                            │      ├── Plugin System              │
                            │      └── Heartbeat                  │
                            │                                     │
                            └─────────────────────────────────────┘
```

## Server Implementation

### Main Entry: `src/gateway/server.impl.ts`

```typescript
// src/gateway/server.impl.ts

export type GatewayServer = {
  close: (opts?: {
    reason?: string;
    restartExpectedMs?: number | null
  }) => Promise<void>;
};

export type GatewayServerOptions = {
  // Bind address policy
  // - loopback: 127.0.0.1 (local only)
  // - lan: 0.0.0.0 (all interfaces)
  // - tailnet: Tailscale IP only
  // - auto: prefer loopback, fallback to LAN
  bind?: "loopback" | "lan" | "tailnet" | "auto";

  // Advanced override for bind host
  host?: string;

  // Enable/disable Control UI
  controlUiEnabled?: boolean;

  // Enable/disable OpenAI-compatible endpoint
  openAiChatCompletionsEnabled?: boolean;

  // Gateway authentication config
  auth?: GatewayAuthConfig;

  // Tailscale exposure config
  tailscale?: GatewayTailscaleConfig;
};

export async function startGatewayServer(
  port = 18789,
  opts: GatewayServerOptions = {},
): Promise<GatewayServer> {
  // Implementation follows...
}
```

### Startup Sequence

The Gateway startup is a carefully orchestrated sequence:

```typescript
// src/gateway/server.impl.ts - startGatewayServer (simplified)

export async function startGatewayServer(port, opts) {
  // 1. Load configuration
  const cfg = await loadConfig();

  // 2. Migrate legacy config if needed
  await migrateLegacyConfig();

  // 3. Create subsystem loggers
  const log = createSubsystemLogger("gateway");
  const logChannels = log.child("channels");
  const logCron = log.child("cron");

  // 4. Create core services
  const nodeRegistry = new NodeRegistry();
  const execApprovalManager = new ExecApprovalManager();
  const channelManager = await createChannelManager({
    config: cfg,
    logger: logChannels,
  });

  // 5. Load plugins
  const pluginServices = await loadGatewayPlugins({
    config: cfg,
    logger: logPlugins,
  });

  // 6. Build cron service
  const cronService = buildGatewayCronService({
    config: cfg,
    logger: logCron,
  });

  // 7. Create runtime state
  const runtimeState = createGatewayRuntimeState({
    config: cfg,
    channelManager,
    nodeRegistry,
    cronService,
  });

  // 8. Start WebSocket server
  const wss = new WebSocketServer({ noServer: true });
  attachGatewayWsHandlers(wss, {
    runtimeState,
    handlers: coreGatewayHandlers,
  });

  // 9. Create HTTP server with Express
  const app = express();
  setupHttpEndpoints(app, runtimeState);

  // 10. Bind to port
  const server = app.listen(port, host);

  // 11. Start sidecars (discovery, Tailscale, etc.)
  await startGatewaySidecars({
    config: cfg,
    server,
    runtimeState,
  });

  // 12. Start maintenance timers
  startGatewayMaintenanceTimers(runtimeState);

  // 13. Start heartbeat
  startHeartbeatRunner(runtimeState);

  // Return close handler
  return {
    close: createGatewayCloseHandler(runtimeState),
  };
}
```

## WebSocket Protocol

### Message Format

The Gateway uses a JSON-based RPC protocol:

```typescript
// src/gateway/protocol/base.ts
import { Type } from "@sinclair/typebox";

// Request message
export const GatewayRequest = Type.Object({
  id: Type.String(),           // Unique request ID
  method: Type.String(),       // Method name (e.g., "chat")
  params: Type.Unknown(),      // Method parameters
});

// Response message
export const GatewayResponse = Type.Object({
  id: Type.String(),           // Matching request ID
  result: Type.Optional(Type.Unknown()),
  error: Type.Optional(Type.Object({
    code: Type.Number(),
    message: Type.String(),
  })),
});

// Event message (server-push)
export const GatewayEvent = Type.Object({
  event: Type.String(),        // Event name
  data: Type.Unknown(),        // Event payload
});
```

### WebSocket Handler: `src/gateway/server-ws-runtime.ts`

```typescript
// src/gateway/server-ws-runtime.ts

export function attachGatewayWsHandlers(
  wss: WebSocketServer,
  ctx: {
    runtimeState: GatewayRuntimeState;
    handlers: GatewayHandlers;
  }
) {
  wss.on("connection", (ws: WebSocket) => {
    // Track client connection
    const clientId = generateClientId();

    ws.on("message", async (data) => {
      try {
        const message = JSON.parse(data.toString());

        // Validate message format
        if (!isValidRequest(message)) {
          sendError(ws, message.id, "Invalid request format");
          return;
        }

        // Find handler for method
        const handler = ctx.handlers[message.method];
        if (!handler) {
          sendError(ws, message.id, `Unknown method: ${message.method}`);
          return;
        }

        // Execute handler
        const result = await handler(message.params, {
          clientId,
          runtimeState: ctx.runtimeState,
          sendEvent: (event, data) => {
            ws.send(JSON.stringify({ event, data }));
          },
        });

        // Send response
        ws.send(JSON.stringify({
          id: message.id,
          result,
        }));
      } catch (error) {
        sendError(ws, message.id, error.message);
      }
    });

    ws.on("close", () => {
      // Cleanup client state
    });
  });
}
```

## Gateway Methods

### Method Handlers: `src/gateway/server-methods.js`

```typescript
// src/gateway/server-methods.js

export const coreGatewayHandlers: GatewayHandlers = {
  // Chat with agent
  async chat(params, ctx) {
    const { message, sessionKey, agentId } = params;
    return runAgentTurn({
      message,
      sessionKey,
      agentId,
      runtimeState: ctx.runtimeState,
    });
  },

  // Get system status
  async status(params, ctx) {
    return getGatewayStatus(ctx.runtimeState);
  },

  // List sessions
  async sessions(params, ctx) {
    return listSessions(ctx.runtimeState);
  },

  // Get/set configuration
  async config(params, ctx) {
    if (params.set) {
      return setConfig(params.key, params.value);
    }
    return getConfig(params.key);
  },

  // Cron job management
  async cron(params, ctx) {
    return handleCronMethod(params, ctx.runtimeState);
  },

  // Node registration (mobile/desktop apps)
  async nodes(params, ctx) {
    return handleNodesMethod(params, ctx.runtimeState);
  },

  // Execution approvals
  async approvals(params, ctx) {
    return handleApprovalsMethod(params, ctx.runtimeState);
  },
};
```

### Method List: `src/gateway/server-methods-list.ts`

```typescript
// src/gateway/server-methods-list.ts

export const GATEWAY_METHODS = [
  "chat",
  "status",
  "health",
  "sessions",
  "sessions.patch",
  "sessions.clear",
  "config",
  "config.set",
  "config.reload",
  "cron.list",
  "cron.add",
  "cron.remove",
  "nodes.register",
  "nodes.list",
  "nodes.invoke",
  "approvals.pending",
  "approvals.respond",
  // ... more methods
] as const;

export const GATEWAY_EVENTS = [
  "agent.message",
  "agent.tool",
  "agent.thinking",
  "channel.connected",
  "channel.disconnected",
  "health.changed",
  "config.changed",
  // ... more events
] as const;
```

## HTTP Endpoints

### Express Setup

```typescript
// src/gateway/server-http.ts

export function setupHttpEndpoints(
  app: Express,
  runtimeState: GatewayRuntimeState
) {
  // Health check
  app.get("/health", (req, res) => {
    const health = getHealthSnapshot(runtimeState);
    res.json(health);
  });

  // Control UI (browser dashboard)
  if (runtimeState.config.gateway?.controlUi?.enabled !== false) {
    app.use("/ui", express.static(CONTROL_UI_PATH));
  }

  // WebChat interface
  app.use("/chat", express.static(WEBCHAT_PATH));

  // OpenAI-compatible chat completions
  if (runtimeState.config.gateway?.http?.endpoints?.chatCompletions?.enabled) {
    app.post("/v1/chat/completions", async (req, res) => {
      await handleChatCompletions(req, res, runtimeState);
    });
  }

  // Plugin HTTP routes
  for (const plugin of runtimeState.plugins) {
    if (plugin.httpRoutes) {
      app.use(plugin.httpRoutes);
    }
  }

  // WebSocket upgrade handling
  app.on("upgrade", (req, socket, head) => {
    runtimeState.wss.handleUpgrade(req, socket, head, (ws) => {
      runtimeState.wss.emit("connection", ws, req);
    });
  });
}
```

## Channel Management

### Channel Manager: `src/gateway/server-channels.ts`

```typescript
// src/gateway/server-channels.ts

export async function createChannelManager(opts: {
  config: OpenClawConfig;
  logger: Logger;
}): Promise<ChannelManager> {
  const { config, logger } = opts;

  // Track active channel monitors
  const monitors = new Map<ChannelId, ChannelMonitor>();

  // Start configured channels
  for (const channelId of listConfiguredChannels(config)) {
    const plugin = getChannelPlugin(channelId);
    if (!plugin) continue;

    const monitor = await startChannelMonitor({
      channelId,
      plugin,
      config,
      logger: logger.child(channelId),
      onMessage: (message) => {
        // Route to agent
        handleInboundMessage(message);
      },
    });

    monitors.set(channelId, monitor);
  }

  return {
    monitors,
    getMonitor: (id) => monitors.get(id),
    stopChannel: async (id) => {
      const monitor = monitors.get(id);
      if (monitor) {
        await monitor.stop();
        monitors.delete(id);
      }
    },
    restartChannel: async (id) => {
      await this.stopChannel(id);
      // Re-start logic...
    },
  };
}
```

## Inbound Message Handling

### Chat Handler: `src/gateway/server-chat.ts`

```typescript
// src/gateway/server-chat.ts

export function createAgentEventHandler(
  runtimeState: GatewayRuntimeState
) {
  return async function handleAgentEvent(event: InboundEvent) {
    const { channel, accountId, peer, message, media } = event;

    // 1. Resolve routing
    const route = resolveAgentRoute({
      cfg: runtimeState.config,
      channel,
      accountId,
      peer,
    });

    // 2. Check security (allowlists, DM policies)
    const allowed = await checkInboundSecurity({
      channel,
      peer,
      config: runtimeState.config,
    });

    if (!allowed) {
      // Silently ignore unauthorized messages
      return;
    }

    // 3. Create or retrieve session
    const session = await getOrCreateSession({
      sessionKey: route.sessionKey,
      agentId: route.agentId,
    });

    // 4. Build inbound context
    const inboundContext = await finalizeInboundContext({
      message,
      media,
      peer,
      channel,
      session,
    });

    // 5. Dispatch to agent
    const response = await dispatchReplyFromConfig({
      context: inboundContext,
      config: runtimeState.config,
      agentId: route.agentId,
    });

    // 6. Deliver response
    if (response) {
      await deliverOutbound({
        channel,
        to: peer.id,
        message: response,
      });
    }
  };
}
```

## Core Services

### Cron Service: `src/gateway/server-cron.ts`

```typescript
// src/gateway/server-cron.ts

export function buildGatewayCronService(opts: {
  config: OpenClawConfig;
  logger: Logger;
}) {
  const jobs = new Map<string, CronJob>();

  return {
    async addJob(spec: CronJobSpec) {
      const job = new CronJob({
        cronTime: spec.schedule,
        onTick: async () => {
          await runCronJob(spec);
        },
        start: true,
      });
      jobs.set(spec.id, job);
    },

    async removeJob(id: string) {
      const job = jobs.get(id);
      if (job) {
        job.stop();
        jobs.delete(id);
      }
    },

    listJobs() {
      return Array.from(jobs.keys()).map((id) => ({
        id,
        running: jobs.get(id)?.running,
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
```

### Node Registry: `src/gateway/node-registry.ts`

```typescript
// src/gateway/node-registry.ts

export class NodeRegistry {
  private nodes = new Map<string, RegisteredNode>();

  register(node: NodeRegistration): string {
    const id = generateNodeId();
    this.nodes.set(id, {
      ...node,
      id,
      connectedAt: Date.now(),
      lastHeartbeat: Date.now(),
    });
    return id;
  }

  heartbeat(id: string) {
    const node = this.nodes.get(id);
    if (node) {
      node.lastHeartbeat = Date.now();
    }
  }

  unregister(id: string) {
    this.nodes.delete(id);
  }

  list(): RegisteredNode[] {
    return Array.from(this.nodes.values());
  }

  getByType(type: NodeType): RegisteredNode[] {
    return this.list().filter((n) => n.type === type);
  }
}
```

### Exec Approval Manager: `src/gateway/exec-approval-manager.ts`

```typescript
// src/gateway/exec-approval-manager.ts

export class ExecApprovalManager {
  private pending = new Map<string, PendingApproval>();
  private listeners = new Set<ApprovalListener>();

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResult> {
    const id = generateApprovalId();

    // Create pending approval
    const pending: PendingApproval = {
      id,
      request,
      createdAt: Date.now(),
      resolve: null,
      reject: null,
    };

    // Create promise that waits for response
    const promise = new Promise<ApprovalResult>((resolve, reject) => {
      pending.resolve = resolve;
      pending.reject = reject;
    });

    this.pending.set(id, pending);

    // Notify listeners (UI clients)
    for (const listener of this.listeners) {
      listener.onApprovalRequested(pending);
    }

    // Wait for response with timeout
    const result = await Promise.race([
      promise,
      timeout(request.timeoutMs).then(() => ({ approved: false, timedOut: true })),
    ]);

    this.pending.delete(id);
    return result;
  }

  respond(id: string, approved: boolean) {
    const pending = this.pending.get(id);
    if (pending?.resolve) {
      pending.resolve({ approved });
    }
  }

  listPending(): PendingApproval[] {
    return Array.from(this.pending.values());
  }
}
```

## Health & Presence

### Health State: `src/gateway/server/health-state.ts`

```typescript
// src/gateway/server/health-state.ts

let healthVersion = 0;
let presenceVersion = 0;
let healthCache: HealthSnapshot | null = null;

export function incrementPresenceVersion() {
  presenceVersion++;
}

export function getPresenceVersion(): number {
  return presenceVersion;
}

export function getHealthVersion(): number {
  return healthVersion;
}

export async function refreshGatewayHealthSnapshot(
  runtimeState: GatewayRuntimeState
): Promise<HealthSnapshot> {
  const channels = await probeChannelHealth(runtimeState.channelManager);
  const nodes = runtimeState.nodeRegistry.list().map(nodeToHealthEntry);
  const cron = runtimeState.cronService.listJobs();

  healthCache = {
    version: ++healthVersion,
    timestamp: Date.now(),
    channels,
    nodes,
    cron,
    uptime: process.uptime(),
  };

  return healthCache;
}

export function getHealthCache(): HealthSnapshot | null {
  return healthCache;
}
```

## Graceful Shutdown

### Close Handler: `src/gateway/server-close.ts`

```typescript
// src/gateway/server-close.ts

export function createGatewayCloseHandler(
  runtimeState: GatewayRuntimeState
) {
  return async function close(opts?: {
    reason?: string;
    restartExpectedMs?: number | null;
  }) {
    const { reason = "shutdown", restartExpectedMs = null } = opts ?? {};

    // 1. Stop accepting new connections
    runtimeState.wss.close();

    // 2. Notify connected clients
    for (const client of runtimeState.wss.clients) {
      client.send(JSON.stringify({
        event: "gateway.closing",
        data: { reason, restartExpectedMs },
      }));
      client.close();
    }

    // 3. Stop cron service
    runtimeState.cronService.stopAll();

    // 4. Stop channel monitors
    await runtimeState.channelManager.stopAll();

    // 5. Stop sidecars
    await stopGatewaySidecars(runtimeState);

    // 6. Close HTTP server
    await new Promise<void>((resolve) => {
      runtimeState.httpServer.close(() => resolve());
    });

    // 7. Cleanup
    stopDiagnosticHeartbeat();
  };
}
```

## Configuration Reloading

### Config Reload: `src/gateway/config-reload.ts`

```typescript
// src/gateway/config-reload.ts

export function startGatewayConfigReloader(
  runtimeState: GatewayRuntimeState
) {
  // Watch config file for changes
  const watcher = watch(CONFIG_PATH, async () => {
    try {
      // Reload config
      const newConfig = await loadConfig();

      // Validate
      const validation = validateConfigObject(newConfig);
      if (!validation.success) {
        console.error("Config validation failed:", validation.errors);
        return;
      }

      // Apply changes
      await applyConfigChanges(runtimeState, newConfig);

      // Update runtime state
      runtimeState.config = newConfig;

      // Notify clients
      broadcastEvent(runtimeState, "config.changed", {
        timestamp: Date.now(),
      });
    } catch (error) {
      console.error("Config reload failed:", error);
    }
  });

  return () => watcher.close();
}
```

## Exploration Exercises

1. **Start the Gateway**: Run `openclaw gateway run --verbose` and observe the startup logs.

2. **Connect via WebSocket**: Use a WebSocket client to connect to `ws://localhost:18789` and send a status request.

3. **Explore methods**: Look at `src/gateway/server-methods/` to see all available RPC methods.

4. **Add a custom method**: Create a simple "ping" method that returns "pong".

5. **Monitor health**: Watch how `health-state.ts` tracks channel and node health.

## Next Steps

In the next tutorial, we'll explore [Messaging Channels](./04-channels.md) - how OpenClaw connects to different messaging platforms.
