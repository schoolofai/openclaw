# OpenClaw Architecture Tutorial Series

Welcome to the OpenClaw codebase tutorial series! This comprehensive guide is designed for junior engineers who want to understand the end-to-end architecture and software components of OpenClaw.

## What is OpenClaw?

OpenClaw is a personal AI assistant that you run on your own devices. It connects to messaging channels (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, and more) and provides a Gateway control plane with CLI, web UI, and mobile/macOS app integration.

## Tutorial Structure

This series is organized into progressive modules that build upon each other:

| # | Module | Description |
|---|--------|-------------|
| 01 | [Introduction](./01-introduction.md) | Project overview, directory structure, and key concepts |
| 02 | [CLI Architecture](./02-cli-architecture.md) | Entry points, command registration, and Commander.js integration |
| 03 | [Gateway Server](./03-gateway.md) | WebSocket control plane, HTTP endpoints, and server lifecycle |
| 04 | [Messaging Channels](./04-channels.md) | Channel abstraction, core channels, and plugin system |
| 05 | [Agent System](./05-agent-system.md) | AI agent runtime, sessions, tools, and model selection |
| 06 | [Routing](./06-routing.md) | Session keys, agent routing, and binding configuration |
| 07 | [Infrastructure](./07-infrastructure.md) | Outbound delivery, media pipeline, and safety gates |
| 08 | [Configuration](./08-configuration.md) | Config types, validation, loading, and runtime overrides |
| 09 | [Plugin System](./09-plugins.md) | Creating plugins, channel adapters, and service providers |
| 10 | [Advanced Topics](./10-advanced.md) | Hooks, cron jobs, memory systems, and extensions |

## Prerequisites

Before diving in, you should have:

- Basic understanding of TypeScript and Node.js
- Familiarity with async/await patterns
- Understanding of WebSocket communication
- Basic knowledge of CLI tools

## Key Technologies

OpenClaw uses these core technologies:

- **TypeScript** - Primary language (ESM modules)
- **Node.js 22+** - Runtime environment
- **Commander.js** - CLI framework
- **WebSocket (ws)** - Real-time communication
- **Zod** - Schema validation
- **pnpm** - Package management
- **Vitest** - Testing framework

## Architecture Overview

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    Messaging Channels                    │
                    │  WhatsApp | Telegram | Discord | Slack | Signal | iMessage│
                    │  + Extensions: Teams | Matrix | Mattermost | Zalo | LINE │
                    └────────────────────────┬────────────────────────────────┘
                                             │
                                             ▼
                            ┌────────────────────────────────┐
                            │     Gateway WebSocket           │
                            │  (Control Plane, Port 18789)    │
                            └────────────────────────────────┘
                             │          │          │          │
                        ┌────┴────┬─────┴────┬─────┴────┬────┴────┐
                        ▼         ▼          ▼          ▼         ▼
                     Pi Agent   CLI       WebChat     macOS     iOS/Android
                     (RPC)    (Commands)   (UI)       App       Nodes
```

## Getting Started

1. Clone the repository
2. Install dependencies: `pnpm install`
3. Build the project: `pnpm build`
4. Start reading from [01-introduction.md](./01-introduction.md)

## How to Use This Guide

Each tutorial includes:

- **Conceptual explanations** - Understanding the "why"
- **Code examples** - Real code from the codebase with file paths
- **Diagrams** - Visual representations of data flow
- **Exercises** - Suggested exploration tasks

Happy learning!
