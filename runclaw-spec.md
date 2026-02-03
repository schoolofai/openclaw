# RunClaw.io — Technical Specification

## Overview

RunClaw.io is a managed hosting platform for OpenClaw, the open-source personal AI agent. Users subscribe, we provision a hardened VPS with OpenClaw pre-configured, and they access it via `username.runclaw.io`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      RunClaw.io                            │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Next.js 14 (Vercel)                       │ │
│  │                                                        │ │
│  │  Routes:                                               │ │
│  │  • /                     Landing page                  │ │
│  │  • /dashboard            User dashboard                │ │
│  │  • /api/instances/*      Instance management           │ │
│  │  • /api/stripe/*         Payment webhooks              │ │
│  │  • /api/cron/*           Scheduled jobs                │ │
│  └────────────────────────────────────────────────────────┘ │
│                            │                                 │
│              ┌─────────────┴─────────────┐                  │
│              ▼                           ▼                  │
│  ┌────────────────────┐      ┌────────────────────┐        │
│  │     Appwrite       │      │      Stripe        │        │
│  │     Cloud          │      │                    │        │
│  │                    │      │  • Subscriptions   │        │
│  │  • Authentication  │      │  • Payment events  │        │
│  │  • Database        │      │  • Customer portal │        │
│  │  • Permissions     │      │                    │        │
│  └────────────────────┘      └────────────────────┘        │
│                                                              │
└──────────────────────────────┬──────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   Hetzner    │  │  Cloudflare  │  │   Customer   │
    │   Cloud API  │  │     API      │  │     VPS      │
    │              │  │              │  │  Instances   │
    │  • Create    │  │  • DNS CNAME │  │              │
    │  • Delete    │  │  • Wildcard  │  │  • OpenClaw  │
    │  • List      │  │    SSL       │  │  • Caddy     │
    └──────────────┘  └──────────────┘  └──────────────┘
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | Next.js 14 + Tailwind + shadcn/ui | Landing, dashboard, API |
| Hosting | Vercel | Zero-config deployment, cron jobs |
| Database | Appwrite Cloud (Documents) | Users, instances, events |
| Auth | Appwrite Auth | Email/password, OAuth, magic links |
| Payments | Stripe | Subscriptions, webhooks |
| VPS | Hetzner Cloud | Customer OpenClaw instances |
| DNS | Cloudflare | Wildcard subdomain routing |
| On-VPS | Docker Compose (Caddy + OpenClaw) | Reverse proxy + application |

---

## Appwrite Setup

### Project Structure

```
Appwrite Project: runclaw
├── Database: main
│   ├── Collection: users
│   ├── Collection: instances
│   ├── Collection: webhook_events
│   └── Collection: instance_events
└── Auth: enabled (email/password)
```

### Collection Schemas

#### Collection: users

| Attribute | Type | Required | Default | Notes |
|-----------|------|----------|---------|-------|
| email | string (255) | Yes | - | Unique index |
| stripe_customer_id | string (255) | No | null | Unique index |
| created_at | datetime | Yes | Now | Auto-set |
| updated_at | datetime | Yes | Now | Update on change |

**Indexes:**
- `email_unique` - Unique on `email`
- `stripe_customer_unique` - Unique on `stripe_customer_id`

**Permissions:**
```
Read:  user:{userId}
Write: user:{userId}
```

#### Collection: instances

| Attribute | Type | Required | Default | Notes |
|-----------|------|----------|---------|-------|
| user_id | string (36) | Yes | - | Reference to user |
| subdomain | string (63) | Yes | - | Unique index |
| hetzner_server_id | integer | No | null | |
| ip_address | string (45) | No | null | IPv4 or IPv6 |
| region | string (10) | Yes | "fsn1" | |
| server_type | string (10) | Yes | "cx22" | |
| status | enum | Yes | "provisioning" | See values below |
| status_message | string (500) | No | null | |
| stripe_subscription_id | string (255) | No | null | |
| plan | enum | Yes | "starter" | starter, pro, dedicated |
| provision_started_at | datetime | Yes | Now | |
| provision_completed_at | datetime | No | null | |
| callback_secret | string (64) | Yes | - | |
| last_health_check_at | datetime | No | null | |
| created_at | datetime | Yes | Now | |
| updated_at | datetime | Yes | Now | |

**Status enum values:** `provisioning`, `running`, `unhealthy`, `stopped`, `failed`, `deleting`

**Indexes:**
- `subdomain_unique` - Unique on `subdomain`
- `user_id_idx` - Key on `user_id`
- `status_idx` - Key on `status`
- `stripe_sub_idx` - Key on `stripe_subscription_id`

**Permissions:**
```
Read:  user:{user_id}
Write: user:{user_id}
```

#### Collection: webhook_events

| Attribute | Type | Required | Default | Notes |
|-----------|------|----------|---------|-------|
| stripe_event_id | string (255) | Yes | - | Unique index |
| event_type | string (100) | Yes | - | |
| processed_at | datetime | Yes | Now | |
| payload | string (16000) | No | null | JSON string |
| success | boolean | Yes | false | |
| error_message | string (1000) | No | null | |
| created_at | datetime | Yes | Now | |

**Indexes:**
- `stripe_event_unique` - Unique on `stripe_event_id`

**Permissions:**
```
Read:  team:admins
Write: team:admins
```
(Server-side only via API key)

#### Collection: instance_events

| Attribute | Type | Required | Default | Notes |
|-----------|------|----------|---------|-------|
| instance_id | string (36) | Yes | - | Reference |
| event_type | string (50) | Yes | - | |
| details | string (5000) | No | null | JSON string |
| created_at | datetime | Yes | Now | |

**Event types:** `created`, `provisioning_started`, `provisioning_completed`, `provisioning_failed`, `health_check_passed`, `health_check_failed`, `stopped`, `started`, `deleted`, `subscription_cancelled`

**Indexes:**
- `instance_id_idx` - Key on `instance_id`
- `created_at_idx` - Key on `created_at`

**Permissions:**
```
Read:  user:{document.instance.user_id}  // Via relationship or server-side
Write: team:admins
```

---

## Appwrite SDK Setup

### Installation

```bash
npm install appwrite node-appwrite
```

### Client Configuration (Browser)

```typescript
// lib/appwrite/client.ts
import { Client, Account, Databases } from 'appwrite'

const client = new Client()
  .setEndpoint(process.env.NEXT_PUBLIC_APPWRITE_ENDPOINT!)  // https://cloud.appwrite.io/v1
  .setProject(process.env.NEXT_PUBLIC_APPWRITE_PROJECT_ID!)

export const account = new Account(client)
export const databases = new Databases(client)

export const DATABASE_ID = process.env.NEXT_PUBLIC_APPWRITE_DATABASE_ID!

export const COLLECTIONS = {
  USERS: 'users',
  INSTANCES: 'instances',
  WEBHOOK_EVENTS: 'webhook_events',
  INSTANCE_EVENTS: 'instance_events'
} as const
```

### Server Configuration (API Routes)

```typescript
// lib/appwrite/server.ts
import { Client, Databases, Users, Query } from 'node-appwrite'

const client = new Client()
  .setEndpoint(process.env.APPWRITE_ENDPOINT!)
  .setProject(process.env.APPWRITE_PROJECT_ID!)
  .setKey(process.env.APPWRITE_API_KEY!)  // Server API key with full permissions

export const databases = new Databases(client)
export const users = new Users(client)

export const DATABASE_ID = process.env.APPWRITE_DATABASE_ID!

export const COLLECTIONS = {
  USERS: 'users',
  INSTANCES: 'instances',
  WEBHOOK_EVENTS: 'webhook_events',
  INSTANCE_EVENTS: 'instance_events'
} as const

export { Query }
```

### Authentication Helpers

```typescript
// lib/appwrite/auth.ts
import { account } from './client'
import { ID } from 'appwrite'

export async function signUp(email: string, password: string) {
  // Create auth account
  const authUser = await account.create(ID.unique(), email, password)
  
  // Create session
  await account.createEmailPasswordSession(email, password)
  
  return authUser
}

export async function signIn(email: string, password: string) {
  return account.createEmailPasswordSession(email, password)
}

export async function signOut() {
  return account.deleteSession('current')
}

export async function getCurrentUser() {
  try {
    return await account.get()
  } catch {
    return null
  }
}

export async function getSession() {
  try {
    return await account.getSession('current')
  } catch {
    return null
  }
}
```

### Server-Side Session Verification

```typescript
// lib/appwrite/session.ts
import { Client, Account } from 'node-appwrite'
import { cookies } from 'next/headers'

export async function getServerUser() {
  const sessionCookie = cookies().get('a_session_' + process.env.APPWRITE_PROJECT_ID!)
  
  if (!sessionCookie) return null
  
  const client = new Client()
    .setEndpoint(process.env.APPWRITE_ENDPOINT!)
    .setProject(process.env.APPWRITE_PROJECT_ID!)
    .setSession(sessionCookie.value)
  
  const account = new Account(client)
  
  try {
    return await account.get()
  } catch {
    return null
  }
}
```

---

## API Routes Specification

### Overview

| Route | Method | Purpose | Auth Required |
|-------|--------|---------|---------------|
| `/api/instances/create` | POST | Create new instance | Yes |
| `/api/instances/delete` | POST | Delete instance | Yes |
| `/api/instances/ready` | POST | Callback from VPS | No (secret) |
| `/api/instances/list` | GET | List user's instances | Yes |
| `/api/stripe/webhook` | POST | Stripe event handler | No (signature) |
| `/api/stripe/portal` | POST | Get billing portal URL | Yes |
| `/api/cron/health` | GET | Health check all instances | Vercel Cron |
| `/api/cron/reconcile` | GET | Weekly orphan cleanup | Vercel Cron |
| `/api/cron/provision-timeout` | GET | Timeout stuck provisions | Vercel Cron |

---

### POST /api/instances/create

Creates a new OpenClaw instance for authenticated user.

**Request:**
```typescript
{
  subdomain: string,  // 3-20 chars, alphanumeric + hyphens
  plan: "starter" | "pro" | "dedicated",
  region?: "fsn1" | "nbg1" | "hel1" | "ash"  // default: fsn1
}
```

**Response (Success - 201):**
```typescript
{
  success: true,
  instance: {
    id: string,
    subdomain: string,
    status: "provisioning",
    url: string,  // "https://subdomain.runclaw.io"
    estimated_ready: string  // ISO timestamp, ~3 min from now
  }
}
```

**Response (Error - 400/402/409):**
```typescript
{
  success: false,
  error: {
    code: "INVALID_SUBDOMAIN" | "SUBDOMAIN_TAKEN" | "NO_ACTIVE_SUBSCRIPTION" | "INSTANCE_LIMIT_REACHED",
    message: string
  }
}
```

**Flow:**
```
1. Validate subdomain (format, uniqueness, reserved words)
2. Verify user has active Stripe subscription
3. Check instance limit for plan
4. Generate callback_secret (32 char random)
5. Create instance record (status: provisioning)
6. Call Hetzner API to create server with cloud-init
7. Call Cloudflare API to create DNS record
8. Update instance with hetzner_server_id and ip_address
9. Log instance_event: created
10. Return instance details
```

**Subdomain Validation Rules:**
- Length: 3-20 characters
- Characters: lowercase alphanumeric and hyphens
- Cannot start or end with hyphen
- Cannot be reserved words: www, api, app, admin, dashboard, mail, ftp, ssh, etc.

**Code Example:**
```typescript
// app/api/instances/create/route.ts
import { databases, DATABASE_ID, COLLECTIONS, Query } from '@/lib/appwrite/server'
import { getServerUser } from '@/lib/appwrite/session'
import { createServer } from '@/lib/hetzner'
import { createDnsRecord } from '@/lib/cloudflare'
import { generateCloudInit } from '@/lib/cloud-init'
import { ID } from 'node-appwrite'
import crypto from 'crypto'

export async function POST(req: Request) {
  const user = await getServerUser()
  if (!user) {
    return Response.json({ success: false, error: { code: 'UNAUTHORIZED' } }, { status: 401 })
  }
  
  const { subdomain, plan = 'starter', region = 'fsn1' } = await req.json()
  
  // Validate subdomain
  if (!isValidSubdomain(subdomain)) {
    return Response.json({ 
      success: false, 
      error: { code: 'INVALID_SUBDOMAIN', message: 'Invalid subdomain format' } 
    }, { status: 400 })
  }
  
  // Check if subdomain taken
  const existing = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    [Query.equal('subdomain', subdomain)]
  )
  
  if (existing.total > 0) {
    return Response.json({ 
      success: false, 
      error: { code: 'SUBDOMAIN_TAKEN', message: 'Subdomain already in use' } 
    }, { status: 409 })
  }
  
  // Generate callback secret
  const callbackSecret = crypto.randomBytes(32).toString('hex')
  const instanceId = ID.unique()
  
  // Create instance document
  const instance = await databases.createDocument(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    instanceId,
    {
      user_id: user.$id,
      subdomain,
      status: 'provisioning',
      plan,
      region,
      server_type: planToServerType(plan),
      callback_secret: callbackSecret,
      provision_started_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }
  )
  
  try {
    // Create Hetzner server
    const { serverId, ipAddress } = await createServer(
      subdomain,
      callbackSecret,
      instanceId,
      planToServerType(plan),
      region
    )
    
    // Create DNS record
    await createDnsRecord(subdomain, ipAddress)
    
    // Update instance with server details
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTIONS.INSTANCES,
      instanceId,
      {
        hetzner_server_id: serverId,
        ip_address: ipAddress,
        updated_at: new Date().toISOString()
      }
    )
    
    // Log event
    await databases.createDocument(
      DATABASE_ID,
      COLLECTIONS.INSTANCE_EVENTS,
      ID.unique(),
      {
        instance_id: instanceId,
        event_type: 'created',
        details: JSON.stringify({ plan, region }),
        created_at: new Date().toISOString()
      }
    )
    
    return Response.json({
      success: true,
      instance: {
        id: instanceId,
        subdomain,
        status: 'provisioning',
        url: `https://${subdomain}.runclaw.io`,
        estimated_ready: new Date(Date.now() + 3 * 60 * 1000).toISOString()
      }
    }, { status: 201 })
    
  } catch (err) {
    // Cleanup on failure
    await databases.deleteDocument(DATABASE_ID, COLLECTIONS.INSTANCES, instanceId)
    throw err
  }
}
```

---

### POST /api/instances/delete

Deletes an instance and associated resources.

**Request:**
```typescript
{
  instance_id: string
}
```

**Response (Success - 200):**
```typescript
{
  success: true,
  message: "Instance scheduled for deletion"
}
```

**Flow:**
```
1. Verify instance belongs to authenticated user
2. Update instance status to "deleting"
3. Call Hetzner API to delete server
4. Call Cloudflare API to delete DNS record
5. Delete instance record from database
6. Log instance_event: deleted
```

---

### POST /api/instances/ready

Webhook called by VPS when OpenClaw is ready. Not authenticated via user session — uses shared secret.

**Request:**
```typescript
{
  instance_id: string,
  callback_secret: string,
  openclaw_version?: string
}
```

**Response (Success - 200):**
```typescript
{
  success: true
}
```

**Flow:**
```
1. Find instance by ID
2. Verify callback_secret matches
3. Verify instance status is "provisioning"
4. Update instance:
   - status: "running"
   - provision_completed_at: NOW()
   - last_health_check_at: NOW()
5. Log instance_event: provisioning_completed
```

**Security Notes:**
- callback_secret is generated per-instance, 32 random characters
- Secret is embedded in cloud-init, never exposed to user
- One-time use: after status changes from "provisioning", callback is rejected

**Code Example:**
```typescript
// app/api/instances/ready/route.ts
import { databases, DATABASE_ID, COLLECTIONS } from '@/lib/appwrite/server'
import { ID } from 'node-appwrite'

export async function POST(req: Request) {
  const { instance_id, callback_secret, openclaw_version } = await req.json()
  
  // Find instance
  let instance
  try {
    instance = await databases.getDocument(
      DATABASE_ID,
      COLLECTIONS.INSTANCES,
      instance_id
    )
  } catch {
    return Response.json({ success: false, error: 'Instance not found' }, { status: 404 })
  }
  
  // Verify secret
  if (instance.callback_secret !== callback_secret) {
    return Response.json({ success: false, error: 'Invalid secret' }, { status: 403 })
  }
  
  // Verify status
  if (instance.status !== 'provisioning') {
    return Response.json({ success: false, error: 'Invalid status' }, { status: 400 })
  }
  
  // Update instance
  const now = new Date().toISOString()
  await databases.updateDocument(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    instance_id,
    {
      status: 'running',
      provision_completed_at: now,
      last_health_check_at: now,
      updated_at: now
    }
  )
  
  // Log event
  await databases.createDocument(
    DATABASE_ID,
    COLLECTIONS.INSTANCE_EVENTS,
    ID.unique(),
    {
      instance_id,
      event_type: 'provisioning_completed',
      details: JSON.stringify({ openclaw_version }),
      created_at: now
    }
  )
  
  return Response.json({ success: true })
}
```

---

### GET /api/instances/list

Returns all instances for authenticated user.

**Response (Success - 200):**
```typescript
{
  instances: [
    {
      id: string,
      subdomain: string,
      url: string,
      status: "provisioning" | "running" | "unhealthy" | "stopped" | "failed",
      status_message?: string,
      plan: string,
      region: string,
      ip_address?: string,
      created_at: string,
      last_health_check_at?: string
    }
  ]
}
```

**Code Example:**
```typescript
// app/api/instances/list/route.ts
import { databases, DATABASE_ID, COLLECTIONS, Query } from '@/lib/appwrite/server'
import { getServerUser } from '@/lib/appwrite/session'

export async function GET() {
  const user = await getServerUser()
  if (!user) {
    return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 })
  }
  
  const result = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    [Query.equal('user_id', user.$id)]
  )
  
  const instances = result.documents.map(doc => ({
    id: doc.$id,
    subdomain: doc.subdomain,
    url: `https://${doc.subdomain}.runclaw.io`,
    status: doc.status,
    status_message: doc.status_message,
    plan: doc.plan,
    region: doc.region,
    ip_address: doc.ip_address,
    created_at: doc.created_at,
    last_health_check_at: doc.last_health_check_at
  }))
  
  return Response.json({ instances })
}
```

---

### POST /api/stripe/webhook

Handles Stripe webhook events with idempotency protection.

**Headers:**
```
Stripe-Signature: t=...,v1=...
```

**Handled Events:**

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Link Stripe customer to user, mark subscription active |
| `customer.subscription.updated` | Update instance plan if changed |
| `customer.subscription.deleted` | Stop and delete associated instance |
| `invoice.payment_failed` | Mark instance as "payment_failed", send warning |
| `invoice.payment_succeeded` | Clear any payment_failed status |

**Idempotency Flow:**
```
1. Extract Stripe-Signature header
2. Verify webhook signature using Stripe SDK
3. Extract event.id from payload
4. Check webhook_events collection for existing event.id
5. If exists: return 200 immediately (already processed)
6. If not exists: 
   a. Insert into webhook_events (stripe_event_id, event_type, payload)
   b. Process the event
   c. Update webhook_events with success/error status
7. Return 200 (Stripe expects 200 even on processing errors)
```

**Code Example:**
```typescript
// app/api/stripe/webhook/route.ts
import Stripe from 'stripe'
import { databases, DATABASE_ID, COLLECTIONS, Query } from '@/lib/appwrite/server'
import { ID } from 'node-appwrite'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const body = await req.text()
  const signature = req.headers.get('stripe-signature')!
  
  // Verify signature
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    )
  } catch (err) {
    return new Response('Invalid signature', { status: 400 })
  }
  
  // Idempotency check
  const existing = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.WEBHOOK_EVENTS,
    [Query.equal('stripe_event_id', event.id)]
  )
  
  if (existing.total > 0) {
    // Already processed
    return new Response('OK', { status: 200 })
  }
  
  // Record event before processing
  const webhookEventId = ID.unique()
  await databases.createDocument(
    DATABASE_ID,
    COLLECTIONS.WEBHOOK_EVENTS,
    webhookEventId,
    {
      stripe_event_id: event.id,
      event_type: event.type,
      payload: JSON.stringify(event.data.object),
      success: false,
      processed_at: new Date().toISOString(),
      created_at: new Date().toISOString()
    }
  )
  
  try {
    // Process based on event type
    switch (event.type) {
      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(event.data.object as Stripe.Subscription)
        break
      case 'invoice.payment_failed':
        await handlePaymentFailed(event.data.object as Stripe.Invoice)
        break
      // ... other handlers
    }
    
    // Mark as successful
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTIONS.WEBHOOK_EVENTS,
      webhookEventId,
      { success: true }
    )
      
  } catch (err) {
    // Log error but still return 200
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTIONS.WEBHOOK_EVENTS,
      webhookEventId,
      { 
        success: false, 
        error_message: err instanceof Error ? err.message : 'Unknown error'
      }
    )
  }
  
  return new Response('OK', { status: 200 })
}

async function handleSubscriptionDeleted(subscription: Stripe.Subscription) {
  // Find instance linked to this subscription
  const result = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    [Query.equal('stripe_subscription_id', subscription.id)]
  )
  
  if (result.total === 0) return
  
  const instance = result.documents[0]
  
  // Delete the instance
  await deleteInstance(instance.$id)
}

async function handlePaymentFailed(invoice: Stripe.Invoice) {
  // Find instance and mark as payment failed
  // Implementation here
}
```

---

### GET /api/cron/health

Runs every 5 minutes via Vercel Cron. Checks health of all running instances.

**vercel.json:**
```json
{
  "crons": [
    {
      "path": "/api/cron/health",
      "schedule": "*/5 * * * *"
    }
  ]
}
```

**Flow:**
```
1. Query all instances where status = "running"
2. For each instance (in parallel, max 10 concurrent):
   a. Fetch https://{subdomain}.runclaw.io/health with 5s timeout
   b. If success (200):
      - Update last_health_check_at
      - If was "unhealthy", change to "running"
   c. If failure:
      - Increment failure counter (store in DB)
      - If 3+ consecutive failures:
        - Update status to "unhealthy"
        - Log instance_event: health_check_failed
        - (Optional) Email user
```

**Code Example:**
```typescript
// app/api/cron/health/route.ts
import { databases, DATABASE_ID, COLLECTIONS, Query } from '@/lib/appwrite/server'
import { ID } from 'node-appwrite'

export async function GET(req: Request) {
  // Verify this is from Vercel Cron
  const authHeader = req.headers.get('authorization')
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 })
  }
  
  const result = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    [Query.equal('status', 'running')]
  )
  
  const instances = result.documents
  
  const results = await Promise.allSettled(
    instances.map(instance => checkHealth(instance))
  )
  
  const healthy = results.filter(r => r.status === 'fulfilled' && r.value).length
  const unhealthy = results.length - healthy
  
  return Response.json({ 
    checked: results.length,
    healthy,
    unhealthy
  })
}

async function checkHealth(instance: any): Promise<boolean> {
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 5000)
    
    const res = await fetch(
      `https://${instance.subdomain}.runclaw.io/health`,
      { signal: controller.signal }
    )
    
    clearTimeout(timeout)
    
    if (res.ok) {
      await databases.updateDocument(
        DATABASE_ID,
        COLLECTIONS.INSTANCES,
        instance.$id,
        { 
          last_health_check_at: new Date().toISOString(),
          status: 'running',  // Recover from unhealthy if needed
          updated_at: new Date().toISOString()
        }
      )
      return true
    }
  } catch (err) {
    // Timeout or network error
  }
  
  // Track consecutive failures
  await databases.createDocument(
    DATABASE_ID,
    COLLECTIONS.INSTANCE_EVENTS,
    ID.unique(),
    {
      instance_id: instance.$id,
      event_type: 'health_check_failed',
      details: JSON.stringify({ timestamp: new Date().toISOString() }),
      created_at: new Date().toISOString()
    }
  )
  
  // Check if 3+ recent failures (last 15 minutes)
  const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString()
  const failures = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCE_EVENTS,
    [
      Query.equal('instance_id', instance.$id),
      Query.equal('event_type', 'health_check_failed'),
      Query.greaterThan('created_at', fifteenMinutesAgo)
    ]
  )
  
  if (failures.total >= 3) {
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTIONS.INSTANCES,
      instance.$id,
      { 
        status: 'unhealthy',
        updated_at: new Date().toISOString()
      }
    )
  }
  
  return false
}
```

---

### GET /api/cron/provision-timeout

Runs every 10 minutes. Handles instances stuck in "provisioning" state.

**vercel.json:**
```json
{
  "crons": [
    {
      "path": "/api/cron/provision-timeout",
      "schedule": "*/10 * * * *"
    }
  ]
}
```

**Logic:**
```
1. Find instances where:
   - status = "provisioning"
   - provision_started_at < NOW() - 10 minutes
2. For each stuck instance:
   a. Update status to "failed"
   b. Set status_message: "Provisioning timed out"
   c. Log instance_event: provisioning_failed
   d. Delete Hetzner server (cleanup)
   e. Delete Cloudflare DNS record
   f. (Optional) Email user: "Something went wrong, please try again"
```

**Code Example:**
```typescript
// app/api/cron/provision-timeout/route.ts
import { databases, DATABASE_ID, COLLECTIONS, Query } from '@/lib/appwrite/server'
import { deleteServer } from '@/lib/hetzner'
import { deleteDnsRecord } from '@/lib/cloudflare'
import { ID } from 'node-appwrite'

export async function GET(req: Request) {
  const authHeader = req.headers.get('authorization')
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 })
  }
  
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString()
  
  const result = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    [
      Query.equal('status', 'provisioning'),
      Query.lessThan('provision_started_at', tenMinutesAgo)
    ]
  )
  
  const stuckInstances = result.documents
  
  if (stuckInstances.length === 0) {
    return Response.json({ timedOut: 0 })
  }
  
  for (const instance of stuckInstances) {
    // Mark as failed
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTIONS.INSTANCES,
      instance.$id,
      { 
        status: 'failed',
        status_message: 'Provisioning timed out after 10 minutes',
        updated_at: new Date().toISOString()
      }
    )
    
    // Log event
    await databases.createDocument(
      DATABASE_ID,
      COLLECTIONS.INSTANCE_EVENTS,
      ID.unique(),
      {
        instance_id: instance.$id,
        event_type: 'provisioning_failed',
        details: JSON.stringify({ reason: 'timeout' }),
        created_at: new Date().toISOString()
      }
    )
    
    // Cleanup Hetzner
    if (instance.hetzner_server_id) {
      try {
        await deleteServer(instance.hetzner_server_id)
      } catch (err) {
        console.error('Failed to delete Hetzner server', err)
      }
    }
    
    // Cleanup Cloudflare
    try {
      await deleteDnsRecord(instance.subdomain)
    } catch (err) {
      console.error('Failed to delete DNS record', err)
    }
    
    // TODO: Email user about failure
  }
  
  return Response.json({ timedOut: stuckInstances.length })
}
```

---

### GET /api/cron/reconcile

Runs weekly (Sundays 3am UTC). Finds orphaned resources and cleans up.

**vercel.json:**
```json
{
  "crons": [
    {
      "path": "/api/cron/reconcile",
      "schedule": "0 3 * * 0"
    }
  ]
}
```

**Checks Performed:**

1. **Orphaned Hetzner Servers**
   - Servers exist in Hetzner but no matching instance in DB
   - Or instance exists but subscription is cancelled

2. **Orphaned DNS Records**
   - DNS records in Cloudflare but no matching instance

3. **Orphaned DB Records**
   - Instances in DB marked "running" but Hetzner server doesn't exist

**Flow:**
```
1. Fetch all Hetzner servers with name prefix "claw-"
2. Fetch all instances from DB
3. Fetch all active Stripe subscriptions

For each Hetzner server:
  - If no matching instance in DB → DELETE server (orphan)
  - If matching instance has no active subscription → DELETE (cancelled)
  - Log all actions

For each DB instance with status "running":
  - If no matching Hetzner server → Mark as "failed"
  
Generate report:
  - Servers deleted
  - DNS records deleted
  - Instances marked failed
  - Potential revenue leak prevented
```

**Code Example:**
```typescript
// app/api/cron/reconcile/route.ts
import { databases, DATABASE_ID, COLLECTIONS, Query } from '@/lib/appwrite/server'
import { listServers, deleteServer } from '@/lib/hetzner'
import { deleteDnsRecord } from '@/lib/cloudflare'
import Stripe from 'stripe'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function GET(req: Request) {
  const authHeader = req.headers.get('authorization')
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 })
  }
  
  const report = {
    hetznerServersDeleted: 0,
    dnsRecordsDeleted: 0,
    instancesMarkedFailed: 0,
    errors: [] as string[]
  }
  
  // 1. Get all Hetzner servers
  const hetznerServers = await listServers()
  const clawServers = hetznerServers.filter(s => s.name.startsWith('claw-'))
  
  // 2. Get all DB instances
  const instancesResult = await databases.listDocuments(
    DATABASE_ID,
    COLLECTIONS.INSTANCES,
    [Query.limit(1000)]  // Adjust based on expected scale
  )
  const instances = instancesResult.documents
  
  const instanceByHetznerId = new Map(
    instances.map(i => [i.hetzner_server_id, i])
  )
  
  // 3. Get all active Stripe subscriptions
  const activeSubscriptions = new Set<string>()
  for await (const sub of stripe.subscriptions.list({ status: 'active' })) {
    activeSubscriptions.add(sub.id)
  }
  
  // 4. Find orphaned Hetzner servers
  for (const server of clawServers) {
    const instance = instanceByHetznerId.get(server.id)
    
    const isOrphan = !instance
    const isCancelled = instance && 
      instance.stripe_subscription_id && 
      !activeSubscriptions.has(instance.stripe_subscription_id)
    
    if (isOrphan || isCancelled) {
      try {
        await deleteServer(server.id)
        report.hetznerServersDeleted++
        
        if (instance) {
          // Also delete the DNS record
          try {
            await deleteDnsRecord(instance.subdomain)
            report.dnsRecordsDeleted++
          } catch (err) {
            report.errors.push(`Failed to delete DNS for ${instance.subdomain}: ${err}`)
          }
          
          // Delete the instance document
          await databases.deleteDocument(
            DATABASE_ID,
            COLLECTIONS.INSTANCES,
            instance.$id
          )
        }
      } catch (err) {
        report.errors.push(`Failed to delete server ${server.id}: ${err}`)
      }
    }
  }
  
  // 5. Find DB instances without Hetzner server
  const hetznerServerIds = new Set(clawServers.map(s => s.id))
  
  for (const instance of instances) {
    if (
      instance.status === 'running' && 
      instance.hetzner_server_id &&
      !hetznerServerIds.has(instance.hetzner_server_id)
    ) {
      await databases.updateDocument(
        DATABASE_ID,
        COLLECTIONS.INSTANCES,
        instance.$id,
        { 
          status: 'failed',
          status_message: 'Server not found during reconciliation',
          updated_at: new Date().toISOString()
        }
      )
      
      report.instancesMarkedFailed++
    }
  }
  
  // Log the reconciliation run
  console.log('Reconciliation report:', report)
  
  // TODO: Send report to admin email/Slack
  
  return Response.json(report)
}
```

---

### POST /api/stripe/portal

Returns URL to Stripe Customer Portal for managing subscription.

**Response (Success - 200):**
```typescript
{
  url: string  // Stripe portal URL, redirect user here
}
```

---

## External API Integrations

### Hetzner Cloud API

**Base URL:** `https://api.hetzner.cloud/v1`

**Authentication:** Bearer token in header

**Endpoints Used:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/servers` | POST | Create server |
| `/servers/{id}` | DELETE | Delete server |
| `/servers` | GET | List all servers |

**Create Server Request:**
```typescript
interface CreateServerRequest {
  name: string                    // "claw-{subdomain}"
  server_type: string             // "cx22", "cx32", etc.
  image: string                   // "ubuntu-24.04"
  location: string                // "fsn1", "nbg1", etc.
  user_data: string               // cloud-init script (base64 or plain)
  ssh_keys?: number[]             // Optional: your admin SSH key IDs
  labels?: Record<string, string> // Optional: metadata
}
```

**Create Server Response:**
```typescript
interface CreateServerResponse {
  server: {
    id: number
    name: string
    status: string
    public_net: {
      ipv4: { ip: string }
      ipv6: { ip: string }
    }
    server_type: { name: string }
    datacenter: { name: string }
  }
  action: {
    id: number
    status: string
  }
}
```

**Implementation:**
```typescript
// lib/hetzner.ts

const HETZNER_API = 'https://api.hetzner.cloud/v1'
const HETZNER_TOKEN = process.env.HETZNER_API_TOKEN!

export async function createServer(
  subdomain: string,
  callbackSecret: string,
  instanceId: string,
  serverType: string = 'cx22',
  location: string = 'fsn1'
) {
  const cloudInit = generateCloudInit(subdomain, callbackSecret, instanceId)
  
  const res = await fetch(`${HETZNER_API}/servers`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${HETZNER_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      name: `claw-${subdomain}`,
      server_type: serverType,
      image: 'ubuntu-24.04',
      location: location,
      user_data: cloudInit,
      labels: {
        service: 'runclaw',
        instance_id: instanceId
      }
    })
  })
  
  if (!res.ok) {
    const error = await res.json()
    throw new Error(`Hetzner API error: ${error.error?.message || res.statusText}`)
  }
  
  const data = await res.json()
  
  return {
    serverId: data.server.id,
    ipAddress: data.server.public_net.ipv4.ip
  }
}

export async function deleteServer(serverId: number) {
  const res = await fetch(`${HETZNER_API}/servers/${serverId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${HETZNER_TOKEN}`
    }
  })
  
  if (!res.ok && res.status !== 404) {
    throw new Error(`Failed to delete server: ${res.statusText}`)
  }
}

export async function listServers(): Promise<HetznerServer[]> {
  const res = await fetch(`${HETZNER_API}/servers`, {
    headers: {
      'Authorization': `Bearer ${HETZNER_TOKEN}`
    }
  })
  
  const data = await res.json()
  return data.servers
}
```

---

### Cloudflare API

**Base URL:** `https://api.cloudflare.com/client/v4`

**Authentication:** Bearer token in header

**Endpoints Used:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/zones/{zone_id}/dns_records` | POST | Create DNS record |
| `/zones/{zone_id}/dns_records/{id}` | DELETE | Delete DNS record |
| `/zones/{zone_id}/dns_records` | GET | List DNS records |

**Implementation:**
```typescript
// lib/cloudflare.ts

const CF_API = 'https://api.cloudflare.com/client/v4'
const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN!
const CF_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID!  // Zone for runclaw.io

export async function createDnsRecord(subdomain: string, ipAddress: string) {
  const res = await fetch(`${CF_API}/zones/${CF_ZONE_ID}/dns_records`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CF_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      type: 'A',
      name: `${subdomain}.runclaw.io`,
      content: ipAddress,
      ttl: 300,
      proxied: true  // Enable Cloudflare proxy (DDoS protection, SSL)
    })
  })
  
  if (!res.ok) {
    const error = await res.json()
    throw new Error(`Cloudflare API error: ${error.errors?.[0]?.message || res.statusText}`)
  }
  
  const data = await res.json()
  return data.result.id
}

export async function deleteDnsRecord(subdomain: string) {
  // First, find the record ID
  const listRes = await fetch(
    `${CF_API}/zones/${CF_ZONE_ID}/dns_records?name=${subdomain}.runclaw.io`,
    {
      headers: { 'Authorization': `Bearer ${CF_TOKEN}` }
    }
  )
  
  const listData = await listRes.json()
  const record = listData.result?.[0]
  
  if (!record) return  // Already deleted
  
  // Delete the record
  await fetch(`${CF_API}/zones/${CF_ZONE_ID}/dns_records/${record.id}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${CF_TOKEN}` }
  })
}
```

---

## Cloud-Init Template

This script runs automatically when the VPS boots for the first time.

```yaml
#cloud-config

# ============================================
# SYSTEM SETUP
# ============================================
package_update: true
package_upgrade: true

packages:
  - docker.io
  - docker-compose-v2
  - ufw
  - fail2ban
  - unattended-upgrades

# ============================================
# FILES
# ============================================
write_files:
  # Docker Compose configuration
  - path: /opt/openclaw/docker-compose.yml
    permissions: '0644'
    content: |
      version: "3.8"
      
      services:
        caddy:
          image: caddy:2-alpine
          restart: unless-stopped
          ports:
            - "80:80"
            - "443:443"
          volumes:
            - ./Caddyfile:/etc/caddy/Caddyfile:ro
            - caddy_data:/data
            - caddy_config:/config
          depends_on:
            - openclaw
        
        openclaw:
          image: openclaw/openclaw:latest
          restart: unless-stopped
          volumes:
            - openclaw_data:/app/data
          environment:
            - NODE_ENV=production
      
      volumes:
        caddy_data:
        caddy_config:
        openclaw_data:

  # Caddy reverse proxy config
  - path: /opt/openclaw/Caddyfile
    permissions: '0644'
    content: |
      {SUBDOMAIN}.runclaw.io {
        reverse_proxy openclaw:3000
        
        # Security headers
        header {
          X-Content-Type-Options "nosniff"
          X-Frame-Options "DENY"
          X-XSS-Protection "1; mode=block"
          Referrer-Policy "strict-origin-when-cross-origin"
        }
        
        # Logging
        log {
          output file /data/access.log {
            roll_size 10mb
            roll_keep 5
          }
        }
      }

  # Fail2ban jail config
  - path: /etc/fail2ban/jail.local
    permissions: '0644'
    content: |
      [DEFAULT]
      bantime = 1h
      findtime = 10m
      maxretry = 5
      
      [sshd]
      enabled = true
      port = 22
      filter = sshd
      logpath = /var/log/auth.log
      maxretry = 3
      bantime = 24h

# ============================================
# COMMANDS
# ============================================
runcmd:
  # ---- Firewall ----
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 80/tcp
  - ufw allow 443/tcp
  - ufw allow 22/tcp  # Keep SSH but secured
  - ufw --force enable
  
  # ---- SSH Hardening ----
  - sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  - sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  - sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
  - systemctl restart sshd
  
  # ---- Start Fail2ban ----
  - systemctl enable fail2ban
  - systemctl start fail2ban
  
  # ---- Enable auto-updates ----
  - systemctl enable unattended-upgrades
  - systemctl start unattended-upgrades
  
  # ---- Docker permissions ----
  - systemctl enable docker
  - systemctl start docker
  
  # ---- Start OpenClaw ----
  - cd /opt/openclaw && docker compose pull
  - cd /opt/openclaw && docker compose up -d
  
  # ---- Wait for healthy and callback ----
  - |
    max_attempts=60
    attempt=0
    until curl -sf http://localhost:3000/health > /dev/null 2>&1; do
      attempt=$((attempt + 1))
      if [ $attempt -ge $max_attempts ]; then
        echo "OpenClaw failed to start"
        exit 1
      fi
      sleep 5
    done
    
    curl -X POST https://runclaw.io/api/instances/ready \
      -H "Content-Type: application/json" \
      -d '{
        "instance_id": "{INSTANCE_ID}",
        "callback_secret": "{CALLBACK_SECRET}",
        "openclaw_version": "latest"
      }'
```

**Template Generation:**
```typescript
// lib/cloud-init.ts

export function generateCloudInit(
  subdomain: string,
  callbackSecret: string,
  instanceId: string
): string {
  const template = `... the YAML above ...`
  
  return template
    .replace(/{SUBDOMAIN}/g, subdomain)
    .replace(/{CALLBACK_SECRET}/g, callbackSecret)
    .replace(/{INSTANCE_ID}/g, instanceId)
}
```

---

## Pricing Plans

| Plan | Hetzner Type | Specs | Your Cost | User Price | Margin |
|------|--------------|-------|-----------|------------|--------|
| **Starter** | CX22 | 2 vCPU, 4GB RAM, 40GB SSD | €4.35/mo | $15/mo | ~$10 |
| **Pro** | CX32 | 4 vCPU, 8GB RAM, 80GB SSD | €8.35/mo | $29/mo | ~$20 |
| **Dedicated** | CX42 | 8 vCPU, 16GB RAM, 160GB SSD | €15.90/mo | $49/mo | ~$33 |

**Stripe Products to Create:**
```
Product: RunClaw Starter
  - Price: $15/month, recurring
  - Metadata: { plan: "starter", server_type: "cx22" }

Product: RunClaw Pro
  - Price: $29/month, recurring
  - Metadata: { plan: "pro", server_type: "cx32" }

Product: RunClaw Dedicated
  - Price: $49/month, recurring
  - Metadata: { plan: "dedicated", server_type: "cx42" }
```

---

## Environment Variables

```bash
# Appwrite
NEXT_PUBLIC_APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1
NEXT_PUBLIC_APPWRITE_PROJECT_ID=your-project-id
NEXT_PUBLIC_APPWRITE_DATABASE_ID=main
APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1
APPWRITE_PROJECT_ID=your-project-id
APPWRITE_DATABASE_ID=main
APPWRITE_API_KEY=your-server-api-key  # Server-side only, full permissions

# Stripe
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_...

# Hetzner
HETZNER_API_TOKEN=...

# Cloudflare
CLOUDFLARE_API_TOKEN=...
CLOUDFLARE_ZONE_ID=...  # Zone ID for runclaw.io

# Vercel Cron
CRON_SECRET=...  # Random string to authenticate cron endpoints

# App
NEXT_PUBLIC_APP_URL=https://runclaw.io
```

---

## Directory Structure

```
runclaw/
├── app/
│   ├── page.tsx                          # Landing page
│   ├── layout.tsx                        # Root layout
│   ├── globals.css
│   │
│   ├── (auth)/
│   │   ├── login/page.tsx
│   │   └── signup/page.tsx
│   │
│   ├── dashboard/
│   │   ├── page.tsx                      # Instance list
│   │   ├── new/page.tsx                  # Create instance form
│   │   └── [id]/page.tsx                 # Instance details
│   │
│   └── api/
│       ├── instances/
│       │   ├── create/route.ts
│       │   ├── delete/route.ts
│       │   ├── list/route.ts
│       │   └── ready/route.ts
│       │
│       ├── stripe/
│       │   ├── webhook/route.ts
│       │   └── portal/route.ts
│       │
│       └── cron/
│           ├── health/route.ts
│           ├── provision-timeout/route.ts
│           └── reconcile/route.ts
│
├── lib/
│   ├── appwrite/
│   │   ├── client.ts                     # Browser client (Account, Databases)
│   │   ├── server.ts                     # Server client (API key auth)
│   │   ├── auth.ts                       # Auth helpers (signUp, signIn, etc.)
│   │   └── session.ts                    # Server-side session verification
│   ├── hetzner.ts
│   ├── cloudflare.ts
│   ├── cloud-init.ts
│   ├── stripe.ts
│   └── utils.ts
│
├── components/
│   ├── ui/                               # shadcn components
│   ├── instance-card.tsx
│   ├── create-instance-form.tsx
│   └── ...
│
├── vercel.json                           # Cron configuration
├── package.json
└── .env.local
```

---

## Security Checklist

### Infrastructure
- [x] UFW firewall (only 80, 443, 22)
- [x] Fail2ban for SSH brute-force protection
- [x] SSH password auth disabled
- [x] Root login disabled
- [x] Automatic security updates enabled
- [x] Cloudflare proxy enabled (DDoS protection)

### Application
- [x] Document-level permissions on all collections
- [x] Webhook signature verification (Stripe)
- [x] Callback secret per instance
- [x] Server API key never exposed to client
- [x] HTTPS enforced via Caddy

### Operational
- [x] Provisioning timeout (10 min max)
- [x] Weekly reconciliation (orphan cleanup)
- [x] Health checks every 5 minutes
- [x] Webhook idempotency (no double processing)

---

## Launch Checklist

### Before Launch
- [ ] Hetzner account verified with payment method
- [ ] Cloudflare zone set up for runclaw.io
- [ ] Stripe products and prices created
- [ ] Stripe webhook endpoint configured
- [ ] Appwrite project created with collections and indexes
- [ ] Appwrite API key generated with correct permissions
- [ ] Environment variables set in Vercel
- [ ] Test full flow: signup → pay → provision → access → cancel

### Post-Launch Monitoring
- [ ] Check Vercel cron logs daily (first week)
- [ ] Monitor Hetzner billing for unexpected charges
- [ ] Watch Stripe for failed payments
- [ ] Review reconciliation reports weekly

---

## Future Enhancements (Out of Scope for V1)

- Custom domains (user brings their own)
- Backup/restore functionality  
- Multiple instances per user
- Team/organization accounts
- Usage analytics dashboard
- OpenClaw version pinning
- Region selection in UI
- Auto-scaling (burst capacity)
- Admin dashboard for support
