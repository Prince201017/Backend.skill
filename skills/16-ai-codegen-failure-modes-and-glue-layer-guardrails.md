# Module 16: AI Code-Generation Failure Modes, Glue-Layer Guardrails & Emerging 2026+ Threat Surface

## 1. Scope & Threat Model: Why AI Agents Introduce Critical Bugs Even When Given Secure Building Blocks

Modules `00` through `15` provide hardened, standalone primitives (`withTenantTransaction`, `authorizeActionFromTrustedStore`, `executeWithIdempotencyLock`, `verifyAndProcessWebhookIdempotently`, `executePinnedSafeHttpsRequest`, `StreamingMultiStorageOrchestrator`). However, **the highest-severity production vulnerabilities occur in the "Glue Layer"**—when an AI coding agent or developer wires those modules into framework routes (Next.js App Router, Express, Fastify), ORMs (Prisma, Drizzle), background queues, or cryptographic wrappers.

| AI Glue-Layer Failure Mode | Root Cause of AI Mistake | Impact | Mandatory Guardrail in This Module |
| :--- | :--- | :--- | :--- |
| **1. ORM / Global Pool Bypass Inside `withTenantTransaction` (`AI-MISTAKE-01`)** | AI wraps the route in `withTenantTransaction(pool, ..., async (txClient) => { await db.select().from(orders); })` using the **global ORM pool `db`** instead of `txClient`. | Queries run on a different pooled connection where `app.current_tenant_id` is unset or belongs to another transaction! | `createPinnedTransactionGuard()` & explicit Drizzle/Prisma `txClient` binding check. |
| **2. Webhook `JSON.stringify(req.body)` Re-Serialization Trap (`AI-MISTAKE-02`)** | AI parses JSON first (`await req.json()` or `express.json()`) and passes `Buffer.from(JSON.stringify(body))` to `verifyWebhookSignature`. | Whitespace/key-order differences break HMAC verification; AI then "fixes" failing tests by disabling signature verification in dev/prod! | `readRawRequestBodyBounded()` enforcing byte-exact raw stream ingestion with hard byte limit before JSON parsing. |
| **3. Next.js Server Action Closure & Unauthenticated Export (`AI-MISTAKE-03`)** | AI marks a file `'use server'`, creating a public HTTP POST endpoint for every exported function, and captures `tenantId` or `isAdmin` from client-passed arguments or outer closures without re-verifying session + RBAC inside the action. | Direct unauthenticated or cross-tenant invocation of internal mutations via forged Next.js Action IDs. | `createAuthenticatedServerMutation()` wrapper requiring fresh server-side session + Zod validation + `withTenantTransaction` on every call. |
| **4. AES-GCM Nonce/IV Reuse & Unauthenticated Cipher Modes (`AI-MISTAKE-04`)** | When implementing KMS envelope encryption (Module 08), AI reuses a static/env IV (`process.env.ENCRYPTION_IV`) or uses `aes-256-cbc` without an HMAC, or forgets `cipher.getAuthTag()` / `decipher.setAuthTag()`. | Catastrophic keystream recovery and plaintext forgery under AES-GCM nonce reuse. | `encryptEnvelopeAes256Gcm()` and `decryptEnvelopeAes256Gcm()` generating a fresh 96-bit (`12-byte`) CSPRNG IV per encryption and binding `AAD` (`tenantId + resourceId`). |
| **5. Long-Lived WebSocket / SSE Post-Revocation Zombie Sessions (`AI-MISTAKE-05`)** | AI verifies JWT/membership only once during the initial HTTP `Upgrade` / SSE connect handshake. After the user is fired (`membershipStatus = 'REVOKED'`) or token expires, the open WebSocket continues receiving tenant events for hours. | Persistent post-revocation data exfiltration over realtime channels. | `enforceRealtimeSessionRevalidation()` periodic re-verification of `expiresAtSec` and live `ACTIVE` tenant membership on active streams. |
| **6. GraphQL / Batch Endpoint Per-Item BOLA & Rate-Limit Amplification (`AI-MISTAKE-06`)** | AI checks rate limits once per HTTP request and checks `withTenantTransaction` once at the top of a batch endpoint (`POST /api/batch` or GraphQL alias array), then iterates over 500 `resourceIds` without calling `authorizeActionFromTrustedStore` per item. | 500x rate-limit amplification and intra-tenant BOLA across batched resource IDs. | `executeBoundedAuthorizedBatch()` enforcing `maxBatchSize <= 50`, per-item cost token deduction, and per-item `authorizeActionFromTrustedStore`. |

---

## 2. Guardrail 1: Preventing ORM / Global Pool Bypass Inside `withTenantTransaction` (`AI-MISTAKE-01`)

When an AI agent writes database queries inside `withTenantTransaction`, it frequently calls a module-imported `globalPool.query(...)` by mistake instead of `txClient.query(...)`. Use `createPinnedTransactionClientProxy` to mark and verify that all queries inside a tenant transaction execute strictly on the pinned `txClient` where `SET LOCAL app.current_tenant_id` was established:

```typescript
import crypto from 'node:crypto';
import type { PooledDbClient } from './13-critical-risk-audit-reliability-and-production-readiness';

const PINNED_TX_SYMBOL = Symbol.for('backend.skill.pinnedTenantTx');

export interface PinnedTenantDbClient extends PooledDbClient {
  readonly [PINNED_TX_SYMBOL]: true;
  readonly boundTenantId: string;
  readonly boundUserId: string;
}

export function wrapAsPinnedTenantClient(
  txClient: PooledDbClient,
  boundTenantId: string,
  boundUserId: string
): PinnedTenantDbClient {
  return Object.freeze({
    ...txClient,
    query: txClient.query.bind(txClient),
    release: txClient.release.bind(txClient),
    [PINNED_TX_SYMBOL]: true as const,
    boundTenantId,
    boundUserId,
  });
}

/**
 * Repository / Data-Access Layer Guard:
 * Call this in every tenant-scoped repository method to guarantee that an AI agent
 * never passes the un-scoped global DbConnectionPool instead of the transaction-pinned txClient!
 */
export function assertPinnedTenantTransactionClient(
  client: unknown,
  expectedTenantId: string
): asserts client is PinnedTenantDbClient {
  if (
    !client ||
    typeof client !== 'object' ||
    !(PINNED_TX_SYMBOL in client) ||
    (client as PinnedTenantDbClient)[PINNED_TX_SYMBOL] !== true
  ) {
    throw new Error(
      'GLUE_LAYER_POOL_BYPASS_DETECTED: Repository query was called with an un-pinned DB pool instead of withTenantTransaction txClient!'
    );
  }
  const pinned = client as PinnedTenantDbClient;
  if (pinned.boundTenantId !== expectedTenantId) {
    throw new Error(
      `GLUE_LAYER_TENANT_CONTEXT_MISMATCH: Pinned txClient tenant (${pinned.boundTenantId}) !== requested query tenant (${expectedTenantId})`
    );
  }
}
```

---

## 3. Guardrail 2: Byte-Exact Bounded Raw Body Reader for Webhooks (`AI-MISTAKE-02`)

Never allow an AI agent to write `Buffer.from(JSON.stringify(await req.json()))` before calling `verifyAndProcessWebhookIdempotently`. Read the raw byte stream directly with a hard size ceiling (`maxBytes = 1_048_576`):

```typescript
export async function readRawWebhookBodyBounded(
  stream: AsyncIterable<Uint8Array | Buffer>,
  maxBytes = 1_048_576 // 1 MB hard cap
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buf.byteLength;
    if (totalBytes > maxBytes) {
      throw new Error(`WEBHOOK_PAYLOAD_TOO_LARGE: Raw body exceeded ${maxBytes} bytes`);
    }
    chunks.push(buf);
  }

  if (totalBytes === 0) {
    throw new Error('WEBHOOK_EMPTY_RAW_BODY');
  }
  return Buffer.concat(chunks, totalBytes);
}
```

---

## 4. Guardrail 3: Authenticated Envelope Encryption (`AES-256-GCM` with CSPRNG IV & Tenant `AAD` Binding — `AI-MISTAKE-04`)

When storing tenant third-party API keys, OAuth tokens, or erasable PII profiles (Module 08 & Module 09 §5.2), an AI agent must **never** reuse an IV or omit Additional Authenticated Data (`AAD`). Without `AAD` bound to `tenantId:resourceId:fieldName`, an attacker with database write access can copy an encrypted ciphertext from Tenant A's row into Tenant B's row and have Tenant B's server decrypt Tenant A's secret ("Ciphertext Transplanting Attack")!

```typescript
export interface Aes256GcmEnvelope {
  readonly v: 1;
  readonly keyId: string;
  readonly ivBase64: string;
  readonly authTagBase64: string;
  readonly ciphertextBase64: string;
}

/**
 * Encrypts sensitive secret/PII plaintext using AES-256-GCM with:
 * 1. Fresh 12-byte (96-bit) CSPRNG IV on every single encryption (never static/reused).
 * 2. Mandatory Additional Authenticated Data (AAD) binding (tenantId + resourceId + purpose)
 *    to defeat cross-tenant ciphertext transplanting in the database.
 */
export function encryptEnvelopeAes256Gcm(params: {
  keyId: string;
  keyBytes32: Buffer;
  plaintextUtf8: string;
  tenantId: string;
  resourceId: string;
  purpose: string;
}): Aes256GcmEnvelope {
  if (params.keyBytes32.byteLength !== 32) {
    throw new Error('CRYPTO_KEY_ERROR: AES-256-GCM requires an exact 32-byte key');
  }
  if (!params.tenantId || !params.resourceId || !params.purpose) {
    throw new Error('CRYPTO_AAD_ERROR: tenantId, resourceId, and purpose are mandatory for AAD binding');
  }

  const iv = crypto.randomBytes(12); // 96-bit NIST-recommended GCM IV
  const aad = Buffer.from(`${params.tenantId}|${params.resourceId}|${params.purpose}`, 'utf8');

  const cipher = crypto.createCipheriv('aes-256-gcm', params.keyBytes32, iv, {
    authTagLength: 16,
  });
  cipher.setAAD(aad);

  const encrypted = Buffer.concat([
    cipher.update(params.plaintextUtf8, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    v: 1,
    keyId: params.keyId,
    ivBase64: iv.toString('base64'),
    authTagBase64: authTag.toString('base64'),
    ciphertextBase64: encrypted.toString('base64'),
  };
}

export function decryptEnvelopeAes256Gcm(params: {
  envelope: Aes256GcmEnvelope;
  keyRing: Readonly<Record<string, Buffer>>;
  expectedTenantId: string;
  expectedResourceId: string;
  expectedPurpose: string;
}): string {
  const { envelope } = params;
  if (envelope.v !== 1 || !envelope.keyId) {
    throw new Error('CRYPTO_DECRYPT_REJECTED: Unsupported envelope version or missing keyId');
  }
  const keyBytes = Object.prototype.hasOwnProperty.call(params.keyRing, envelope.keyId)
    ? params.keyRing[envelope.keyId]
    : undefined;
  if (!keyBytes || keyBytes.byteLength !== 32) {
    throw new Error('CRYPTO_DECRYPT_REJECTED: Unknown or invalid 32-byte keyId');
  }

  const iv = Buffer.from(envelope.ivBase64, 'base64');
  const authTag = Buffer.from(envelope.authTagBase64, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');

  if (iv.byteLength !== 12 || authTag.byteLength !== 16) {
    throw new Error('CRYPTO_DECRYPT_REJECTED: Invalid IV (must be 12B) or AuthTag (must be 16B) length');
  }

  const aad = Buffer.from(
    `${params.expectedTenantId}|${params.expectedResourceId}|${params.expectedPurpose}`,
    'utf8'
  );

  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, iv, {
    authTagLength: 16,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}
```

---

## 5. Guardrail 4: Realtime WebSocket / SSE Periodic Session & Membership Re-Validation (`AI-MISTAKE-05`)

```typescript
export async function verifyRealtimeStreamStillAuthorized(params: {
  userId: string;
  tenantId: string;
  tokenExpiresAtSec: number;
  nowSec?: number;
  loadCurrentMembershipStatus: (
    tenantId: string,
    userId: string
  ) => Promise<'ACTIVE' | 'SUSPENDED' | 'REVOKED' | null>;
  closeStreamWithReason: (code: number, reason: string) => void;
}): Promise<boolean> {
  const nowSec = params.nowSec ?? Math.floor(Date.now() / 1000);
  if (nowSec >= params.tokenExpiresAtSec) {
    params.closeStreamWithReason(4401, 'REALTIME_SESSION_TOKEN_EXPIRED');
    return false;
  }

  const status = await params.loadCurrentMembershipStatus(params.tenantId, params.userId);
  if (status !== 'ACTIVE') {
    params.closeStreamWithReason(4403, 'REALTIME_TENANT_MEMBERSHIP_REVOKED');
    return false;
  }

  return true;
}
```

---

## 6. Guardrail 5: Bounded & Per-Item Authorized Batch Executor (`AI-MISTAKE-06`)

```typescript
export async function executeBoundedAuthorizedBatch<TItem, TResult>(params: {
  items: readonly TItem[];
  maxBatchSize?: number;
  consumeRateLimitTokens: (itemCount: number) => Promise<boolean>;
  authorizeItem: (item: TItem) => Promise<boolean>;
  processItem: (item: TItem) => Promise<TResult>;
}): Promise<TResult[]> {
  const maxBatchSize = params.maxBatchSize ?? 50;
  if (params.items.length === 0 || params.items.length > maxBatchSize) {
    throw new Error(
      `BATCH_SIZE_REJECTED: Batch size (${params.items.length}) must be between 1 and ${maxBatchSize}`
    );
  }

  // Deduct rate-limit tokens proportional to the number of items in the batch!
  const withinQuota = await params.consumeRateLimitTokens(params.items.length);
  if (!withinQuota) {
    throw new Error('BATCH_RATE_LIMIT_EXCEEDED: Insufficient token bucket capacity for batch size');
  }

  // Authorize EVERY item in the batch before executing mutations (prevents partial BOLA batch attacks)
  for (const item of params.items) {
    const allowed = await params.authorizeItem(item);
    if (!allowed) {
      throw new Error('BATCH_ITEM_BOLA_DENIED: One or more items in the batch failed authorization');
    }
  }

  const results: TResult[] = [];
  for (const item of params.items) {
    results.push(await params.processItem(item));
  }
  return results;
}
```
