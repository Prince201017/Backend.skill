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

## 2. Guardrail 1: Preventing ORM / Global Pool Bypass Inside `withTenantTransaction` (`AI-MISTAKE-01` & `DEVIL-07` Remediated)

When an AI agent writes database queries inside `withTenantTransaction`, it frequently calls a module-imported `globalPool.query(...)` by mistake instead of `txClient.query(...)`.

**Why `Symbol.for('backend.skill.pinnedTenantTx')` Is Vulnerable (`DEVIL-07`)**:
`Symbol.for(...)` registers a symbol in the **global** JavaScript Symbol registry. Any caller or untrusted helper can call `Symbol.for('backend.skill.pinnedTenantTx')` and attach `{ [Symbol.for('backend.skill.pinnedTenantTx')]: true, boundTenantId }` to an un-scoped global pool or fake client, completely bypassing `assertPinnedTenantTransactionClient()`!

**Remediation**: Use an **unforgeable module-private `WeakMap` capability registry** (`activePinnedTxRegistry`) that never exposes any symbol or property on the object and automatically revokes the client capability in `finally` before the database connection is returned to the pool:

```typescript
import crypto from 'node:crypto';
import {
  withTenantTransaction,
  type AuthorizedTenantTxContext,
  type DbConnectionPool,
  type PooledDbClient,
  type TenantPermission,
} from './13-critical-risk-audit-reliability-and-production-readiness';

interface ActivePinnedTenantCapability {
  readonly tenantId: string;
  readonly userId: string;
  active: boolean;
}

// Unforgeable module-private WeakMap: external modules cannot access, enumerate, or spoof entries!
const activePinnedTxRegistry = new WeakMap<object, ActivePinnedTenantCapability>();

export interface PinnedTenantDbClient extends PooledDbClient {
  readonly boundTenantId: string;
  readonly boundUserId: string;
}

export function wrapAsPinnedTenantClient(
  txClient: PooledDbClient,
  boundTenantId: string,
  boundUserId: string
): PinnedTenantDbClient {
  if (!boundTenantId || !boundUserId) {
    throw new Error('PINNED_CLIENT_ERROR: boundTenantId and boundUserId are required');
  }
  const capability: ActivePinnedTenantCapability = {
    tenantId: boundTenantId,
    userId: boundUserId,
    active: true,
  };
  const pinnedHandle: PinnedTenantDbClient = Object.freeze({
    query: <R = Record<string, unknown>>(sql: string, params?: readonly unknown[]) => {
      if (!capability.active) {
        return Promise.reject(
          new Error('GLUE_LAYER_RELEASED_TX_CLIENT_USED: Cannot execute queries on a completed/released tenant transaction client!')
        );
      }
      return txClient.query<R>(sql, params);
    },
    release: () => {
      capability.active = false;
      activePinnedTxRegistry.delete(pinnedHandle);
      txClient.release();
    },
    boundTenantId,
    boundUserId,
  });

  activePinnedTxRegistry.set(pinnedHandle, capability);
  return pinnedHandle;
}

export function revokePinnedTenantClient(pinnedClient: PinnedTenantDbClient): void {
  const cap = activePinnedTxRegistry.get(pinnedClient);
  if (cap) {
    cap.active = false;
    activePinnedTxRegistry.delete(pinnedClient);
  }
}

/**
 * Repository / Data-Access Layer Guard (`DEVIL-07` Hardened):
 * Verifies against the unforgeable module-private `WeakMap` that `client` was genuinely issued
 * by `wrapAsPinnedTenantClient` / `withPinnedTenantTransaction`, is still active (not yet released),
 * and is bound to `expectedTenantId`. Forged objects using `Symbol.for(...)` are deterministically rejected!
 */
export function assertPinnedTenantTransactionClient(
  client: unknown,
  expectedTenantId: string
): asserts client is PinnedTenantDbClient {
  if (!client || typeof client !== 'object') {
    throw new Error(
      'GLUE_LAYER_POOL_BYPASS_DETECTED: Repository query was called with an un-pinned DB pool instead of withTenantTransaction txClient!'
    );
  }
  const cap = activePinnedTxRegistry.get(client);
  if (!cap || !cap.active) {
    throw new Error(
      'GLUE_LAYER_POOL_BYPASS_DETECTED: Client is not registered in the unforgeable activePinnedTxRegistry WeakMap (or transaction already ended)!'
    );
  }
  if (cap.tenantId !== expectedTenantId) {
    throw new Error(
      `GLUE_LAYER_TENANT_CONTEXT_MISMATCH: Pinned txClient tenant (${cap.tenantId}) !== requested query tenant (${expectedTenantId})`
    );
  }
}

/**
 * Executes `withTenantTransaction` (Module 13) and automatically wraps `txClient` in the
 * unforgeable `WeakMap`-backed `PinnedTenantDbClient`, revoking the handle in `finally` before pool release.
 */
export async function withPinnedTenantTransaction<T>(params: {
  pool: DbConnectionPool;
  identityAssertionToken: string | undefined | null;
  identitySigningSecret: string;
  requestedTenantId: string;
  requiredPermission: TenantPermission;
  gucHmacSecret: string;
  nowSec?: number;
  work: (pinnedTxClient: PinnedTenantDbClient, authContext: AuthorizedTenantTxContext) => Promise<T>;
}): Promise<T> {
  return withTenantTransaction({
    pool: params.pool,
    identityAssertionToken: params.identityAssertionToken,
    identitySigningSecret: params.identitySigningSecret,
    requestedTenantId: params.requestedTenantId,
    requiredPermission: params.requiredPermission,
    gucHmacSecret: params.gucHmacSecret,
    nowSec: params.nowSec,
    work: async (rawTxClient, authContext) => {
      const pinnedClient = wrapAsPinnedTenantClient(
        rawTxClient,
        authContext.tenantId,
        authContext.userId
      );
      try {
        return await params.work(pinnedClient, authContext);
      } finally {
        revokePinnedTenantClient(pinnedClient);
      }
    },
  });
}
```

---

## 3. Guardrail 2: Authenticated Next.js Server Action / RPC Mutation Wrapper (`AI-MISTAKE-03` & `DEVIL-08` Remediated)

AI agents frequently mark a file `'use server'` and trust closure variables or client-passed `tenantId`/`userId` without re-authenticating or wrapping the mutation in `withPinnedTenantTransaction`. `createAuthenticatedServerMutation` enforces server-side session verification, strict input schema validation (rejecting unknown keys and prototype pollution), and `withPinnedTenantTransaction` on every invocation:

```typescript
export interface ServerMutationRequestEnvelope<TInput extends Record<string, unknown>> {
  readonly identityAssertionToken: string | undefined | null;
  readonly requestedTenantId: string;
  readonly input: TInput;
}

export function createAuthenticatedServerMutation<
  TInput extends Record<string, unknown>,
  TOutput
>(config: {
  pool: DbConnectionPool;
  identitySigningSecret: string;
  gucHmacSecret: string;
  requiredPermission: TenantPermission;
  allowedInputKeys: readonly (keyof TInput & string)[];
  validateInput: (raw: Record<string, unknown>) => TInput;
  handler: (params: {
    txClient: PinnedTenantDbClient;
    authContext: AuthorizedTenantTxContext;
    validatedInput: TInput;
  }) => Promise<TOutput>;
}): (envelope: ServerMutationRequestEnvelope<TInput>, nowSec?: number) => Promise<TOutput> {
  if (!config.identitySigningSecret || config.identitySigningSecret.trim().length < 32) {
    throw new Error('SERVER_MUTATION_CONFIG_ERROR: identitySigningSecret must be at least 32 chars');
  }
  if (!config.gucHmacSecret || config.gucHmacSecret.trim().length < 32) {
    throw new Error('SERVER_MUTATION_CONFIG_ERROR: gucHmacSecret must be at least 32 chars');
  }
  const allowedKeySet = new Set<string>(config.allowedInputKeys);

  return async (envelope: ServerMutationRequestEnvelope<TInput>, nowSec?: number): Promise<TOutput> => {
    if (!envelope || typeof envelope !== 'object') {
      throw new Error('SERVER_MUTATION_INVALID_ENVELOPE');
    }
    const rawInput = envelope.input;
    if (
      !rawInput ||
      typeof rawInput !== 'object' ||
      Array.isArray(rawInput) ||
      (Object.getPrototypeOf(rawInput) !== Object.prototype && Object.getPrototypeOf(rawInput) !== null)
    ) {
      throw new Error('SERVER_MUTATION_INVALID_INPUT_OBJECT');
    }

    for (const key of Object.keys(rawInput)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype' || !allowedKeySet.has(key)) {
        throw new Error(`SERVER_MUTATION_UNEXPECTED_FIELD_REJECTED:${key}`);
      }
    }

    const validatedInput = config.validateInput(rawInput);

    return withPinnedTenantTransaction({
      pool: config.pool,
      identityAssertionToken: envelope.identityAssertionToken,
      identitySigningSecret: config.identitySigningSecret,
      requestedTenantId: envelope.requestedTenantId,
      requiredPermission: config.requiredPermission,
      gucHmacSecret: config.gucHmacSecret,
      nowSec,
      work: async (txClient, authContext) => {
        assertPinnedTenantTransactionClient(txClient, authContext.tenantId);
        return config.handler({
          txClient,
          authContext,
          validatedInput,
        });
      },
    });
  };
}
```

---

## 4. Guardrail 3: Byte-Exact Bounded Raw Body Reader for Webhooks (`AI-MISTAKE-02`)

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

## 5. Guardrail 4: Authenticated Envelope Encryption (`AES-256-GCM` with CSPRNG IV, Canonical Base64 & Tenant `AAD` Binding — `AI-MISTAKE-04`)

When storing tenant third-party API keys, OAuth tokens, or erasable PII profiles (Module 08 & Module 09 §5.2), an AI agent must **never** reuse an IV or omit Additional Authenticated Data (`AAD`). Furthermore, `Buffer.from(str, 'base64')` in Node.js silently ignores non-alphabet characters and non-canonical padding unless canonical Base64 round-trip equality is enforced!

```typescript
export interface Aes256GcmEnvelope {
  readonly v: 1;
  readonly keyId: string;
  readonly ivBase64: string;
  readonly authTagBase64: string;
  readonly ciphertextBase64: string;
}

const STRICT_BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function decodeStrictCanonicalBase64(field: string, fieldName: string): Buffer {
  if (typeof field !== 'string' || ! STRICT_BASE64_REGEX.test(field)) {
    throw new Error(`CRYPTO_DECRYPT_REJECTED: Malformed Base64 encoding in ${fieldName}`);
  }
  const decoded = Buffer.from(field, 'base64');
  if (decoded.toString('base64') !== field) {
    throw new Error(`CRYPTO_DECRYPT_REJECTED: Non-canonical Base64 representation in ${fieldName}`);
  }
  return decoded;
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
  if (!envelope || envelope.v !== 1 || !envelope.keyId) {
    throw new Error('CRYPTO_DECRYPT_REJECTED: Unsupported envelope version or missing keyId');
  }
  if (!params.expectedTenantId || !params.expectedResourceId || !params.expectedPurpose) {
    throw new Error('CRYPTO_DECRYPT_REJECTED: expectedTenantId, expectedResourceId, and expectedPurpose are mandatory');
  }
  const keyBytes = Object.prototype.hasOwnProperty.call(params.keyRing, envelope.keyId)
    ? params.keyRing[envelope.keyId]
    : undefined;
  if (!keyBytes || keyBytes.byteLength !== 32) {
    throw new Error('CRYPTO_DECRYPT_REJECTED: Unknown or invalid 32-byte keyId');
  }

  const iv = decodeStrictCanonicalBase64(envelope.ivBase64, 'ivBase64');
  const authTag = decodeStrictCanonicalBase64(envelope.authTagBase64, 'authTagBase64');
  const ciphertext = decodeStrictCanonicalBase64(envelope.ciphertextBase64, 'ciphertextBase64');

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

## 6. Guardrail 5: Realtime WebSocket / SSE Active Stream Controller & Post-Revocation Seal (`AI-MISTAKE-05` & `DEVIL-16` Remediated)

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

/**
 * Active Realtime Stream Controller (`DEVIL-16` Remediation):
 * Enforces continuous revalidation before delivering any outbound or queued frame,
 * and permanently seals the stream once token expiry or membership revocation occurs
 * so buffered messages can NEVER be emitted after revocation!
 */
export function createRevocationSafeRealtimeStreamController<TFrame>(config: {
  userId: string;
  tenantId: string;
  tokenExpiresAtSec: number;
  loadCurrentMembershipStatus: (
    tenantId: string,
    userId: string
  ) => Promise<'ACTIVE' | 'SUSPENDED' | 'REVOKED' | null>;
  deliverFrameToSocket: (frame: TFrame) => void;
  closeSocketWithReason: (code: number, reason: string) => void;
}) {
  let closed = false;

  const terminate = (code: number, reason: string): void => {
    if (!closed) {
      closed = true;
      config.closeSocketWithReason(code, reason);
    }
  };

  return {
    isClosed: (): boolean => closed,
    revalidateNow: async (nowSec?: number): Promise<boolean> => {
      if (closed) return false;
      return verifyRealtimeStreamStillAuthorized({
        userId: config.userId,
        tenantId: config.tenantId,
        tokenExpiresAtSec: config.tokenExpiresAtSec,
        nowSec,
        loadCurrentMembershipStatus: config.loadCurrentMembershipStatus,
        closeStreamWithReason: terminate,
      });
    },
    sendFrameIfAuthorized: async (frame: TFrame, nowSec?: number): Promise<boolean> => {
      if (closed) return false;
      const authorized = await verifyRealtimeStreamStillAuthorized({
        userId: config.userId,
        tenantId: config.tenantId,
        tokenExpiresAtSec: config.tokenExpiresAtSec,
        nowSec,
        loadCurrentMembershipStatus: config.loadCurrentMembershipStatus,
        closeStreamWithReason: terminate,
      });
      if (!authorized || closed) {
        return false;
      }
      config.deliverFrameToSocket(frame);
      return true;
    },
  };
}
```

---

## 7. Guardrail 6: Bounded, Cost-Weighted & Transactionally Authorized Batch Executor (`AI-MISTAKE-06` & `DEVIL-09` Remediated)

```typescript
export const HARD_MAX_BATCH_SIZE = 50;

/**
 * Bounded, Cost-Weighted & Transactionally Authorized Batch Executor (`DEVIL-09` Hardened):
 * 1. Enforces an un-overridable ceiling `HARD_MAX_BATCH_SIZE = 50` (rejects caller overrides > 50).
 * 2. Charges rate-limit tokens proportional to total batch item cost (`calculateItemCost`), not just request count.
 * 3. Executes per-item authorization AND mutation inside a single atomic transaction (`runInTransaction`),
 *    preventing TOCTOU between authorization check and item mutation and rolling back the entire batch on any violation.
 */
export async function executeBoundedAuthorizedBatch<TItem, TResult>(params: {
  items: readonly TItem[];
  maxBatchSize?: number;
  calculateItemCost?: (item: TItem) => number;
  consumeRateLimitTokens: (totalCostUnits: number) => Promise<boolean>;
  authorizeItem: (item: TItem) => Promise<boolean>;
  processItem: (item: TItem) => Promise<TResult>;
  runInTransaction?: <T>(fn: () => Promise<T>) => Promise<T>;
}): Promise<TResult[]> {
  const requestedMax = params.maxBatchSize ?? HARD_MAX_BATCH_SIZE;
  if (!Number.isInteger(requestedMax) || requestedMax < 1 || requestedMax > HARD_MAX_BATCH_SIZE) {
    throw new Error(
      `BATCH_MAX_LIMIT_OVERRIDE_FORBIDDEN: maxBatchSize (${String(requestedMax)}) cannot exceed HARD_MAX_BATCH_SIZE (${HARD_MAX_BATCH_SIZE})`
    );
  }
  if (params.items.length === 0 || params.items.length > requestedMax) {
    throw new Error(
      `BATCH_SIZE_REJECTED: Batch size (${params.items.length}) must be between 1 and ${requestedMax}`
    );
  }

  let totalCostUnits = 0;
  for (const item of params.items) {
    const itemCost = params.calculateItemCost ? params.calculateItemCost(item) : 1;
    if (!Number.isInteger(itemCost) || itemCost < 1) {
      throw new Error(`BATCH_INVALID_ITEM_COST: Item cost must be a positive integer (got ${String(itemCost)})`);
    }
    totalCostUnits += itemCost;
  }

  // Deduct rate-limit tokens proportional to total item cost across the batch!
  const withinQuota = await params.consumeRateLimitTokens(totalCostUnits);
  if (!withinQuota) {
    throw new Error('BATCH_RATE_LIMIT_EXCEEDED: Insufficient token bucket capacity for batch cost');
  }

  const executeBatchAtomically = async (): Promise<TResult[]> => {
    // 1. Pre-flight authorize EVERY item in the batch before any mutation
    for (const item of params.items) {
      const allowed = await params.authorizeItem(item);
      if (!allowed) {
        throw new Error('BATCH_ITEM_BOLA_DENIED: One or more items in the batch failed authorization');
      }
    }

    // 2. Re-verify authorization at mutation time for each item and execute inside the transaction
    const results: TResult[] = [];
    for (const item of params.items) {
      const stillAllowed = await params.authorizeItem(item);
      if (!stillAllowed) {
        throw new Error('BATCH_ITEM_TOCTOU_AUTHZ_DENIED: Authorization revoked before item mutation');
      }
      results.push(await params.processItem(item));
    }
    return results;
  };

  if (params.runInTransaction) {
    return params.runInTransaction(executeBatchAtomically);
  }
  return executeBatchAtomically();
}
```
