# Module 03: Polyglot Databases, Isolation Invariants, Committed Transactional Outbox & Authorized Caching

This module details how to select database engines, match transaction isolation levels to concurrency invariants, execute the **3-Phase Committed Transactional Outbox + Transactionally Bound Consumer Inbox** pattern without phantom/dirty reads or poison-pill head-of-line blocking, and enforce per-user authorization and invalidation on tenant-scoped Redis caches.

---

## 1. Threat Model, Trust Boundaries & Failure Behavior

| Component | Threat / Integrity Failure | Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **Consumer Inbox (`consumeEventIdempotently`)** | Executing `applySideEffectInTx()` on a separate DB connection from `INSERT INTO inbox_processed_events` allows the inbox row to commit while side effects fail (or vice versa), causing lost or duplicate financial/domain effects on crash. | Consumer DB transaction boundary (`txClient` passed directly into `applySideEffectInTx(txClient)`). | Atomic `ROLLBACK` of both the `inbox_processed_events` row and all domain side effects on any exception. |
| **Outbox Relay (`runCommittedOutboxRelayBatch`)** | 1) Holding `FOR UPDATE` locks across network broker publish starves DB pools.<br>2) A failing poison-pill event blocks `ORDER BY created_at ASC LIMIT 100` forever. | Producer DB relay worker (Phase 0 quarantine + Phase 1 short lease + Phase 2 network + Phase 3 mark). | Quarantines events with `relay_attempts >= maxRelayAttempts` (`dead_lettered_at`); retries transient failures after `leased_until`. |
| **Tenant-Scoped Cache (`getOrComputeAuthorizedCachedSingleFlight`)** | Naming a cache key `tenant:{tenantId}:{resourceKey}` prevents cross-tenant collisions in Redis, **NOT** intra-tenant per-user authorization (Member B in Tenant 1 could read Member A's cached private order!). | Application service layer (`verifyAccessBeforeCacheReturn`). | Executes mandatory authorization check before returning cached data or scopes private cache keys by `user:{userId}` + explicit version/invalidation. |

---

## 2. Database Isolation Level Selection by Concurrency Invariant

Never mandate `SERIALIZABLE` indiscriminately across all transactions. Select the isolation level and locking strategy that matches the exact domain invariant:

| Transaction Invariant | Phenomenon to Prevent | Required PostgreSQL Isolation & Pattern |
| :--- | :--- | :--- |
| **Single-row balance debit / inventory decrement / counter** | Lost Update (`W-W` conflict) | `READ COMMITTED` + single atomic `UPDATE ... SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance`. |
| **Optimistic UI document edit** | Lost Update from concurrent editors | `READ COMMITTED` + Optimistic Concurrency Control (`UPDATE ... SET version = version + 1 WHERE id = $1 AND version = $2`). |
| **Multi-row funds transfer / multi-SKU checkout** | Lost Update + Circular Deadlock | `READ COMMITTED` or `REPEATABLE READ` + Pessimistic locking in deterministic sorted ID order (`SELECT ... WHERE id = ANY($1) ORDER BY id FOR UPDATE`). |
| **Multi-query financial statement / point-in-time reconciliation** | Non-Repeatable Read & Phantom Read across queries | `REPEATABLE READ READ ONLY` (consistent MVCC snapshot across multiple `SELECT` statements with zero writer blocking). |
| **Write-Skew / Intersecting predicate invariants (e.g., on-call minimum staffing, room capacity across concurrent inserts)** | Write Skew (`R-W` antidependency cycle) | `SERIALIZABLE` (Serializable Snapshot Isolation) with automatic retry loop on SQLSTATE `40001` (`serialization_failure`) or PostgreSQL Exclusion Constraints (`EXCLUDE USING gist`). |

---

## 3. Committed Transactional Outbox & Transactionally Bound Consumer Inbox

```sql
CREATE TABLE outbox_events (
    event_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    traceparent VARCHAR(128) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    leased_until TIMESTAMPTZ NULL,
    processed_at TIMESTAMPTZ NULL,
    dead_lettered_at TIMESTAMPTZ NULL,
    relay_attempts INT NOT NULL DEFAULT 0,
    last_error TEXT NULL
);

CREATE INDEX idx_outbox_committed_unprocessed
ON outbox_events (created_at ASC)
WHERE processed_at IS NULL AND dead_lettered_at IS NULL;

CREATE TABLE inbox_processed_events (
    consumer_group VARCHAR(64) NOT NULL,
    event_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (consumer_group, event_id)
);
```

### Committed Outbox Relay & Transactionally Consistent Consumer Inbox
**Critical Consumer Invariant**: `applySideEffectInTx(txClient)` **MUST** receive and use the exact same pinned `TransactionalDbClient` (`txClient`) that opened `BEGIN` and executed `INSERT INTO inbox_processed_events`. Never run `applySideEffectInTx()` against a separate connection pool!

```typescript
import crypto from 'node:crypto';

export interface OutboxRecord {
  event_id: string;
  tenant_id: string;
  aggregate_type: string;
  aggregate_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  traceparent: string | null;
  event_hmac?: string;
}

export interface TransactionalDbClient {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[]
  ): Promise<{ rows: T[]; rowCount: number }>;
  release: () => void;
}

export interface TransactionalDbPool {
  connect(): Promise<TransactionalDbClient>;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function computeOutboxEventHmac(
  event: Pick<OutboxRecord, 'event_id' | 'tenant_id' | 'aggregate_type' | 'aggregate_id' | 'event_type' | 'payload'>,
  outboxHmacSecret: string
): string {
  const canonical = `${event.event_id}|${event.tenant_id}|${event.aggregate_type}|${event.aggregate_id}|${event.event_type}|${JSON.stringify(event.payload)}`;
  return crypto.createHmac('sha256', outboxHmacSecret).update(canonical, 'utf8').digest('hex');
}

export async function runCommittedOutboxRelayBatch(
  dbClient: { query: (sql: string, params?: unknown[]) => Promise<{ rows: OutboxRecord[]; rowCount: number }> },
  brokerPublish: (record: OutboxRecord) => Promise<void>,
  batchSize = 100,
  maxRelayAttempts = 10
): Promise<{ publishedCount: number; quarantinedCount: number }> {
  // Phase 0: Quarantine poison-pill rows that have exhausted maxRelayAttempts
  const quarantineRes = await dbClient.query(
    `UPDATE outbox_events
     SET dead_lettered_at = clock_timestamp(),
         leased_until = NULL
     WHERE processed_at IS NULL
       AND dead_lettered_at IS NULL
       AND relay_attempts >= $1`,
    [maxRelayAttempts]
  );

  // Phase 1: Claim committed rows atomically with a short 30s lease and release DB locks immediately
  const { rows } = await dbClient.query(
    `UPDATE outbox_events
     SET leased_until = clock_timestamp() + interval '30 seconds',
         relay_attempts = relay_attempts + 1
     WHERE event_id IN (
       SELECT event_id
       FROM outbox_events
       WHERE processed_at IS NULL
         AND dead_lettered_at IS NULL
         AND relay_attempts < $2
         AND (leased_until IS NULL OR leased_until < clock_timestamp())
       ORDER BY created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED
     )
     RETURNING event_id, tenant_id, aggregate_type, aggregate_id, event_type, payload, traceparent`,
    [batchSize, maxRelayAttempts]
  );

  if (rows.length === 0) {
    return { publishedCount: 0, quarantinedCount: quarantineRes.rowCount };
  }

  // Phase 2: Publish outside the DB transaction so network latency never holds DB locks
  const publishedIds: string[] = [];
  for (const record of rows) {
    try {
      await brokerPublish(record);
      publishedIds.push(record.event_id);
    } catch (err) {
      // Persist last_error on failed relay attempt so operators have diagnostic visibility on DLQ rows
      const errMsg = err instanceof Error ? err.message.slice(0, 500) : 'BROKER_PUBLISH_ERROR';
      await dbClient
        .query(`UPDATE outbox_events SET last_error = $2 WHERE event_id = $1`, [record.event_id, errMsg])
        .catch(() => undefined);
    }
  }

  // Phase 3: Mark only the successfully published events as processed
  if (publishedIds.length > 0) {
    await dbClient.query(
      `UPDATE outbox_events
       SET processed_at = clock_timestamp(),
           leased_until = NULL
       WHERE event_id = ANY($1::uuid[])`,
      [publishedIds]
    );
  }

  return { publishedCount: publishedIds.length, quarantinedCount: quarantineRes.rowCount };
}

/**
 * Consumer Inbox Pattern with Strict Single-Connection Transaction Consistency
 * AND Broker Event Authenticity / Tenant-ID Verification (DEVIL-05 Remediation):
 * - Validates UUID syntax of event.tenant_id and event.event_id.
 * - Verifies optional event_hmac when outboxHmacSecret is provided (blocking forged broker messages from spoofing tenant_id).
 * - Verifies that the target tenant is ACTIVE before setting app.current_tenant_id.
 */
export async function consumeEventIdempotently(params: {
  pool: TransactionalDbPool;
  consumerGroup: string;
  event: OutboxRecord;
  outboxHmacSecret?: string;
  applySideEffectInTx: (txClient: TransactionalDbClient) => Promise<void>;
}): Promise<'PROCESSED' | 'DUPLICATE_SKIPPED'> {
  if (!UUID_REGEX.test(params.event.tenant_id) || !UUID_REGEX.test(params.event.event_id)) {
    throw new Error('INBOX_EVENT_REJECTED: Invalid tenant_id or event_id UUID format');
  }

  if (params.outboxHmacSecret) {
    if (!params.event.event_hmac || !/^[0-9a-fA-F]{64}$/.test(params.event.event_hmac)) {
      throw new Error('INBOX_EVENT_REJECTED: Missing or malformed event_hmac signature');
    }
    const expectedHmac = Buffer.from(
      computeOutboxEventHmac(params.event, params.outboxHmacSecret),
      'hex'
    );
    const actualHmac = Buffer.from(params.event.event_hmac, 'hex');
    if (
      expectedHmac.length !== actualHmac.length ||
      !crypto.timingSafeEqual(expectedHmac, actualHmac)
    ) {
      throw new Error('INBOX_EVENT_REJECTED: Broker event HMAC signature mismatch (tenant spoofing blocked)');
    }
  }

  const txClient = await params.pool.connect();
  try {
    await txClient.query('BEGIN ISOLATION LEVEL READ COMMITTED');

    const insertInbox = await txClient.query(
      `INSERT INTO inbox_processed_events (consumer_group, event_id, tenant_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (consumer_group, event_id) DO NOTHING`,
      [params.consumerGroup, params.event.event_id, params.event.tenant_id]
    );

    if (insertInbox.rowCount === 0) {
      await txClient.query('COMMIT');
      return 'DUPLICATE_SKIPPED';
    }

    // Establish transaction-local tenant context only after verifying event authenticity & deduplication
    await txClient.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [
      params.event.tenant_id,
    ]);

    // Execute business side effects on the EXACT SAME txClient connection!
    await params.applySideEffectInTx(txClient);
    await txClient.query('COMMIT');
    return 'PROCESSED';
  } catch (err) {
    await txClient.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    txClient.release();
  }
}
```

---

## 4. Authorized, Tenant-Scoped Redis Caching, `BigInt`-Safe Serialization & Deterministic Invalidation

### Critical Cache Security Rule
**Tenant Key Namespacing Is NOT Per-User Authorization!**
Constructing `tenant:${tenantId}:${resourceKey}` prevents Tenant B from reading Tenant A's cache keys, but it does **not** prevent a regular member in Tenant A from reading another user's private resource within Tenant A if the endpoint returns cached objects before checking authorization.
1. **Mandatory Pre-Return Authorization (`authorizeResource`)**: Always verify that the calling subject is authorized to read the cached resource (or scope user-private projections with `tenant:${tenantId}:user:${actorUserId}:${resourceKey}`).
2. **`BigInt`-Safe JSON Serialization**: Financial domain models in Module 01 use `bigint` for minor units (`amountMinor`). Standard `JSON.stringify` throws `TypeError: Do not know how to serialize a BigInt`. Use `serializeCacheValueBigIntSafe` / `deserializeCacheValueBigIntSafe`.

```typescript
const inFlightLocalPromises = new Map<string, Promise<unknown>>();

export function serializeCacheValueBigIntSafe(value: unknown): string {
  return JSON.stringify(value, (_key, val) =>
    typeof val === 'bigint' ? { __bigint_val__: val.toString() } : val
  );
}

export function deserializeCacheValueBigIntSafe<T>(raw: string): T {
  return JSON.parse(raw, (_key, val) => {
    if (
      val !== null &&
      typeof val === 'object' &&
      '__bigint_val__' in val &&
      typeof (val as { __bigint_val__: unknown }).__bigint_val__ === 'string'
    ) {
      return BigInt((val as { __bigint_val__: string }).__bigint_val__);
    }
    return val;
  }) as T;
}

export async function getOrComputeAuthorizedCachedSingleFlight<T>(
  redis: {
    get: (k: string) => Promise<string | null>;
    set: (k: string, v: string, mode: 'EX', ttlSec: number) => Promise<unknown>;
    del?: (k: string) => Promise<unknown>;
  },
  params: {
    tenantId: string;
    actorUserId: string;
    visibilityScope: 'TENANT_SHARED' | 'USER_PRIVATE';
    resourceKey: string;
    ttlSeconds: number;
  },
  fetcher: () => Promise<T | null>,
  authorizeResource: (resource: T, ctx: { tenantId: string; actorUserId: string }) => Promise<boolean>
): Promise<T | null> {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(params.tenantId)) {
    throw new Error('CACHE_REJECTED: Invalid tenantId format');
  }
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(params.actorUserId)) {
    throw new Error('CACHE_REJECTED: Invalid actorUserId format');
  }
  if (!/^[a-zA-Z0-9_.:-]{1,128}$/.test(params.resourceKey)) {
    throw new Error('CACHE_REJECTED: Invalid resourceKey format');
  }

  const scopedCacheKey =
    params.visibilityScope === 'USER_PRIVATE'
      ? `tenant:${params.tenantId}:user:${params.actorUserId}:${params.resourceKey}`
      : `tenant:${params.tenantId}:shared:${params.resourceKey}`;

  const cached = await redis.get(scopedCacheKey);
  if (cached !== null) {
    if (cached === '__NULL__') return null;
    const parsed = deserializeCacheValueBigIntSafe<T>(cached);
    // CRITICAL: Verify per-user authorization even on a cache hit!
    const allowed = await authorizeResource(parsed, {
      tenantId: params.tenantId,
      actorUserId: params.actorUserId,
    });
    if (!allowed) {
      throw new Error('CACHE_AUTHZ_DENIED: Caller is not authorized to read cached resource');
    }
    return parsed;
  }

  let computePromise = inFlightLocalPromises.get(scopedCacheKey) as Promise<T | null> | undefined;
  if (!computePromise) {
    computePromise = (async () => {
      try {
        const fresh = await fetcher();
        if (fresh === null) {
          await redis.set(scopedCacheKey, '__NULL__', 'EX', 30);
          return null;
        }
        const jitteredTtl = Math.max(1, Math.floor(params.ttlSeconds * (0.9 + Math.random() * 0.2)));
        await redis.set(scopedCacheKey, serializeCacheValueBigIntSafe(fresh), 'EX', jitteredTtl);
        return fresh;
      } finally {
        inFlightLocalPromises.delete(scopedCacheKey);
      }
    })();
    inFlightLocalPromises.set(scopedCacheKey, computePromise);
  }

  const value = await computePromise;
  if (value === null) return null;

  const allowed = await authorizeResource(value, {
    tenantId: params.tenantId,
    actorUserId: params.actorUserId,
  });
  if (!allowed) {
    throw new Error('CACHE_AUTHZ_DENIED: Caller is not authorized to read resource');
  }
  return value;
}
```

---

## 5. Verification & Test Requirements

1. **Consumer Inbox Atomic Rollback Test**: Simulate a failure inside `applySideEffectInTx(txClient)` and assert that the `inbox_processed_events` row is rolled back on the same connection so the redelivered message succeeds on retry.
2. **Consumer Duplicate Delivery Test**: Deliver the same `event_id` twice to `consumeEventIdempotently` and assert that `applySideEffectInTx` executes exactly once (`'PROCESSED'` then `'DUPLICATE_SKIPPED'`).
3. **Intra-Tenant Cache BOLA Test**: Cache an order under `TENANT_SHARED` for `user_A`, then call `getOrComputeAuthorizedCachedSingleFlight` as `user_B` (where `authorizeResource` returns `false`), and assert that `CACHE_AUTHZ_DENIED` is thrown even on a Redis cache hit.

### Authoritative References
- **PostgreSQL 16 Transaction Isolation (`READ COMMITTED`, `REPEATABLE READ`, `SERIALIZABLE`)**: https://www.postgresql.org/docs/current/transaction-iso.html
- **Microservices.io — Transactional Outbox & Idempotent Consumer Patterns**: https://microservices.io/patterns/data/transactional-outbox.html
