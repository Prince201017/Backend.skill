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
export interface OutboxRecord {
  event_id: string;
  tenant_id: string;
  aggregate_type: string;
  aggregate_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  traceparent: string | null;
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
    } catch {
      // Failed row remains unprocessed and will retry after leased_until expires
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
 * Consumer Inbox Pattern with Strict Single-Connection Transaction Consistency:
 * Checks out a dedicated client from the pool, sets transaction-local tenant context,
 * inserts (consumer_group, event_id) into inbox_processed_events, and passes the
 * EXACT SAME txClient to applySideEffectInTx(txClient) before COMMIT.
 */
export async function consumeEventIdempotently(params: {
  pool: TransactionalDbPool;
  consumerGroup: string;
  event: OutboxRecord;
  applySideEffectInTx: (txClient: TransactionalDbClient) => Promise<void>;
}): Promise<'PROCESSED' | 'DUPLICATE_SKIPPED'> {
  const txClient = await params.pool.connect();
  try {
    await txClient.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    await txClient.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [
      params.event.tenant_id,
    ]);

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

## 4. Authorized, Tenant-Scoped Redis Caching & Deterministic Cache Invalidation

### Critical Cache Security Rule
**Tenant Key Namespacing Is NOT Per-User Authorization!**
Constructing `tenant:${tenantId}:${resourceKey}` prevents Tenant B from reading Tenant A's cache keys, but it does **not** prevent a regular member in Tenant A from reading another user's private resource within Tenant A if the endpoint returns cached objects before checking authorization.
1. **Mandatory Pre-Return Authorization (`authorizeCachedValue`)**: Always verify that the calling subject is authorized to read the cached resource (or scope user-private projections with `tenant:${tenantId}:user:${actorUserId}:${resourceKey}`).
2. **Deterministic Invalidation**: Invalidate or version-bump cache keys (`del` on mutation commit or outbox consumer) in addition to jittered TTLs.

```typescript
const inFlightLocalPromises = new Map<string, Promise<unknown>>();

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
    const parsed = JSON.parse(cached) as T;
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
        await redis.set(scopedCacheKey, JSON.stringify(fresh), 'EX', jitteredTtl);
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
