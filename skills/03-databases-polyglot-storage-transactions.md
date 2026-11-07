# Module 03: Polyglot Databases, Isolation Invariants, Committed Transactional Outbox & Caching

This reference details how to select database engines, choose transaction isolation levels based on concurrency invariants, implement the **Committed Transactional Outbox + Consumer Inbox** pattern without phantom/dirty-read bugs, and run stampede-safe Redis caching.

---

## 1. Database Isolation Level Selection by Concurrency Invariant

Never mandate `SERIALIZABLE` indiscriminately across all transactions (which introduces unnecessary serialization aborts and lock contention). Select the isolation level and locking strategy that matches the exact domain invariant:

| Transaction Invariant | Phenomenon to Prevent | Recommended PostgreSQL Isolation & Pattern |
| :--- | :--- | :--- |
| **Single-row balance debit / inventory decrement / counter** | Lost Update (`W-W` conflict) | `READ COMMITTED` + single atomic `UPDATE ... SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance`. |
| **Optimistic UI document edit** | Lost Update from concurrent editors | `READ COMMITTED` + Optimistic Concurrency Control (`UPDATE ... SET version = version + 1 WHERE id = $1 AND version = $2`). |
| **Multi-row funds transfer / multi-SKU checkout** | Lost Update + Circular Deadlock | `READ COMMITTED` or `REPEATABLE READ` + Pessimistic locking in deterministic sorted ID order (`SELECT ... WHERE id = ANY($1) ORDER BY id FOR UPDATE`). |
| **Multi-query financial statement / point-in-time reconciliation** | Non-Repeatable Read & Phantom Read across queries | `REPEATABLE READ READ ONLY` (consistent MVCC snapshot across multiple `SELECT` statements with zero writer blocking). |
| **Write-Skew / Intersecting predicate invariants (e.g., at least 1 doctor on call, room capacity across concurrent inserts)** | Write Skew (`R-W` antidependency cycle) | `SERIALIZABLE` (Serializable Snapshot Isolation) with automatic retry loop on SQLSTATE `40001` (`serialization_failure`) or PostgreSQL Exclusion Constraints (`EXCLUDE USING gist`). |

---

## 2. Committed Transactional Outbox & Consumer Inbox Pattern

**Critical Correctness Rule**: An Outbox Relay / CDC worker **MUST ONLY read committed outbox records**. Reading uncommitted rows would publish events for transactions that subsequently roll back, corrupting downstream systems.

### The 7-Step Committed Outbox -> Broker -> Idempotent Inbox Sequence
1. **Begin PostgreSQL Transaction** (`BEGIN`).
2. **Update Domain Records** (`INSERT` / `UPDATE` domain tables).
3. **Insert Outbox Event** (`INSERT INTO outbox_events ...`).
4. **Commit Transaction** (`COMMIT`). Only after commit is the outbox row visible to `READ COMMITTED` readers and committed to the WAL.
5. **Relay Reads Committed Events**: Outbox Relay executes `SELECT ... FROM outbox_events WHERE processed_at IS NULL ORDER BY created_at ASC LIMIT 100 FOR UPDATE SKIP LOCKED` inside its own `READ COMMITTED` transaction (or streams committed WAL records via Debezium).
6. **Publish with At-Least-Once Delivery**: Relay publishes each event to Kafka / RabbitMQ / NATS / BullMQ, awaits broker ACK, and updates `processed_at = clock_timestamp()`.
7. **Consumer Deduplicates Using `event_id`**: Downstream consumer inserts `event_id` into `inbox_processed_events` inside the same transaction as its business side effects (`ON CONFLICT DO NOTHING`).

```sql
-- Outbox Table (Producer Side)
CREATE TABLE outbox_events (
    event_id UUID PRIMARY KEY,
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

-- Inbox Deduplication Table (Consumer Side)
CREATE TABLE inbox_processed_events (
    consumer_group VARCHAR(64) NOT NULL,
    event_id UUID NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (consumer_group, event_id)
);
```

### Committed Outbox Relay (3-Phase Lease Claim + Poison-Pill Quarantine — Zero DB Locks Held Across Network I/O) & Idempotent Consumer
Never hold a PostgreSQL `BEGIN ... FOR UPDATE` transaction open while awaiting external broker network I/O (which exhausts connection pools and rolls back all 100 rows if row 99 fails to publish), and never allow a failing poison-pill event to retry infinitely and block the head of `ORDER BY created_at ASC LIMIT 100`:
1. **Phase 0 (Poison-Pill Quarantine)**: Quarantine any unprocessed outbox row whose `relay_attempts >= maxRelayAttempts` (`SET dead_lettered_at = clock_timestamp()`) so it never starves newer events.
2. **Phase 1 (Short DB Transaction)**: Atomically claim a batch of committed rows using `FOR UPDATE SKIP LOCKED` and set `leased_until = clock_timestamp() + interval '30 seconds'`, then release the DB lock immediately.
3. **Phase 2 (Network I/O Outside DB Transaction)**: Publish each claimed event to the broker and collect `publishedIds`.
4. **Phase 3 (Short DB Update)**: Mark `processed_at = clock_timestamp()` for all `publishedIds` that succeeded.

```typescript
export interface OutboxRecord {
  event_id: string;
  aggregate_type: string;
  aggregate_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  traceparent: string | null;
}

/**
 * Step 5 & 6: Quarantines poison-pill events exceeding maxRelayAttempts, claims committed rows
 * with a short lease, releases the DB transaction, publishes over the network, and marks succeeded rows.
 */
export async function runCommittedOutboxRelayBatch(
  dbClient: { query: (sql: string, params?: unknown[]) => Promise<{ rows: OutboxRecord[]; rowCount: number }> },
  brokerPublish: (record: OutboxRecord) => Promise<void>,
  batchSize = 100,
  maxRelayAttempts = 10
): Promise<number> {
  // Phase 0: Quarantine poison-pill rows that have exhausted maxRelayAttempts (prevents head-of-line blocking!)
  await dbClient.query(
    `UPDATE outbox_events
     SET dead_lettered_at = clock_timestamp(),
         leased_until = NULL
     WHERE processed_at IS NULL
       AND dead_lettered_at IS NULL
       AND relay_attempts >= $1`,
    [maxRelayAttempts]
  );

  // Phase 1: Claim committed rows atomically and release DB locks immediately
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
     RETURNING event_id, aggregate_type, aggregate_id, event_type, payload, traceparent`,
    [batchSize, maxRelayAttempts]
  );

  if (rows.length === 0) {
    return 0;
  }

  // Phase 2: Publish outside the DB transaction so network latency never holds DB locks
  const publishedIds: string[] = [];
  for (const record of rows) {
    try {
      await brokerPublish(record);
      publishedIds.push(record.event_id);
    } catch {
      // Individual failed row remains unprocessed and will retry after leased_until expires
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

  return publishedIds.length;
}

/**
 * Step 7: Consumer deduplicates at-least-once broker deliveries using event_id.
 */
export async function consumeEventIdempotently(
  dbClient: { query: (sql: string, params?: unknown[]) => Promise<{ rowCount: number }> },
  consumerGroup: string,
  event: OutboxRecord,
  applySideEffectInTx: () => Promise<void>
): Promise<'PROCESSED' | 'DUPLICATE_SKIPPED'> {
  await dbClient.query('BEGIN ISOLATION LEVEL READ COMMITTED');
  try {
    const insertInbox = await dbClient.query(
      `INSERT INTO inbox_processed_events (consumer_group, event_id)
       VALUES ($1, $2)
       ON CONFLICT (consumer_group, event_id) DO NOTHING`,
      [consumerGroup, event.event_id]
    );

    if (insertInbox.rowCount === 0) {
      // Already processed by a previous delivery; commit no-op and ACK message
      await dbClient.query('COMMIT');
      return 'DUPLICATE_SKIPPED';
    }

    await applySideEffectInTx();
    await dbClient.query('COMMIT');
    return 'PROCESSED';
  } catch (err) {
    await dbClient.query('ROLLBACK');
    throw err;
  }
}
```

---

## 3. Multi-Database Read-Your-Own-Writes & Deadlock-Free Transfers

When scaling with Primary + Read Replicas:
1. **Mutations**: Always route to Primary.
2. **Read-Your-Own-Writes**: Set `SET ryow:{tenantId}:{userId} 1 PX 3000` in Redis after any write; route subsequent reads from that actor to Primary until the replica catch-up window expires.
3. **Deterministic Lock Ordering**: Whenever locking multiple rows in a transaction, sort target primary keys lexicographically (`ORDER BY id FOR UPDATE`) so two concurrent transactions can never form a deadlock cycle.

---

## 4. Tenant-Scoped Redis Caching with Single-Flight Stampede Protection & Jitter

**Critical Multi-Tenancy Rule**: Never allow un-namespaced cache keys in a multi-tenant system. Require `tenantId` and `resourceKey` to match strict format allowlists and construct `tenant:{tenantId}:{resourceKey}` so Tenant B can never read or poison Tenant A's cached objects.

```typescript
const inFlightLocalPromises = new Map<string, Promise<unknown>>();

export async function getOrComputeCachedSingleFlight<T>(
  redis: {
    get: (k: string) => Promise<string | null>;
    set: (k: string, v: string, mode: 'EX', ttlSec: number) => Promise<unknown>;
  },
  params: {
    tenantId: string;
    resourceKey: string;
    ttlSeconds: number;
  },
  fetcher: () => Promise<T | null>
): Promise<T | null> {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(params.tenantId)) {
    throw new Error('CACHE_REJECTED: Invalid tenantId format');
  }
  if (!/^[a-zA-Z0-9_.:-]{1,128}$/.test(params.resourceKey)) {
    throw new Error('CACHE_REJECTED: Invalid resourceKey format');
  }
  const scopedCacheKey = `tenant:${params.tenantId}:${params.resourceKey}`;

  const cached = await redis.get(scopedCacheKey);
  if (cached !== null) {
    return cached === '__NULL__' ? null : (JSON.parse(cached) as T);
  }

  // Coalesce concurrent cache misses within the same process (Single-Flight)
  const existingPromise = inFlightLocalPromises.get(scopedCacheKey) as Promise<T | null> | undefined;
  if (existingPromise) {
    return existingPromise;
  }

  const computePromise = (async () => {
    try {
      const fresh = await fetcher();
      if (fresh === null) {
        await redis.set(scopedCacheKey, '__NULL__', 'EX', 45);
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
  return computePromise;
}
```


