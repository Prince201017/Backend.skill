# Module 03: Databases, Polyglot Storage Management, ACID Transactions & Caching

This reference details how to select, combine, and operate Relational Databases (PostgreSQL, MySQL), NoSQL Databases (MongoDB), and In-Memory Stores (Redis) without data loss, race conditions, or consistency drift.

---

## 1. Polyglot Database Selection Matrix

| Workload Pattern | Primary Engine | Why & How to Configure |
| :--- | :--- | :--- |
| **Core Entities, Users, Tenants, RBAC, Billing, Ledgers, Inventory** | **PostgreSQL** (or MySQL 8+ InnoDB) | Strict ACID transactions, foreign keys, row-level locking (`FOR UPDATE SKIP LOCKED`), `NUMERIC` precision, and `JSONB` for controlled extensibility. |
| **High-Volume Event Logs, Dynamic Product Attributes, Content Trees** | **MongoDB** | Flexible document schemas validated via `$jsonSchema`, compound indexes matching ESR (Equality, Sort, Range) rule, replica-set read preferences. |
| **Sessions, Rate Limits, Distributed Locks, Hot Cache, BullMQ Queues** | **Redis** (Cluster / Sentinel) | Sub-millisecond atomic pipelines and Lua scripts, TTL eviction, Pub/Sub invalidation channels. |
| **Blobs, Documents, Media, Backups** | **S3 / GCS / R2** | Infinitely scalable object storage with immutable versioning and lifecycle tiering. |

---

## 2. Multi-Database Management & Read-Your-Own-Writes Routing

When scaling with a Primary (Read/Write) database and multiple Read Replicas:
1. **Write Operations (`INSERT`, `UPDATE`, `DELETE`)**: Always route to the **Primary** pool.
2. **Read-Your-Own-Writes Consistency**: After a user mutates data, set a short-lived marker in Redis (`SET ryow:{userId} 1 PX 3000` for 3 seconds). Any `GET` request from that user while the marker exists routes to the **Primary** pool instead of a lagging Read Replica, preventing the user from seeing stale state right after saving.
3. **Connection Pool Sizing**:
   $$\text{Optimal Pool Size per Node} = \frac{\text{Total DB Max Connections} - \text{Reserved Superuser/Admin Connections}}{\text{Number of App Replicas}}$$
   Always place **PgBouncer** (in `transaction` pooling mode) in front of PostgreSQL when running serverless functions or horizontally scaled Kubernetes pods.

---

## 3. PostgreSQL ACID Transaction & Transactional Outbox Pattern

Never publish an event to Redis/MongoDB/Kafka before the PostgreSQL transaction commits. Use the **Transactional Outbox**:

```sql
-- 1. Domain Ledger & Outbox Schema
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    currency CHAR(3) NOT NULL,
    balance_minor BIGINT NOT NULL DEFAULT 0 CHECK (balance_minor >= 0),
    version INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ledger_entries (
    id UUID PRIMARY KEY,
    transaction_group_id UUID NOT NULL,
    account_id UUID NOT NULL REFERENCES accounts(id),
    direction VARCHAR(6) NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    trace_id VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    processed_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_outbox_unprocessed ON outbox_events(created_at) WHERE processed_at IS NULL;
```

### Deadlock-Free Atomic Transfer Implementation
To prevent deadlocks when locking two accounts concurrently (`Account A -> Account B` vs `Account B -> Account A`), **always acquire row locks in deterministic lexicographical ID order**:

```typescript
export async function executeAtomicTransfer(
  dbClient: { query: (sql: string, params?: unknown[]) => Promise<{ rows: any[]; rowCount: number }> },
  params: {
    transferId: string;
    fromAccountId: string;
    toAccountId: string;
    amountMinor: bigint;
    traceId: string;
  }
): Promise<void> {
  if (params.fromAccountId === params.toAccountId) {
    throw new Error('Cannot transfer to the same account');
  }
  if (params.amountMinor <= 0n) {
    throw new Error('Transfer amount must be positive');
  }

  // Deterministic lock ordering eliminates circular wait deadlocks
  const orderedIds = [params.fromAccountId, params.toAccountId].sort();

  await dbClient.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  try {
    await dbClient.query(
      `SELECT id, balance_minor FROM accounts WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE`,
      [orderedIds]
    );

    const debitRes = await dbClient.query(
      `UPDATE accounts
       SET balance_minor = balance_minor - $1, version = version + 1, updated_at = clock_timestamp()
       WHERE id = $2 AND balance_minor >= $1
       RETURNING balance_minor`,
      [params.amountMinor.toString(), params.fromAccountId]
    );

    if (debitRes.rowCount === 0) {
      throw new Error('INSUFFICIENT_FUNDS');
    }

    await dbClient.query(
      `UPDATE accounts
       SET balance_minor = balance_minor + $1, version = version + 1, updated_at = clock_timestamp()
       WHERE id = $2`,
      [params.amountMinor.toString(), params.toAccountId]
    );

    // Double-entry ledger records (Debit + Credit sum to 0 net change)
    await dbClient.query(
      `INSERT INTO ledger_entries (id, transaction_group_id, account_id, direction, amount_minor)
       VALUES (gen_random_uuid(), $1, $2, 'DEBIT', $4),
              (gen_random_uuid(), $1, $3, 'CREDIT', $4)`,
      [params.transferId, params.fromAccountId, params.toAccountId, params.amountMinor.toString()]
    );

    // Write Outbox Event in the exact same transaction
    await dbClient.query(
      `INSERT INTO outbox_events (id, aggregate_type, aggregate_id, event_type, payload, trace_id)
       VALUES (gen_random_uuid(), 'transfer', $1, 'transfer.completed', $2::jsonb, $3)`,
      [
        params.transferId,
        JSON.stringify({
          transferId: params.transferId,
          fromAccountId: params.fromAccountId,
          toAccountId: params.toAccountId,
          amountMinor: params.amountMinor.toString(),
        }),
        params.traceId,
      ]
    );

    await dbClient.query('COMMIT');
  } catch (err) {
    await dbClient.query('ROLLBACK');
    throw err;
  }
}
```

---

## 4. Redis Caching with Stampede Protection (Single-Flight + Lock)

```typescript
export async function getOrComputeCached<T>(
  redis: {
    get: (k: string) => Promise<string | null>;
    set: (k: string, v: string, mode: 'EX', ttlSec: number) => Promise<unknown>;
  },
  cacheKey: string,
  ttlSeconds: number,
  fetcher: () => Promise<T | null>
): Promise<T | null> {
  const cached = await redis.get(cacheKey);
  if (cached !== null) {
    if (cached === '__NULL__') return null; // Negative cache hit
    return JSON.parse(cached) as T;
  }

  const fresh = await fetcher();
  if (fresh === null) {
    // Negative caching prevents cache penetration attacks on non-existent IDs
    await redis.set(cacheKey, '__NULL__', 'EX', 45);
    return null;
  }

  // Add +-10% random jitter to TTL to prevent synchronized mass cache expiration (avalanche)
  const jitteredTtl = Math.max(1, Math.floor(ttlSeconds * (0.9 + Math.random() * 0.2)));
  await redis.set(cacheKey, JSON.stringify(fresh), 'EX', jitteredTtl);
  return fresh;
}
```
