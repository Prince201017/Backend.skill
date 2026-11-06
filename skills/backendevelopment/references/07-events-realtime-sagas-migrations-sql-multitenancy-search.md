# Module 07: Event-Driven Architecture, WebSockets, SSE, Sagas, Zero-Downtime Migrations, Advanced SQL, Multi-Tenancy & Search

This reference covers the 8 core data-intensive and real-time backend engineering domains required for scalable distributed applications.

---

## 1. Event-Driven Architecture (Kafka, RabbitMQ, NATS & Event Schemas)

### Broker Topology & Partition Ordering
- **Apache Kafka**: Partitioned append-only commit log. Always set the message **Partition Key** to the `aggregate_id` (e.g., `order_id` or `account_id`) so all events for a single domain entity (`OrderCreated -> OrderPaid -> OrderShipped`) land on the exact same partition and are consumed strictly in order.
- **RabbitMQ**: Use Topic or Direct exchanges with durable queues (`durable: true`, `deliveryMode: 2` persistent messages), publisher confirms (`confirmChannel`), and explicit consumer `ack`/`nack` with `prefetch(N)` backpressure.
- **NATS JetStream**: Use subject hierarchies (`orders.{tenantId}.{eventType}`), stream deduplication headers (`Nats-Msg-Id: {eventId}`), and explicit consumer ack policies.

### Canonical CloudEvents 1.0 Envelope & Schema Compatibility
Enforce backward/forward schema compatibility (Avro / Protobuf / JSON Schema Registry): never rename or change the type of existing event fields; add new optional fields with defaults or publish a new versioned event type (`order.created.v2`).

```json
{
  "specversion": "1.0",
  "id": "019300e8-8a10-7000-9c11-4f8a2b1c9d0e",
  "source": "urn:service:billing-service",
  "type": "com.example.billing.invoice.paid.v1",
  "subject": "inv_019300e8",
  "time": "2026-11-05T20:05:00.000Z",
  "datacontenttype": "application/json",
  "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
  "data": {
    "tenantId": "019300a0-0000-7000-8000-000000000001",
    "invoiceId": "inv_019300e8",
    "amountPaidMinor": "15000",
    "currency": "USD"
  }
}
```

---

## 2. WebSocket Engineering (Lifecycle, Rooms, Presence & Heartbeats)

1. **Authentication at Upgrade**: Authenticate during the HTTP `Upgrade` handshake (`Sec-WebSocket-Protocol` or short-lived single-use ticket exchanged over HTTPS) and re-validate token expiration periodically on active sockets.
2. **Ping/Pong Heartbeats & Dead-Peer Detection**:
   - Server sends a protocol-level `ping` (or application-level `{"type":"ping"}`) every `25s`.
   - If no `pong` arrives within `10s`, terminate the socket and clean up room/presence memberships to prevent zombie file-descriptor leaks.
3. **Horizontal Scaling via Redis / NATS PubSub Backplane**:
   - Because User A may connect to Pod 1 and User B to Pod 2, room broadcasts (`room:{tenantId}:{roomId}`) publish to a Redis/NATS channel so every pod forwards the frame to its locally connected room subscribers.
4. **Presence with Expiring Leases**:
   - Store presence in Redis (`ZADD presence:{roomId} <nowMs> <userId>`), refresh on each heartbeat, and prune stale members (`ZREMRANGEBYSCORE presence:{roomId} -inf <nowMs - 45000>`).
5. **Backpressure Protection**: Check `ws.bufferedAmount` before writing high-frequency frames; drop non-critical ephemeral frames (like cursor coordinates) or disconnect slow consumers if `bufferedAmount > maxBufferBytes` (e.g., 4MB).

---

## 3. Server-Sent Events (SSE) Streaming & `Last-Event-ID` Resume

SSE is the preferred protocol for unidirectional server-to-client streams (live notifications, job progress, financial tickers, streaming AI responses).

```typescript
/**
 * Production SSE Frame Formatter with Event ID, Retry Hint, and Proxy Anti-Buffering Headers
 */
export const SSE_RESPONSE_HEADERS: Record<string, string> = {
  'Content-Type': 'text/event-stream; charset=utf-8',
  'Cache-Control': 'no-cache, no-transform',
  Connection: 'keep-alive',
  'X-Accel-Buffering': 'no', // Prevents Nginx from buffering SSE chunks!
};

export function formatSseFrame(params: {
  id: string;
  event: string;
  data: unknown;
  retryMs?: number;
}): string {
  const lines: string[] = [];
  lines.push(`id: ${params.id}`);
  lines.push(`event: ${params.event}`);
  if (params.retryMs !== undefined) {
    lines.push(`retry: ${params.retryMs}`);
  }
  const serialized = JSON.stringify(params.data);
  for (const line of serialized.split('\n')) {
    lines.push(`data: ${line}`);
  }
  return lines.join('\n') + '\n\n';
}
```
- **Reconnection Resume (`Last-Event-ID`)**: When a browser reconnects after a network drop, it automatically sends the `Last-Event-ID` HTTP header. Query the event store/Redis stream (`XRANGE stream:{channelId} (${lastEventId} +`) to replay missed events seamlessly before switching to live push.
- **Keep-Alive Comments**: Emit `: heartbeat\n\n` every `15s` so load balancers and NAT gateways do not close idle connections.

---

## 4. Distributed Transactions: Sagas & Compensating Actions

Never use blocking Two-Phase Commit (2PC/XA) across microservices or external APIs. Use an **Orchestrated Saga** with persistent step state and idempotent **Compensating Transactions**:

| Saga StepPhase | Forward Action | Compensating Action (Backward Recovery) |
| :--- | :--- | :--- |
| **1. Reserve Inventory (Compensatable)** | `POST /inventory/reservations` (`status = RESERVED`) | `DELETE /inventory/reservations/{reservationId}` (`status = RELEASED`) |
| **2. Charge Payment (Pivot Transaction)** | `POST /payments/charges` (with `Idempotency-Key`) | `POST /payments/refunds` (if post-pivot step fails) |
| **3. Issue Entitlement / Shipment (Retryable)** | `POST /fulfillment/shipments` (retried until success) | N/A (Retried forward via durable queue until completion) |

```typescript
export interface SagaStep<TContext> {
  stepName: string;
  executeForward: (ctx: TContext) => Promise<void>;
  compensateBackward?: (ctx: TContext) => Promise<void>;
}

export async function runOrchestratedSaga<TContext>(
  sagaId: string,
  ctx: TContext,
  steps: SagaStep<TContext>[],
  recordStepState: (sagaId: string, stepName: string, state: 'STARTED' | 'COMPLETED' | 'COMPENSATING' | 'COMPENSATED' | 'FAILED') => Promise<void>
): Promise<void> {
  const completedSteps: SagaStep<TContext>[] = [];

  try {
    for (const step of steps) {
      await recordStepState(sagaId, step.stepName, 'STARTED');
      await step.executeForward(ctx);
      await recordStepState(sagaId, step.stepName, 'COMPLETED');
      completedSteps.push(step);
    }
  } catch (forwardError) {
    // Execute compensating transactions in reverse order for all completed steps
    for (let i = completedSteps.length - 1; i >= 0; i--) {
      const step = completedSteps[i];
      if (!step.compensateBackward) continue;
      await recordStepState(sagaId, step.stepName, 'COMPENSATING');
      await step.compensateBackward(ctx);
      await recordStepState(sagaId, step.stepName, 'COMPENSATED');
    }
    throw forwardError;
  }
}
```

---

## 5. Zero-Downtime Database Migrations (Expand-and-Contract Pattern)

Never run destructive or table-locking DDL (`ALTER TABLE RENAME COLUMN`, `DROP COLUMN`, or non-concurrent index builds) directly during a live deployment while old application pods are still running.

### The 4-Phase Expand-and-Contract Protocol
1. **Phase 1 — Expand (Additive DDL)**:
   - Add the new nullable column (`ALTER TABLE users ADD COLUMN full_name TEXT NULL;`).
   - Always set `SET lock_timeout = '2s';` and `SET statement_timeout = '60s';` at the start of every migration script so a migration waiting on a lock fails fast instead of queueing all production traffic behind an `ACCESS EXCLUSIVE` lock.
   - Build indexes without blocking writes: `CREATE INDEX CONCURRENTLY idx_users_full_name ON users(full_name);`
   - To add a `NOT NULL` or `CHECK` constraint without a full-table lock:
     ```sql
     ALTER TABLE users ADD CONSTRAINT chk_full_name_nonempty CHECK (full_name <> '') NOT VALID;
     ALTER TABLE users VALIDATE CONSTRAINT chk_full_name_nonempty; -- Uses SHARE UPDATE EXCLUSIVE (does not block reads/writes!)
     ```
2. **Phase 2 — Dual-Write & Backfill**:
   - Deploy application code that writes to **both** the old column and the new column, while still reading from the old column.
   - Backfill historical rows in small batched transactions (`LIMIT 5000` with `pg_sleep(0.05)` between batches) to avoid replication lag and WAL bloat.
3. **Phase 3 — Switch Reads**:
   - Verify 100% backfill completion, then deploy code that reads from the new column.
4. **Phase 4 — Contract (Cleanup)**:
   - Stop writing to the old column in code, then drop the obsolete column in a subsequent migration release.

---

## 6. Advanced SQL Engineering (Query Planning, Partitioning, CTEs & Window Functions)

1. **Query Planning (`EXPLAIN (ANALYZE, BUFFERS)`)**:
   - Inspect `Buffers: shared hit=... read=...` and verify index usage (`Index Scan` / `Index Only Scan` vs. unintended `Seq Scan` on large tables).
   - Design composite indexes following the **ESR Rule**: **E**quality predicates first, **S**ort columns second, **R**ange predicates last, plus `INCLUDE (...)` covering columns for Index-Only Scans.
2. **Declarative Table Partitioning**:
   - Partition high-growth time-series/audit/ledger tables by range (`PARTITION BY RANGE (created_at)`) or multi-tenant tables by hash (`PARTITION BY HASH (tenant_id)`) so partition pruning skips irrelevant partitions and old partitions can be detached/archived (`ALTER TABLE ... DETACH PARTITION ... CONCURRENTLY`) without `DELETE` vacuum overhead.
3. **CTEs & Window Functions**:
   ```sql
   -- Running account balance & per-tenant top-N query using Window Functions and CTEs
   WITH ranked_transactions AS (
       SELECT
           id,
           tenant_id,
           account_id,
           amount_minor,
           created_at,
           SUM(amount_minor) OVER (
               PARTITION BY account_id
               ORDER BY created_at ASC, id ASC
               ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
           ) AS running_balance_minor,
           ROW_NUMBER() OVER (
               PARTITION BY tenant_id
               ORDER BY amount_minor DESC
           ) AS rank_in_tenant
       FROM ledger_entries
       WHERE tenant_id = $1
         AND created_at >= $2
   )
   SELECT * FROM ranked_transactions WHERE rank_in_tenant <= 10;
   ```

---

## 7. Multi-Tenancy Architecture (RLS Pool, Schema-per-Tenant, DB-per-Tenant)

| Model | Isolation Mechanism | Best For | Mandatory Safeguards |
| :--- | :--- | :--- | :--- |
| **1. Pool Model (Shared Schema + RLS)** | `tenant_id UUID NOT NULL` on every table + PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`) | High-scale B2B SaaS (`100` to `1,000,000+` tenants) | Set transaction-scoped context (`SET LOCAL app.current_tenant_id = '...';`) at the start of every DB transaction so leaked pooled connections never retain another tenant's context. |
| **2. Bridge Model (Schema-per-Tenant)** | Separate PostgreSQL schema (`tenant_abc.orders`) inside shared cluster | Moderate tenant counts (`50–500`) needing custom extensions | Automate parallel schema migration runners and cap total table count per cluster to avoid catalog bloat. |
| **3. Silo Model (Database-per-Tenant)** | Dedicated DB instance/database per enterprise tenant | Regulated healthcare/financial enterprises requiring CMEK & data residency | Tenant routing lookup registry cached in Redis + per-tenant connection pool manager. |

```sql
-- PostgreSQL Row-Level Security (RLS) Enforcement Template
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY; -- Applies even to table owner!

CREATE POLICY tenant_isolation_policy ON orders
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
```

---

## 8. Search Infrastructure (Elasticsearch / OpenSearch / Meilisearch & Hybrid Vector Search)

- **Index Sync via Committed Outbox**: Never update Elasticsearch/Meilisearch synchronously inside user HTTP requests. Consume committed `outbox_events` and bulk-index (`_bulk` API) with explicit document `_id` and `_version_type: external` (`version` column from PostgreSQL) so out-of-order events can never overwrite newer documents.
- **Zero-Downtime Reindexing via Index Aliases**:
  - Application queries always target an alias (`products_read`) rather than a physical index name.
  - When changing analyzer/mapping settings: create `products_v2`, backfill from PostgreSQL, then atomically swap the alias (`remove products_v1`, `add products_v2`).
- **Hybrid Lexical + Semantic Search (Reciprocal Rank Fusion — RRF)**:
  Combine BM25 keyword scores with vector cosine similarity (`pgvector` HNSW index) using RRF:
  $$\text{RRF\_Score}(d) = \frac{1}{k + \text{rank}_{\text{BM25}}(d)} + \frac{1}{k + \text{rank}_{\text{vector}}(d)} \quad (k = 60)$$
