# Module 07: Event-Driven Architecture, WebSockets, SSE, Durable Sagas, Zero-Downtime Migrations & Multi-Tenancy

This module covers event streaming, WebSocket/SSE framing, **crash-recoverable durable Saga orchestration** (replacing volatile in-memory `completedSteps` arrays with persistent step state), **Expand-and-Contract zero-downtime migrations** with compatibility checks, batched backfills, and rollback plans, plus PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`).

---

## 1. Threat Model, Trust Boundaries & Failure Behavior

| Component | Threat / Failure Vector | Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **Saga Orchestrator (`runOrResumeDurableSaga`)** | Tracking `completedSteps` only in a local JavaScript array loses all progress if the orchestrator pod crashes after Step 1 completes, leaving reserved funds/inventory stranded forever. | Persistent `saga_instances` & `saga_step_logs` tables (`DurableSagaStateStore`). | On restart/resume, loads persisted step history, skips already-completed forward steps, and compensates all completed steps in reverse order with idempotency keys. |
| **SSE Stream Formatter (`formatSseFrame`)** | Injecting `\r` or `\n` into `id` or `event` forges arbitrary SSE frames (`event: admin_override`). | Outbound SSE serializer. | Rejects `\r`, `\n`, and `\0` in `id`/`event` and splits `data` across all WHATWG line endings (`\r\n`, `\r`, `\n`). |
| **Zero-Downtime Migrations** | Running `ALTER TABLE ADD COLUMN ... NOT NULL` without a default or running `CREATE INDEX` without `CONCURRENTLY` acquires an `ACCESS EXCLUSIVE` / `SHARE` lock that blocks all production traffic. | CI migration linter & `SET lock_timeout = '2s'`. | Aborts DDL immediately after `2s` if lock cannot be acquired; enforces 4-phase Expand-and-Contract with batched backfill. |

---

## 2. Event-Driven Architecture & SSE Frame Injection Defense

```typescript
export const SSE_RESPONSE_HEADERS: Record<string, string> = {
  'Content-Type': 'text/event-stream; charset=utf-8',
  'Cache-Control': 'no-cache, no-transform',
  Connection: 'keep-alive',
  'X-Accel-Buffering': 'no',
};

export function formatSseFrame(params: {
  id: string;
  event: string;
  data: unknown;
  retryMs?: number;
}): string {
  if (/[\r\n\0]/.test(params.id) || /[\r\n\0]/.test(params.event)) {
    throw new Error('SSE_FRAME_INJECTION_BLOCKED: CR, LF, and Null characters are forbidden in id/event');
  }
  const lines: string[] = [];
  lines.push(`id: ${params.id}`);
  lines.push(`event: ${params.event}`);
  if (params.retryMs !== undefined) {
    if (!Number.isInteger(params.retryMs) || params.retryMs < 0) {
      throw new Error('SSE_INVALID_RETRY_MS');
    }
    lines.push(`retry: ${params.retryMs}`);
  }
  const serialized = JSON.stringify(params.data) ?? 'null';
  for (const line of serialized.split(/\r\n|\r|\n/)) {
    lines.push(`data: ${line}`);
  }
  return lines.join('\n') + '\n\n';
}
```

---

## 3. Remediated Durable Saga Orchestrator (Crash Recovery, Resumability & Idempotent Compensation)

### Why In-Memory `completedSteps` Is Not Durable Saga State
If a saga executes Step 1 (`reserve_inventory`), commits it, and the Node.js process crashes while calling Step 2 (`charge_card`), an in-memory `completedSteps` array vanishes. When a recovery worker picks up the saga, it must read the durable step log from PostgreSQL to know which steps already succeeded and whether the saga is moving forward or compensating backward.

```sql
CREATE TABLE saga_instances (
    saga_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    saga_type VARCHAR(64) NOT NULL,
    status VARCHAR(40) NOT NULL CHECK (status IN (
        'RUNNING_FORWARD',
        'COMPENSATING_BACKWARD',
        'COMPLETED',
        'COMPENSATED_ROLLED_BACK',
        'RECONCILIATION_REQUIRED'
    )),
    context_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE saga_step_logs (
    saga_id UUID NOT NULL REFERENCES saga_instances(saga_id) ON DELETE CASCADE,
    step_index INT NOT NULL,
    step_name VARCHAR(64) NOT NULL,
    status VARCHAR(40) NOT NULL CHECK (status IN (
        'FORWARD_STARTED',
        'FORWARD_COMPLETED',
        'FORWARD_FAILED',
        'FORWARD_AMBIGUOUS_TIMEOUT',
        'COMPENSATING',
        'COMPENSATED',
        'COMPENSATION_FAILED_INTERVENTION_REQUIRED'
    )),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (saga_id, step_index)
);
```

```typescript
export type DurableSagaStatus =
  | 'RUNNING_FORWARD'
  | 'COMPENSATING_BACKWARD'
  | 'COMPLETED'
  | 'COMPENSATED_ROLLED_BACK'
  | 'RECONCILIATION_REQUIRED';

export type DurableStepStatus =
  | 'FORWARD_STARTED'
  | 'FORWARD_COMPLETED'
  | 'FORWARD_FAILED'
  | 'FORWARD_AMBIGUOUS_TIMEOUT'
  | 'COMPENSATING'
  | 'COMPENSATED'
  | 'COMPENSATION_FAILED_INTERVENTION_REQUIRED';

export interface SagaStepDefinition<TContext> {
  stepName: string;
  stepTimeoutMs?: number;
  executeForward: (ctx: TContext, idempotencyKey: string, signal: AbortSignal) => Promise<void>;
  compensateBackward?: (ctx: TContext, idempotencyKey: string, signal: AbortSignal) => Promise<void>;
}

export interface PersistedSagaStepRecord {
  stepIndex: number;
  stepName: string;
  status: DurableStepStatus;
}

export interface DurableSagaStateStore<TContext> {
  loadOrCreateSagaInstance(params: {
    sagaId: string;
    tenantId: string;
    sagaType: string;
    initialContext: TContext;
  }): Promise<{
    sagaStatus: DurableSagaStatus;
    context: TContext;
    steps: ReadonlyArray<PersistedSagaStepRecord>;
  }>;

  recordStepStatus(
    sagaId: string,
    stepIndex: number,
    stepName: string,
    status: DurableStepStatus
  ): Promise<void>;

  updateSagaStatus(sagaId: string, status: DurableSagaStatus): Promise<void>;
}

export class SagaAmbiguousStepTimeoutError extends Error {
  public readonly isAmbiguousTimeout = true;
  constructor(message: string) {
    super(message);
  }
}

/**
 * Durable, Crash-Recoverable Saga Orchestrator:
 * - Persists every step state transition before and after execution.
 * - On crash recovery, loads persisted steps from DurableSagaStateStore, skips already FORWARD_COMPLETED steps,
 *   or resumes backward compensation for all FORWARD_COMPLETED / COMPENSATING steps in reverse order.
 */
export async function runOrResumeDurableSaga<TContext>(params: {
  sagaId: string;
  tenantId: string;
  sagaType: string;
  initialContext: TContext;
  steps: readonly SagaStepDefinition<TContext>[];
  store: DurableSagaStateStore<TContext>;
  maxCompensationAttempts?: number;
}): Promise<{ finalStatus: DurableSagaStatus }> {
  const maxCompAttempts = params.maxCompensationAttempts ?? 3;
  const loaded = await params.store.loadOrCreateSagaInstance({
    sagaId: params.sagaId,
    tenantId: params.tenantId,
    sagaType: params.sagaType,
    initialContext: params.initialContext,
  });

  if (loaded.sagaStatus === 'COMPLETED' || loaded.sagaStatus === 'COMPENSATED_ROLLED_BACK') {
    return { finalStatus: loaded.sagaStatus };
  }
  if (loaded.sagaStatus === 'RECONCILIATION_REQUIRED') {
    return { finalStatus: 'RECONCILIATION_REQUIRED' };
  }

  const stepMap = new Map<number, PersistedSagaStepRecord>();
  for (const s of loaded.steps) {
    stepMap.set(s.stepIndex, s);
  }

  let shouldCompensate = loaded.sagaStatus === 'COMPENSATING_BACKWARD';

  // Phase 1: Forward execution (resumes from the first non-completed step)
  if (!shouldCompensate) {
    for (let i = 0; i < params.steps.length; i++) {
      const step = params.steps[i];
      const existing = stepMap.get(i);

      if (existing?.status === 'FORWARD_COMPLETED') {
        continue; // Already completed before crash; skip!
      }

      await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_STARTED');
      const timeoutMs = step.stepTimeoutMs ?? 10_000;
      const controller = new AbortController();
      const timer = setTimeout(
        () => controller.abort(new SagaAmbiguousStepTimeoutError(`Step ${step.stepName} timed out`)),
        timeoutMs
      );

      try {
        await step.executeForward(
          loaded.context,
          `${params.sagaId}:step:${i}:${step.stepName}:forward`,
          controller.signal
        );
        clearTimeout(timer);
        await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_COMPLETED');
        stepMap.set(i, { stepIndex: i, stepName: step.stepName, status: 'FORWARD_COMPLETED' });
      } catch (err) {
        clearTimeout(timer);
        if (err instanceof SagaAmbiguousStepTimeoutError || (err instanceof Error && 'isAmbiguousTimeout' in err)) {
          // Ambiguous pivot timeout: halt and mark for reconciliation rather than blind compensation/retry
          await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_AMBIGUOUS_TIMEOUT');
          await params.store.updateSagaStatus(params.sagaId, 'RECONCILIATION_REQUIRED');
          return { finalStatus: 'RECONCILIATION_REQUIRED' };
        }
        await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_FAILED');
        stepMap.set(i, { stepIndex: i, stepName: step.stepName, status: 'FORWARD_FAILED' });
        shouldCompensate = true;
        await params.store.updateSagaStatus(params.sagaId, 'COMPENSATING_BACKWARD');
        break;
      }
    }
  }

  if (!shouldCompensate) {
    await params.store.updateSagaStatus(params.sagaId, 'COMPLETED');
    return { finalStatus: 'COMPLETED' };
  }

  // Phase 2: Backward compensation in reverse order across all durable steps that started/completed forward
  let anyCompensationFailed = false;
  for (let i = params.steps.length - 1; i >= 0; i--) {
    const step = params.steps[i];
    const recorded = stepMap.get(i);
    if (!recorded) continue;
    if (recorded.status === 'COMPENSATED') continue;
    if (
      recorded.status !== 'FORWARD_COMPLETED' &&
      recorded.status !== 'FORWARD_STARTED' &&
      recorded.status !== 'COMPENSATING'
    ) {
      continue;
    }
    if (!step.compensateBackward) {
      await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'COMPENSATED');
      continue;
    }

    await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'COMPENSATING');
    let compensated = false;

    for (let attempt = 1; attempt <= maxCompAttempts; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), step.stepTimeoutMs ?? 10_000);
      try {
        await step.compensateBackward(
          loaded.context,
          `${params.sagaId}:step:${i}:${step.stepName}:compensate`,
          controller.signal
        );
        clearTimeout(timer);
        await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'COMPENSATED');
        compensated = true;
        break;
      } catch {
        clearTimeout(timer);
      }
    }

    if (!compensated) {
      anyCompensationFailed = true;
      await params.store.recordStepStatus(
        params.sagaId,
        i,
        step.stepName,
        'COMPENSATION_FAILED_INTERVENTION_REQUIRED'
      );
    }
  }

  const finalStatus: DurableSagaStatus = anyCompensationFailed
    ? 'RECONCILIATION_REQUIRED'
    : 'COMPENSATED_ROLLED_BACK';
  await params.store.updateSagaStatus(params.sagaId, finalStatus);
  return { finalStatus };
}
```

---

## 4. Zero-Downtime Database Migrations (Compatibility Checks, Batched Backfill & Rollback)

### Pre-Migration Compatibility & Rollback Protocol
1. **N-1 Application Compatibility Rule**: Every schema migration deployed before a rolling code rollout MUST be 100% compatible with the currently running `N-1` application version (never drop or rename a column still referenced by running pods).
2. **Lock & Statement Timeouts**:
   ```sql
   SET lock_timeout = '2s';
   SET statement_timeout = '60s';
   ```
3. **4-Phase Expand-and-Contract with Explicit Rollback Plans**:
   - **Phase 1 (Expand)**: Add nullable column (`ALTER TABLE orders ADD COLUMN tax_jurisdiction VARCHAR(32) NULL;`) + `CREATE INDEX CONCURRENTLY`. *Rollback*: `DROP INDEX CONCURRENTLY` and `ALTER TABLE DROP COLUMN` (safe because no code writes to it yet).
   - **Phase 2 (Dual-Write & Checkpointed Batch Backfill)**: Deploy app code that writes to both old and new columns. Run batched backfill (`UPDATE orders SET tax_jurisdiction = 'US' WHERE id > $lastCursor AND tax_jurisdiction IS NULL ORDER BY id ASC LIMIT 2000`). *Rollback*: Revert app deployment to read old column; dual-written data remains intact.
   - **Phase 3 (Validate Constraint & Switch Reads)**: Add `NOT VALID` constraint (`ALTER TABLE orders ADD CONSTRAINT chk_tax_jur_not_null CHECK (tax_jurisdiction IS NOT NULL) NOT VALID; ALTER TABLE orders VALIDATE CONSTRAINT chk_tax_jur_not_null;`) and switch reads. *Rollback*: Revert app to read old column and drop constraint if needed.
   - **Phase 4 (Contract)**: Remove dual-write from code, verify zero queries reference old column, and drop old column in the next release.

---

## 5. Multi-Tenancy PostgreSQL RLS Template

```sql
CREATE ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON orders
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
```

---

## 6. Verification & Test Requirements

1. **Saga Crash Recovery & Resumability Test (`TEST-24`)**:
   - Run a 3-step saga where Step 1 (`reserve_inventory`) completes and persists `'FORWARD_COMPLETED'`, then simulate an orchestrator crash before Step 2. Resume the saga using `runOrResumeDurableSaga` where Step 2 fails: assert Step 1 is **not** re-executed forward, and Step 1's `compensateBackward` is executed and marked `'COMPENSATED'`.
2. **SSE CRLF/CR Frame Injection Test**:
   - Assert `formatSseFrame({ id: '1\r\nevent: pwned', event: 'msg', data: {} })` throws `SSE_FRAME_INJECTION_BLOCKED`.

### Authoritative References
- **Chris Richardson — Saga Pattern & Countermeasures**: https://microservices.io/patterns/data/saga.html
- **PostgreSQL 16 Row Security Policies (`FORCE ROW LEVEL SECURITY`)**: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
