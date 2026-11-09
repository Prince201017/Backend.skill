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
    fencing_token BIGINT NOT NULL DEFAULT 0,
    lease_owner VARCHAR(128) NULL,
    lease_expires_at TIMESTAMPTZ NULL,
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
    fencing_token BIGINT NOT NULL DEFAULT 0,
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

export type PriorStepExecutionStatus =
  | 'CONFIRMED_COMPLETED_DOWNSTREAM'
  | 'CONFIRMED_NEVER_EXECUTED_DOWNSTREAM'
  | 'INDETERMINATE_REQUIRES_RECONCILIATION';

export interface SagaStepDefinition<TContext> {
  stepName: string;
  stepTimeoutMs?: number;
  executeForward: (ctx: TContext, idempotencyKey: string, signal: AbortSignal) => Promise<void>;
  compensateBackward?: (ctx: TContext, idempotencyKey: string, signal: AbortSignal) => Promise<void>;
  /**
   * DEVIL-13 Remediation: When a recovery worker finds a step in 'FORWARD_STARTED' or
   * 'FORWARD_AMBIGUOUS_TIMEOUT', it MUST reconcile downstream side-effect status before
   * deciding whether to mark completed, re-run forward, or halt for reconciliation.
   */
  reconcilePriorExecution?: (
    ctx: TContext,
    idempotencyKey: string,
    signal: AbortSignal
  ) => Promise<PriorStepExecutionStatus>;
}

export interface PersistedSagaStepRecord {
  stepIndex: number;
  stepName: string;
  status: DurableStepStatus;
}

export interface DurableSagaStateStore<TContext> {
  acquireSagaLease(params: {
    sagaId: string;
    tenantId: string;
    sagaType: string;
    workerId: string;
    leaseDurationMs: number;
    initialContext: TContext;
  }): Promise<
    | {
        acquired: true;
        fencingToken: bigint;
        sagaStatus: DurableSagaStatus;
        context: TContext;
        steps: ReadonlyArray<PersistedSagaStepRecord>;
      }
    | {
        acquired: false;
        reason: 'ACTIVE_LEASE_HELD_BY_ANOTHER_WORKER';
      }
  >;

  recordStepStatus(
    sagaId: string,
    stepIndex: number,
    stepName: string,
    status: DurableStepStatus,
    fencingToken: bigint
  ): Promise<void>;

  updateSagaStatus(sagaId: string, status: DurableSagaStatus, fencingToken: bigint): Promise<void>;
}

export class SagaAmbiguousStepTimeoutError extends Error {
  public readonly isAmbiguousTimeout = true;
  constructor(message: string) {
    super(message);
  }
}

/**
 * Durable, Crash-Recoverable Saga Orchestrator (`DEVIL-13` Hardened):
 * - Acquires an exclusive worker lease with a monotonic `fencingToken: bigint` to prevent concurrent recovery split-brain.
 * - Persists every step state transition fenced by `fencingToken`.
 * - If a step is found in `'FORWARD_STARTED'` or `'FORWARD_AMBIGUOUS_TIMEOUT'` during recovery, calls
 *   `step.reconcilePriorExecution()` (if provided) before re-executing; if no reconciler exists or the state
 *   is indeterminate, halts in `'RECONCILIATION_REQUIRED'` instead of blindly re-running or compensating.
 */
export async function runOrResumeDurableSaga<TContext>(params: {
  sagaId: string;
  tenantId: string;
  sagaType: string;
  workerId?: string;
  leaseDurationMs?: number;
  initialContext: TContext;
  steps: readonly SagaStepDefinition<TContext>[];
  store: DurableSagaStateStore<TContext>;
  maxCompensationAttempts?: number;
}): Promise<{ finalStatus: DurableSagaStatus }> {
  const maxCompAttempts = params.maxCompensationAttempts ?? 3;
  const lease = await params.store.acquireSagaLease({
    sagaId: params.sagaId,
    tenantId: params.tenantId,
    sagaType: params.sagaType,
    workerId: params.workerId ?? 'default-saga-worker',
    leaseDurationMs: params.leaseDurationMs ?? 30_000,
    initialContext: params.initialContext,
  });

  if (!lease.acquired) {
    throw new Error(`SAGA_LEASE_CONFLICT: ${lease.reason}`);
  }

  const { fencingToken } = lease;

  if (lease.sagaStatus === 'COMPLETED' || lease.sagaStatus === 'COMPENSATED_ROLLED_BACK') {
    return { finalStatus: lease.sagaStatus };
  }
  if (lease.sagaStatus === 'RECONCILIATION_REQUIRED') {
    return { finalStatus: 'RECONCILIATION_REQUIRED' };
  }

  const stepMap = new Map<number, PersistedSagaStepRecord>();
  for (const s of lease.steps) {
    stepMap.set(s.stepIndex, s);
  }

  let shouldCompensate = lease.sagaStatus === 'COMPENSATING_BACKWARD';

  // Phase 1: Forward execution (resumes from the first non-completed step)
  if (!shouldCompensate) {
    for (let i = 0; i < params.steps.length; i++) {
      const step = params.steps[i];
      const existing = stepMap.get(i);
      const forwardIdempotencyKey = `${params.sagaId}:step:${i}:${step.stepName}:forward`;

      if (existing?.status === 'FORWARD_COMPLETED') {
        continue; // Already completed before crash; skip!
      }

      // DEVIL-13 Fix: If a prior run crashed after recording 'FORWARD_STARTED' or 'FORWARD_AMBIGUOUS_TIMEOUT',
      // never blindly re-run or compensate without reconciling downstream execution status first!
      if (existing?.status === 'FORWARD_STARTED' || existing?.status === 'FORWARD_AMBIGUOUS_TIMEOUT') {
        if (!step.reconcilePriorExecution) {
          await params.store.recordStepStatus(
            params.sagaId,
            i,
            step.stepName,
            'FORWARD_AMBIGUOUS_TIMEOUT',
            fencingToken
          );
          await params.store.updateSagaStatus(params.sagaId, 'RECONCILIATION_REQUIRED', fencingToken);
          return { finalStatus: 'RECONCILIATION_REQUIRED' };
        }

        const reconcileController = new AbortController();
        const reconcileTimer = setTimeout(() => reconcileController.abort(), step.stepTimeoutMs ?? 10_000);
        let priorOutcome: PriorStepExecutionStatus;
        try {
          priorOutcome = await step.reconcilePriorExecution(
            lease.context,
            forwardIdempotencyKey,
            reconcileController.signal
          );
          clearTimeout(reconcileTimer);
        } catch {
          clearTimeout(reconcileTimer);
          priorOutcome = 'INDETERMINATE_REQUIRES_RECONCILIATION';
        }

        if (priorOutcome === 'CONFIRMED_COMPLETED_DOWNSTREAM') {
          await params.store.recordStepStatus(
            params.sagaId,
            i,
            step.stepName,
            'FORWARD_COMPLETED',
            fencingToken
          );
          stepMap.set(i, { stepIndex: i, stepName: step.stepName, status: 'FORWARD_COMPLETED' });
          continue;
        }

        if (priorOutcome === 'INDETERMINATE_REQUIRES_RECONCILIATION') {
          await params.store.recordStepStatus(
            params.sagaId,
            i,
            step.stepName,
            'FORWARD_AMBIGUOUS_TIMEOUT',
            fencingToken
          );
          await params.store.updateSagaStatus(params.sagaId, 'RECONCILIATION_REQUIRED', fencingToken);
          return { finalStatus: 'RECONCILIATION_REQUIRED' };
        }
        // priorOutcome === 'CONFIRMED_NEVER_EXECUTED_DOWNSTREAM': safe to proceed with forward execution below
      }

      await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_STARTED', fencingToken);
      const timeoutMs = step.stepTimeoutMs ?? 10_000;
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeoutPromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const timeoutErr = new SagaAmbiguousStepTimeoutError(`Step ${step.stepName} timed out`);
          controller.abort(timeoutErr);
          reject(timeoutErr);
        }, timeoutMs);
      });

      try {
        await Promise.race([
          step.executeForward(lease.context, forwardIdempotencyKey, controller.signal),
          timeoutPromise,
        ]);
        if (timer) clearTimeout(timer);
        await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_COMPLETED', fencingToken);
        stepMap.set(i, { stepIndex: i, stepName: step.stepName, status: 'FORWARD_COMPLETED' });
      } catch (err) {
        if (timer) clearTimeout(timer);
        const isTimeoutAbort =
          controller.signal.aborted ||
          err instanceof SagaAmbiguousStepTimeoutError ||
          (err instanceof Error && ('isAmbiguousTimeout' in err || err.name === 'AbortError'));
        if (isTimeoutAbort) {
          // Ambiguous pivot timeout: halt and mark for reconciliation rather than blind compensation/retry
          await params.store.recordStepStatus(
            params.sagaId,
            i,
            step.stepName,
            'FORWARD_AMBIGUOUS_TIMEOUT',
            fencingToken
          );
          await params.store.updateSagaStatus(params.sagaId, 'RECONCILIATION_REQUIRED', fencingToken);
          return { finalStatus: 'RECONCILIATION_REQUIRED' };
        }
        await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'FORWARD_FAILED', fencingToken);
        stepMap.set(i, { stepIndex: i, stepName: step.stepName, status: 'FORWARD_FAILED' });
        shouldCompensate = true;
        await params.store.updateSagaStatus(params.sagaId, 'COMPENSATING_BACKWARD', fencingToken);
        break;
      }
    }
  }

  if (!shouldCompensate) {
    await params.store.updateSagaStatus(params.sagaId, 'COMPLETED', fencingToken);
    return { finalStatus: 'COMPLETED' };
  }

  // Phase 2: Backward compensation in reverse order across all durable steps that completed forward
  let anyCompensationFailed = false;
  for (let i = params.steps.length - 1; i >= 0; i--) {
    const step = params.steps[i];
    const recorded = stepMap.get(i);
    if (!recorded) continue;
    if (recorded.status === 'COMPENSATED') continue;
    if (recorded.status === 'FORWARD_STARTED' || recorded.status === 'FORWARD_AMBIGUOUS_TIMEOUT') {
      // Never blindly compensate an unconfirmed step without reconciling first
      anyCompensationFailed = true;
      continue;
    }
    if (recorded.status !== 'FORWARD_COMPLETED' && recorded.status !== 'COMPENSATING') {
      continue;
    }
    if (!step.compensateBackward) {
      await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'COMPENSATED', fencingToken);
      continue;
    }

    await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'COMPENSATING', fencingToken);
    let compensated = false;

    for (let attempt = 1; attempt <= maxCompAttempts; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), step.stepTimeoutMs ?? 10_000);
      try {
        await step.compensateBackward(
          lease.context,
          `${params.sagaId}:step:${i}:${step.stepName}:compensate`,
          controller.signal
        );
        clearTimeout(timer);
        await params.store.recordStepStatus(params.sagaId, i, step.stepName, 'COMPENSATED', fencingToken);
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
        'COMPENSATION_FAILED_INTERVENTION_REQUIRED',
        fencingToken
      );
    }
  }

  const finalStatus: DurableSagaStatus = anyCompensationFailed
    ? 'RECONCILIATION_REQUIRED'
    : 'COMPENSATED_ROLLED_BACK';
  await params.store.updateSagaStatus(params.sagaId, finalStatus, fencingToken);
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
   - **Phase 1 (Expand)**: Add nullable column (`ALTER TABLE public.orders ADD COLUMN tax_jurisdiction VARCHAR(32) NULL;`) + `CREATE INDEX CONCURRENTLY`. *Rollback*: `DROP INDEX CONCURRENTLY` and `ALTER TABLE DROP COLUMN` (safe because no code writes to it yet).
   - **Phase 2 (Dual-Write & Checkpointed Batch Backfill — `DEVIL-62` Remediated)**: Deploy app code that writes to both old and new columns. Because standard PostgreSQL forbids `ORDER BY` and `LIMIT` directly on an `UPDATE` statement, execute the checkpointed batch backfill using a CTE with `ORDER BY id ASC LIMIT 2000 FOR UPDATE SKIP LOCKED`:
     ```sql
     WITH batch AS (
       SELECT id
       FROM public.orders
       WHERE id > $1
         AND tax_jurisdiction IS NULL
       ORDER BY id ASC
       LIMIT 2000
       FOR UPDATE SKIP LOCKED
     )
     UPDATE public.orders AS o
     SET tax_jurisdiction = 'US'
     FROM batch
     WHERE o.id = batch.id
     RETURNING o.id;
     ```
     *Rollback*: Revert app deployment to read old column; dual-written data remains intact.
   - **Phase 3 (Validate Constraint & Switch Reads)**: Add `NOT VALID` constraint (`SET lock_timeout = '2s'; ALTER TABLE public.orders ADD CONSTRAINT chk_tax_jur_not_null CHECK (tax_jurisdiction IS NOT NULL) NOT VALID; SET statement_timeout = '30min'; ALTER TABLE public.orders VALIDATE CONSTRAINT chk_tax_jur_not_null;`) and switch reads. *Rollback*: Revert app to read old column and drop constraint if needed.
   - **Phase 4 (Contract)**: Remove dual-write from code, verify zero queries reference old column, and drop old column in the next release.

---

## 5. Multi-Tenancy PostgreSQL RLS Architecture, Cryptographic MAC Verification & Bootstrap Isolation (`DEVIL-01` & `DEVIL-02` Remediated)

### Explicit Threat Model & Cryptographic GUC Binding
1. **Why Plain `current_setting('app.current_tenant_id')` Is Vulnerable (`DEVIL-01`)**:
   In PostgreSQL, any role can call `SELECT set_config('app.current_tenant_id', '<victim_uuid>', true)`. If an application query has a SQL injection flaw or an unvalidated helper sets `app.current_tenant_id` without a transaction-bound HMAC, an attacker can switch tenants mid-transaction.
2. **Database-Side Cryptographic Verification (`security.verify_active_tenant_context` & `security.verify_active_user_context`)**:
   - A restricted schema `security` owned by `db_migrator` holds the HMAC verification key in a protected table (`security.guc_hmac_keys`) inaccessible to `app_runtime`.
   - `security.verify_active_tenant_context(target_tenant_id uuid)` and `security.verify_active_user_context(target_user_id uuid)` are `SECURITY DEFINER` functions with `SET search_path = pg_catalog, public` that recompute `encode(extensions.hmac(target_id::text || ':' || txid_current()::text, secret_key, 'sha256'), 'hex')` and compare it in constant time (`security.constant_time_hex_equal_32`) to `current_setting('app.current_tenant_mac', true)` / `current_setting('app.current_user_mac', true)`.
   - Every RLS policy on `public.tenant_members` and tenant domain tables (`public.orders`, etc.) calls these verification functions so raw `set_config('app.current_tenant_id', ...)` without a matching `txid_current()`-bound HMAC is rejected fail-closed!

```sql
SET lock_timeout = '3s';
SET statement_timeout = '10s';

CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

-- 1. Dedicated Migration Owner vs. Least-Privilege Runtime Role (Idempotent for Clean DB Install)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_migrator') THEN
    CREATE ROLE db_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
    CREATE ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_runtime;

-- 1b. Prerequisite Base Domain Tables & Tenant-Bounded Search Index
CREATE TABLE IF NOT EXISTS public.tenants (
    id UUID PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DELETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS public.tenant_members (
    tenant_id UUID NOT NULL REFERENCES public.tenants (id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'BILLING_ADMIN', 'MEMBER', 'READONLY')),
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.orders (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES public.tenants (id) ON DELETE RESTRICT,
    customer_user_id UUID NOT NULL,
    order_number VARCHAR(64) NOT NULL,
    tax_jurisdiction VARCHAR(32) NOT NULL DEFAULT 'US',
    total_minor BIGINT NOT NULL CHECK (total_minor >= 0),
    currency_code CHAR(3) NOT NULL DEFAULT 'USD',
    search_vector tsvector GENERATED ALWAYS AS (
      to_tsvector('simple', coalesce(order_number, '') || ' ' || coalesce(tax_jurisdiction, ''))
    ) STORED,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, order_number)
);

CREATE INDEX IF NOT EXISTS idx_orders_tenant_created_at
  ON public.orders (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_orders_tenant_search_gin
  ON public.orders USING GIN (search_vector);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.tenants, public.tenant_members, public.orders TO app_runtime;

-- 2. Restricted Security Schema & Protected HMAC Key Table (Inaccessible to app_runtime)
CREATE SCHEMA IF NOT EXISTS security AUTHORIZATION db_migrator;
REVOKE ALL ON SCHEMA security FROM PUBLIC;
GRANT USAGE ON SCHEMA security TO app_runtime;

CREATE TABLE IF NOT EXISTS security.guc_hmac_keys (
    key_id INT PRIMARY KEY DEFAULT 1 CHECK (key_id = 1),
    hmac_secret TEXT NOT NULL CHECK (char_length(hmac_secret) >= 32)
);
REVOKE ALL ON TABLE security.guc_hmac_keys FROM PUBLIC;
REVOKE ALL ON TABLE security.guc_hmac_keys FROM app_runtime;

CREATE OR REPLACE FUNCTION security.constant_time_hex_equal_32(expected_hex TEXT, actual_hex TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
  v_expected BYTEA;
  v_actual BYTEA;
  v_diff INT := 0;
  v_i INT;
BEGIN
  IF expected_hex IS NULL OR actual_hex IS NULL THEN
    RETURN FALSE;
  END IF;
  IF pg_catalog.char_length(expected_hex) <> 64 OR pg_catalog.char_length(actual_hex) <> 64 THEN
    RETURN FALSE;
  END IF;
  IF expected_hex !~ '^[0-9a-fA-F]{64}$' OR actual_hex !~ '^[0-9a-fA-F]{64}$' THEN
    RETURN FALSE;
  END IF;
  v_expected := pg_catalog.decode(expected_hex, 'hex');
  v_actual := pg_catalog.decode(actual_hex, 'hex');
  IF pg_catalog.octet_length(v_expected) <> 32 OR pg_catalog.octet_length(v_actual) <> 32 THEN
    RETURN FALSE;
  END IF;
  FOR v_i IN 0..31 LOOP
    v_diff := v_diff | (pg_catalog.get_byte(v_expected, v_i) # pg_catalog.get_byte(v_actual, v_i));
  END LOOP;
  RETURN v_diff = 0;
END;
$$;

CREATE OR REPLACE FUNCTION security.verify_active_user_context(row_user_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_user_id TEXT;
  v_user_mac TEXT;
  v_secret TEXT;
  v_expected_mac TEXT;
BEGIN
  v_user_id := NULLIF(current_setting('app.current_user_id', true), '');
  v_user_mac := NULLIF(current_setting('app.current_user_mac', true), '');
  IF v_user_id IS NULL OR v_user_mac IS NULL OR row_user_id IS NULL THEN
    RETURN FALSE;
  END IF;
  IF v_user_id::uuid <> row_user_id THEN
    RETURN FALSE;
  END IF;
  SELECT hmac_secret INTO v_secret FROM security.guc_hmac_keys WHERE key_id = 1;
  IF v_secret IS NULL OR char_length(v_secret) < 32 THEN
    RETURN FALSE;
  END IF;
  v_expected_mac := encode(
    extensions.hmac(
      convert_to('user:' || v_user_id || ':' || txid_current()::text, 'UTF8'),
      convert_to(v_secret, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
  RETURN security.constant_time_hex_equal_32(v_expected_mac, v_user_mac);
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION security.verify_active_tenant_context(row_tenant_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_tenant_id TEXT;
  v_tenant_mac TEXT;
  v_secret TEXT;
  v_expected_mac TEXT;
BEGIN
  v_tenant_id := NULLIF(current_setting('app.current_tenant_id', true), '');
  v_tenant_mac := NULLIF(current_setting('app.current_tenant_mac', true), '');
  IF v_tenant_id IS NULL OR v_tenant_mac IS NULL OR row_tenant_id IS NULL THEN
    RETURN FALSE;
  END IF;
  IF v_tenant_id::uuid <> row_tenant_id THEN
    RETURN FALSE;
  END IF;
  SELECT hmac_secret INTO v_secret FROM security.guc_hmac_keys WHERE key_id = 1;
  IF v_secret IS NULL OR char_length(v_secret) < 32 THEN
    RETURN FALSE;
  END IF;
  v_expected_mac := encode(
    extensions.hmac(
      convert_to(v_tenant_id || ':' || txid_current()::text, 'UTF8'),
      convert_to(v_secret, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
  RETURN security.constant_time_hex_equal_32(v_expected_mac, v_tenant_mac);
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
$$;

REVOKE ALL ON FUNCTION security.constant_time_hex_equal_32(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION security.verify_active_user_context(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION security.verify_active_tenant_context(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.verify_active_user_context(UUID) TO app_runtime;
GRANT EXECUTE ON FUNCTION security.verify_active_tenant_context(UUID) TO app_runtime;

-- 3. Solve the tenant_members Bootstrap Paradox Securely (DEVIL-02 Remediation):
-- During withTenantTransaction() bootstrap, ONLY app.current_user_id + app.current_user_mac are set
-- while app.current_tenant_id remains empty (''). This policy verifies the cryptographic MAC on
-- app.current_user_id (for self-membership lookup) OR app.current_tenant_id (after tenant activation).
ALTER TABLE public.tenant_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_members FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_members_self_or_active_tenant_policy ON public.tenant_members
  FOR SELECT
  TO app_runtime
  USING (
    security.verify_active_user_context(user_id)
    OR security.verify_active_tenant_context(tenant_id)
  );

-- 4. Strict Cryptographic Tenant Isolation Policy on Domain Tables (Fail-Closed on Missing/Forged MAC)
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON public.orders
  AS RESTRICTIVE
  FOR ALL
  TO app_runtime
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));
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
