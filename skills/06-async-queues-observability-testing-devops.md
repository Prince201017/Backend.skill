# Module 06: Lease-Safe Asynchronous Job Queues,Fenced Heartbeats, Crash Recovery & Observability

This module provides production blueprints for lease-safe background job processing (validating due time and attempt limits during atomic acquisition, explicit heartbeat failure handling with lease-deadline fencing so stale workers never continue committing results, cooperative cancellation, and DLQ replay) alongside expanded recursive secret redaction in structured JSON logs.

---

## 1. Threat Model, Trust Boundaries & Failure Behavior

| Component | Threat / Failure Vector | Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **Job Acquisition (`acquireJobLease`)** | Acquiring a job without checking `next_run_at <= clock_timestamp()` or `attempt < max_attempts` runs backoff jobs prematurely or loops dead-letter jobs indefinitely. | PostgreSQL `UPDATE ... WHERE` acquisition query & `JobLeaseManager`. | Rejects acquisition if `next_run_at > now` or `attempt >= max_attempts`. |
| **Worker Lease Heartbeat (`executeQueueWorkerJob`)** | Swallowing heartbeat exceptions in `catch {}` allows a network-partitioned worker to keep executing past `lease_expires_at` while a second worker reclaims the job, resulting in duplicate side effects. | Worker heartbeat loop & `markJobCompleted` fencing check. | Tracks `leaseDeadlineMs`; aborts `AbortController` immediately if `renewJobLease` returns `false` OR if heartbeat errors prevent renewal within the safety window; blocks `markJobCompleted` when aborted or when `fencing_token` mismatches. |
| **Structured Logger (`redactSensitiveFields`)** | Exact-match key regex (`^password$`) misses `passwordHash`, `x-api-key`, `clientSecret`, or `refreshToken`. | Log serializer boundary. | Matches normalized substring patterns across keys and redacts JWTs, API keys, PEM keys, Basic Auth, and PANs in string values. |

---

## 2. Atomic Job Acquisition with Due-Time, Max-Attempt & Fencing Enforcement

```sql
CREATE TABLE background_jobs (
    job_id UUID PRIMARY KEY,
    job_type VARCHAR(64) NOT NULL,
    tenant_id UUID NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED_RETRYABLE', 'DEAD_LETTER')),
    lease_owner VARCHAR(128) NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5 CHECK (max_attempts >= 1),
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_error TEXT NULL,
    result_summary JSONB NULL,
    traceparent VARCHAR(128) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_jobs_runnable
ON background_jobs (next_run_at ASC)
WHERE status IN ('QUEUED', 'FAILED_RETRYABLE', 'IN_PROGRESS');

-- Atomic Lease Acquisition Query:
-- Enforces due time (next_run_at <= clock_timestamp()), attempt ceiling (attempt < max_attempts),
-- and expired-lease crash recovery, incrementing fencing_token monotonically.
UPDATE background_jobs
SET status = 'IN_PROGRESS',
    lease_owner = $2,
    lease_expires_at = clock_timestamp() + ($3::bigint * interval '1 millisecond'),
    fencing_token = fencing_token + 1,
    attempt = attempt + 1
WHERE job_id = $1
  AND attempt < max_attempts
  AND (
    (status IN ('QUEUED', 'FAILED_RETRYABLE') AND next_run_at <= clock_timestamp())
    OR (status = 'IN_PROGRESS' AND lease_expires_at < clock_timestamp())
  )
RETURNING fencing_token, attempt, max_attempts, EXTRACT(EPOCH FROM lease_expires_at) * 1000 AS lease_expires_at_ms;
```

---

## 3. Remediated Worker Harness with Explicit Heartbeat Failure Handling & Fencing

```typescript
export interface AsyncJobEnvelope<TPayload> {
  jobId: string;
  jobType: string;
  tenantId: string;
  actorUserId: string;
  traceparent: string;
  attempt: number;
  maxAttempts: number;
  createdAtUtc: string;
  payload: TPayload;
}

export type JobAcquisitionResult =
  | { status: 'ALREADY_COMPLETED' }
  | { status: 'NOT_YET_DUE'; nextRunAtMs: number }
  | { status: 'EXHAUSTED_MAX_ATTEMPTS' }
  | { status: 'IN_PROGRESS'; currentLeaseOwner: string; leaseExpiresAt: string }
  | {
      status: 'ACQUIRED';
      fencingToken: bigint;
      attempt: number;
      maxAttempts: number;
      leaseDeadlineMs: number;
    };

export interface JobLeaseManager {
  acquireJobLease(
    jobId: string,
    workerInstanceId: string,
    leaseDurationMs: number,
    nowMs?: number
  ): Promise<JobAcquisitionResult>;

  renewJobLease(
    jobId: string,
    workerInstanceId: string,
    fencingToken: bigint,
    leaseDurationMs: number,
    nowMs?: number
  ): Promise<{ renewed: boolean; newLeaseDeadlineMs?: number }>;

  markJobCompleted(params: {
    jobId: string;
    workerInstanceId: string;
    fencingToken: bigint;
    durationMs: number;
  }): Promise<boolean>;

  markJobFailedOrDeadLetter(params: {
    jobId: string;
    workerInstanceId: string;
    fencingToken: bigint;
    attempt: number;
    maxAttempts: number;
    errorReason: string;
    nextRunDelayMs: number;
  }): Promise<'SCHEDULED_RETRY' | 'MOVED_TO_DLQ' | 'STALE_WORKER_IGNORED'>;

  replayDeadLetterJob(jobId: string, operatorUserId: string): Promise<void>;
}

export async function executeQueueWorkerJob<TPayload>(
  envelope: AsyncJobEnvelope<TPayload>,
  workerInstanceId: string,
  leaseDurationMs: number,
  deps: {
    leaseManager: JobLeaseManager;
    logger: StructuredLogger;
  },
  handler: (
    payload: TPayload,
    ctx: { signal: AbortSignal; fencingToken: bigint; assertLeaseValid: () => void }
  ) => Promise<void>
): Promise<
  | 'COMPLETED'
  | 'SKIPPED_COMPLETED'
  | 'SKIPPED_IN_PROGRESS'
  | 'SKIPPED_NOT_YET_DUE'
  | 'SKIPPED_EXHAUSTED'
> {
  const startNs = process.hrtime.bigint();
  const acquisition = await deps.leaseManager.acquireJobLease(
    envelope.jobId,
    workerInstanceId,
    leaseDurationMs
  );

  if (acquisition.status === 'ALREADY_COMPLETED') {
    return 'SKIPPED_COMPLETED';
  }
  if (acquisition.status === 'IN_PROGRESS') {
    return 'SKIPPED_IN_PROGRESS';
  }
  if (acquisition.status === 'NOT_YET_DUE') {
    return 'SKIPPED_NOT_YET_DUE';
  }
  if (acquisition.status === 'EXHAUSTED_MAX_ATTEMPTS') {
    return 'SKIPPED_EXHAUSTED';
  }

  const { fencingToken, attempt, maxAttempts } = acquisition;
  let currentLeaseDeadlineMs = acquisition.leaseDeadlineMs;
  let consecutiveHeartbeatFailures = 0;

  const abortController = new AbortController();
  const heartbeatIntervalMs = Math.max(100, Math.floor(leaseDurationMs / 3));

  const assertLeaseValid = () => {
    if (abortController.signal.aborted) {
      throw abortController.signal.reason instanceof Error
        ? abortController.signal.reason
        : new Error('JOB_LEASE_ABORTED');
    }
    if (Date.now() >= currentLeaseDeadlineMs) {
      const err = new Error('JOB_LEASE_DEADLINE_EXPIRED');
      abortController.abort(err);
      throw err;
    }
  };

  const heartbeatTimer = setInterval(async () => {
    try {
      const res = await deps.leaseManager.renewJobLease(
        envelope.jobId,
        workerInstanceId,
        fencingToken,
        leaseDurationMs
      );
      if (!res.renewed) {
        const lostErr = new Error('JOB_LEASE_LOST_FENCING_REJECTED');
        deps.logger.error('Worker lost job lease ownership; aborting handler', {
          jobId: envelope.jobId,
          workerInstanceId,
          fencingToken: fencingToken.toString(),
        });
        abortController.abort(lostErr);
        return;
      }
      consecutiveHeartbeatFailures = 0;
      if (res.newLeaseDeadlineMs !== undefined) {
        currentLeaseDeadlineMs = res.newLeaseDeadlineMs;
      } else {
        currentLeaseDeadlineMs = Date.now() + leaseDurationMs;
      }
    } catch (hbErr) {
      consecutiveHeartbeatFailures += 1;
      const safetyCutoffMs = currentLeaseDeadlineMs - Math.floor(heartbeatIntervalMs / 2);
      // CRITICAL: Never ignore persistent heartbeat failures! Abort before the lease expires so a stale worker stops.
      if (consecutiveHeartbeatFailures >= 2 || Date.now() >= safetyCutoffMs) {
        const failErr = new Error(
          `JOB_LEASE_HEARTBEAT_FAILED: ${hbErr instanceof Error ? hbErr.message : String(hbErr)}`
        );
        deps.logger.error('Worker heartbeat renewal failed past safety threshold; aborting handler', {
          jobId: envelope.jobId,
          workerInstanceId,
          fencingToken: fencingToken.toString(),
          consecutiveHeartbeatFailures,
        });
        abortController.abort(failErr);
      }
    }
  }, heartbeatIntervalMs);

  try {
    await handler(envelope.payload, {
      signal: abortController.signal,
      fencingToken,
      assertLeaseValid,
    });

    // Verify lease is still valid and unaborted BEFORE attempting to commit completion!
    assertLeaseValid();

    const durationMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);
    const committed = await deps.leaseManager.markJobCompleted({
      jobId: envelope.jobId,
      workerInstanceId,
      fencingToken,
      durationMs,
    });

    if (!committed) {
      throw new Error('FENCING_TOKEN_REJECTED_ON_COMPLETE');
    }

    return 'COMPLETED';
  } catch (err) {
    const errorReason = err instanceof Error ? err.message : String(err);

    // If the worker lost its lease or fencing token, do NOT overwrite the new lease owner's state!
    if (
      errorReason === 'FENCING_TOKEN_REJECTED_ON_COMPLETE' ||
      errorReason === 'JOB_LEASE_LOST_FENCING_REJECTED' ||
      errorReason === 'JOB_LEASE_DEADLINE_EXPIRED'
    ) {
      throw err;
    }

    const capMs = 300_000;
    const baseDelayMs = Math.min(capMs, 1000 * 2 ** attempt);
    const jitteredDelayMs = Math.floor(Math.random() * baseDelayMs);

    await deps.leaseManager.markJobFailedOrDeadLetter({
      jobId: envelope.jobId,
      workerInstanceId,
      fencingToken,
      attempt,
      maxAttempts,
      errorReason,
      nextRunDelayMs: jitteredDelayMs,
    });

    throw err;
  } finally {
    clearInterval(heartbeatTimer);
  }
}
```

---

## 4. Observability: Expanded Recursive Secret Redaction & Structured JSON Logger

```typescript
/**
 * Matches sensitive field names across camelCase, snake_case, kebab-case, and HTTP headers
 * (e.g., passwordHash, x-api-key, clientSecret, refreshToken, authorization, cvvCode, otpCode).
 */
export function isSensitiveFieldName(rawKey: string): boolean {
  const normalized = rawKey.toLowerCase().replace(/[^a-z0-9]/g, '');
  const sensitiveSubstrings = [
    'password',
    'passcode',
    'passwd',
    'secret',
    'token',
    'apikey',
    'authorization',
    'cookie',
    'sessionid',
    'privatekey',
    'cvv',
    'cvc',
    'cardnumber',
    'pan',
    'ssn',
    'taxid',
    'otp',
    'pin',
    'pepper',
    'signature',
  ];
  return sensitiveSubstrings.some((sub) => normalized.includes(sub));
}

export function redactSensitiveFields(
  obj: unknown,
  depth = 0,
  seen: WeakSet<object> = new WeakSet()
): unknown {
  if (depth > 8 || obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    return obj
      .replace(/Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi, 'Bearer [REDACTED_JWT]')
      .replace(/Basic\s+[A-Za-z0-9+/=]{8,}/gi, 'Basic [REDACTED_BASIC_AUTH]')
      .replace(/\b(sk_live_|sk_test_|rk_live_|whsec_)[A-Za-z0-9_]+/g, '[REDACTED_KEY]')
      .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED_PEM_KEY]');
  }
  if (typeof obj !== 'object') return obj;
  if (seen.has(obj)) return '[CIRCULAR_REF]';
  seen.add(obj);

  if (Array.isArray(obj)) {
    return obj.slice(0, 100).map((item) => redactSensitiveFields(item, depth + 1, seen));
  }

  const sanitized: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    sanitized[key] = isSensitiveFieldName(key)
      ? '[REDACTED_SECRET]'
      : redactSensitiveFields(value, depth + 1, seen);
  }
  return { ...sanitized };
}

export class StructuredLogger {
  constructor(
    private readonly serviceName: string,
    private readonly environment: string,
    private readonly version: string
  ) {}

  private write(level: 'INFO' | 'WARN' | 'ERROR', message: string, context: Record<string, unknown>) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service: this.serviceName,
      env: this.environment,
      version: this.version,
      message,
      ...(redactSensitiveFields(context) as Record<string, unknown>),
    };
    process.stdout.write(JSON.stringify(entry) + '\n');
  }

  public info(message: string, context: Record<string, unknown> = {}) {
    this.write('INFO', message, context);
  }
  public warn(message: string, context: Record<string, unknown> = {}) {
    this.write('WARN', message, context);
  }
  public error(message: string, context: Record<string, unknown> = {}) {
    this.write('ERROR', message, context);
  }
}
```

---

## 5. Verification & Test Requirements

1. **Worker Lease Expiration & Stale Worker Completion Test (`TEST-22`, `TEST-23`)**:
   - Worker 1 acquires job (`fencingToken = 1`). Simulate lease loss (`renewJobLease` returns `{ renewed: false }`) while Worker 2 acquires the job (`fencingToken = 2`). Assert Worker 1's `AbortSignal` fires immediately and Worker 1's completion attempt is rejected with `JOB_LEASE_LOST_FENCING_REJECTED` / `FENCING_TOKEN_REJECTED_ON_COMPLETE` without overwriting Worker 2.
2. **Due-Time & Max-Attempts Acquisition Guard Test**:
   - Assert that a job with `next_run_at > now` returns `NOT_YET_DUE` and a job with `attempt >= max_attempts` returns `EXHAUSTED_MAX_ATTEMPTS`.

### Authoritative References
- **Martin Kleppmann — How to do distributed locking (Fencing Tokens)**: https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html
- **OpenTelemetry Log Data Model**: https://opentelemetry.io/docs/specs/otel/logs/data-model/
