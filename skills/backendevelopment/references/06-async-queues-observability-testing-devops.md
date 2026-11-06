# Module 06: Lease-Safe Asynchronous Job Queues, Crash Recovery, Observability, Testing & DevOps

This reference provides production blueprints for lease-safe background job processing (atomic job acquisition, `IN_PROGRESS` duplicate protection, lease ownership, heartbeat renewal, crash recovery, and DLQ replay), structured observability, automated testing, and Docker/Kubernetes/CI-CD pipelines.

---

## 1. Lease-Safe Asynchronous Job Queue & Worker Architecture

Message brokers provide **at-least-once delivery**, meaning a job message can be delivered to two workers simultaneously or re-delivered after a network blip.

### Mandatory Worker Correctness Rules
1. **Explicit Handling of All 3 Lock States (`ALREADY_COMPLETED`, `IN_PROGRESS`, `ACQUIRED`)**:
   - If `lockStatus === 'ALREADY_COMPLETED'`: Return immediately (`no-op`).
   - If `lockStatus === 'IN_PROGRESS'`: Another active worker holds an unexpired lease on this job. **Return immediately without running the handler** so duplicate concurrent execution cannot occur.
   - If `lockStatus === 'ACQUIRED'`: Execute the handler under a periodic lease heartbeat.
2. **Atomic Job Acquisition with Lease Expiration & Fencing Token**:
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
       max_attempts INT NOT NULL DEFAULT 5,
       next_run_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
       last_error TEXT NULL,
       traceparent VARCHAR(128) NULL,
       created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
       completed_at TIMESTAMPTZ NULL
   );

   CREATE INDEX idx_jobs_runnable
   ON background_jobs (next_run_at ASC)
   WHERE status IN ('QUEUED', 'FAILED_RETRYABLE', 'IN_PROGRESS');
   ```
3. **Atomic Lease Acquisition Query (Includes Crash Recovery of Expired Leases)**:
   ```sql
   UPDATE background_jobs
   SET status = 'IN_PROGRESS',
       lease_owner = $2,
       lease_expires_at = clock_timestamp() + ($3 || ' milliseconds')::interval,
       fencing_token = fencing_token + 1,
       attempt = attempt + 1
   WHERE job_id = $1
     AND (
       status IN ('QUEUED', 'FAILED_RETRYABLE')
       OR (status = 'IN_PROGRESS' AND lease_expires_at < clock_timestamp())
     )
   RETURNING fencing_token, attempt, max_attempts;
   ```

### Production Worker Harness with Lease Heartbeat, Fencing & DLQ Replay
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
  | { status: 'IN_PROGRESS'; currentLeaseOwner: string; leaseExpiresAt: string }
  | { status: 'ACQUIRED'; fencingToken: bigint; attempt: number; maxAttempts: number };

export interface JobLeaseManager {
  acquireJobLease(
    jobId: string,
    workerInstanceId: string,
    leaseDurationMs: number
  ): Promise<JobAcquisitionResult>;

  renewJobLease(
    jobId: string,
    workerInstanceId: string,
    fencingToken: bigint,
    leaseDurationMs: number
  ): Promise<boolean>;

  markJobCompleted(
    jobId: string,
    workerInstanceId: string,
    fencingToken: bigint,
    durationMs: number
  ): Promise<boolean>;

  markJobFailedOrDeadLetter(params: {
    jobId: string;
    workerInstanceId: string;
    fencingToken: bigint;
    attempt: number;
    maxAttempts: number;
    errorReason: string;
    nextRunDelayMs: number;
  }): Promise<'SCHEDULED_RETRY' | 'MOVED_TO_DLQ'>;

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
  handler: (payload: TPayload, ctx: { signal: AbortSignal; fencingToken: bigint }) => Promise<void>
): Promise<'COMPLETED' | 'SKIPPED_COMPLETED' | 'SKIPPED_IN_PROGRESS'> {
  const startNs = process.hrtime.bigint();
  const acquisition = await deps.leaseManager.acquireJobLease(
    envelope.jobId,
    workerInstanceId,
    leaseDurationMs
  );

  // 1. Explicitly handle ALREADY_COMPLETED
  if (acquisition.status === 'ALREADY_COMPLETED') {
    deps.logger.info('Skipping duplicate job delivery (already completed)', {
      jobId: envelope.jobId,
      workerInstanceId,
      traceparent: envelope.traceparent,
    });
    return 'SKIPPED_COMPLETED';
  }

  // 2. Explicitly handle IN_PROGRESS (prevents concurrent duplicate execution!)
  if (acquisition.status === 'IN_PROGRESS') {
    deps.logger.warn('Skipping job delivery because another worker holds an active lease', {
      jobId: envelope.jobId,
      workerInstanceId,
      currentLeaseOwner: acquisition.currentLeaseOwner,
      leaseExpiresAt: acquisition.leaseExpiresAt,
      traceparent: envelope.traceparent,
    });
    return 'SKIPPED_IN_PROGRESS';
  }

  // 3. Status is ACQUIRED: start periodic lease renewal heartbeat and pass AbortSignal to handler
  const { fencingToken, attempt, maxAttempts } = acquisition;
  const abortController = new AbortController();
  const heartbeatIntervalMs = Math.max(1000, Math.floor(leaseDurationMs / 3));

  const heartbeatTimer = setInterval(async () => {
    try {
      const renewed = await deps.leaseManager.renewJobLease(
        envelope.jobId,
        workerInstanceId,
        fencingToken,
        leaseDurationMs
      );
      if (!renewed) {
        deps.logger.error('Worker lost job lease fencing check; aborting in-flight handler', {
          jobId: envelope.jobId,
          workerInstanceId,
          fencingToken: fencingToken.toString(),
        });
        abortController.abort(new Error('JOB_LEASE_LOST'));
      }
    } catch {
      // Transient heartbeat error; next tick will retry before leaseDurationMs expires
    }
  }, heartbeatIntervalMs);

  try {
    await handler(envelope.payload, {
      signal: abortController.signal,
      fencingToken,
    });

    clearInterval(heartbeatTimer);
    const durationMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);

    const committed = await deps.leaseManager.markJobCompleted(
      envelope.jobId,
      workerInstanceId,
      fencingToken,
      durationMs
    );

    if (!committed) {
      throw new Error('FENCING_TOKEN_REJECTED_ON_COMPLETE');
    }

    deps.logger.info('Worker job completed', {
      jobId: envelope.jobId,
      jobType: envelope.jobType,
      workerInstanceId,
      fencingToken: fencingToken.toString(),
      duration_ms: durationMs,
      traceparent: envelope.traceparent,
    });

    return 'COMPLETED';
  } catch (err) {
    clearInterval(heartbeatTimer);
    const errorReason = err instanceof Error ? err.message : String(err);

    // Full jitter exponential backoff: random(0, min(300_000, 1000 * 2^attempt))
    const capMs = 300_000;
    const baseDelayMs = Math.min(capMs, 1000 * 2 ** attempt);
    const jitteredDelayMs = Math.floor(Math.random() * baseDelayMs);

    const outcome = await deps.leaseManager.markJobFailedOrDeadLetter({
      jobId: envelope.jobId,
      workerInstanceId,
      fencingToken,
      attempt,
      maxAttempts,
      errorReason,
      nextRunDelayMs: jitteredDelayMs,
    });

    deps.logger.error('Worker job failed', {
      jobId: envelope.jobId,
      jobType: envelope.jobType,
      attempt,
      maxAttempts,
      outcome,
      nextRunDelayMs: jitteredDelayMs,
      error: errorReason,
      traceparent: envelope.traceparent,
    });

    throw err;
  }
}
```

### Dead-Letter Queue (DLQ) Replay Procedure
1. Inspect root cause in `background_jobs WHERE status = 'DEAD_LETTER'` (fix downstream bug or bad config first).
2. Reset job state atomically via `replayDeadLetterJob`:
   ```sql
   UPDATE background_jobs
   SET status = 'QUEUED',
       attempt = 0,
       lease_owner = NULL,
       lease_expires_at = NULL,
       next_run_at = clock_timestamp()
   WHERE job_id = $1 AND status = 'DEAD_LETTER';
   ```
3. Record an immutable audit log entry (`dlq.job_replayed`, `operator_user_id`, `job_id`).

---

## 2. Observability: Structured JSON Logging, Metrics & Distributed Tracing

```typescript
const SENSITIVE_KEY_REGEX = /^(password|passcode|secret|token|access_token|refresh_token|authorization|cookie|otp|cvv|pan|credit_card|ssn|api_key)$/i;

export function redactSensitiveFields(obj: unknown, depth = 0): unknown {
  if (depth > 8 || obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map((item) => redactSensitiveFields(item, depth + 1));

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    sanitized[key] = SENSITIVE_KEY_REGEX.test(key)
      ? '[REDACTED]'
      : redactSensitiveFields(value, depth + 1);
  }
  return sanitized;
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

## 3. Automated Testing Strategy & DevOps

- **Unit Tests**: Pure domain logic, Largest-Remainder financial proration, GST inclusive/exclusive math, partial refund credit notes, IPv6 prefix expansion, and RBA risk evaluation.
- **Integration Tests (Testcontainers)**: Real PostgreSQL + Redis containers testing Committed Outbox relay (`FOR UPDATE SKIP LOCKED`), concurrent worker lease contention (verifying `IN_PROGRESS` skips duplicate execution), and streaming upload byte-cutoff gates.
- **End-to-End (E2E) Tests**: Complete user workflows across authentication, file upload + malware scan promotion, checkout, webhook verification, and ledger reconciliation.
