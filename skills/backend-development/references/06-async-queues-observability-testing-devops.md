# Module 06: Asynchronous Job Queues, Observability (Logs, Metrics, Tracing), Automated Testing & DevOps

This reference provides production blueprints for asynchronous background queues and workers, structured observability (ELK/Datadog JSON logging, Prometheus metrics, OpenTelemetry distributed tracing), the 3-tier automated testing pyramid, and Docker/Kubernetes/CI-CD deployment pipelines.

---

## 1. Asynchronous Job Queues & Workers (BullMQ / Celery / Sidekiq Pattern)

Offload any task taking $> 200\text{ms}$ or involving external I/O (PDF generation, video transcoding, malware scanning, bulk email campaigns, webhook delivery) to a background queue:

```typescript
export interface AsyncJobEnvelope<TPayload> {
  jobId: string;           // Deterministic or UUIDv7 idempotency key
  jobType: 'report.pdf' | 'file.malware_scan' | 'email.bulk_campaign' | 'video.transcode';
  tenantId: string;
  actorUserId: string;
  traceparent: string;      // W3C Trace Context propagated from HTTP request to Worker!
  attempt: number;
  maxAttempts: number;
  createdAtUtc: string;
  payload: TPayload;
}

/**
 * Worker Execution Harness with Idempotency, Trace Propagation, and Dead-Letter Queue (DLQ) Routing
 */
export async function executeQueueWorkerJob<TPayload>(
  envelope: AsyncJobEnvelope<TPayload>,
  deps: {
    acquireJobLock: (jobId: string) => Promise<'ACQUIRED' | 'ALREADY_COMPLETED' | 'IN_PROGRESS'>;
    markJobCompleted: (jobId: string, durationMs: number) => Promise<void>;
    sendToDeadLetterQueue: (envelope: AsyncJobEnvelope<TPayload>, errorReason: string) => Promise<void>;
    logger: StructuredLogger;
  },
  handler: (payload: TPayload) => Promise<void>
): Promise<void> {
  const startNs = process.hrtime.bigint();
  const lockStatus = await deps.acquireJobLock(envelope.jobId);

  if (lockStatus === 'ALREADY_COMPLETED') {
    deps.logger.info('Skipping duplicate job delivery (already completed)', {
      jobId: envelope.jobId,
      traceparent: envelope.traceparent,
    });
    return;
  }

  try {
    await handler(envelope.payload);
    const durationMs = Number((process.hrtime.bigint() - startNs) / 1_000_000n);
    await deps.markJobCompleted(envelope.jobId, durationMs);

    deps.logger.info('Worker job completed successfully', {
      jobId: envelope.jobId,
      jobType: envelope.jobType,
      tenantId: envelope.tenantId,
      traceparent: envelope.traceparent,
      duration_ms: durationMs,
    });
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    deps.logger.error('Worker job failed', {
      jobId: envelope.jobId,
      jobType: envelope.jobType,
      attempt: envelope.attempt,
      maxAttempts: envelope.maxAttempts,
      traceparent: envelope.traceparent,
      error: errorMessage,
    });

    if (envelope.attempt >= envelope.maxAttempts) {
      await deps.sendToDeadLetterQueue(envelope, errorMessage);
    }
    throw err; // Re-throw so BullMQ/Celery schedules exponential backoff retry
  }
}
```

---

## 2. Observability: Structured JSON Logging, Metrics & Distributed Tracing

### Structured JSON Logger with Automatic PII/Secret Redaction
Never use `console.log()` in production. Emit structured JSON for ELK Stack (Elasticsearch, Logstash, Kibana), Datadog, or Grafana Loki:

```typescript
const SENSITIVE_KEY_REGEX = /^(password|passcode|secret|token|access_token|refresh_token|authorization|cookie|otp|cvv|pan|credit_card|ssn|api_key)$/i;

export function redactSensitiveFields(obj: unknown, depth = 0): unknown {
  if (depth > 8 || obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map((item) => redactSensitiveFields(item, depth + 1));

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (SENSITIVE_KEY_REGEX.test(key)) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = redactSensitiveFields(value, depth + 1);
    }
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

### Core Metrics to Export (`/metrics` OpenTelemetry / Prometheus)
- `http_requests_total{method, route, status_code}` (Counter)
- `http_request_duration_seconds{method, route, status_code}` (Histogram with buckets `[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]`)
- `db_pool_connections_active` / `db_pool_connections_waiting` (Gauge)
- `circuit_breaker_state{dependency_name}` (`0=CLOSED, 1=HALF_OPEN, 2=OPEN`)
- `job_queue_depth{queue_name}` and `job_dlq_total{queue_name}` (Gauge / Counter)

---

## 3. Automated Testing Strategy (Unit, Integration, E2E)

| Test Layer | Scope & Speed | Mandatory Assertions |
| :--- | :--- | :--- |
| **1. Unit Tests** | Pure functions, domain entities, financial math, OTP/ID generators, RBAC/ABAC evaluators, file magic-byte validators (`< 5ms` per test). | Boundary values (`0`, `-1`, `MAX_SAFE_INTEGER`), rounding ties, expired tokens, tampered HMAC signatures, polyglot file headers. |
| **2. Integration Tests** | Real PostgreSQL + Redis + Object Storage via **Testcontainers**. Zero mocked SQL! | ACID rollback on mid-transaction failure, concurrent race-condition tests (`20 parallel balance debits` -> no negative balance), idempotency key replay, BOLA cross-tenant isolation. |
| **3. End-to-End (E2E) Tests** | Complete user journeys over HTTP against a booted production build. | Signup -> OTP verify -> Login -> Upload file -> Malware scan promotion -> Checkout -> Signed payment webhook -> Verify double-entry ledger & audit log. |

---

## 4. DevOps, Docker Containerization, Kubernetes & CI/CD

### Hardened Multi-Stage `Dockerfile`
```dockerfile
# Stage 1: Dependencies & Build
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

# Stage 2: Minimal Non-Root Production Runtime
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Run as non-root user (UID 10001) and create isolated noexec upload scratch dir outside app root
RUN addgroup -g 10001 -S appgroup && adduser -u 10001 -S appuser -G appgroup \
    && mkdir -p /var/data/quarantine_uploads && chown -R appuser:appgroup /var/data/quarantine_uploads \
    && chmod 0700 /var/data/quarantine_uploads

COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package.json ./package.json

USER 10001
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

### Kubernetes Production Deployment + HPA Manifest
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-api
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: backend-api
  template:
    metadata:
      labels:
        app: backend-api
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: registry.example.com/backend-api:sha-9f8e7d6
          ports:
            - containerPort: 3000
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: "250m"
              memory: "512Mi"
            limits:
              cpu: "1000m"
              memory: "1Gi"
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: backend-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: backend-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```
