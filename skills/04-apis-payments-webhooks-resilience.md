# Module 04: APIs (REST & GraphQL), Versioning, OpenAPI Governance, Payments, Rate Limiting & Circuit Breakers

This reference covers API contracts, versioning, OpenAPI/Swagger generation, payment gateway integrations, idempotency, rate limiting/throttling, and circuit breakers.

---

## 1. API Versioning, RFC 9457 Error Contracts & OpenAPI / Swagger Governance

### URL & Header Versioning Strategy
- **URL Namespace Versioning**: `/api/v1/orders`, `/api/v2/orders`.
- **Deprecation Lifecycle Headers**: When a v1 endpoint is scheduled for retirement while old mobile clients still use it, inject:
  ```http
  Deprecation: @1798761600
  Sunset: Thu, 31 Dec 2026 23:59:59 GMT
  Link: <https://api.example.com/docs/migrations/v2>; rel="deprecation"
  ```

### Standard RFC 9457 Problem Details Error Response
Never return inconsistent `{ error: "..." }` or `{ message: "..." }` shapes. Standardize all 4xx/5xx responses:

```json
{
  "type": "https://api.example.com/errors/validation-failed",
  "title": "Request Validation Failed",
  "status": 422,
  "detail": "One or more fields failed validation.",
  "instance": "/api/v1/orders",
  "requestId": "019300e8-7c2a-7000-8b12-9a4f8c1d2e3f",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "timestamp": "2026-11-05T16:26:45.000Z",
  "errors": [
    {
      "field": "items[0].quantity",
      "code": "TOO_SMALL",
      "message": "Quantity must be greater than or equal to 1"
    }
  ]
}
```

### Safe Error Boundary Serializer (Zero Stack-Trace or SQL Constraint Leakage)
Never serialize raw `Error.stack`, database error codes/table names (`duplicate key value violates unique constraint "users_email_key"`), or internal file paths in HTTP responses. Only expose operational `AppError` details; mask all unexpected/internal exceptions as generic `500 Internal Server Error` while logging the full stack internally with `traceId`:

```typescript
export class OperationalAppError extends Error {
  constructor(
    public readonly status: number,
    public readonly typeSlug: string,
    public readonly title: string,
    public readonly detail: string,
    public readonly fieldErrors?: Array<{ field: string; code: string; message: string }>
  ) {
    super(detail);
  }
}

export function toSafeProblemDetailsResponse(params: {
  error: unknown;
  instancePath: string;
  requestId: string;
  traceId: string;
  logInternalError: (err: unknown, meta: { requestId: string; traceId: string }) => void;
}): { status: number; headers: Record<string, string>; body: Record<string, unknown> } {
  const timestamp = new Date().toISOString();
  const headers = {
    'Content-Type': 'application/problem+json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'X-Request-Id': params.requestId,
    'X-Trace-Id': params.traceId,
  };

  if (params.error instanceof OperationalAppError) {
    return {
      status: params.error.status,
      headers,
      body: {
        type: `https://api.example.com/errors/${params.error.typeSlug}`,
        title: params.error.title,
        status: params.error.status,
        detail: params.error.detail,
        instance: params.instancePath,
        requestId: params.requestId,
        traceId: params.traceId,
        timestamp,
        ...(params.error.fieldErrors ? { errors: params.error.fieldErrors } : {}),
      },
    };
  }

  // Unexpected/internal error (e.g., PostgreSQL syntax/constraint error, Redis timeout, TypeError):
  // Log full stack & DB metadata internally, but return an opaque 500 response to the client!
  params.logInternalError(params.error, {
    requestId: params.requestId,
    traceId: params.traceId,
  });

  return {
    status: 500,
    headers,
    body: {
      type: 'https://api.example.com/errors/internal-server-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An unexpected internal error occurred. Reference traceId for support.',
      instance: params.instancePath,
      requestId: params.requestId,
      traceId: params.traceId,
      timestamp,
    },
  };
}
```

---

## 2. Payment Endpoints, Atomic Idempotency State Machine & Signed Webhook Verification

### Atomic Idempotency Middleware State Machine
Every mutating financial or order endpoint (`POST /api/v1/payments/intents`, `POST /api/v1/refunds`, `POST /api/v1/orders`) MUST enforce an `Idempotency-Key` header using a single atomic `INSERT ... ON CONFLICT` state transition (never a race-prone `SELECT`-then-`INSERT`):

```sql
CREATE TABLE idempotency_keys (
    tenant_id UUID NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    endpoint VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL, -- SHA-256 of canonical request body
    status VARCHAR(16) NOT NULL CHECK (status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED')),
    response_status INT NULL,
    response_body JSONB NULL,
    locked_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, idempotency_key)
);
```

```typescript
import crypto from 'node:crypto';

export interface IdempotencyRow {
  request_hash: string;
  status: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  response_status: number | null;
  response_body: Record<string, unknown> | null;
  is_lock_expired: boolean;
}

export async function executeWithIdempotencyLock(params: {
  tenantId: string;
  idempotencyKey: string;
  endpoint: string;
  canonicalRequestBody: string;
  lockTtlSeconds?: number;
  db: {
    tryAcquireLock: (
      tenantId: string,
      key: string,
      endpoint: string,
      reqHash: string,
      ttlSec: number
    ) => Promise<{ acquired: boolean; existing?: IdempotencyRow }>;
    completeLock: (
      tenantId: string,
      key: string,
      status: number,
      body: Record<string, unknown>
    ) => Promise<void>;
    releaseFailedLock: (tenantId: string, key: string) => Promise<void>;
  };
  handler: () => Promise<{ status: number; body: Record<string, unknown> }>;
}): Promise<{ status: number; body: Record<string, unknown>; replayed: boolean }> {
  if (!params.idempotencyKey || !/^[a-zA-Z0-9_.:-]{8,128}$/.test(params.idempotencyKey)) {
    throw new OperationalAppError(
      400,
      'invalid-idempotency-key',
      'Invalid Idempotency-Key Header',
      'Idempotency-Key must be 8..128 alphanumeric/safe characters.'
    );
  }

  const reqHash = crypto
    .createHash('sha256')
    .update(`${params.endpoint}:${params.canonicalRequestBody}`, 'utf8')
    .digest('hex');

  const lockRes = await params.db.tryAcquireLock(
    params.tenantId,
    params.idempotencyKey,
    params.endpoint,
    reqHash,
    params.lockTtlSeconds ?? 60
  );

  if (!lockRes.acquired) {
    const ex = lockRes.existing;
    if (!ex) {
      throw new OperationalAppError(
        409,
        'idempotency-lock-contention',
        'Idempotency Lock Contention',
        'Could not acquire idempotency lock due to a concurrent request.'
      );
    }
    if (ex.request_hash !== reqHash) {
      throw new OperationalAppError(
        422,
        'idempotency-payload-mismatch',
        'Idempotency Key Payload Mismatch',
        'The same Idempotency-Key was reused with different request parameters.'
      );
    }
    if (ex.status === 'COMPLETED' && ex.response_status !== null && ex.response_body !== null) {
      return {
        status: ex.response_status,
        body: ex.response_body,
        replayed: true,
      };
    }
    // CRITICAL: Never fall through to params.handler() when !lockRes.acquired!
    // Even if an earlier lock expired or failed, the caller must atomically claim ownership inside tryAcquireLock
    // (INSERT ... ON CONFLICT DO UPDATE ... WHERE status = 'FAILED' OR locked_until < clock_timestamp()).
    throw new OperationalAppError(
      409,
      'request-in-flight',
      'Concurrent Request In Flight',
      'A request with this Idempotency-Key is currently being processed or being reclaimed. Retry after 2 seconds.'
    );
  }

  try {
    const result = await params.handler();
    await params.db.completeLock(
      params.tenantId,
      params.idempotencyKey,
      result.status,
      result.body
    );
    return { ...result, replayed: false };
  } catch (err) {
    await params.db.releaseFailedLock(params.tenantId, params.idempotencyKey);
    throw err;
  }
}
```

### Cryptographic Payment Webhook Verification (Anti-Replay + Constant-Time HMAC)
```typescript
export function verifyWebhookSignature(params: {
  rawBodyBuffer: Buffer;
  signatureHeader: string; // Supports multiple v1 signatures during secret rotation: "t=1762388805,v1=sig1,v1=sig2"
  webhookSecrets: string[]; // Supports active + retiring webhook secrets
  toleranceSeconds?: number;
}): { valid: boolean; reason?: string } {
  const tolerance = params.toleranceSeconds ?? 300; // 5 minutes max replay window
  if (!params.signatureHeader || params.webhookSecrets.length === 0) {
    return { valid: false, reason: 'MISSING_SIGNATURE_OR_SECRET' };
  }

  let timestampStr: string | undefined;
  const v1Signatures: string[] = [];

  for (const token of params.signatureHeader.split(',')) {
    const [k, v] = token.trim().split('=');
    if (k === 't' && v) timestampStr = v;
    if (k === 'v1' && v && /^[0-9a-fA-F]{64}$/.test(v)) {
      v1Signatures.push(v);
    }
  }

  const timestampSec = Number(timestampStr);
  if (!Number.isInteger(timestampSec) || v1Signatures.length === 0) {
    return { valid: false, reason: 'MALFORMED_SIGNATURE_HEADER' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - timestampSec) > tolerance) {
    return { valid: false, reason: 'TIMESTAMP_OUTSIDE_TOLERANCE_WINDOW' };
  }

  const signedPayload = Buffer.concat([
    Buffer.from(`${timestampSec}.`, 'utf8'),
    params.rawBodyBuffer,
  ]);

  let matchedAny = false;
  for (const secret of params.webhookSecrets) {
    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(signedPayload)
      .digest();

    for (const sigHex of v1Signatures) {
      const providedSig = Buffer.from(sigHex, 'hex');
      if (
        expectedSig.length === providedSig.length &&
        crypto.timingSafeEqual(expectedSig, providedSig)
      ) {
        matchedAny = true;
      }
    }
  }

  if (!matchedAny) {
    return { valid: false, reason: 'SIGNATURE_MISMATCH' };
  }

  return { valid: true };
}
```

---

## 3. Distributed Rate Limiting & Throttling (Atomic Redis Token Bucket Lua Script)

Never implement rate limiting with separate `GET` and `SET` calls (race conditions allow bursts under concurrency). Execute an atomic Redis Lua script with strict input bounds:

```lua
-- KEYS[1] = rate limit bucket key (e.g., "rl:login:ip:203.0.113.5")
-- ARGV[1] = capacity (max burst tokens, e.g., 10)
-- ARGV[2] = refill_rate_per_ms (tokens added per millisecond, MUST be > 0)
-- ARGV[3] = now_ms (current timestamp in milliseconds)
-- ARGV[4] = requested_tokens (usually 1)

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

if not capacity or capacity <= 0 or not refill_rate or refill_rate <= 0 or not requested or requested <= 0 then
  return redis.error_reply("ERR_INVALID_RATE_LIMIT_ARGUMENTS")
end

local data = redis.call("HMGET", key, "tokens", "last_refill")
local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  last_refill = now_ms
else
  local elapsed = math.max(0, now_ms - last_refill)
  tokens = math.min(capacity, tokens + (elapsed * refill_rate))
  last_refill = now_ms
end

local allowed = 0
local retry_after_ms = 0

if tokens >= requested then
  tokens = tokens - requested
  allowed = 1
else
  retry_after_ms = math.ceil((requested - tokens) / refill_rate)
end

local ttl_ms = math.max(1000, math.ceil((capacity / refill_rate) * 2))
redis.call("HMSET", key, "tokens", tokens, "last_refill", last_refill)
redis.call("PEXPIRE", key, ttl_ms)

return { allowed, math.floor(tokens), retry_after_ms }
```

---

## 4. Circuit Breaker Pattern (With Half-Open Probe Concurrency Gate)

Wrap every outbound third-party call (payment gateway, KYC provider, shipping carrier, SMS gateway) in a stateful Circuit Breaker with hard timeouts AND a **Half-Open Probe Concurrency Cap** (`halfOpenMaxConcurrentProbes`) so 500 concurrent requests do not stampede a recovering downstream service the instant `openCooldownMs` elapses:

```typescript
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  name: string;
  failureThreshold: number;            // e.g., 5 consecutive failures
  successThreshold: number;            // e.g., 2 successes in HALF_OPEN to close
  openCooldownMs: number;              // e.g., 30_000ms (30s) before testing HALF_OPEN
  requestTimeoutMs: number;            // e.g., 3_500ms hard timeout per call
  halfOpenMaxConcurrentProbes?: number; // Default 1 (prevents Half-Open thundering herd!)
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private failureCount = 0;
  private halfOpenSuccessCount = 0;
  private halfOpenInFlightProbes = 0;
  private nextAttemptAtMs = 0;

  constructor(private readonly opts: CircuitBreakerOptions) {}

  public getState(): CircuitState {
    if (this.state === 'OPEN' && Date.now() >= this.nextAttemptAtMs) {
      this.state = 'HALF_OPEN';
      this.halfOpenSuccessCount = 0;
      this.halfOpenInFlightProbes = 0;
    }
    return this.state;
  }

  public async execute<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const currentState = this.getState();
    if (currentState === 'OPEN') {
      throw new Error(
        `CIRCUIT_OPEN:${this.opts.name} (retry after ${Math.max(0, this.nextAttemptAtMs - Date.now())}ms)`
      );
    }

    const maxProbes = this.opts.halfOpenMaxConcurrentProbes ?? 1;
    const isHalfOpenProbe = currentState === 'HALF_OPEN';
    if (isHalfOpenProbe) {
      if (this.halfOpenInFlightProbes >= maxProbes) {
        throw new Error(`CIRCUIT_HALF_OPEN_PROBE_LIMIT_REACHED:${this.opts.name}`);
      }
      this.halfOpenInFlightProbes += 1;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.requestTimeoutMs);

    try {
      const result = await operation(controller.signal);
      clearTimeout(timer);
      this.onSuccess();
      return result;
    } catch (error) {
      clearTimeout(timer);
      this.onFailure();
      throw error;
    } finally {
      if (isHalfOpenProbe) {
        this.halfOpenInFlightProbes = Math.max(0, this.halfOpenInFlightProbes - 1);
      }
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.halfOpenSuccessCount += 1;
      if (this.halfOpenSuccessCount >= this.opts.successThreshold) {
        this.state = 'CLOSED';
        this.halfOpenInFlightProbes = 0;
      }
    }
  }

  private onFailure(): void {
    this.failureCount += 1;
    if (this.state === 'HALF_OPEN' || this.failureCount >= this.opts.failureThreshold) {
      this.state = 'OPEN';
      this.halfOpenInFlightProbes = 0;
      this.nextAttemptAtMs = Date.now() + this.opts.openCooldownMs;
    }
  }
}
```

