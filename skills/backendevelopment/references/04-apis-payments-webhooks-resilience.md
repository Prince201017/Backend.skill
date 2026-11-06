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

---

## 2. Payment Endpoints, Idempotency Keys & Signed Webhook Verification

### Idempotency Middleware State Machine
Every mutating financial or order endpoint (`POST /api/v1/payments/intents`, `POST /api/v1/refunds`) MUST enforce an `Idempotency-Key` header:

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

- If `(tenant_id, idempotency_key)` exists:
  - If `request_hash` differs from the current payload: return `422 Unprocessable Entity` (`IDEMPOTENCY_KEY_PAYLOAD_MISMATCH`).
  - If `status === 'IN_PROGRESS'` and `locked_until > NOW()`: return `409 Conflict` (`REQUEST_IN_FLIGHT`) with `Retry-After: 2`.
  - If `status === 'COMPLETED'`: return the stored `response_status` and `response_body` with header `Idempotent-Replayed: true`.

### Cryptographic Payment Webhook Verification (Anti-Replay + Constant-Time HMAC)
```typescript
import crypto from 'node:crypto';

export function verifyWebhookSignature(params: {
  rawBodyBuffer: Buffer;
  signatureHeader: string; // e.g., "t=1762388805,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd"
  webhookSecret: string;
  toleranceSeconds?: number;
}): { valid: boolean; reason?: string } {
  const tolerance = params.toleranceSeconds ?? 300; // 5 minutes max replay window
  const parts = Object.fromEntries(
    params.signatureHeader.split(',').map((kv) => kv.split('=') as [string, string])
  );

  const timestampSec = Number(parts.t);
  const signatureHex = parts.v1;
  if (!Number.isInteger(timestampSec) || !signatureHex) {
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

  const expectedSig = crypto
    .createHmac('sha256', params.webhookSecret)
    .update(signedPayload)
    .digest();

  const providedSig = Buffer.from(signatureHex, 'hex');
  if (expectedSig.length !== providedSig.length) {
    return { valid: false, reason: 'INVALID_SIGNATURE_LENGTH' };
  }

  if (!crypto.timingSafeEqual(expectedSig, providedSig)) {
    return { valid: false, reason: 'SIGNATURE_MISMATCH' };
  }

  return { valid: true };
}
```

---

## 3. Distributed Rate Limiting & Throttling (Atomic Redis Token Bucket Lua Script)

Never implement rate limiting with separate `GET` and `SET` calls (race conditions allow bursts under concurrency). Execute an atomic Redis Lua script:

```lua
-- KEYS[1] = rate limit bucket key (e.g., "rl:login:ip:203.0.113.5")
-- ARGV[1] = capacity (max burst tokens, e.g., 10)
-- ARGV[2] = refill_rate_per_ms (tokens added per millisecond)
-- ARGV[3] = now_ms (current timestamp in milliseconds)
-- ARGV[4] = requested_tokens (usually 1)

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

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

local ttl_ms = math.ceil((capacity / refill_rate) * 2)
redis.call("HMSET", key, "tokens", tokens, "last_refill", last_refill)
redis.call("PEXPIRE", key, ttl_ms)

return { allowed, math.floor(tokens), retry_after_ms }
```

---

## 4. Circuit Breaker Pattern (Preventing Cascading System Crashes)

Wrap every outbound third-party call (payment gateway, KYC provider, shipping carrier, SMS gateway) in a stateful Circuit Breaker with hard timeouts:

```typescript
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  name: string;
  failureThreshold: number;      // e.g., 5 consecutive failures
  successThreshold: number;      // e.g., 2 successes in HALF_OPEN to close
  openCooldownMs: number;        // e.g., 30_000ms (30s) before testing HALF_OPEN
  requestTimeoutMs: number;      // e.g., 3_500ms hard timeout per call
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private failureCount = 0;
  private halfOpenSuccessCount = 0;
  private nextAttemptAtMs = 0;

  constructor(private readonly opts: CircuitBreakerOptions) {}

  public getState(): CircuitState {
    if (this.state === 'OPEN' && Date.now() >= this.nextAttemptAtMs) {
      this.state = 'HALF_OPEN';
      this.halfOpenSuccessCount = 0;
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
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.halfOpenSuccessCount += 1;
      if (this.halfOpenSuccessCount >= this.opts.successThreshold) {
        this.state = 'CLOSED';
      }
    }
  }

  private onFailure(): void {
    this.failureCount += 1;
    if (this.state === 'HALF_OPEN' || this.failureCount >= this.opts.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttemptAtMs = Date.now() + this.opts.openCooldownMs;
    }
  }
}
```
