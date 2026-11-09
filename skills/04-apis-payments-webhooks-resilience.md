# Module 04: APIs, Versioning, Fenced Payment Idempotency, Persistent Webhook Anti-Replay & Resilience

This module provides production-grade implementations for RFC 9457 error boundaries, **fenced payment idempotency state machines with ambiguous timeout reconciliation**, **persistent database-backed webhook replay & out-of-order protection**, atomic Redis Lua token-bucket rate limiting, and half-open-gated circuit breakers.

---

## 1. Threat Model, Trust Boundaries & Failure Behavior

| Control | Threat / Failure Vector | Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **Payment Idempotency (`executeWithIdempotencyLock`)** | 1) TTL lock expires while Worker 1 is still running; Worker 2 acquires lock and charges a second time, or Worker 1 overwrites Worker 2's completed state.<br>2) Provider times out after receiving the charge request; naive retry issues a duplicate charge. | Application + PostgreSQL `idempotency_keys` table (`lock_owner`, monotonic `fencing_token`, lease heartbeat). | Rejects stale worker completion if `lock_owner` or `fencing_token` changed; transitions post-write timeouts to `UNKNOWN_RECONCILIATION_REQUIRED` and reconciles before any retry. |
| **Webhook Anti-Replay (`verifyAndProcessWebhookIdempotently`)** | HMAC signature + 300s timestamp window alone allows an attacker or retrying proxy to replay a valid signed webhook hundreds of times inside the 5-minute window, or deliver older events out of order. | Ingress raw-body verifier + PostgreSQL `webhook_events` & aggregate version check. | Atomically records `(provider, provider_event_id)` in DB; ignores duplicates (`DUPLICATE_ALREADY_PROCESSED`) and stale out-of-order events (`OUT_OF_ORDER_STALE_EVENT_IGNORED`). |
| **Error Boundary (`toSafeProblemDetailsResponse`)** | Returning raw `err.message` or `err.stack` leaks SQL table/constraint names and internal paths. | Global HTTP response boundary. | Exposes only `OperationalAppError` fields; masks unexpected errors as generic `500` correlated by `traceId`. |

---

## 2. API Versioning & Safe RFC 9457 Error Boundary Serializer

```typescript
export class OperationalAppError extends Error {
  public readonly status: number;
  public readonly typeSlug: string;
  public readonly title: string;
  public readonly detail: string;
  public readonly fieldErrors?: Array<{ field: string; code: string; message: string }>;

  constructor(
    status: number,
    typeSlug: string,
    title: string,
    detail: string,
    fieldErrors?: Array<{ field: string; code: string; message: string }>
  ) {
    super(detail);
    this.status = status;
    this.typeSlug = typeSlug;
    this.title = title;
    this.detail = detail;
    this.fieldErrors = fieldErrors;
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

## 3. Remediated Payment Idempotency Engine (Fencing Tokens, Lease Renewal & Ambiguous Outcome Reconciliation)

### Why TTL Locks Without Fencing & Reconciliation Are Unsafe
1. **Stale Worker Overwrite**: If Worker 1 pauses (GC pause or slow network) past `locked_until`, Worker 2 acquires the expired lock with `fencing_token = 2`. If Worker 1 wakes up and calls `completeLock` without checking `lock_owner` and `fencing_token`, Worker 1 overwrites Worker 2's state.
2. **Ambiguous Provider Timeout Double-Charge**: If a payment gateway times out *after* the HTTP request body was sent, the charge may have succeeded on the provider side. Releasing the lock as `FAILED_TERMINAL` and letting the client retry with a new provider call causes a duplicate charge.

```sql
CREATE TABLE idempotency_keys (
    tenant_id UUID NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    endpoint VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    provider_idempotency_key CHAR(64) NOT NULL,
    status VARCHAR(40) NOT NULL CHECK (status IN (
        'PENDING',
        'SUCCEEDED',
        'FAILED_TERMINAL',
        'UNKNOWN_RECONCILIATION_REQUIRED'
    )),
    lock_owner VARCHAR(128) NULL,
    fencing_token BIGINT NOT NULL DEFAULT 1,
    locked_until TIMESTAMPTZ NOT NULL,
    response_status INT NULL,
    response_body JSONB NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, idempotency_key)
);

-- Atomic Lock Acquisition & Stale-Lease Takeover Query (Increments fencing_token monotonically):
-- INSERT INTO idempotency_keys (tenant_id, idempotency_key, endpoint, request_hash, provider_idempotency_key, status, lock_owner, fencing_token, locked_until)
-- VALUES ($1, $2, $3, $4, $5, 'PENDING', $6, 1, clock_timestamp() + ($7::int * interval '1 second'))
-- ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
-- SET status = CASE
--       WHEN idempotency_keys.status = 'UNKNOWN_RECONCILIATION_REQUIRED' THEN 'UNKNOWN_RECONCILIATION_REQUIRED'
--       ELSE 'PENDING'
--     END,
--     lock_owner = EXCLUDED.lock_owner,
--     fencing_token = idempotency_keys.fencing_token + 1,
--     locked_until = EXCLUDED.locked_until,
--     updated_at = clock_timestamp()
-- WHERE idempotency_keys.request_hash = EXCLUDED.request_hash
--   AND (
--     idempotency_keys.status = 'FAILED_TERMINAL'
--     OR (idempotency_keys.status IN ('PENDING', 'UNKNOWN_RECONCILIATION_REQUIRED') AND idempotency_keys.locked_until < clock_timestamp())
--   )
-- RETURNING fencing_token, status, provider_idempotency_key;
```

```typescript
import crypto from 'node:crypto';

export type IdempotencyRecordStatus =
  | 'PENDING'
  | 'SUCCEEDED'
  | 'FAILED_TERMINAL'
  | 'UNKNOWN_RECONCILIATION_REQUIRED';

export interface IdempotencyRow {
  request_hash: string;
  provider_idempotency_key: string;
  status: IdempotencyRecordStatus;
  lock_owner: string | null;
  fencing_token: bigint;
  response_status: number | null;
  response_body: Record<string, unknown> | null;
  is_lock_expired: boolean;
}

export class AmbiguousPaymentProviderTimeoutError extends Error {
  public readonly isAmbiguousProviderOutcome = true;
  constructor(message: string) {
    super(message);
  }
}

export interface FencedIdempotencyDbPort {
  tryAcquireOrTakeoverExpiredLock(params: {
    tenantId: string;
    key: string;
    endpoint: string;
    reqHash: string;
    providerIdempotencyKey: string;
    lockOwnerToken: string;
    ttlSeconds: number;
  }): Promise<
    | {
        acquired: true;
        fencingToken: bigint;
        currentStatus: 'PENDING' | 'UNKNOWN_RECONCILIATION_REQUIRED';
        providerIdempotencyKey: string;
      }
    | { acquired: false; existing: IdempotencyRow | null }
  >;

  renewLockLease(params: {
    tenantId: string;
    key: string;
    lockOwnerToken: string;
    fencingToken: bigint;
    ttlSeconds: number;
  }): Promise<boolean>;

  completeLockConditionally(params: {
    tenantId: string;
    key: string;
    lockOwnerToken: string;
    fencingToken: bigint;
    status: 'SUCCEEDED' | 'FAILED_TERMINAL';
    responseStatus: number;
    responseBody: Record<string, unknown>;
  }): Promise<boolean>;

  markUnknownReconciliationRequiredConditionally(params: {
    tenantId: string;
    key: string;
    lockOwnerToken: string;
    fencingToken: bigint;
  }): Promise<boolean>;

  releaseTerminalFailedLockConditionally(params: {
    tenantId: string;
    key: string;
    lockOwnerToken: string;
    fencingToken: bigint;
  }): Promise<boolean>;
}

export function canonicalizeJsonDeep(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJsonDeep(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj)
    .filter((k) => k !== '__proto__' && k !== 'constructor' && k !== 'prototype')
    .sort();
  const pairs = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJsonDeep(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

export async function executeWithIdempotencyLock(params: {
  tenantId: string;
  idempotencyKey: string;
  endpoint: string;
  canonicalRequestBody: string | Record<string, unknown>;
  lockTtlSeconds?: number;
  db: FencedIdempotencyDbPort;
  reconcileAmbiguousPayment?: (
    providerIdempotencyKey: string,
    signal: AbortSignal
  ) => Promise<
    | { resolved: 'SUCCEEDED'; status: number; body: Record<string, unknown> }
    | { resolved: 'NOT_FOUND_SAFE_TO_EXECUTE' }
    | { resolved: 'STILL_UNKNOWN' }
  >;
  handler: (ctx: {
    providerIdempotencyKey: string;
    fencingToken: bigint;
    signal: AbortSignal;
  }) => Promise<{ status: number; body: Record<string, unknown> }>;
}): Promise<{ status: number; body: Record<string, unknown>; replayed: boolean; fencingToken?: bigint }> {
  if (!params.idempotencyKey || !/^[a-zA-Z0-9_.:-]{8,128}$/.test(params.idempotencyKey)) {
    throw new OperationalAppError(
      400,
      'invalid-idempotency-key',
      'Invalid Idempotency-Key Header',
      'Idempotency-Key must be 8..128 alphanumeric/safe characters.'
    );
  }

  const normalizedBody =
    typeof params.canonicalRequestBody === 'string'
      ? params.canonicalRequestBody
      : canonicalizeJsonDeep(params.canonicalRequestBody);

  const reqHash = crypto
    .createHash('sha256')
    .update(`${params.endpoint}:${normalizedBody}`, 'utf8')
    .digest('hex');

  // Stable deterministic provider-side idempotency key bound to tenant + endpoint + client key
  const providerIdempotencyKey = crypto
    .createHash('sha256')
    .update(`provider:${params.tenantId}:${params.endpoint}:${params.idempotencyKey}`, 'utf8')
    .digest('hex');

  const lockOwnerToken = crypto.randomUUID();
  const ttlSeconds = params.lockTtlSeconds ?? 30;

  const lockRes = await params.db.tryAcquireOrTakeoverExpiredLock({
    tenantId: params.tenantId,
    key: params.idempotencyKey,
    endpoint: params.endpoint,
    reqHash,
    providerIdempotencyKey,
    lockOwnerToken,
    ttlSeconds,
  });

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
    if (ex.status === 'SUCCEEDED' && ex.response_status !== null && ex.response_body !== null) {
      return {
        status: ex.response_status,
        body: ex.response_body,
        replayed: true,
        fencingToken: ex.fencing_token,
      };
    }
    if (ex.status === 'UNKNOWN_RECONCILIATION_REQUIRED') {
      throw new OperationalAppError(
        409,
        'payment-reconciliation-in-progress',
        'Payment Outcome Reconciliation Required',
        'Previous payment attempt experienced an ambiguous provider timeout and is being reconciled. Do not issue a new key.'
      );
    }
    throw new OperationalAppError(
      409,
      'request-in-flight',
      'Concurrent Request In Flight',
      'A request with this Idempotency-Key is currently being processed.'
    );
  }

  const { fencingToken, currentStatus } = lockRes;
  const abortController = new AbortController();
  const heartbeatIntervalMs = Math.max(250, Math.floor((ttlSeconds * 1000) / 3));

  const heartbeatTimer = setInterval(async () => {
    try {
      const renewed = await params.db.renewLockLease({
        tenantId: params.tenantId,
        key: params.idempotencyKey,
        lockOwnerToken,
        fencingToken,
        ttlSeconds,
      });
      if (!renewed) {
        abortController.abort(new Error('IDEMPOTENCY_LEASE_LOST'));
      }
    } catch {
      abortController.abort(new Error('IDEMPOTENCY_LEASE_RENEWAL_ERROR'));
    }
  }, heartbeatIntervalMs);

  try {
    // If recovering an UNKNOWN_RECONCILIATION_REQUIRED lock after lease expiry, reconcile FIRST!
    if (currentStatus === 'UNKNOWN_RECONCILIATION_REQUIRED') {
      if (!params.reconcileAmbiguousPayment) {
        throw new OperationalAppError(
          409,
          'payment-reconciliation-required',
          'Ambiguous Payment Outcome Requires Reconciliation',
          'Cannot automatically re-run handler without reconciling prior ambiguous provider state.'
        );
      }
      const recon = await params.reconcileAmbiguousPayment(
        lockRes.providerIdempotencyKey,
        abortController.signal
      );
      if (recon.resolved === 'SUCCEEDED') {
        const committed = await params.db.completeLockConditionally({
          tenantId: params.tenantId,
          key: params.idempotencyKey,
          lockOwnerToken,
          fencingToken,
          status: 'SUCCEEDED',
          responseStatus: recon.status,
          responseBody: recon.body,
        });
        if (!committed) {
          throw new Error('IDEMPOTENCY_FENCING_TOKEN_REJECTED_STALE_OWNER');
        }
        return { status: recon.status, body: recon.body, replayed: true, fencingToken };
      }
      if (recon.resolved === 'STILL_UNKNOWN') {
        await params.db.markUnknownReconciliationRequiredConditionally({
          tenantId: params.tenantId,
          key: params.idempotencyKey,
          lockOwnerToken,
          fencingToken,
        });
        throw new OperationalAppError(
          503,
          'payment-reconciliation-pending',
          'Payment Reconciliation Still Pending',
          'Provider status is still indeterminate; please retry with the same Idempotency-Key shortly.'
        );
      }
      // resolved === 'NOT_FOUND_SAFE_TO_EXECUTE': provider confirmed prior call never arrived; safe to execute below
    }

    const result = await params.handler({
      providerIdempotencyKey: lockRes.providerIdempotencyKey,
      fencingToken,
      signal: abortController.signal,
    });

    if (abortController.signal.aborted) {
      throw new Error('IDEMPOTENCY_FENCING_TOKEN_REJECTED_STALE_OWNER');
    }

    const committed = await params.db.completeLockConditionally({
      tenantId: params.tenantId,
      key: params.idempotencyKey,
      lockOwnerToken,
      fencingToken,
      status: 'SUCCEEDED',
      responseStatus: result.status,
      responseBody: result.body,
    });

    if (!committed) {
      throw new Error('IDEMPOTENCY_FENCING_TOKEN_REJECTED_STALE_OWNER');
    }

    return { ...result, replayed: false, fencingToken };
  } catch (err) {
    if (
      err instanceof AmbiguousPaymentProviderTimeoutError ||
      (err instanceof Error && 'isAmbiguousProviderOutcome' in err)
    ) {
      // CRITICAL: Never release lock as FAILED_TERMINAL when provider outcome is ambiguous!
      await params.db.markUnknownReconciliationRequiredConditionally({
        tenantId: params.tenantId,
        key: params.idempotencyKey,
        lockOwnerToken,
        fencingToken,
      });
      throw err;
    }

    if (!(err instanceof Error && err.message === 'IDEMPOTENCY_FENCING_TOKEN_REJECTED_STALE_OWNER')) {
      await params.db.releaseTerminalFailedLockConditionally({
        tenantId: params.tenantId,
        key: params.idempotencyKey,
        lockOwnerToken,
        fencingToken,
      });
    }
    throw err;
  } finally {
    clearInterval(heartbeatTimer);
  }
}
```

---

## 4. Persistent Webhook Anti-Replay, Signature Verification & Out-of-Order Guard

### Why Signature + Timestamp Verification Alone Does Not Prevent Replay
Validating `t=<timestamp>,v1=<hmac>` within $\pm 300\text{s}$ proves only that the payload was signed by the provider within the last 5 minutes. If a webhook is delivered twice (or replayed by an attacker within that 300-second window), signature verification will succeed both times!
- **Mandatory Control**: Combine raw-body HMAC verification with **atomic persistent event deduplication** (`UNIQUE (provider, provider_event_id)` in PostgreSQL) AND **monotonic entity event timestamp/version ordering** so delayed out-of-order webhooks never overwrite newer state.

```sql
CREATE TABLE webhook_events (
    provider VARCHAR(32) NOT NULL,
    provider_event_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    entity_id VARCHAR(128) NOT NULL,
    provider_created_at_sec BIGINT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL CHECK (status IN ('PROCESSING', 'PROCESSED', 'FAILED_RETRYABLE')),
    lock_owner VARCHAR(128) NULL,
    locked_until TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ NULL,
    PRIMARY KEY (provider, provider_event_id)
);
```

```typescript
export function verifyWebhookSignature(params: {
  rawBodyBuffer: Buffer;
  signatureHeader: string;
  webhookSecrets: string[];
  toleranceSeconds?: number;
  nowMs?: number;
}): { valid: boolean; reason?: string; timestampSec?: number } {
  const tolerance = params.toleranceSeconds ?? 300;
  if (!params.signatureHeader || params.webhookSecrets.length === 0) {
    return { valid: false, reason: 'MISSING_SIGNATURE_OR_SECRET' };
  }
  // DEVIL-04 Guard: Cap signature header size and secret count to prevent O(N*M) HMAC CPU exhaustion
  if (params.signatureHeader.length > 1024 || params.webhookSecrets.length > 5) {
    return { valid: false, reason: 'SIGNATURE_HEADER_OR_KEYRING_OVERSIZED' };
  }

  let timestampStr: string | undefined;
  const v1Signatures: string[] = [];

  for (const token of params.signatureHeader.split(',')) {
    const eqIdx = token.indexOf('=');
    if (eqIdx <= 0) continue;
    const k = token.slice(0, eqIdx).trim();
    const v = token.slice(eqIdx + 1).trim();
    if (k === 't' && v) timestampStr = v;
    if (k === 'v1' && v && /^[0-9a-fA-F]{64}$/.test(v)) {
      if (v1Signatures.length >= 5) {
        return { valid: false, reason: 'TOO_MANY_V1_SIGNATURES_IN_HEADER' };
      }
      v1Signatures.push(v);
    }
  }

  const timestampSec = Number(timestampStr);
  if (!Number.isInteger(timestampSec) || v1Signatures.length === 0) {
    return { valid: false, reason: 'MALFORMED_SIGNATURE_HEADER' };
  }

  const nowSec = Math.floor((params.nowMs ?? Date.now()) / 1000);
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

  return { valid: true, timestampSec };
}

export interface PersistentWebhookStore {
  /**
   * Mandatory authoritative entity-to-tenant resolver (DEVIL-12):
   * Resolves the authoritative tenantId for entityId from the server database
   * (never trusting unverified metadata.tenantId inside the webhook payload!).
   */
  resolveAuthoritativeEntityTenant(entityId: string): Promise<{
    tenantId: string;
    providerIdempotencyKey?: string;
  } | null>;

  /**
   * Atomically claims (provider, providerEventId) in PostgreSQL with a monotonic fencingToken.
   * If (provider, providerEventId) already exists with a different payloadSha256, returns
   * 'PAYLOAD_HASH_MISMATCH_TAMPERED' to block duplicate ID tampering!
   */
  claimWebhookEvent(params: {
    provider: string;
    providerEventId: string;
    eventType: string;
    entityId: string;
    tenantId: string;
    providerCreatedAtSec: number;
    payloadSha256: string;
    lockOwner: string;
    leaseSeconds: number;
  }): Promise<
    | { claimStatus: 'CLAIMED'; fencingToken: bigint }
    | { claimStatus: 'DUPLICATE_ALREADY_PROCESSED' }
    | { claimStatus: 'IN_FLIGHT_CONCURRENT' }
    | { claimStatus: 'PAYLOAD_HASH_MISMATCH_TAMPERED' }
  >;

  /**
   * Executes inside a single DB transaction gated by (lockOwner, fencingToken):
   * checks whether providerCreatedAtSec >= entity's last_webhook_created_at_sec,
   * reconciles any UNKNOWN_RECONCILIATION_REQUIRED idempotency_keys row sharing resolvedProviderIdempotencyKey,
   * applies the domain mutation if newer, and marks the webhook PROCESSED.
   */
  applyOrderedDomainEffectAndMarkProcessed(params: {
    provider: string;
    providerEventId: string;
    entityId: string;
    tenantId: string;
    providerCreatedAtSec: number;
    lockOwner: string;
    fencingToken: bigint;
    resolvedProviderIdempotencyKey?: string;
    applyEffect: () => Promise<void>;
  }): Promise<
    | 'APPLIED_AND_PROCESSED'
    | 'OUT_OF_ORDER_STALE_EVENT_IGNORED'
    | 'FENCING_TOKEN_REJECTED_STALE_WORKER'
  >;

  markWebhookFailedRetryable(params: {
    provider: string;
    providerEventId: string;
    lockOwner: string;
    fencingToken: bigint;
  }): Promise<void>;
}

export async function verifyAndProcessWebhookIdempotently(params: {
  provider: string;
  rawBodyBuffer: Buffer;
  signatureHeader: string;
  webhookSecrets: string[];
  store: PersistentWebhookStore;
  parseEventEnvelope: (rawJson: string) => {
    providerEventId: string;
    eventType: string;
    entityId: string;
    claimedTenantId?: string;
    providerCreatedAtSec: number;
  };
  applyDomainEffect: () => Promise<void>;
  toleranceSeconds?: number;
  nowMs?: number;
}): Promise<{
  outcome:
    | 'PROCESSED'
    | 'DUPLICATE_ALREADY_PROCESSED'
    | 'OUT_OF_ORDER_STALE_EVENT_IGNORED'
    | 'IN_FLIGHT_CONCURRENT';
}> {
  if (!Buffer.isBuffer(params.rawBodyBuffer) || params.rawBodyBuffer.byteLength === 0) {
    throw new OperationalAppError(
      400,
      'webhook-raw-body-required',
      'Raw Webhook Body Buffer Required',
      'Webhook signature verification requires the exact unparsed rawBodyBuffer.'
    );
  }

  // 1. Cryptographic signature & timestamp verification against exact rawBodyBuffer
  const sigVerdict = verifyWebhookSignature({
    rawBodyBuffer: params.rawBodyBuffer,
    signatureHeader: params.signatureHeader,
    webhookSecrets: params.webhookSecrets,
    toleranceSeconds: params.toleranceSeconds,
    nowMs: params.nowMs,
  });

  if (!sigVerdict.valid) {
    throw new OperationalAppError(
      401,
      'webhook-signature-invalid',
      'Invalid Webhook Signature',
      `Webhook verification failed: ${sigVerdict.reason ?? 'UNKNOWN'}`
    );
  }

  const envelope = params.parseEventEnvelope(params.rawBodyBuffer.toString('utf8'));
  if (!envelope.providerEventId || !envelope.entityId) {
    throw new OperationalAppError(
      400,
      'webhook-malformed-envelope',
      'Malformed Webhook Envelope',
      'Webhook payload is missing required id or entity identifier.'
    );
  }

  // 2. Mandatory Authoritative Entity-to-Tenant Attribution Verification (DEVIL-12)
  if (typeof params.store.resolveAuthoritativeEntityTenant !== 'function') {
    throw new Error('WEBHOOK_CONFIG_ERROR: store.resolveAuthoritativeEntityTenant is mandatory');
  }
  const authEntity = await params.store.resolveAuthoritativeEntityTenant(envelope.entityId);
  if (!authEntity) {
    throw new OperationalAppError(
      404,
      'webhook-entity-not-found',
      'Webhook Target Entity Not Found',
      'Referenced entityId does not exist in authoritative store.'
    );
  }
  if (envelope.claimedTenantId !== undefined && envelope.claimedTenantId !== authEntity.tenantId) {
    throw new OperationalAppError(
      403,
      'webhook-cross-tenant-attribution-mismatch',
      'Webhook Tenant Attribution Mismatch',
      'Webhook metadata tenantId does not match the authoritative tenant owner of entityId.'
    );
  }
  const resolvedProviderIdempotencyKey = authEntity.providerIdempotencyKey;

  const payloadSha256 = crypto.createHash('sha256').update(params.rawBodyBuffer).digest('hex');
  const lockOwner = crypto.randomUUID();

  // 3. Atomic persistent claim in PostgreSQL with payloadSha256 collision check & fencingToken
  const claim = await params.store.claimWebhookEvent({
    provider: params.provider,
    providerEventId: envelope.providerEventId,
    eventType: envelope.eventType,
    entityId: envelope.entityId,
    tenantId: authEntity.tenantId,
    providerCreatedAtSec: envelope.providerCreatedAtSec,
    payloadSha256,
    lockOwner,
    leaseSeconds: 30,
  });

  if (claim.claimStatus === 'PAYLOAD_HASH_MISMATCH_TAMPERED') {
    throw new OperationalAppError(
      409,
      'webhook-event-id-payload-mismatch',
      'Webhook Event ID Payload Hash Mismatch',
      'A webhook with this providerEventId was already recorded with a different payload SHA-256 digest.'
    );
  }
  if (claim.claimStatus === 'DUPLICATE_ALREADY_PROCESSED') {
    return { outcome: 'DUPLICATE_ALREADY_PROCESSED' };
  }
  if (claim.claimStatus === 'IN_FLIGHT_CONCURRENT') {
    return { outcome: 'IN_FLIGHT_CONCURRENT' };
  }

  const { fencingToken } = claim;

  // 4. Apply domain mutation with out-of-order protection, fencing token verification, and atomic mark PROCESSED
  try {
    const res = await params.store.applyOrderedDomainEffectAndMarkProcessed({
      provider: params.provider,
      providerEventId: envelope.providerEventId,
      entityId: envelope.entityId,
      tenantId: authEntity.tenantId,
      providerCreatedAtSec: envelope.providerCreatedAtSec,
      lockOwner,
      fencingToken,
      resolvedProviderIdempotencyKey,
      applyEffect: params.applyDomainEffect,
    });

    if (res === 'FENCING_TOKEN_REJECTED_STALE_WORKER') {
      throw new Error('WEBHOOK_FENCING_TOKEN_REJECTED_STALE_WORKER');
    }
    if (res === 'OUT_OF_ORDER_STALE_EVENT_IGNORED') {
      return { outcome: 'OUT_OF_ORDER_STALE_EVENT_IGNORED' };
    }
    return { outcome: 'PROCESSED' };
  } catch (err) {
    if (!(err instanceof Error && err.message === 'WEBHOOK_FENCING_TOKEN_REJECTED_STALE_WORKER')) {
      await params.store.markWebhookFailedRetryable({
        provider: params.provider,
        providerEventId: envelope.providerEventId,
        lockOwner,
        fencingToken,
      });
    }
    throw err;
  }
}
```

---

## 5. Distributed Rate Limiting (Atomic Redis Token Bucket Lua Script)

```lua
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

## 6. Circuit Breaker Pattern (With Half-Open Probe Concurrency Gate)

```typescript
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  name: string;
  failureThreshold: number;
  successThreshold: number;
  openCooldownMs: number;
  requestTimeoutMs: number;
  halfOpenMaxConcurrentProbes?: number;
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private failureCount = 0;
  private halfOpenSuccessCount = 0;
  private halfOpenInFlightProbes = 0;
  private nextAttemptAtMs = 0;

  private readonly opts: CircuitBreakerOptions;

  constructor(opts: CircuitBreakerOptions) {
    this.opts = opts;
  }

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

---

## 7. Verification & Test Requirements

1. **Concurrent Duplicate Payment Request & Stale Worker Fencing (`TEST-09`, `TEST-10`)**:
   - Worker 1 acquires lock (`fencingToken = 1`), its lease expires, and Worker 2 takes over the lock (`fencingToken = 2`) and completes. When Worker 1 subsequently calls `completeLockConditionally` with `fencingToken = 1`, it is rejected with `IDEMPOTENCY_FENCING_TOKEN_REJECTED_STALE_OWNER`.
2. **Ambiguous Payment Provider Timeout & Reconciliation (`TEST-11`)**:
   - Handler throws `AmbiguousPaymentProviderTimeoutError`. Row transitions to `UNKNOWN_RECONCILIATION_REQUIRED` (not `FAILED_TERMINAL`). A subsequent retry after lease expiry invokes `reconcileAmbiguousPayment(providerIdempotencyKey)` and returns the reconciled `SUCCEEDED` charge without calling `handler` a second time.
3. **Webhook Replay Inside Timestamp Window, Concurrent Delivery & Out-of-Order Events (`TEST-12`, `TEST-13`)**:
   - Delivering the exact same valid signed webhook twice within the 300s tolerance window executes `applyDomainEffect` once (`PROCESSED`) and returns `DUPLICATE_ALREADY_PROCESSED` on the second delivery.
   - Delivering an older webhook (`providerCreatedAtSec: 1000`) after a newer webhook (`providerCreatedAtSec: 2000`) returns `OUT_OF_ORDER_STALE_EVENT_IGNORED`.

### Authoritative References
- **RFC 9457 — Problem Details for HTTP APIs**: https://datatracker.ietf.org/doc/html/rfc9457
- **IETF Draft — `Idempotency-Key` HTTP Header Field**: https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header
- **Stripe Webhook Signature & Replay Prevention Best Practices**: https://docs.stripe.com/webhooks/signatures
