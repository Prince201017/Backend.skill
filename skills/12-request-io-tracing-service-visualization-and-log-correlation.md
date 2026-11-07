# Module 12: Request I/O Tracing, Service Visualization & Log Correlation

## 1. Scope & Threat Model

This module defines the end-to-end telemetry, W3C Trace Context propagation (`traceparent`), AsyncLocalStorage context management, and bounded I/O envelope serialization required for distributed backend observability and visual flow inspection.

### Trust Boundaries & Failure Modes
1. **Unbounded Trace / Hop Envelope Memory Exhaustion**:
   - *Vulnerability*: Checking `Buffer.byteLength <= 32768` only on individual hop payloads (`recordHop`) while allowing `exportCorrelatedTraceEnvelope()` to accumulate hundreds of hops into a multi-megabyte JSON payload causes OOM crashes or log-ingestion pipeline drops.
   - *Enforcement*: Enforce the strict `MAX_ENVELOPE_BYTES = 32_768` (32 KB) budget on **both** individual hop payloads and the serialized full trace envelope (`exportCorrelatedTraceEnvelope()`), deterministically truncating excess hop previews if the aggregate envelope approaches 32 KB.
2. **Secret Leakage in Correlated I/O Envelopes**:
   - *Vulnerability*: Recording request/response headers or body previews in trace spans without comprehensive secret key and value redaction leaks `passwordHash`, `x-api-key`, `Authorization: Bearer ...`, `clientSecret`, `refreshToken`, PEM private keys, and credit card PANs into observability stores.
   - *Enforcement*: Pass all headers, query params, and payload previews through `redactTraceEnvelopeSecrets()` before storing or exporting any span.
3. **Concurrent Span Context Mutation (`store.activeSpanId` Race Condition)**:
   - *Vulnerability*: Mutating `store.activeSpanId = spanId` in place inside an `AsyncLocalStorage` store object shared across concurrent `Promise.all()` branches corrupts parent-child span relationships (`parentSpanId` points to a sibling branch instead of the true parent).
   - *Enforcement*: Never mutate `AsyncLocalStorage` store properties in place. Always create an immutable child context via `traceStorage.run({ ...parentStore, activeSpanId: newSpanId }, fn)`.

---

## 2. Immutable `AsyncLocalStorage` Trace Context, Comprehensive Redaction & 32 KB Bounded Envelopes

```typescript
// Executable TypeScript — Concurrent-Safe Trace Context & 32 KB Bounded Envelope Exporter
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';

export const MAX_HOP_PAYLOAD_BYTES = 8_192;   // 8 KB max per individual hop preview
export const MAX_TRACE_ENVELOPE_BYTES = 32_768; // Hard 32 KB limit on full exported trace envelope

export interface TraceHopSpan {
  spanId: string;
  parentSpanId: string | null;
  serviceName: string;
  operationName: string;
  direction: 'INBOUND' | 'OUTBOUND_HTTP' | 'DATABASE' | 'CACHE' | 'QUEUE';
  startedAtMs: number;
  durationMs: number;
  statusCode?: number;
  redactedRequestPreview?: unknown;
  redactedResponsePreview?: unknown;
  errorMessage?: string;
}

export interface SharedTraceBuffer {
  readonly traceId: string;
  readonly tenantId: string;
  readonly requestId: string;
  readonly hops: TraceHopSpan[];
}

export interface ImmutableTraceContextStore {
  readonly shared: SharedTraceBuffer;
  readonly activeSpanId: string;
}

const traceContextStorage = new AsyncLocalStorage<ImmutableTraceContextStore>();

const NORMALIZED_SECRET_KEYS = new Set([
  'password',
  'passwd',
  'passwordhash',
  'passhash',
  'secret',
  'clientsecret',
  'webhooksecret',
  'signingsecret',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'sessiontoken',
  'resettoken',
  'apikey',
  'xapikey',
  'authorization',
  'proxyauthorization',
  'cookie',
  'setcookie',
  'privatekey',
  'secretkey',
  'serviceaccountkey',
  'cvv',
  'cvc',
  'pan',
  'cardnumber',
  'ssn',
  'taxid',
  'otp',
  'pin',
]);

export function isSensitiveTraceKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (NORMALIZED_SECRET_KEYS.has(normalized)) {
    return true;
  }
  return (
    normalized.endsWith('secret') ||
    normalized.endsWith('token') ||
    normalized.endsWith('password') ||
    normalized.endsWith('passwordhash') ||
    normalized.endsWith('apikey') ||
    normalized.endsWith('privatekey')
  );
}

const SECRET_STRING_PATTERNS: readonly RegExp[] = [
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /Basic\s+[A-Za-z0-9+/=]+/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:sk_live_|sk_test_|rk_live_|whsec_|ghp_|xoxb-|xoxp-)[A-Za-z0-9_]+\b/g,
  /\b(?:\d[ -]*?){13,19}\b/g,
];

export function redactTraceEnvelopeSecrets(input: unknown, depth = 0): unknown {
  if (depth > 8) return '[MAX_DEPTH_TRUNCATED]';
  if (input === null || input === undefined) return input;

  if (typeof input === 'string') {
    let scrubbed = input;
    for (const pattern of SECRET_STRING_PATTERNS) {
      scrubbed = scrubbed.replace(pattern, '[REDACTED_SECRET]');
    }
    return scrubbed;
  }

  if (typeof input !== 'object') return input;

  if (Array.isArray(input)) {
    return input.map((item) => redactTraceEnvelopeSecrets(item, depth + 1));
  }

  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (isSensitiveTraceKey(key)) {
      output[key] = '[REDACTED]';
    } else {
      output[key] = redactTraceEnvelopeSecrets(value, depth + 1);
    }
  }
  return output;
}

function boundPreviewPayload(value: unknown, maxBytes: number): unknown {
  if (value === undefined) return undefined;
  const redacted = redactTraceEnvelopeSecrets(value);
  const serialized = JSON.stringify(redacted);
  if (!serialized) return undefined;
  const byteLen = Buffer.byteLength(serialized, 'utf8');
  if (byteLen <= maxBytes) {
    return redacted;
  }
  return {
    _truncated: true,
    _originalBytes: byteLen,
    preview: serialized.slice(0, Math.max(128, maxBytes - 128)),
  };
}

export async function runInRootTraceContext<T>(
  params: {
    traceId?: string;
    tenantId: string;
    requestId: string;
    rootOperationName: string;
  },
  fn: () => Promise<T>
): Promise<{ result: T; envelope: CorrelatedTraceEnvelope }> {
  const traceId = params.traceId ?? randomBytes(16).toString('hex');
  const rootSpanId = randomBytes(8).toString('hex');
  const shared: SharedTraceBuffer = {
    traceId,
    tenantId: params.tenantId,
    requestId: params.requestId,
    hops: [],
  };

  const rootStore: ImmutableTraceContextStore = {
    shared,
    activeSpanId: rootSpanId,
  };

  const startedAtMs = Date.now();
  const result = await traceContextStorage.run(rootStore, fn);
  const durationMs = Math.max(0, Date.now() - startedAtMs);

  shared.hops.unshift({
    spanId: rootSpanId,
    parentSpanId: null,
    serviceName: 'api-gateway-entry',
    operationName: params.rootOperationName,
    direction: 'INBOUND',
    startedAtMs,
    durationMs,
    statusCode: 200,
  });

  return {
    result,
    envelope: exportCorrelatedTraceEnvelope(shared),
  };
}

/**
 * Executes a child span without mutating the parent AsyncLocalStorage store in place.
 * Parallel calls via Promise.all() each receive their own immutable child store,
 * preserving exact parentSpanId lineage across concurrent branches.
 */
export async function executeTracedHop<T>(
  params: {
    serviceName: string;
    operationName: string;
    direction: TraceHopSpan['direction'];
    requestPreview?: unknown;
  },
  fn: (spanContext: { traceparent: string; spanId: string; parentSpanId: string | null }) => Promise<{
    result: T;
    statusCode?: number;
    responsePreview?: unknown;
  }>
): Promise<T> {
  const currentStore = traceContextStorage.getStore();
  const spanId = randomBytes(8).toString('hex');
  const parentSpanId = currentStore ? currentStore.activeSpanId : null;
  const traceId = currentStore ? currentStore.shared.traceId : randomBytes(16).toString('hex');
  const traceparent = `00-${traceId}-${spanId}-01`;

  const startedAtMs = Date.now();

  const runCallback = async (): Promise<T> => {
    try {
      const { result, statusCode, responsePreview } = await fn({
        traceparent,
        spanId,
        parentSpanId,
      });
      if (currentStore) {
        currentStore.shared.hops.push({
          spanId,
          parentSpanId,
          serviceName: params.serviceName,
          operationName: params.operationName,
          direction: params.direction,
          startedAtMs,
          durationMs: Math.max(0, Date.now() - startedAtMs),
          statusCode,
          redactedRequestPreview: boundPreviewPayload(params.requestPreview, MAX_HOP_PAYLOAD_BYTES),
          redactedResponsePreview: boundPreviewPayload(responsePreview, MAX_HOP_PAYLOAD_BYTES),
        });
      }
      return result;
    } catch (err) {
      if (currentStore) {
        currentStore.shared.hops.push({
          spanId,
          parentSpanId,
          serviceName: params.serviceName,
          operationName: params.operationName,
          direction: params.direction,
          startedAtMs,
          durationMs: Math.max(0, Date.now() - startedAtMs),
          statusCode: 500,
          redactedRequestPreview: boundPreviewPayload(params.requestPreview, MAX_HOP_PAYLOAD_BYTES),
          errorMessage: err instanceof Error ? String(redactTraceEnvelopeSecrets(err.message)) : 'UNKNOWN_ERROR',
        });
      }
      throw err;
    }
  };

  if (!currentStore) {
    return runCallback();
  }

  // Create a new immutable store object for this child execution tree
  const childStore: ImmutableTraceContextStore = {
    shared: currentStore.shared,
    activeSpanId: spanId,
  };
  return traceContextStorage.run(childStore, runCallback);
}

export interface CorrelatedTraceEnvelope {
  traceId: string;
  tenantId: string;
  requestId: string;
  hopCount: number;
  envelopeTruncated: boolean;
  byteLength: number;
  hops: TraceHopSpan[];
}

export function exportCorrelatedTraceEnvelope(shared: SharedTraceBuffer): CorrelatedTraceEnvelope {
  const sanitizedHops: TraceHopSpan[] = shared.hops.map((hop) => ({
    ...hop,
    redactedRequestPreview: boundPreviewPayload(hop.redactedRequestPreview, MAX_HOP_PAYLOAD_BYTES),
    redactedResponsePreview: boundPreviewPayload(hop.redactedResponsePreview, MAX_HOP_PAYLOAD_BYTES),
  }));

  const candidate: CorrelatedTraceEnvelope = {
    traceId: shared.traceId,
    tenantId: shared.tenantId,
    requestId: shared.requestId,
    hopCount: sanitizedHops.length,
    envelopeTruncated: false,
    byteLength: 0,
    hops: sanitizedHops,
  };

  let serialized = JSON.stringify(candidate);
  let byteLength = Buffer.byteLength(serialized, 'utf8');

  if (byteLength <= MAX_TRACE_ENVELOPE_BYTES) {
    candidate.byteLength = byteLength;
    return candidate;
  }

  // Step 1: Strip request/response previews on non-root hops to fit within 32 KB
  candidate.envelopeTruncated = true;
  candidate.hops = sanitizedHops.map((hop) => ({
    spanId: hop.spanId,
    parentSpanId: hop.parentSpanId,
    serviceName: hop.serviceName,
    operationName: hop.operationName,
    direction: hop.direction,
    startedAtMs: hop.startedAtMs,
    durationMs: hop.durationMs,
    statusCode: hop.statusCode,
    errorMessage: hop.errorMessage,
  }));

  serialized = JSON.stringify(candidate);
  byteLength = Buffer.byteLength(serialized, 'utf8');

  // Step 2: Drop oldest non-root hops until strictly <= 32,768 bytes
  while (byteLength > MAX_TRACE_ENVELOPE_BYTES && candidate.hops.length > 1) {
    candidate.hops.pop();
    serialized = JSON.stringify(candidate);
    byteLength = Buffer.byteLength(serialized, 'utf8');
  }

  candidate.byteLength = byteLength;
  return candidate;
}
```
