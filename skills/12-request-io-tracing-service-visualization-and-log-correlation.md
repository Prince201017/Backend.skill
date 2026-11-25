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
export const MAX_IN_MEMORY_TRACE_HOPS = 256;    // Bounded in-memory hop ring cap per request trace

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
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^/\s:@]+:[^/\s@]+@/gi,
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /Basic\s+[A-Za-z0-9+/=]+/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:sk_live_|sk_test_|rk_live_|whsec_|sk-proj-|sk-ant-|ghp_|xoxb-|xoxp-)[A-Za-z0-9_\-]+\b/g,
  /\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35})\b/g,
  /\b(?:\d[ -]*?){13,19}\b/g,
];

export function truncateUtf8ToMaxBytes(str: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) return str;
  // Decode byte slice and drop any trailing replacement char from a split multi-byte codepoint
  let sliced = buf.subarray(0, maxBytes).toString('utf8');
  while (sliced.endsWith('\uFFFD') && Buffer.byteLength(sliced, 'utf8') > 0) {
    sliced = sliced.slice(0, -1);
  }
  while (Buffer.byteLength(sliced, 'utf8') > maxBytes && sliced.length > 0) {
    sliced = sliced.slice(0, -1);
  }
  return sliced;
}

export function redactTraceEnvelopeSecrets(
  input: unknown,
  depth = 0,
  seen: WeakSet<object> = new WeakSet()
): unknown {
  if (depth > 8) return '[MAX_DEPTH_TRUNCATED]';
  if (input === null || input === undefined) return input;
  if (typeof input === 'bigint') return input.toString();

  if (typeof input === 'string') {
    let scrubbed = input
      .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
      .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
    for (const pattern of SECRET_STRING_PATTERNS) {
      scrubbed = scrubbed.replace(pattern, '[REDACTED_SECRET]');
    }
    return scrubbed;
  }

  if (typeof input !== 'object') return input;
  if (seen.has(input)) return '[CIRCULAR_REF]';
  seen.add(input);

  if (input instanceof Error) {
    return {
      name: redactTraceEnvelopeSecrets(input.name, depth + 1, seen),
      message: redactTraceEnvelopeSecrets(input.message, depth + 1, seen),
      ...(input.stack ? { stack: redactTraceEnvelopeSecrets(input.stack, depth + 1, seen) } : {}),
    };
  }

  if (Array.isArray(input)) {
    return input.slice(0, 100).map((item) => redactTraceEnvelopeSecrets(item, depth + 1, seen));
  }

  const output: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (isSensitiveTraceKey(key)) {
      output[key] = '[REDACTED]';
    } else {
      output[key] = redactTraceEnvelopeSecrets(value, depth + 1, seen);
    }
  }
  return { ...output };
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
    preview: truncateUtf8ToMaxBytes(serialized, Math.max(64, maxBytes - 128)),
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
  let traceId: string;
  if (params.traceId !== undefined) {
    // Enforce W3C Trace Context 16-byte lowercase hex trace-id (blocks CRLF/header injection into traceparent)
    if (!/^[0-9a-fA-F]{32}$/.test(params.traceId) || /^0{32}$/.test(params.traceId)) {
      throw new Error('TRACE_INVALID_TRACE_ID: traceId must be a non-zero 32-character hexadecimal W3C trace-id');
    }
    traceId = params.traceId.toLowerCase();
  } else {
    traceId = randomBytes(16).toString('hex');
  }
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
  try {
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
  } catch (err) {
    const durationMs = Math.max(0, Date.now() - startedAtMs);
    shared.hops.unshift({
      spanId: rootSpanId,
      parentSpanId: null,
      serviceName: 'api-gateway-entry',
      operationName: params.rootOperationName,
      direction: 'INBOUND',
      startedAtMs,
      durationMs,
      statusCode: 500,
      errorMessage: err instanceof Error ? String(redactTraceEnvelopeSecrets(err.message)) : 'ROOT_ERROR',
    });
    if (err instanceof Error) {
      (err as Error & { traceEnvelope?: CorrelatedTraceEnvelope }).traceEnvelope =
        exportCorrelatedTraceEnvelope(shared);
    }
    throw err;
  }
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
        if (currentStore.shared.hops.length >= MAX_IN_MEMORY_TRACE_HOPS) {
          currentStore.shared.hops.shift();
        }
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
        if (currentStore.shared.hops.length >= MAX_IN_MEMORY_TRACE_HOPS) {
          currentStore.shared.hops.shift();
        }
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
    operationName:
      Buffer.byteLength(hop.operationName, 'utf8') > 256
        ? `${truncateUtf8ToMaxBytes(hop.operationName, 240)}...[TRUNCATED]`
        : hop.operationName,
    serviceName:
      Buffer.byteLength(hop.serviceName, 'utf8') > 128
        ? `${truncateUtf8ToMaxBytes(hop.serviceName, 112)}...[TRUNCATED]`
        : hop.serviceName,
    errorMessage:
      hop.errorMessage && Buffer.byteLength(hop.errorMessage, 'utf8') > 2048
        ? `${truncateUtf8ToMaxBytes(hop.errorMessage, 1024)}...[TRUNCATED]`
        : hop.errorMessage,
    redactedRequestPreview: boundPreviewPayload(hop.redactedRequestPreview, MAX_HOP_PAYLOAD_BYTES),
    redactedResponsePreview: boundPreviewPayload(hop.redactedResponsePreview, MAX_HOP_PAYLOAD_BYTES),
  }));

  const candidate: CorrelatedTraceEnvelope = {
    traceId: truncateUtf8ToMaxBytes(shared.traceId, 128),
    tenantId: truncateUtf8ToMaxBytes(shared.tenantId, 128),
    requestId: truncateUtf8ToMaxBytes(shared.requestId, 128),
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

  // Step 1: Strip request/response previews on hops to fit within 32 KB
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

  // Step 2 (DEVIL-21 Fix): Drop OLDEST non-root hops first (index 1, preserving root hop at index 0
  // and the most recent tail hops) until strictly <= 32,768 bytes!
  while (byteLength > MAX_TRACE_ENVELOPE_BYTES && candidate.hops.length > 1) {
    candidate.hops.splice(1, 1);
    serialized = JSON.stringify(candidate);
    byteLength = Buffer.byteLength(serialized, 'utf8');
  }

  // Step 3 (DEVIL-21 Fix): Guarantee <= 32,768 UTF-8 bytes even when only a single oversized root hop remains
  if (byteLength > MAX_TRACE_ENVELOPE_BYTES && candidate.hops.length === 1) {
    const rootHop = candidate.hops[0];
    candidate.hops = [
      {
        spanId: truncateUtf8ToMaxBytes(rootHop.spanId, 32),
        parentSpanId: null,
        serviceName: truncateUtf8ToMaxBytes(rootHop.serviceName, 64),
        operationName: truncateUtf8ToMaxBytes(rootHop.operationName, 128),
        direction: rootHop.direction,
        startedAtMs: rootHop.startedAtMs,
        durationMs: rootHop.durationMs,
        statusCode: rootHop.statusCode,
        errorMessage: rootHop.errorMessage
          ? `${truncateUtf8ToMaxBytes(rootHop.errorMessage, 512)}...[TRUNCATED]`
          : undefined,
      },
    ];
    serialized = JSON.stringify(candidate);
    byteLength = Buffer.byteLength(serialized, 'utf8');
  }

  candidate.byteLength = byteLength;
  return candidate;
}
```
