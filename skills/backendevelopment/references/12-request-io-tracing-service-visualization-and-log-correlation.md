# 12. Incoming/Outgoing Request I/O Tracing, Service Dependency Visualization & Correlated Log Telemetry

This module defines the zero-loss observability, request/response I/O envelope tracing, service-to-service topology capture, and correlated structured JSON log telemetry architecture required to inspect every incoming request, internal BaaS/database hop, outbox relay, and outgoing external API call in real time.

---

## 1. Architectural Principles for Request I/O & Service Telemetry

1. **W3C `traceparent` Propagation Everywhere**:
   - Every incoming HTTP, WebSocket, or Webhook request MUST either extract a valid W3C Trace Context (`traceparent: 00-<32-hex-trace-id>-<16-hex-parent-span-id>-<01>`) or mint a fresh CSPRNG 128-bit `trace_id` and 64-bit root `span_id`.
   - Every internal hop (Auth/RBA evaluation, Supabase/Firebase/PostgreSQL query, Committed Outbox write, Queue worker execution, and Outgoing 3P HTTP call) MUST create a child `span_id` linked via `parent_span_id` and propagate `traceparent` in outbound headers or outbox metadata.
2. **Bounded, PII-Scrubbed I/O Envelope Capture**:
   - Capturing raw incoming and outgoing payloads without bounds or sanitization causes memory exhaustion (OOM) and compliance violations (GDPR/PCI-DSS).
   - Every captured I/O payload snapshot MUST pass through:
     - **Recursive Key & Pattern Scrubbing**: Redact `password`, `secret`, `token`, `authorization`, `cookie`, `cvv`, `pan`, `ssn`, and OTP codes before serialization.
     - **Byte-Length Truncation Guard**: Truncate individual string fields exceeding `4,096` bytes and cap total captured envelope snapshots at `32 KB` (`[TRUNCATED_PAYLOAD: original_bytes=...]`).
3. **Deterministic Service Hop Topology**:
   - Every request trace is modeled as a Directed Acyclic Graph (DAG) of typed service hops:
     1. `INGRESS_GATEWAY`: TLS termination, Trusted Proxy IP extraction, Prototype Pollution & NoSQL `$` sanitization, Rate Limiting.
     2. `AUTH_RBA_ENGINE`: JWT cryptographic verification (`alg` whitelist), Session Binding, Risk-Based Authentication (RBA) scoring, BOLA/RBAC/ABAC policy evaluation.
     3. `BAAS_DATA_PLANE`: Supabase (`auth.jwt() -> 'app_metadata'` RLS), Firebase (`firestore.rules` 8-Pillar evaluation), or PostgreSQL transactional execution + Committed Outbox (`outbox_events`) insertion.
     4. `ASYNC_OUTBOX_RELAY`: Polling/CDC of committed outbox rows, priority queue routing (`P0_CRITICAL`..`P3_BULK`), atomic worker lease acquisition (`fencing_token`).
     5. `EGRESS_EXTERNAL_PROVIDER`: DNS-pinned SSRF-safe outbound dispatch to Stripe, AWS SES, Postmark, Twilio, FCM, or webhooks with Definitive-vs-Ambiguous failover classification.
4. **Correlated Structured JSON Logs**:
   - Every log entry emitted during any service hop MUST carry `trace_id`, `span_id`, `service`, `hop_index`, `level` (`DEBUG` | `INFO` | `WARN` | `ERROR` | `SECURITY_AUDIT`), `duration_ms`, and structured `context` so operators can filter logs by clicking any node in the service topology graph.

---

## 2. Production TypeScript Implementation: I/O Envelope Tracer, PII Scrubber & Correlated Logger

```typescript
import { randomBytes } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'SECURITY_AUDIT';

export type ServiceHopType =
  | 'INGRESS_GATEWAY'
  | 'AUTH_RBA_ENGINE'
  | 'BAAS_DATA_PLANE'
  | 'ASYNC_OUTBOX_RELAY'
  | 'EGRESS_EXTERNAL_PROVIDER';

export type HopStatus = 'OK' | 'DEGRADED_FAILOVER' | 'BLOCKED_SECURITY' | 'ERROR';

export interface CorrelatedLogEntry {
  timestamp: string;
  level: LogLevel;
  trace_id: string;
  span_id: string;
  parent_span_id: string | null;
  service: string;
  hop_type: ServiceHopType;
  event: string;
  message: string;
  duration_ms?: number;
  http_status?: number;
  security_rule?: string;
  metadata: Record<string, unknown>;
}

export interface ServiceHopSnapshot {
  span_id: string;
  parent_span_id: string | null;
  hop_index: number;
  hop_type: ServiceHopType;
  service_name: string;
  operation: string;
  status: HopStatus;
  started_at: string;
  duration_ms: number;
  policy_or_query?: string;
  input_envelope: {
    headers?: Record<string, string>;
    payload: Record<string, unknown>;
    byte_size: number;
  };
  output_envelope: {
    status_code: number;
    headers?: Record<string, string>;
    payload: Record<string, unknown>;
    byte_size: number;
  };
  error_code?: string;
}

export interface RequestTraceEnvelope {
  trace_id: string;
  traceparent: string;
  started_at: string;
  total_duration_ms: number;
  http_method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  route: string;
  client_ip: string;
  tenant_id: string;
  actor_id: string | null;
  final_status: number;
  overall_outcome: HopStatus;
  incoming_request: {
    headers: Record<string, string>;
    body: Record<string, unknown>;
  };
  outgoing_response: {
    status: number;
    headers: Record<string, string>;
    body: Record<string, unknown>;
  };
  service_hops: ServiceHopSnapshot[];
  logs: CorrelatedLogEntry[];
}

const SENSITIVE_KEY_REGEX =
  /^(password|passcode|secret|token|access_token|refresh_token|authorization|cookie|set-cookie|api_key|apikey|client_secret|cvv|cvc|pan|card_number|ssn|tax_id|otp|code|private_key)$/i;

const VALUE_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  // Bearer / JWT tokens
  { pattern: /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi, replacement: 'Bearer [REDACTED_JWT]' },
  // Raw credit card numbers (13-19 digits)
  { pattern: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[REDACTED_PAN]' },
];

const MAX_STRING_LENGTH = 4096;
const MAX_DEPTH = 8;

/**
 * Recursively scrubs PII, credentials, and tokens from arbitrary I/O payloads
 * while enforcing strict recursion depth and string length caps.
 */
export function scrubIoPayload(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) {
    return '[TRUNCATED_MAX_DEPTH]';
  }
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    let scrubbed = value;
    for (const { pattern, replacement } of VALUE_PATTERNS) {
      scrubbed = scrubbed.replace(pattern, replacement);
    }
    if (scrubbed.length > MAX_STRING_LENGTH) {
      return `${scrubbed.slice(0, MAX_STRING_LENGTH)}...[TRUNCATED_${scrubbed.length}_BYTES]`;
    }
    return scrubbed;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => scrubIoPayload(item, depth + 1));
  }
  if (typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        result[k] = '[REDACTED_SECRET]';
      } else {
        result[k] = scrubIoPayload(v, depth + 1);
      }
    }
    return result;
  }
  return String(value);
}

export interface TraceContextStore {
  traceId: string;
  rootSpanId: string;
  activeSpanId: string;
  tenantId: string;
  actorId: string | null;
  hops: ServiceHopSnapshot[];
  logs: CorrelatedLogEntry[];
}

export const traceStorage = new AsyncLocalStorage<TraceContextStore>();

export function parseOrMintTraceparent(header?: string | null): {
  traceId: string;
  parentSpanId: string | null;
  rootSpanId: string;
  traceparent: string;
} {
  const w3cRegex = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
  const match = header ? w3cRegex.exec(header.trim().toLowerCase()) : null;

  const traceId =
    match && match[1] !== '00000000000000000000000000000000'
      ? match[1]
      : randomBytes(16).toString('hex');
  const parentSpanId =
    match && match[2] !== '0000000000000000' ? match[2] : null;
  const rootSpanId = randomBytes(8).toString('hex');

  return {
    traceId,
    parentSpanId,
    rootSpanId,
    traceparent: `00-${traceId}-${rootSpanId}-01`,
  };
}

/**
 * Emits a structured JSON log entry bound to the current W3C trace_id and span_id.
 */
export function emitCorrelatedLog(params: {
  level: LogLevel;
  service: string;
  hopType: ServiceHopType;
  event: string;
  message: string;
  durationMs?: number;
  httpStatus?: number;
  securityRule?: string;
  metadata?: Record<string, unknown>;
}): CorrelatedLogEntry {
  const store = traceStorage.getStore();
  const entry: CorrelatedLogEntry = {
    timestamp: new Date().toISOString(),
    level: params.level,
    trace_id: store?.traceId ?? randomBytes(16).toString('hex'),
    span_id: store?.activeSpanId ?? randomBytes(8).toString('hex'),
    parent_span_id: store?.rootSpanId ?? null,
    service: params.service,
    hop_type: params.hopType,
    event: params.event,
    message: params.message,
    duration_ms: params.durationMs,
    http_status: params.httpStatus,
    security_rule: params.securityRule,
    metadata: (scrubIoPayload(params.metadata ?? {}) as Record<string, unknown>) ?? {},
  };

  if (store) {
    store.logs.push(entry);
  }
  return entry;
}

/**
 * Wraps any service hop (Ingress, Auth/RBA, Supabase/Firebase/DB, Outbox, Outbound API)
 * to automatically capture scrubbed input/output envelopes, execution latency, and correlated logs.
 */
export async function traceServiceHop<TOutput extends Record<string, unknown>>(params: {
  hopType: ServiceHopType;
  serviceName: string;
  operation: string;
  policyOrQuery?: string;
  inputHeaders?: Record<string, string>;
  inputPayload: Record<string, unknown>;
  execute: (spanId: string) => Promise<{
    status: HopStatus;
    statusCode: number;
    outputHeaders?: Record<string, string>;
    outputPayload: TOutput;
    errorCode?: string;
  }>;
}): Promise<TOutput> {
  const store = traceStorage.getStore();
  const spanId = randomBytes(8).toString('hex');
  const parentSpanId = store?.activeSpanId ?? null;
  const startedAt = new Date().toISOString();
  const startHr = performance.now();

  if (store) {
    store.activeSpanId = spanId;
  }

  const scrubbedInput = scrubIoPayload(params.inputPayload) as Record<string, unknown>;
  const scrubbedInHeaders = scrubIoPayload(params.inputHeaders ?? {}) as Record<string, string>;
  const inBytes = Buffer.byteLength(JSON.stringify(scrubbedInput), 'utf8');

  try {
    const result = await params.execute(spanId);
    const durationMs = Number((performance.now() - startHr).toFixed(2));
    const scrubbedOutput = scrubIoPayload(result.outputPayload) as Record<string, unknown>;
    const scrubbedOutHeaders = scrubIoPayload(result.outputHeaders ?? {}) as Record<string, string>;
    const outBytes = Buffer.byteLength(JSON.stringify(scrubbedOutput), 'utf8');

    if (store) {
      store.hops.push({
        span_id: spanId,
        parent_span_id: parentSpanId,
        hop_index: store.hops.length + 1,
        hop_type: params.hopType,
        service_name: params.serviceName,
        operation: params.operation,
        status: result.status,
        started_at: startedAt,
        duration_ms: durationMs,
        policy_or_query: params.policyOrQuery,
        input_envelope: {
          headers: scrubbedInHeaders,
          payload: scrubbedInput,
          byte_size: inBytes,
        },
        output_envelope: {
          status_code: result.statusCode,
          headers: scrubbedOutHeaders,
          payload: scrubbedOutput,
          byte_size: outBytes,
        },
        error_code: result.errorCode,
      });
    }

    return result.outputPayload;
  } finally {
    if (store && parentSpanId) {
      store.activeSpanId = parentSpanId;
    }
  }
}
```
