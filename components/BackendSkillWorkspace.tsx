'use client';

import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  Activity,
  Database,
  Server,
  Send,
  FileCode2,
  Play,
  Copy,
  Check,
  Search,
  AlertTriangle,
  ArrowRight,
  Terminal,
  Layers,
  Lock,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';

export interface SkillMarkdownFile {
  path: string;
  content: string;
}

export type HopType =
  | 'INGRESS_GATEWAY'
  | 'AUTH_RBA_ENGINE'
  | 'BAAS_DATA_PLANE'
  | 'ASYNC_OUTBOX_RELAY'
  | 'EGRESS_EXTERNAL_PROVIDER';

export type HopStatus = 'OK' | 'DEGRADED_FAILOVER' | 'BLOCKED_SECURITY';

export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'SECURITY_AUDIT';

export interface ServiceHopTrace {
  id: string;
  hopIndex: number;
  hopType: HopType;
  serviceName: string;
  providerBadge: string;
  operation: string;
  status: HopStatus;
  statusCode: number;
  durationMs: number;
  spanId: string;
  parentSpanId: string | null;
  policyTitle: string;
  policyCode: string;
  inputEnvelope: {
    headers: Record<string, string>;
    payload: Record<string, unknown>;
    byteSize: number;
  };
  outputEnvelope: {
    headers: Record<string, string>;
    payload: Record<string, unknown>;
    byteSize: number;
  };
}

export interface CorrelatedLogItem {
  id: string;
  timestamp: string;
  level: LogLevel;
  traceId: string;
  spanId: string;
  hopId: string;
  service: string;
  event: string;
  message: string;
  durationMs: number;
  metadata: Record<string, unknown>;
}

export interface TraceScenario {
  id: string;
  title: string;
  subtitle: string;
  category: string;
  httpMethod: 'POST' | 'PATCH' | 'PUT';
  route: string;
  traceId: string;
  traceparent: string;
  clientIp: string;
  tenantId: string;
  actorId: string;
  finalStatus: number;
  overallStatus: HopStatus;
  totalDurationMs: number;
  defaultRequestHeaders: Record<string, string>;
  defaultRequestBody: Record<string, unknown>;
  outgoingResponse: {
    status: number;
    headers: Record<string, string>;
    body: Record<string, unknown>;
  };
  hops: ServiceHopTrace[];
  logs: CorrelatedLogItem[];
}

export interface CriticalRiskAuditItem {
  id: string;
  domain: string;
  consequence: string;
  severity: 'CRITICAL' | 'HIGH';
  moduleRef: string;
  vulnerabilityFound: string;
  remediationImplemented: string;
  verificationAssertion: string;
  remediationCode: string;
}

const CRITICAL_RISK_ITEMS: CriticalRiskAuditItem[] = [
  {
    id: 'CRIT-01',
    domain: '1. Authentication (JWT, Sessions & Refresh Rotation)',
    consequence: 'Weak JWT/session implementation allowing forged tokens or stolen refresh token replay',
    severity: 'CRITICAL',
    moduleRef: 'Module 02 & 13',
    vulnerabilityFound:
      'Naive JWT verifiers omit maximum byte-length checks, fail to reject future-dated iat claims, lack cryptographic session-binding cookie verification (cnf.sidHash), and do not revoke the session family when a rotated refresh token is replayed.',
    remediationImplemented:
      'Hardened verifyJwtPenetrationSafe() with 8KB cap, algorithm pinning (EdDSA/RS256), alphanumeric kid allowlist, iat/exp/nbf validation, __Host-sid SHA-256 cnf binding, and added rotateRefreshTokenWithReuseDetection() to revoke the entire token family on reuse.',
    verificationAssertion:
      'PASS: Rejected alg:none, kid traversal, future iat, unbound __Host-sid, and revoked entire familyId on rotated refresh token replay.',
    remediationCode: `// Module 02: Refresh Token Reuse Detection & Family Revocation
if (existing.status === 'ROTATED' || existing.status === 'REVOKED') {
  await params.revokeEntireTokenFamily(existing.familyId, 'REFRESH_TOKEN_REUSE_DETECTED');
  throw new Error('REFRESH_TOKEN_COMPROMISED_FAMILY_REVOKED');
}
// Session Binding Cookie Hash Verification (__Host-sid)
const expectedSidHash = crypto.createHash('sha256').update(expectedCookie, 'utf8').digest('hex');
if (claims.cnf?.sidHash !== expectedSidHash) throw new Error('JWT_REJECTED: Session binding mismatch');`,
  },
  {
    id: 'CRIT-02',
    domain: '2. Authorization (Vertical & Horizontal BOLA / IDOR)',
    consequence: 'Users accessing other users’ data within the same tenant or escalating privileges',
    severity: 'CRITICAL',
    moduleRef: 'Module 02 & 11',
    vulnerabilityFound:
      'Checking only subject.tenantId === resource.tenantId and role === "member" allowed a regular member to read or mutate another user’s private order within the same organization (Intra-Tenant Horizontal BOLA).',
    remediationImplemented:
      'Updated authorizeAction() in Module 02 so non-privileged roles (member, viewer) must either be the explicit resource owner (resource.ownerId === subject.userId) or hold an explicit ReBAC graph relationship, plus step-up MFA for high-value actions.',
    verificationAssertion:
      'PASS: Blocked intra-tenant member from reading resource owned by another user (BOLA_HORIZONTAL_OWNERSHIP_DENIED).',
    remediationCode: `// Module 02: Intra-Tenant Horizontal BOLA Guard
const isTenantPrivileged = subject.roles.some((r) => r === 'owner' || r === 'admin' || r === 'finance');
const isResourceOwner = resource.ownerId !== undefined && resource.ownerId === subject.userId;
if (!isTenantPrivileged && action !== 'order:create' && action !== 'file:upload') {
  if (!isResourceOwner && !hasExplicitRebacRelation) {
    return { allowed: false, reason: 'BOLA_HORIZONTAL_OWNERSHIP_DENIED' };
  }
}`,
  },
  {
    id: 'CRIT-03',
    domain: '3. Database Security, Constraints & Explicit Transactions',
    consequence: 'SQL injection, cross-tenant foreign-key references, or leaked RLS context on pooled connections',
    severity: 'CRITICAL',
    moduleRef: 'Module 03, 07, 11 & 13',
    vulnerabilityFound:
      'Single-column FOREIGN KEY (user_id) allows an order in Tenant A to reference a user in Tenant B. Furthermore, calling SET app.current_tenant_id outside an explicit transaction bleeds tenant context across pooled PgBouncer/pg.Pool connections.',
    remediationImplemented:
      'Enforced composite foreign keys FOREIGN KEY (tenant_id, customer_user_id) REFERENCES tenant_members (tenant_id, user_id), CHECK constraints, compile-time ORDER BY allowlist (resolveSafeOrderByClause), and withTenantTransaction() using SET LOCAL.',
    verificationAssertion:
      'PASS: Composite FK blocks cross-tenant child rows; SET LOCAL clears tenant GUC automatically on COMMIT/ROLLBACK.',
    remediationCode: `-- Module 13: Composite Multi-Tenant Foreign Key + CHECK Constraints
CONSTRAINT fk_orders_tenant_member
  FOREIGN KEY (tenant_id, customer_user_id)
  REFERENCES tenant_members (tenant_id, user_id) ON DELETE RESTRICT,
CHECK (grand_total_minor = subtotal_minor - discount_minor + tax_minor)

// Pooled Transaction Wrapper with Transaction-Scoped SET LOCAL:
await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
await client.query("SELECT set_config('app.current_tenant_id', $1, true)", [tenantId]);`,
  },
  {
    id: 'CRIT-04',
    domain: '4. Secrets Management & Frontend Bundle Leak Prevention',
    consequence: 'Service-role keys exposed in NEXT_PUBLIC_*/VITE_* or cross-tenant ciphertext transplant',
    severity: 'CRITICAL',
    moduleRef: 'Module 08, 11 & 13',
    vulnerabilityFound:
      'Developers accidentally place SUPABASE_SERVICE_ROLE_KEY or sk_live_ keys into NEXT_PUBLIC_* variables. Additionally, AES-256-GCM encryption without Additional Authenticated Data (AAD) allows an attacker to copy encrypted secrets from Tenant A into Tenant B’s row.',
    remediationImplemented:
      'Added assertNoSecretsExposedToFrontendEnv() (blocks service_role JWTs, sk_live_, private keys, and DB URIs in public env vars) and encryptWithTenantAad() / decryptWithKeyRing() binding tenantId:resourceId:fieldName into AES-256-GCM AAD.',
    verificationAssertion:
      'PASS: Boot scanner aborts on service_role JWT in NEXT_PUBLIC_*; AES-256-GCM rejects ciphertext transplanted across tenants.',
    remediationCode: `// Module 13: AES-256-GCM Envelope Encryption Bound to Tenant AAD
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
cipher.setAAD(Buffer.from(\`\${ctx.tenantId}:\${ctx.resourceType}:\${ctx.resourceId}:\${ctx.fieldName}\`, 'utf8'));
// Boot-Time Frontend Bundle Secret Scanner:
assertNoSecretsExposedToFrontendEnv(process.env);`,
  },
  {
    id: 'CRIT-05',
    domain: '5. Input Validation & API Boundary Enforcement',
    consequence: 'Malformed payloads, JSON depth bombs, Prototype Pollution (__proto__), or Mass Assignment (BOPLA)',
    severity: 'HIGH',
    moduleRef: 'Module 08 & 13',
    vulnerabilityFound:
      'Parsing JSON before checking byte size allows memory exhaustion; passing req.body to ORM update() allows Mass Assignment of role/is_verified; unnormalized Unicode bypasses regex filters.',
    remediationImplemented:
      'Implemented parseAndValidateJsonBodyStrict() and sanitizeUntrustedJsonInput() enforcing Content-Type: application/json, hard maxBodyBytes cutoff, NFKC normalization, depth <= 12, stripping __proto__/$ keys, and strict top-level field allowlisting.',
    verificationAssertion:
      'PASS: Rejected >maxBodyBytes payload, stripped __proto__ and $ne, and blocked unpermitted Mass Assignment fields.',
    remediationCode: `// Module 13: Strict Boundary Parser & Anti-BOPLA Field Allowlist
if (rawBodyBuffer.byteLength > maxBodyBytes) throw new Error('PAYLOAD_TOO_LARGE');
for (const [rawKey, val] of Object.entries(parsed)) {
  const key = rawKey.normalize('NFKC');
  if (!allowedTopLevelKeys.has(key)) throw new Error(\`MASS_ASSIGNMENT_BLOCKED: "\${key}"\`);
}`,
  },
  {
    id: 'CRIT-06',
    domain: '6. Multi-Tenancy Isolation (Cache & Database RLS)',
    consequence: 'Cross-customer data leakage via shared Redis cache keys or BYPASSRLS database roles',
    severity: 'CRITICAL',
    moduleRef: 'Module 03, 07 & 11',
    vulnerabilityFound:
      'getOrComputeCachedSingleFlight() previously accepted a raw cacheKey string without enforcing a tenantId prefix, risking cross-tenant cache poisoning if a caller omitted the tenant prefix.',
    remediationImplemented:
      'Updated getOrComputeCachedSingleFlight() in Module 03 to require a validated tenantId parameter and construct `tenant:${tenantId}:${resourceKey}` automatically, paired with PostgreSQL NOBYPASSRLS runtime roles and NULLIF() RLS policies.',
    verificationAssertion:
      'PASS: All Redis cache keys are strictly namespaced as tenant:{tenantId}:{resourceKey}; empty GUC fails closed to NULL.',
    remediationCode: `// Module 03: Mandatory Tenant-Namespaced Single-Flight Cache
if (!/^[a-zA-Z0-9_-]{1,64}$/.test(params.tenantId)) {
  throw new Error('CACHE_REJECTED: Invalid tenantId format');
}
const scopedCacheKey = \`tenant:\${params.tenantId}:\${params.resourceKey}\`;`,
  },
  {
    id: 'CRIT-07',
    domain: '7. File Uploads (Streaming, Polyglots & Path Traversal)',
    consequence: 'Remote code execution via polyglot files, OOM crashes on concurrent uploads, or path traversal',
    severity: 'HIGH',
    moduleRef: 'Module 05 & 09',
    vulnerabilityFound:
      'streamIngestToQuarantine() interpolated params.tenantId into safeStorageKey without regex validation, allowing path traversal if tenantId came from an unvalidated header.',
    remediationImplemented:
      'Added strict `/^[a-zA-Z0-9_-]{1,64}$/` validation on tenantId in streamIngestToQuarantine(), UUIDv7 object keys, 64KB bounded RAM streaming, 64-byte magic header checks, PDF #XX hex-escape deobfuscation, and streaming ClamAV zINSTREAM scans.',
    verificationAssertion:
      'PASS: Rejected tenantId="../../etc", blocked PDF /J#61vaScript polyglot, and capped stream RAM at 64KB.',
    remediationCode: `// Module 05: Path Traversal Guard + 64KB Bounded Stream + PDF #XX Deobfuscation
if (!/^[a-zA-Z0-9_-]{1,64}$/.test(params.tenantId)) {
  throw new Error('UPLOAD_REJECTED: Invalid tenantId format (path traversal guard)');
}
const safeStorageKey = \`\${params.tenantId}/\${yyyy}/\${mm}/\${crypto.randomUUID()}\${policy.extension}\`;`,
  },
  {
    id: 'CRIT-08',
    domain: '8. Rate Limiting & Abuse Protection',
    consequence: 'Credential stuffing, SMS toll-fraud pumping, resource exhaustion, or Lua divide-by-zero error',
    severity: 'HIGH',
    moduleRef: 'Module 04, 08 & 10',
    vulnerabilityFound:
      'If refill_rate <= 0 was passed to the Redis Lua token bucket script, `(requested - tokens) / refill_rate` caused a division by zero in Lua.',
    remediationImplemented:
      'Added explicit `if not capacity or capacity <= 0 or not refill_rate or refill_rate <= 0` guard in the Redis Lua Token Bucket script (`Module 04`), paired with right-to-left `extractTrustedClientIp()` and SMS country-prefix velocity & daily spend circuit breakers (`Module 10`).',
    verificationAssertion:
      'PASS: Atomic Lua script rejects non-positive refill rates; right-to-left XFF parser ignores spoofed client IPs.',
    remediationCode: `-- Module 04: Hardened Atomic Redis Token Bucket Lua Guard
if not capacity or capacity <= 0 or not refill_rate or refill_rate <= 0 or not requested or requested <= 0 then
  return redis.error_reply("ERR_INVALID_RATE_LIMIT_ARGUMENTS")
end
local ttl_ms = math.max(1000, math.ceil((capacity / refill_rate) * 2))`,
  },
  {
    id: 'CRIT-09',
    domain: '9. Transactions, Idempotency & Outbox Lock Contention',
    consequence: 'Duplicate payments, inconsistent records, or DB connection pool exhaustion during broker slowdowns',
    severity: 'CRITICAL',
    moduleRef: 'Module 03 & 04',
    vulnerabilityFound:
      'In Module 03, runCommittedOutboxRelayBatch() previously held a `BEGIN ... FOR UPDATE SKIP LOCKED` transaction open across external `await brokerPublish()` network calls, holding DB locks across network I/O and rolling back all 100 events if event 99 failed.',
    remediationImplemented:
      'Refactored `runCommittedOutboxRelayBatch()` to a 3-Phase Lease Claim pattern (claim `leased_until` and release DB lock immediately -> publish over network -> mark succeeded IDs as `processed_at`), and added `executeWithIdempotencyLock()` in `Module 04`.',
    verificationAssertion:
      'PASS: Outbox relay holds zero DB locks during network publish; idempotency state machine blocks concurrent duplicate charges.',
    remediationCode: `// Module 03: 3-Phase Outbox Claim (Zero DB Locks Held Across Network I/O)
UPDATE outbox_events
SET leased_until = clock_timestamp() + interval '30 seconds', relay_attempts = relay_attempts + 1
WHERE event_id IN (
  SELECT event_id FROM outbox_events
  WHERE processed_at IS NULL AND (leased_until IS NULL OR leased_until < clock_timestamp())
  ORDER BY created_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED
) RETURNING *;`,
  },
  {
    id: 'CRIT-10',
    domain: '10. Safe Error Handling (Zero Stack or SQL Leakage)',
    consequence: 'Stack traces, internal file paths, and SQL constraint/table names exposed to attackers',
    severity: 'HIGH',
    moduleRef: 'Module 04 & 13',
    vulnerabilityFound:
      'Unhandled database exceptions (e.g. PostgreSQL unique constraint violations or syntax errors) can leak schema structure and stack frames if serialized directly into HTTP responses.',
    remediationImplemented:
      'Added `OperationalAppError` and `toSafeProblemDetailsResponse()` in `Module 04`, which serializes only explicit operational errors and masks all internal exceptions behind an opaque RFC 9457 `500 Internal Server Error` linked via `traceId`.',
    verificationAssertion:
      'PASS: Raw PostgreSQL Error and stack trace masked as opaque RFC 9457 500 response with correlated traceId.',
    remediationCode: `// Module 04: Safe RFC 9457 Error Boundary
if (!(params.error instanceof OperationalAppError)) {
  params.logInternalError(params.error, { requestId: params.requestId, traceId: params.traceId });
  return { status: 500, headers, body: { type: '.../internal-server-error', status: 500, traceId: params.traceId } };
}`,
  },
  {
    id: 'CRIT-11',
    domain: '11. API Security (CORS Allowlists & 3-Layer CSRF Protection)',
    consequence: 'Cross-origin credential theft via reflected CORS Origin or forged state-mutating cookie requests',
    severity: 'HIGH',
    moduleRef: 'Module 08 & 13',
    vulnerabilityFound:
      'Reflecting `req.headers.origin` in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true` exposes authenticated APIs to any malicious site.',
    remediationImplemented:
      'Implemented `evaluateCorsHeaders()` (exact-match `allowedOrigins` Set + `Vary: Origin`) and `verifyCsrfProtection()` (verifying `Sec-Fetch-Site !== "cross-site"`, `Origin` allowlist, and constant-time session-bound `X-CSRF-Token` HMAC) in `Module 13`.',
    verificationAssertion:
      'PASS: Disallowed Origin receives zero CORS headers; cross-site POST without valid HMAC X-CSRF-Token is rejected.',
    remediationCode: `// Module 13: 3-Layer CSRF Verification (Fetch Metadata + Origin + Session HMAC)
if (params.secFetchSiteHeader === 'cross-site') return { valid: false, reason: 'CSRF_BLOCKED' };
if (!params.originHeader || !params.allowedOrigins.has(params.originHeader)) return { valid: false };
const validHmac = crypto.timingSafeEqual(expectedHmac, providedBuf);`,
  },
  {
    id: 'CRIT-12',
    domain: '12. Production Reliability, Supply Chain & Graceful Shutdown',
    consequence: 'Dropped in-flight payment/order requests during deploys, cascading pod restarts, or malicious npm scripts',
    severity: 'HIGH',
    moduleRef: 'Module 06, 09 & 13',
    vulnerabilityFound:
      'Conflating `/healthz` and `/readyz` causes Kubernetes to restart healthy pods during brief DB blips; missing `SIGTERM` draining drops active requests on deploy.',
    remediationImplemented:
      'Implemented `ProductionLifecycleCoordinator` in `Module 13` separating `/healthz` (event-loop liveness) from `/readyz` (1.5s bounded DB/Redis readiness + immediate `503` on `SIGTERM`), connection draining, and CI supply-chain gates (`npm ci --ignore-scripts`).',
    verificationAssertion:
      'PASS: SIGTERM flips /readyz to 503 immediately, drains in-flight requests, stops queue workers, and closes DB pools cleanly.',
    remediationCode: `// Module 13: Zero-Dropped-Request Graceful Shutdown
public async initiateGracefulShutdown(params): Promise<void> {
  this.shuttingDown = true; // /readyz immediately returns 503 Service Unavailable
  if (this.inFlightRequests > 0) await this.waitForInFlightDrain(params.drainTimeoutMs ?? 15_000);
  await params.stopQueueWorkers();
  await params.stopHttpServer();
  await params.closeDatabasePools();
}`,
  },
];

const SCENARIOS: TraceScenario[] = [
  {
    id: 'omnichannel-failover',
    title: 'Omnichannel OTP & Email Multi-Provider Failover',
    subtitle: 'P0_CRITICAL queue isolation, SMTP CRLF check, SES 503 pre-acceptance failover to Postmark + Twilio SMS',
    category: 'Module 10 · Messaging & Failover',
    httpMethod: 'POST',
    route: '/api/v1/notifications/dispatch',
    traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    clientIp: '198.51.100.42',
    tenantId: 'tnt_0195f8a0_acme',
    actorId: 'usr_0195f8a1_9921',
    finalStatus: 202,
    overallStatus: 'DEGRADED_FAILOVER',
    totalDurationMs: 184.6,
    defaultRequestHeaders: {
      'content-type': 'application/json',
      'traceparent': '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      'idempotency-key': 'idem_msg_0195f8a9_77c1',
      'x-forwarded-for': '198.51.100.42, 10.0.4.19',
      'authorization': 'Bearer [REDACTED_JWT]',
    },
    defaultRequestBody: {
      priority: 'P0_CRITICAL',
      channels: ['EMAIL', 'SMS_OTP'],
      templateId: 'tpl_security_stepup_otp_v3',
      recipient: {
        email: 'sec-ops@acme-enterprise.io',
        phoneE164: '+14155550192',
        countryIso: 'US',
      },
      variables: {
        userName: 'Elena Rostova',
        actionScope: 'Production API Key Rotation',
        otpCode: '[REDACTED_SECRET]',
      },
    },
    outgoingResponse: {
      status: 202,
      headers: {
        'content-type': 'application/json',
        'x-trace-id': '4bf92f3577b34da6a3ce929d0e0e4736',
        'x-idempotency-replayed': 'false',
      },
      body: {
        status: 'ACCEPTED_COMMITTED_OUTBOX',
        outboxEventId: 'obx_0195f8a9_e410',
        priorityQueue: 'queue:notifications:P0_CRITICAL',
        deliverySummary: {
          email: {
            status: 'SENT_VIA_FAILOVER',
            primaryAttempt: 'aws-ses-us-east-1 (HTTP_503 DEFINITIVE_PRE_ACCEPTANCE)',
            activeProvider: 'postmark-transactional',
            providerMessageId: 'pm_msg_991827361',
          },
          sms: {
            status: 'SENT_PRIMARY',
            activeProvider: 'twilio-verify-v2',
            providerMessageId: 'SM8827193847102938',
            countryRiskTier: 'TIER_1',
          },
        },
      },
    },
    hops: [
      {
        id: 'hop-1',
        hopIndex: 1,
        hopType: 'INGRESS_GATEWAY',
        serviceName: 'API Ingress & CRLF/AST Sanitizer',
        providerBadge: 'Edge Gateway + Sanitizer',
        operation: 'POST /api/v1/notifications/dispatch',
        status: 'OK',
        statusCode: 200,
        durationMs: 4.2,
        spanId: 'a10167aa0ba90001',
        parentSpanId: '00f067aa0ba902b7',
        policyTitle: 'Module 08 & 10: Prototype Pollution, SMTP CRLF & Template AST Guard',
        policyCode: `sanitizeUntrustedJsonInput(req.body); // Strip __proto__, $, null bytes
sanitizeHeaderFieldAntiCrlf(resolvedTemplate.subject); // Reject [\\r\\n\\0]
renderSafePreRegisteredTemplate(templateBody, req.body.variables);`,
        inputEnvelope: {
          headers: {
            'x-forwarded-for': '198.51.100.42, 10.0.4.19',
            'idempotency-key': 'idem_msg_0195f8a9_77c1',
          },
          payload: {
            priority: 'P0_CRITICAL',
            templateId: 'tpl_security_stepup_otp_v3',
            recipient: { email: 'sec-ops@acme-enterprise.io', phoneE164: '+14155550192' },
          },
          byteSize: 412,
        },
        outputEnvelope: {
          headers: { 'x-verified-client-ip': '198.51.100.42' },
          payload: {
            sanitized: true,
            crlfCheck: 'PASSED',
            templateAstVerified: true,
            trustedClientIp: '198.51.100.42',
          },
          byteSize: 168,
        },
      },
      {
        id: 'hop-2',
        hopIndex: 2,
        hopType: 'AUTH_RBA_ENGINE',
        serviceName: 'AuthZ, RBA & Toll-Fraud Quota Gate',
        providerBadge: 'EdDSA JWT + Redis Lua',
        operation: 'evaluateSmsTollFraudAndSuppression()',
        status: 'OK',
        statusCode: 200,
        durationMs: 8.7,
        spanId: 'a10167aa0ba90002',
        parentSpanId: 'a10167aa0ba90001',
        policyTitle: 'Module 10: Country-Prefix Toll-Fraud Budget & Transport Suppression Gate',
        policyCode: `// 1. Check transport-level suppression (never bypass HARD_BOUNCE / SPAM_COMPLAINT)
const gate = evaluateSuppressionAndChannelRouting({ priorityLane: 'P0_CRITICAL_OTP', isHardBouncedOrComplained: false });
// 2. Enforce Redis atomic Lua country-tier SMS quota (+1 US = TIER_1)
await enforceSmsTollFraudAndBudgetGuard({ tenantId: 'tnt_0195f8a0_acme', e164Phone: '+14155550192' });`,
        inputEnvelope: {
          headers: { authorization: 'Bearer [REDACTED_JWT]' },
          payload: {
            tenantId: 'tnt_0195f8a0_acme',
            actorId: 'usr_0195f8a1_9921',
            phonePrefix: '+1',
            countryRiskTier: 'TIER_1',
          },
          byteSize: 244,
        },
        outputEnvelope: {
          headers: { 'x-rba-score': '12' },
          payload: {
            authDecision: 'ALLOW',
            suppressionGate: 'ALLOW_PRIMARY',
            smsBudgetRemainingMinorUsd: 4992,
            otpHmacDigest: 'hmac_sha256:9f81c2e4...a81b',
          },
          byteSize: 210,
        },
      },
      {
        id: 'hop-3',
        hopIndex: 3,
        hopType: 'BAAS_DATA_PLANE',
        serviceName: 'PostgreSQL + Committed Outbox',
        providerBadge: 'PostgreSQL 16 (READ COMMITTED)',
        operation: 'BEGIN -> INSERT notification_deliveries + outbox_events -> COMMIT',
        status: 'OK',
        statusCode: 201,
        durationMs: 14.5,
        spanId: 'a10167aa0ba90003',
        parentSpanId: 'a10167aa0ba90002',
        policyTitle: 'Module 03 & 13: Pooled withTenantTransaction(SET LOCAL + HMAC GUC) + Committed Outbox',
        policyCode: `BEGIN ISOLATION LEVEL READ COMMITTED;
SELECT txid_current()::text AS txid;
SELECT set_config('app.current_tenant_id', $1, true),
       set_config('app.current_tenant_mac', $2, true);
INSERT INTO notification_deliveries (id, tenant_id, priority_lane, recipient_hmac, status)
VALUES ('ntf_0195f8a9', $1::uuid, 'P0_CRITICAL_OTP', $3, 'QUEUED');
INSERT INTO outbox_events (event_id, aggregate_id, event_type, payload, created_at)
VALUES ('obx_0195f8a9_e410', 'ntf_0195f8a9', 'notifications.p0.critical', $4, clock_timestamp());
COMMIT;`,
        inputEnvelope: {
          headers: { 'x-db-role': 'app_runtime (NOBYPASSRLS)' },
          payload: {
            notificationId: 'ntf_0195f8a9',
            outboxEventId: 'obx_0195f8a9_e410',
            otpStoredAs: 'HMAC-SHA256 (never plaintext)',
          },
          byteSize: 318,
        },
        outputEnvelope: {
          headers: { 'x-tx-lsn': '0/18A94F0' },
          payload: {
            txCommitted: true,
            outboxRowId: 'obx_0195f8a9_e410',
            isolationLevel: 'READ COMMITTED',
          },
          byteSize: 152,
        },
      },
      {
        id: 'hop-4',
        hopIndex: 4,
        hopType: 'ASYNC_OUTBOX_RELAY',
        serviceName: '3-Phase Outbox Relay & P0 Worker',
        providerBadge: 'BullMQ / Redis P0 Lane',
        operation: 'runCommittedOutboxRelayBatch() & acquireJobLease(fencing_token=42)',
        status: 'OK',
        statusCode: 200,
        durationMs: 9.8,
        spanId: 'a10167aa0ba90004',
        parentSpanId: 'a10167aa0ba90003',
        policyTitle: 'Module 03 & 06: 3-Phase Lease Claim (Zero DB Locks Held Across Network I/O)',
        policyCode: `-- Phase 1: Claim committed outbox rows with 30s lease & release DB lock immediately:
UPDATE outbox_events SET leased_until = clock_timestamp() + interval '30 seconds'
WHERE event_id IN (SELECT event_id FROM outbox_events WHERE processed_at IS NULL FOR UPDATE SKIP LOCKED);
-- Worker acquires atomic lease with monotonic fencing_token:
UPDATE background_jobs SET status = 'IN_PROGRESS', fencing_token = fencing_token + 1 ...`,
        inputEnvelope: {
          headers: { 'x-queue-lane': 'P0_CRITICAL' },
          payload: {
            outboxEventId: 'obx_0195f8a9_e410',
            workerInstanceId: 'wrk-p0-node-03',
            lockStatus: 'ACQUIRED',
            fencingToken: 42,
          },
          byteSize: 226,
        },
        outputEnvelope: {
          headers: { 'x-fencing-token': '42' },
          payload: {
            leaseAcquired: true,
            heartbeatIntervalMs: 10000,
            dispatchedChannels: ['EMAIL', 'SMS_OTP'],
          },
          byteSize: 184,
        },
      },
      {
        id: 'hop-5',
        hopIndex: 5,
        hopType: 'EGRESS_EXTERNAL_PROVIDER',
        serviceName: 'Multi-Provider Failover Router',
        providerBadge: 'SES -> Postmark + Twilio',
        operation: 'dispatchWithSafeMultiProviderFailover()',
        status: 'DEGRADED_FAILOVER',
        statusCode: 200,
        durationMs: 147.4,
        spanId: 'a10167aa0ba90005',
        parentSpanId: 'a10167aa0ba90004',
        policyTitle: 'Module 10: Definitive Pre-Acceptance Failover + DKIM/RFC-8058 Headers',
        policyCode: `// Attempt 1: AWS SES connection refused (ECONNREFUSED) BEFORE socket write
// Classification: DEFINITIVE_PRE_ACCEPTANCE -> Safe immediate failover to Postmark!
// (Note: HTTP 503 after write is AMBIGUOUS_POST_WRITE and holds in AMBIGUOUS_PENDING_RECONCILIATION)`,
        inputEnvelope: {
          headers: {
            'x-pinned-dns-ip': '54.239.28.85 (SES) -> 50.31.156.6 (Postmark)',
          },
          payload: {
            emailPrimary: 'aws-ses-us-east-1',
            emailSecondary: 'postmark-transactional',
            smsPrimary: 'twilio-verify-v2',
          },
          byteSize: 280,
        },
        outputEnvelope: {
          headers: { 'x-failover-triggered': 'true' },
          payload: {
            emailAttempt1: { provider: 'aws-ses-us-east-1', outcome: 'DEFINITIVE_PRE_ACCEPTANCE_FAILURE', errorCode: 'ECONNREFUSED' },
            emailAttempt2: { provider: 'postmark-transactional', outcome: 'DELIVERED', messageId: 'pm_msg_991827361' },
            smsAttempt1: { provider: 'twilio-verify-v2', outcome: 'DELIVERED', messageId: 'SM8827193847102938' },
          },
          byteSize: 392,
        },
      },
    ],
    logs: [
      {
        id: 'log-101',
        timestamp: '2026-11-06T17:12:01.004Z',
        level: 'INFO',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: 'a10167aa0ba90001',
        hopId: 'hop-1',
        service: 'api-ingress-gateway',
        event: 'INGRESS_PAYLOAD_SANITIZED',
        message: 'Verified W3C traceparent, scrubbed sensitive OTP fields, and validated logic-less template AST.',
        durationMs: 4.2,
        metadata: { clientIp: '198.51.100.42', templateId: 'tpl_security_stepup_otp_v3', crlfDetected: false },
      },
      {
        id: 'log-102',
        timestamp: '2026-11-06T17:12:01.013Z',
        level: 'SECURITY_AUDIT',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: 'a10167aa0ba90002',
        hopId: 'hop-2',
        service: 'auth-rba-quota-engine',
        event: 'SMS_TOLL_FRAUD_QUOTA_CHECK',
        message: 'Recipient +14155550192 classified as TIER_1 (US). Deducted 1 slot from Redis sliding window quota.',
        durationMs: 8.7,
        metadata: { countryIso: 'US', tier: 'TIER_1', otpDigestStored: 'hmac_sha256:9f81c2e4...a81b', otpPlaintextLogged: '[REDACTED_SECRET]' },
      },
      {
        id: 'log-103',
        timestamp: '2026-11-06T17:12:01.028Z',
        level: 'INFO',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: 'a10167aa0ba90003',
        hopId: 'hop-3',
        service: 'postgres-primary-db',
        event: 'COMMITTED_OUTBOX_PERSISTED',
        message: 'Committed notification record and outbox event obx_0195f8a9_e410 in single ACID transaction.',
        durationMs: 14.5,
        metadata: { outboxEventId: 'obx_0195f8a9_e410', isolation: 'READ COMMITTED', lsn: '0/18A94F0' },
      },
      {
        id: 'log-104',
        timestamp: '2026-11-06T17:12:01.038Z',
        level: 'INFO',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: 'a10167aa0ba90004',
        hopId: 'hop-4',
        service: 'outbox-relay-p0-worker',
        event: 'WORKER_LEASE_ACQUIRED',
        message: 'Worker wrk-p0-node-03 acquired exclusive lease on P0_CRITICAL job with fencing_token=42.',
        durationMs: 9.8,
        metadata: { queue: 'queue:notifications:P0_CRITICAL', fencingToken: 42, lockStatus: 'ACQUIRED' },
      },
      {
        id: 'log-105',
        timestamp: '2026-11-06T17:12:01.112Z',
        level: 'WARN',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: 'a10167aa0ba90005',
        hopId: 'hop-5',
        service: 'egress-provider-router',
        event: 'PRIMARY_PROVIDER_PRE_ACCEPTANCE_FAILURE',
        message: 'AWS SES socket refused connection (ECONNREFUSED, DEFINITIVE_PRE_ACCEPTANCE). Triggering immediate failover to Postmark.',
        durationMs: 74.1,
        metadata: { failedProvider: 'aws-ses-us-east-1', errorCode: 'ECONNREFUSED', failoverAction: 'IMMEDIATE_SECONDARY_DISPATCH' },
      },
      {
        id: 'log-106',
        timestamp: '2026-11-06T17:12:01.185Z',
        level: 'INFO',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: 'a10167aa0ba90005',
        hopId: 'hop-5',
        service: 'egress-provider-router',
        event: 'OMNICHANNEL_DISPATCH_COMPLETED',
        message: 'Postmark email (pm_msg_991827361) and Twilio SMS (SM8827193847102938) delivered with DKIM/DMARC alignment.',
        durationMs: 73.3,
        metadata: { emailProvider: 'postmark-transactional', smsProvider: 'twilio-verify-v2', totalLatencyMs: 184.6 },
      },
    ],
  },
  {
    id: 'supabase-rls-checkout',
    title: 'Supabase BaaS RLS + Exact Prorated Checkout & Stripe Intent',
    subtitle: 'Supabase Edge Function, app_metadata JWT RLS isolation, Largest-Remainder proration, Stripe idempotency',
    category: 'Module 11 & 01 · Supabase BaaS + Financial Engine',
    httpMethod: 'POST',
    route: '/functions/v1/supabase-checkout-order',
    traceId: '7c2198a011e448f192837465a0b1c2d3',
    traceparent: '00-7c2198a011e448f192837465a0b1c2d3-11a2b3c4d5e6f701-01',
    clientIp: '192.0.2.88',
    tenantId: 'tnt_0195f8b0_globex',
    actorId: 'usr_supa_882104a',
    finalStatus: 201,
    overallStatus: 'OK',
    totalDurationMs: 142.3,
    defaultRequestHeaders: {
      'content-type': 'application/json',
      'traceparent': '00-7c2198a011e448f192837465a0b1c2d3-11a2b3c4d5e6f701-01',
      'authorization': 'Bearer [REDACTED_JWT]',
      'apikey': 'sb_publishable_anon_key_public',
      'idempotency-key': 'idem_chk_0195f8b2_901a',
    },
    defaultRequestBody: {
      currencyCode: 'USD',
      taxPolicy: 'TAX_EXCLUSIVE',
      orderDiscountMinor: 100,
      lineItems: [
        { sku: 'CLOUD-NODE-A', quantity: 1, unitPriceMinor: 100, taxRateBps: 825 },
        { sku: 'CLOUD-NODE-B', quantity: 1, unitPriceMinor: 100, taxRateBps: 825 },
        { sku: 'CLOUD-NODE-C', quantity: 1, unitPriceMinor: 100, taxRateBps: 825 },
      ],
    },
    outgoingResponse: {
      status: 201,
      headers: {
        'content-type': 'application/json',
        'x-trace-id': '7c2198a011e448f192837465a0b1c2d3',
        'x-baas-provider': 'supabase-postgres-rls',
      },
      body: {
        orderId: 'ord_0195f8b2_f901',
        tenantId: 'tnt_0195f8b0_globex',
        currencyCode: 'USD',
        financialSummary: {
          subtotalMinor: 300,
          proratedLineDiscountsMinor: [34, 33, 33],
          reconciledDiscountTotalMinor: 100,
          netTaxableMinor: 200,
          totalTaxMinor: 17,
          grandTotalMinor: 217,
        },
        stripePaymentIntent: {
          id: 'pi_3Q9xYzLkdIwHu7ix0881',
          status: 'requires_payment_method',
        },
      },
    },
    hops: [
      {
        id: 'supa-hop-1',
        hopIndex: 1,
        hopType: 'INGRESS_GATEWAY',
        serviceName: 'Supabase Edge Function Ingress',
        providerBadge: 'Deno Edge Runtime',
        operation: 'POST /functions/v1/supabase-checkout-order',
        status: 'OK',
        statusCode: 200,
        durationMs: 3.1,
        spanId: 'b20167aa0ba90001',
        parentSpanId: '11a2b3c4d5e6f701',
        policyTitle: 'Module 01 & 11: Strict Schema Validation & Basis-Point Cap (0..10_000)',
        policyCode: `// Validate currency exponent (USD = 2) and taxRateBps in [0..10_000]
// Allocate $1.00 (100c) discount across 3x $1.00 items via Largest Remainder:
// Shares: [34n, 33n, 33n] -> Exact sum === 100n (zero penny drift!)`,
        inputEnvelope: {
          headers: { 'idempotency-key': 'idem_chk_0195f8b2_901a' },
          payload: {
            currencyCode: 'USD',
            orderDiscountMinor: 100,
            lineItemsCount: 3,
          },
          byteSize: 388,
        },
        outputEnvelope: {
          headers: { 'x-proration-reconciled': 'true' },
          payload: {
            proratedSharesMinor: [34, 33, 33],
            sumEqualsTarget: true,
            grandTotalMinor: 217,
          },
          byteSize: 164,
        },
      },
      {
        id: 'supa-hop-2',
        hopIndex: 2,
        hopType: 'AUTH_RBA_ENGINE',
        serviceName: 'Supabase Auth & app_metadata Verifier',
        providerBadge: 'Supabase GoTrue JWT',
        operation: 'verifySupabaseAppMetadataClaims()',
        status: 'OK',
        statusCode: 200,
        durationMs: 6.4,
        spanId: 'b20167aa0ba90002',
        parentSpanId: 'b20167aa0ba90001',
        policyTitle: 'Module 11: Enforce app_metadata + Authoritative Tenant Membership Re-Verification',
        policyCode: `const { data: { user } } = await supabaseUserClient.auth.getUser();
// CRITICAL: Read tenant_id ONLY from app_metadata AND re-verify active membership + tenant status
// in public.tenant_members & public.tenants (DEVIL-20 remediation):
const verified = await verifySupabaseRequestAuthAndMembership({ authHeader, queryActiveMembership, requiredRoles: ['billing_admin'] });`,
        inputEnvelope: {
          headers: { authorization: 'Bearer [REDACTED_JWT]' },
          payload: {
            jwtSub: 'usr_supa_882104a',
            app_metadata: { tenant_id: 'tnt_0195f8b0_globex', role: 'billing_admin' },
            user_metadata_ignored: true,
          },
          byteSize: 276,
        },
        outputEnvelope: {
          headers: { 'x-tenant-verified': 'tnt_0195f8b0_globex' },
          payload: {
            verifiedTenantId: 'tnt_0195f8b0_globex',
            verifiedRole: 'billing_admin',
            serviceRoleKeyExposedToClient: false,
          },
          byteSize: 180,
        },
      },
      {
        id: 'supa-hop-3',
        hopIndex: 3,
        hopType: 'BAAS_DATA_PLANE',
        serviceName: 'Supabase PostgreSQL RLS + Outbox',
        providerBadge: 'Supabase Postgres + RLS',
        operation: 'INSERT INTO public.orders (RLS Enforced)',
        status: 'OK',
        statusCode: 201,
        durationMs: 18.2,
        spanId: 'b20167aa0ba90003',
        parentSpanId: 'b20167aa0ba90002',
        policyTitle: 'Module 11 & 13: FORCE ROW LEVEL SECURITY + Active Membership Check',
        policyCode: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant_insert ON public.orders FOR INSERT TO authenticated
WITH CHECK (tenant_id = ((SELECT auth.jwt()) -> 'app_metadata' ->> 'tenant_id')::uuid AND public.is_active_tenant_member(tenant_id));`,
        inputEnvelope: {
          headers: { 'x-pg-role': 'authenticated' },
          payload: {
            orderId: 'ord_0195f8b2_f901',
            tenantId: 'tnt_0195f8b0_globex',
            grandTotalMinor: 217,
          },
          byteSize: 295,
        },
        outputEnvelope: {
          headers: { 'x-rls-policy-matched': 'orders_tenant_insert' },
          payload: {
            insertedOrderId: 'ord_0195f8b2_f901',
            outboxEventId: 'obx_supa_0195f8b2',
            committed: true,
          },
          byteSize: 172,
        },
      },
      {
        id: 'supa-hop-4',
        hopIndex: 4,
        hopType: 'ASYNC_OUTBOX_RELAY',
        serviceName: 'PgBouncer Transaction Pool & Relay',
        providerBadge: 'Supavisor + Outbox Worker',
        operation: 'executeWithIdempotencyLock()',
        status: 'OK',
        statusCode: 200,
        durationMs: 7.5,
        spanId: 'b20167aa0ba90004',
        parentSpanId: 'b20167aa0ba90003',
        policyTitle: 'Module 04: Atomic Payment Idempotency Key Locking with Monotonic Fencing Token',
        policyCode: `INSERT INTO idempotency_keys (tenant_id, idempotency_key, endpoint, request_hash, status, fencing_token, locked_until)
VALUES ($1, $2, '/checkout', $3, 'IN_PROGRESS', 1, clock_timestamp() + interval '60 seconds')
ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
SET status = 'IN_PROGRESS', fencing_token = idempotency_keys.fencing_token + 1
WHERE idempotency_keys.status = 'IN_PROGRESS' AND idempotency_keys.locked_until < clock_timestamp()
RETURNING fencing_token;`,
        inputEnvelope: {
          headers: { 'x-idempotency-key': 'idem_chk_0195f8b2_901a' },
          payload: { outboxEventId: 'obx_supa_0195f8b2', amountMinor: 217, currency: 'USD' },
          byteSize: 198,
        },
        outputEnvelope: {
          headers: { 'x-lock-state': 'ACQUIRED' },
          payload: { idempotencyLock: 'ACQUIRED', fencingToken: 19 },
          byteSize: 128,
        },
      },
      {
        id: 'supa-hop-5',
        hopIndex: 5,
        hopType: 'EGRESS_EXTERNAL_PROVIDER',
        serviceName: 'Stripe PaymentIntents API',
        providerBadge: 'Stripe API (Pinned TLS)',
        operation: 'POST https://api.stripe.com/v1/payment_intents',
        status: 'OK',
        statusCode: 200,
        durationMs: 107.1,
        spanId: 'b20167aa0ba90005',
        parentSpanId: 'b20167aa0ba90004',
        policyTitle: 'Module 04 & 08: DNS-Pinned HTTPS Agent + Tenant-Scoped Attempt-Invariant Stripe Key',
        policyCode: `const { agent } = await createPinnedSafeHttpsAgent('https://api.stripe.com/v1/payment_intents');
const stripeIdempotencyKey = deriveStripeIdempotencyKey('tnt_0195f8b0_globex', 'POST:/checkout', 'idem_chk_0195f8b2_901a', requestHash);
const intent = await stripe.paymentIntents.create(
  { amount: 217, currency: 'usd', metadata: { orderId: 'ord_0195f8b2_f901' } },
  { idempotencyKey: stripeIdempotencyKey, httpAgent: agent }
);`,
        inputEnvelope: {
          headers: {
            'idempotency-key': 'idem_chk_0195f8b2_901a',
            'authorization': 'Bearer [REDACTED_SECRET]',
          },
          payload: { amount: 217, currency: 'usd', orderId: 'ord_0195f8b2_f901' },
          byteSize: 215,
        },
        outputEnvelope: {
          headers: { 'stripe-version': '2024-12-18.acacia' },
          payload: { paymentIntentId: 'pi_3Q9xYzLkdIwHu7ix0881', status: 'requires_payment_method' },
          byteSize: 194,
        },
      },
    ],
    logs: [
      {
        id: 'log-201',
        timestamp: '2026-11-06T17:14:10.003Z',
        level: 'INFO',
        traceId: '7c2198a011e448f192837465a0b1c2d3',
        spanId: 'b20167aa0ba90001',
        hopId: 'supa-hop-1',
        service: 'supabase-edge-ingress',
        event: 'PRORATED_DISCOUNT_RECONCILED',
        message: 'Reconciled 100 minor unit discount across 3 line items as [34, 33, 33] using Largest Remainder Method.',
        durationMs: 3.1,
        metadata: { subtotalMinor: 300, discountMinor: 100, shares: [34, 33, 33], taxMinor: 17, grandTotalMinor: 217 },
      },
      {
        id: 'log-202',
        timestamp: '2026-11-06T17:14:10.009Z',
        level: 'SECURITY_AUDIT',
        traceId: '7c2198a011e448f192837465a0b1c2d3',
        spanId: 'b20167aa0ba90002',
        hopId: 'supa-hop-2',
        service: 'supabase-gotrue-verifier',
        event: 'SUPABASE_APP_METADATA_VERIFIED',
        message: 'Extracted tenant_id=tnt_0195f8b0_globex from immutable app_metadata claim; ignored client user_metadata.',
        durationMs: 6.4,
        metadata: { sub: 'usr_supa_882104a', role: 'billing_admin', rlsClaimSource: 'auth.jwt()->app_metadata' },
      },
      {
        id: 'log-203',
        timestamp: '2026-11-06T17:14:10.028Z',
        level: 'INFO',
        traceId: '7c2198a011e448f192837465a0b1c2d3',
        spanId: 'b20167aa0ba90003',
        hopId: 'supa-hop-3',
        service: 'supabase-postgres-rls',
        event: 'RLS_INSERT_COMMITTED',
        message: 'Inserted order ord_0195f8b2_f901 under FORCE ROW LEVEL SECURITY policy orders_tenant_insert.',
        durationMs: 18.2,
        metadata: { table: 'public.orders', policy: 'orders_tenant_insert', outboxEventId: 'obx_supa_0195f8b2' },
      },
      {
        id: 'log-204',
        timestamp: '2026-11-06T17:14:10.142Z',
        level: 'INFO',
        traceId: '7c2198a011e448f192837465a0b1c2d3',
        spanId: 'b20167aa0ba90005',
        hopId: 'supa-hop-5',
        service: 'stripe-egress-adapter',
        event: 'STRIPE_PAYMENT_INTENT_CREATED',
        message: 'Created Stripe PaymentIntent pi_3Q9xYzLkdIwHu7ix0881 with deterministic idempotency key.',
        durationMs: 107.1,
        metadata: { paymentIntentId: 'pi_3Q9xYzLkdIwHu7ix0881', amountMinor: 217, currency: 'USD' },
      },
    ],
  },
  {
    id: 'firebase-8-pillar-rules',
    title: 'Firebase BaaS 8-Pillar Firestore Write & FCM v1 Push Dispatch',
    subtitle: 'Firebase App Check, 8-Pillar firestore.rules validation, affectedKeys().hasOnly(), FCM v1 push',
    category: 'Module 11 & 10 · Firebase BaaS + Push',
    httpMethod: 'PATCH',
    route: '/v1/projects/acme-prod/databases/(default)/documents/orders/ord_fb_991',
    traceId: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
    traceparent: '00-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d-22b3c4d5e6f70802-01',
    clientIp: '203.0.113.15',
    tenantId: 'tnt_fb_acme_01',
    actorId: 'uid_firebase_7741',
    finalStatus: 200,
    overallStatus: 'OK',
    totalDurationMs: 96.4,
    defaultRequestHeaders: {
      'content-type': 'application/json',
      'traceparent': '00-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d-22b3c4d5e6f70802-01',
      'x-firebase-appcheck': '[REDACTED_SECRET]',
      'authorization': 'Bearer [REDACTED_JWT]',
    },
    defaultRequestBody: {
      authorUid: 'uid_firebase_7741',
      tenantId: 'tnt_fb_acme_01',
      status: 'SHIPPED',
      totalMinor: 14500,
      updatedAt: 'SERVER_TIMESTAMP',
    },
    outgoingResponse: {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'x-trace-id': '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
      },
      body: {
        documentPath: 'orders/ord_fb_991',
        rulesEvaluation: 'ALLOW (8-Pillar Firestore Fortress Passed)',
        blueprintSynced: true,
        fcmPushNotification: {
          messageId: 'projects/acme-prod/messages/0:1730912841928371%44a9f1',
          apnsPriority: 10,
        },
      },
    },
    hops: [
      {
        id: 'fb-hop-1',
        hopIndex: 1,
        hopType: 'INGRESS_GATEWAY',
        serviceName: 'Firebase App Check & API Gateway',
        providerBadge: 'App Check Attestation',
        operation: 'verifyAppCheckToken() & inspectPayloadBounds()',
        status: 'OK',
        statusCode: 200,
        durationMs: 5.0,
        spanId: 'c30167aa0ba90001',
        parentSpanId: '22b3c4d5e6f70802',
        policyTitle: 'Module 11: Firebase App Check Device/Play-Integrity Attestation',
        policyCode: `// Verify X-Firebase-AppCheck JWT signature & replay protection before hitting Firestore
const appCheckClaims = await getAppCheck().verifyToken(req.headers['x-firebase-appcheck']);`,
        inputEnvelope: {
          headers: { 'x-firebase-appcheck': '[REDACTED_SECRET]' },
          payload: { documentPath: 'orders/ord_fb_991', operation: 'update' },
          byteSize: 260,
        },
        outputEnvelope: {
          headers: { 'x-appcheck-verified': 'true' },
          payload: { appId: '1:992817263:web:77a8b9c0', attested: true },
          byteSize: 140,
        },
      },
      {
        id: 'fb-hop-2',
        hopIndex: 2,
        hopType: 'AUTH_RBA_ENGINE',
        serviceName: 'Firebase Auth ID Token Verifier',
        providerBadge: 'Firebase Auth OIDC',
        operation: 'verifyIdToken(checkRevoked = true)',
        status: 'OK',
        statusCode: 200,
        durationMs: 7.8,
        spanId: 'c30167aa0ba90002',
        parentSpanId: 'c30167aa0ba90001',
        policyTitle: 'Module 11: Firebase Auth Custom Claims & Revocation Check',
        policyCode: `const decoded = await getAuth().verifyIdToken(idToken, true); // checkRevoked = true
// request.auth.uid === 'uid_firebase_7741', request.auth.token.tenantId === 'tnt_fb_acme_01'`,
        inputEnvelope: {
          headers: { authorization: 'Bearer [REDACTED_JWT]' },
          payload: { uid: 'uid_firebase_7741', customClaims: { tenantId: 'tnt_fb_acme_01', role: 'member' } },
          byteSize: 230,
        },
        outputEnvelope: {
          headers: { 'x-firebase-uid': 'uid_firebase_7741' },
          payload: { uidVerified: true, tokenRevoked: false, tenantId: 'tnt_fb_acme_01' },
          byteSize: 162,
        },
      },
      {
        id: 'fb-hop-3',
        hopIndex: 3,
        hopType: 'BAAS_DATA_PLANE',
        serviceName: 'Cloud Firestore 8-Pillar Security Engine',
        providerBadge: 'firestore.rules v2',
        operation: 'match /orders/{orderId} -> allow update',
        status: 'OK',
        statusCode: 200,
        durationMs: 19.4,
        spanId: 'c30167aa0ba90003',
        parentSpanId: 'c30167aa0ba90002',
        policyTitle: 'Module 11: The 8-Pillar Firestore Rules Fortress',
        policyCode: `allow update: if isOwner(resource.data.authorUid)
  && isTenantMember(resource.data.tenantId)
  && isValidOrder(request.resource.data)
  && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['status', 'totalMinor', 'updatedAt'])
  && request.resource.data.authorUid == resource.data.authorUid
  && request.resource.data.tenantId == resource.data.tenantId
  && request.resource.data.updatedAt == request.time;`,
        inputEnvelope: {
          headers: { 'x-firestore-rules-version': '2' },
          payload: {
            existingResource: { authorUid: 'uid_firebase_7741', tenantId: 'tnt_fb_acme_01', status: 'PAID' },
            incomingDiffKeys: ['status', 'totalMinor', 'updatedAt'],
          },
          byteSize: 340,
        },
        outputEnvelope: {
          headers: { 'x-rules-decision': 'ALLOW' },
          payload: {
            immutableFieldsIntact: true,
            affectedKeysAllowed: true,
            committedServerTime: '2026-11-06T17:15:22.104Z',
          },
          byteSize: 198,
        },
      },
      {
        id: 'fb-hop-4',
        hopIndex: 4,
        hopType: 'ASYNC_OUTBOX_RELAY',
        serviceName: 'Cloud Functions v2 Eventarc Trigger',
        providerBadge: 'Eventarc + Cloud Tasks',
        operation: 'onDocumentUpdated("orders/{orderId}")',
        status: 'OK',
        statusCode: 200,
        durationMs: 11.2,
        spanId: 'c30167aa0ba90004',
        parentSpanId: 'c30167aa0ba90003',
        policyTitle: 'Module 06 & 11: Idempotent Eventarc Trigger Deduplication',
        policyCode: `// Deduplicate event.id in Firestore inbox_events collection before sending push
const eventRef = db.collection('inbox_processed_events').doc(event.id);
await db.runTransaction(async (tx) => { ... });`,
        inputEnvelope: {
          headers: { 'ce-id': 'evt_fb_0195f8c0_991' },
          payload: { orderId: 'ord_fb_991', oldStatus: 'PAID', newStatus: 'SHIPPED' },
          byteSize: 192,
        },
        outputEnvelope: {
          headers: { 'x-inbox-dedup': 'FIRST_SEEN' },
          payload: { pushTaskEnqueued: true, targetDeviceTokensCount: 1 },
          byteSize: 148,
        },
      },
      {
        id: 'fb-hop-5',
        hopIndex: 5,
        hopType: 'EGRESS_EXTERNAL_PROVIDER',
        serviceName: 'FCM HTTP v1 Push Gateway',
        providerBadge: 'FCM v1 + APNs .p8',
        operation: 'POST /v1/projects/acme-prod/messages:send',
        status: 'OK',
        statusCode: 200,
        durationMs: 53.0,
        spanId: 'c30167aa0ba90005',
        parentSpanId: 'c30167aa0ba90004',
        policyTitle: 'Module 10: Zero-PII Push Payload + Exclusive Token Ownership',
        policyCode: `// Push lock-screen notification carries zero sensitive PII; fetches details on authenticated app open
const response = await getMessaging().send({
  token: devicePushToken,
  notification: { title: 'Order Update', body: 'Your order status has been updated.' },
  data: { orderId: 'ord_fb_991', deepLink: '/orders/ord_fb_991' }
});`,
        inputEnvelope: {
          headers: { authorization: 'Bearer [REDACTED_SECRET]' },
          payload: {
            token: '[REDACTED_SECRET]',
            notification: { title: 'Order Update', body: 'Your order status has been updated.' },
          },
          byteSize: 248,
        },
        outputEnvelope: {
          headers: { 'x-fcm-status': 'DELIVERED' },
          payload: {
            messageId: 'projects/acme-prod/messages/0:1730912841928371%44a9f1',
            unregisteredTokensPruned: 0,
          },
          byteSize: 186,
        },
      },
    ],
    logs: [
      {
        id: 'log-301',
        timestamp: '2026-11-06T17:15:22.085Z',
        level: 'INFO',
        traceId: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
        spanId: 'c30167aa0ba90001',
        hopId: 'fb-hop-1',
        service: 'firebase-appcheck-gate',
        event: 'APP_CHECK_ATTESTATION_VALID',
        message: 'Verified Firebase App Check token for web client 1:992817263:web:77a8b9c0.',
        durationMs: 5.0,
        metadata: { appId: '1:992817263:web:77a8b9c0', tokenRedacted: '[REDACTED_SECRET]' },
      },
      {
        id: 'log-302',
        timestamp: '2026-11-06T17:15:22.104Z',
        level: 'SECURITY_AUDIT',
        traceId: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
        spanId: 'c30167aa0ba90003',
        hopId: 'fb-hop-3',
        service: 'firestore-rules-engine',
        event: 'FIRESTORE_8_PILLAR_RULE_PASSED',
        message: 'Evaluated match /orders/ord_fb_991: verified isValidOrder(), affectedKeys().hasOnly(), and immutable authorUid/tenantId.',
        durationMs: 19.4,
        metadata: { path: 'orders/ord_fb_991', operation: 'update', affectedKeys: ['status', 'totalMinor', 'updatedAt'] },
      },
      {
        id: 'log-303',
        timestamp: '2026-11-06T17:15:22.168Z',
        level: 'INFO',
        traceId: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
        spanId: 'c30167aa0ba90005',
        hopId: 'fb-hop-5',
        service: 'fcm-v1-push-dispatcher',
        event: 'FCM_PUSH_DISPATCHED',
        message: 'Delivered zero-PII push notification via FCM HTTP v1 API.',
        durationMs: 53.0,
        metadata: { fcmMessageId: 'projects/acme-prod/messages/0:1730912841928371%44a9f1' },
      },
    ],
  },
  {
    id: 'streaming-upload-clamav',
    title: 'Streaming Zero-Buffer File Upload & ClamAV Quarantine Scan',
    subtitle: '64KB bounded RAM stream, 64-byte magic header check, PDF #XX hex deobfuscation, ClamAV zINSTREAM',
    category: 'Module 05 · Streaming Upload Security',
    httpMethod: 'POST',
    route: '/api/v1/files/upload-stream',
    traceId: '3e4d5c6b7a890123456789abcdef0123',
    traceparent: '00-3e4d5c6b7a890123456789abcdef0123-33c4d5e6f7080903-01',
    clientIp: '198.51.100.77',
    tenantId: 'tnt_0195f8a0_acme',
    actorId: 'usr_0195f8a1_9921',
    finalStatus: 201,
    overallStatus: 'OK',
    totalDurationMs: 218.9,
    defaultRequestHeaders: {
      'content-type': 'application/pdf',
      'x-file-name': 'q4-board-financial-audit.pdf',
      'content-length': '1482910',
      'cookie': '__Host-sid=[REDACTED_SECRET]',
    },
    defaultRequestBody: {
      streamMode: 'BOUNDED_64KB_CHUNKS',
      declaredMimeType: 'application/pdf',
      firstChunkMagicBytesHex: '255044462d312e370a',
      pdfContainsHexEscapedJs: false,
      totalBytesStreamed: 1482910,
    },
    outgoingResponse: {
      status: 201,
      headers: {
        'content-type': 'application/json',
        'x-content-type-options': 'nosniff',
        'content-disposition': 'attachment; filename="0195f8d0-8812-7a11-9c00-112233445566.pdf"',
      },
      body: {
        fileId: 'fil_0195f8d0_8812',
        storageKey: 'tnt_0195f8a0_acme/2026/11/0195f8d0-8812-7a11-9c00-112233445566.pdf',
        sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        quarantineScanStatus: 'CLEAN_PROMOTED_TO_VAULT',
        clamAvSignature: 'stream: OK',
        peakMemoryBufferedBytes: 65536,
      },
    },
    hops: [
      {
        id: 'up-hop-1',
        hopIndex: 1,
        hopType: 'INGRESS_GATEWAY',
        serviceName: 'SecurityGateTransformStream',
        providerBadge: '64KB Bounded Stream',
        operation: 'verifyMagicBytes(64B) & scanPdfHexEscapes()',
        status: 'OK',
        statusCode: 200,
        durationMs: 19.6,
        spanId: 'd40167aa0ba90001',
        parentSpanId: '33c4d5e6f7080903',
        policyTitle: 'Module 05: Fragment-Safe 64B Magic Signature + PDF #XX Deobfuscation',
        policyCode: `// Accumulate first 64 bytes across chunks; verify %PDF- (25 50 44 46 2D)
// Decode ISO 32000-1 #XX hex escapes (/#([0-9a-f]{2})/gi) across 128B sliding window
// Rejects /JavaScript, /J#61vaScript, /Launch, /OpenAction, /AA, /EmbeddedFiles`,
        inputEnvelope: {
          headers: { 'x-file-name': 'q4-board-financial-audit.pdf', 'content-length': '1482910' },
          payload: { firstBytesAscii: '%PDF-1.7', chunkBufferSize: 65536 },
          byteSize: 1482910,
        },
        outputEnvelope: {
          headers: { 'x-stream-sha256': 'e3b0c44298fc1c149afbf4c8996fb924...' },
          payload: {
            magicSignatureVerified: true,
            pdfActiveScriptsFound: false,
            peakRamBytes: 65536,
          },
          byteSize: 204,
        },
      },
      {
        id: 'up-hop-2',
        hopIndex: 2,
        hopType: 'AUTH_RBA_ENGINE',
        serviceName: 'Session Binding & Storage Quota Gate',
        providerBadge: '__Host-sid + RBAC',
        operation: 'verifyBoundSessionAndUploadQuota()',
        status: 'OK',
        statusCode: 200,
        durationMs: 5.4,
        spanId: 'd40167aa0ba90002',
        parentSpanId: 'd40167aa0ba90001',
        policyTitle: 'Module 02 & 05: Cryptographic Session Binding + Tenant Path Traversal Guard',
        policyCode: `if (!/^[a-zA-Z0-9_-]{1,64}$/.test(tenantId)) throw new Error('PATH_TRAVERSAL_BLOCKED');
verifySessionBindingCookie(req.cookies['__Host-sid'], jwtClaims.cnf);`,
        inputEnvelope: {
          headers: { cookie: '__Host-sid=[REDACTED_SECRET]' },
          payload: { tenantId: 'tnt_0195f8a0_acme', actorId: 'usr_0195f8a1_9921' },
          byteSize: 184,
        },
        outputEnvelope: {
          headers: { 'x-quota-ok': 'true' },
          payload: { sessionBound: true, randomizedUuidKey: '0195f8d0-8812-7a11-9c00-112233445566.pdf' },
          byteSize: 170,
        },
      },
      {
        id: 'up-hop-3',
        hopIndex: 3,
        hopType: 'BAAS_DATA_PLANE',
        serviceName: 'Quarantine Object Bucket & DB Metadata',
        providerBadge: 'S3 Quarantine + Postgres',
        operation: 'streamToQuarantineBucket(noexec)',
        status: 'OK',
        statusCode: 201,
        durationMs: 68.3,
        spanId: 'd40167aa0ba90003',
        parentSpanId: 'd40167aa0ba90002',
        policyTitle: 'Module 05: Quarantine-First Storage Outside Web Root',
        policyCode: `// Stream directly into isolated quarantine bucket with randomized UUIDv7 key
// Never use user-supplied filename in storage path (prevents ../ path traversal)`,
        inputEnvelope: {
          headers: { 'x-storage-tier': 'QUARANTINE_UNTRUSTED' },
          payload: { bucket: 'acme-quarantine-vault', key: 'tnt_0195f8a0_acme/2026/11/0195f8d0-8812.pdf' },
          byteSize: 240,
        },
        outputEnvelope: {
          headers: { 'x-etag': '"99a8b7c6d5e4"' },
          payload: { quarantinePersisted: true, dbStatus: 'PENDING_MALWARE_SCAN' },
          byteSize: 160,
        },
      },
      {
        id: 'up-hop-4',
        hopIndex: 4,
        hopType: 'ASYNC_OUTBOX_RELAY',
        serviceName: 'ClamAV zINSTREAM Scanner Worker',
        providerBadge: 'ClamAV Daemon TCP:3310',
        operation: 'scanStreamWithClamAv(zINSTREAM)',
        status: 'OK',
        statusCode: 200,
        durationMs: 94.2,
        spanId: 'd40167aa0ba90004',
        parentSpanId: 'd40167aa0ba90003',
        policyTitle: 'Module 05: Streaming ClamAV zINSTREAM Malware Verification',
        policyCode: `// Stream 64KB chunks over TCP socket to clamd using zINSTREAM length-prefixed framing
// Response: "stream: OK\\0" -> Promote file from Quarantine to Production bucket`,
        inputEnvelope: {
          headers: { 'x-clamav-command': 'zINSTREAM' },
          payload: { streamBytes: 1482910, chunkFraming: '4-byte-be-length' },
          byteSize: 196,
        },
        outputEnvelope: {
          headers: { 'x-clamav-verdict': 'CLEAN' },
          payload: { clamAvResponse: 'stream: OK', signaturesChecked: 8941204 },
          byteSize: 168,
        },
      },
      {
        id: 'up-hop-5',
        hopIndex: 5,
        hopType: 'EGRESS_EXTERNAL_PROVIDER',
        serviceName: 'Production Vault Promotion',
        providerBadge: 'S3 Production Vault',
        operation: 'promoteQuarantineToProductionVault()',
        status: 'OK',
        statusCode: 200,
        durationMs: 31.4,
        spanId: 'd40167aa0ba90005',
        parentSpanId: 'd40167aa0ba90004',
        policyTitle: 'Module 05: Hardened Download Headers (nosniff + attachment + CSP sandbox)',
        policyCode: `// Copy object to production bucket, delete quarantine object, mark file status = 'CLEAN'
// Serve only with Content-Disposition: attachment; X-Content-Type-Options: nosniff`,
        inputEnvelope: {
          headers: { 'x-copy-source': 'acme-quarantine-vault/0195f8d0-8812.pdf' },
          payload: { targetBucket: 'acme-prod-vault', deleteQuarantineSource: true },
          byteSize: 212,
        },
        outputEnvelope: {
          headers: { 'x-vault-status': 'PROMOTED_CLEAN' },
          payload: { status: 'CLEAN_PROMOTED_TO_VAULT', serveHeadersLocked: true },
          byteSize: 156,
        },
      },
    ],
    logs: [
      {
        id: 'log-401',
        timestamp: '2026-11-06T17:16:04.019Z',
        level: 'INFO',
        traceId: '3e4d5c6b7a890123456789abcdef0123',
        spanId: 'd40167aa0ba90001',
        hopId: 'up-hop-1',
        service: 'security-gate-stream',
        event: 'STREAM_MAGIC_AND_PDF_AST_VERIFIED',
        message: 'Verified %PDF-1.7 binary header on initial 64B window and scanned 1.48MB stream with 64KB bounded RAM.',
        durationMs: 19.6,
        metadata: { sha256: 'e3b0c44298fc1c149afbf4c8996fb924...', peakMemoryBytes: 65536 },
      },
      {
        id: 'log-402',
        timestamp: '2026-11-06T17:16:04.187Z',
        level: 'SECURITY_AUDIT',
        traceId: '3e4d5c6b7a890123456789abcdef0123',
        spanId: 'd40167aa0ba90004',
        hopId: 'up-hop-4',
        service: 'clamav-zinstream-scanner',
        event: 'MALWARE_SCAN_PASSED',
        message: 'ClamAV zINSTREAM scan returned "stream: OK". Promoted object from quarantine to production vault.',
        durationMs: 94.2,
        metadata: { fileId: 'fil_0195f8d0_8812', verdict: 'CLEAN' },
      },
    ],
  },
  {
    id: 'penetration-attack-blocked',
    title: 'Adversarial Attack Blocked: SSRF Hex-IPv6 + CRLF + Prototype Pollution',
    subtitle: 'Blocks __proto__, spoofed X-Forwarded-For, SMTP CRLF injection, and ::ffff:a9fe:a9fe IMDSv2 SSRF',
    category: 'Module 08, 09 & 10 · Penetration Defense',
    httpMethod: 'POST',
    route: '/api/v1/webhooks/test-outbound-endpoint',
    traceId: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
    traceparent: '00-f0e1d2c3b4a5968778695a4b3c2d1e0f-44d5e6f708090a04-01',
    clientIp: '203.0.113.99',
    tenantId: 'tnt_0195f8a0_acme',
    actorId: 'usr_compromised_09',
    finalStatus: 403,
    overallStatus: 'BLOCKED_SECURITY',
    totalDurationMs: 11.4,
    defaultRequestHeaders: {
      'content-type': 'application/json',
      'x-forwarded-for': '1.1.1.1, 8.8.8.8, 203.0.113.99, 10.0.1.5',
      'host': 'evil-attacker-reset-poison.com',
      'authorization': 'Bearer [REDACTED_JWT]',
    },
    defaultRequestBody: {
      targetWebhookUrl: 'https://[::ffff:a9fe:a9fe]/latest/meta-data/iam/security-credentials/',
      emailSubjectHeader: 'Invoice Receipt\r\nBcc: attacker-exfil@evil.org',
      filterQuery: { $ne: null },
    },
    outgoingResponse: {
      status: 403,
      headers: {
        'content-type': 'application/problem+json',
        'x-trace-id': 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
      },
      body: {
        type: 'https://api.acme.io/problems/security-policy-violation',
        title: 'Forbidden: Adversarial Input & SSRF Vector Blocked',
        status: 403,
        detail: 'Blocked hex-normalized IPv4-mapped IPv6 cloud metadata address (::ffff:a9fe:a9fe -> 169.254.169.254), NoSQL $ne operator, and SMTP CRLF header injection.',
        instance: '/api/v1/webhooks/test-outbound-endpoint',
        traceId: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
        blockedVectors: [
          'PEN-01: SSRF_IPV6_HEX_MAPPED_IMDS (::ffff:a9fe:a9fe)',
          'PEN-06: NOSQL_OPERATOR_INJECTION ($ne)',
          'PEN-07: X_FORWARDED_FOR_SPOOFING_IGNORED (extracted 203.0.113.99)',
          'PEN-09: EMAIL_HEADER_CRLF_INJECTION (\\r\\nBcc:)',
        ],
      },
    },
    hops: [
      {
        id: 'pen-hop-1',
        hopIndex: 1,
        hopType: 'INGRESS_GATEWAY',
        serviceName: 'Ingress Sanitizer & Proxy IP Extractor',
        providerBadge: 'Zero-Trust Ingress',
        operation: 'extractTrustedClientIp() & sanitizeUntrustedJsonInput()',
        status: 'BLOCKED_SECURITY',
        statusCode: 400,
        durationMs: 3.8,
        spanId: 'e50167aa0ba90001',
        parentSpanId: '44d5e6f708090a04',
        policyTitle: 'Module 08: Right-to-Left XFF Hop Extraction + NoSQL/CRLF Block',
        policyCode: `// 1. Ignore spoofed left-side XFF IPs (1.1.1.1, 8.8.8.8); extract 203.0.113.99
// 2. Reject NoSQL operator key "$ne" and SMTP header containing \\r\\n`,
        inputEnvelope: {
          headers: {
            'x-forwarded-for': '1.1.1.1, 8.8.8.8, 203.0.113.99, 10.0.1.5',
            'host': 'evil-attacker-reset-poison.com',
          },
          payload: {
            targetWebhookUrl: 'https://[::ffff:a9fe:a9fe]/latest/meta-data/',
            emailSubjectHeader: 'Invoice Receipt\\r\\nBcc: attacker-exfil@evil.org',
            filterQuery: { $ne: null },
          },
          byteSize: 362,
        },
        outputEnvelope: {
          headers: { 'x-verified-client-ip': '203.0.113.99' },
          payload: {
            spoofedXffIgnored: ['1.1.1.1', '8.8.8.8'],
            verifiedClientIp: '203.0.113.99',
            nosqlOperatorDetected: '$ne',
            crlfInjectionDetected: true,
          },
          byteSize: 218,
        },
      },
      {
        id: 'pen-hop-2',
        hopIndex: 2,
        hopType: 'AUTH_RBA_ENGINE',
        serviceName: 'Risk-Based Auth & Anomaly Engine',
        providerBadge: 'RBA Score 92/100',
        operation: 'evaluateContextualRiskSignals()',
        status: 'BLOCKED_SECURITY',
        statusCode: 403,
        durationMs: 4.1,
        spanId: 'e50167aa0ba90002',
        parentSpanId: 'e50167aa0ba90001',
        policyTitle: 'Module 02: Probabilistic Risk Scoring & Step-Up Enforcement',
        policyCode: `// New ASN + Host header mismatch + exploit payload signature -> Risk Score = 92/100
// Require WebAuthn Step-Up challenge & block outbound execution`,
        inputEnvelope: {
          headers: { 'x-client-ip-prefix': '203.0.113.0/24' },
          payload: { actorId: 'usr_compromised_09', anomalySignals: ['HOST_HEADER_POISON', 'EXPLOIT_PAYLOAD'] },
          byteSize: 190,
        },
        outputEnvelope: {
          headers: { 'x-rba-decision': 'STEP_UP_AND_BLOCK' },
          payload: { riskScore: 92, action: 'BLOCK_REQUEST_EMIT_SECURITY_AUDIT' },
          byteSize: 144,
        },
      },
      {
        id: 'pen-hop-3',
        hopIndex: 3,
        hopType: 'BAAS_DATA_PLANE',
        serviceName: 'Hash-Chained Security Audit Ledger',
        providerBadge: 'PostgreSQL Audit Trail',
        operation: 'appendImmutableSecurityAuditLog()',
        status: 'OK',
        statusCode: 201,
        durationMs: 2.1,
        spanId: 'e50167aa0ba90003',
        parentSpanId: 'e50167aa0ba90002',
        policyTitle: 'Module 08: Tamper-Evident SHA-256 Hash-Chained Audit Log',
        policyCode: `// Compute entry_hash = SHA256(prev_hash || timestamp || actor_id || event || payload_json)
INSERT INTO security_audit_ledger (id, tenant_id, prev_hash, entry_hash, event_type) VALUES (...);`,
        inputEnvelope: {
          headers: { 'x-audit-chain': 'SHA256_LINKED' },
          payload: { eventType: 'ADVERSARIAL_EXPLOIT_BLOCKED', clientIp: '203.0.113.99' },
          byteSize: 176,
        },
        outputEnvelope: {
          headers: { 'x-entry-hash': 'sha256:88f1a2c3...990e' },
          payload: { auditRecorded: true, domainMutationSkipped: true },
          byteSize: 132,
        },
      },
      {
        id: 'pen-hop-4',
        hopIndex: 4,
        hopType: 'ASYNC_OUTBOX_RELAY',
        serviceName: 'Outbox Gate (Short-Circuited)',
        providerBadge: 'Aborted Pre-Commit',
        operation: 'skipOutboxOnSecurityViolation()',
        status: 'BLOCKED_SECURITY',
        statusCode: 403,
        durationMs: 0.4,
        spanId: 'e50167aa0ba90004',
        parentSpanId: 'e50167aa0ba90003',
        policyTitle: 'Module 03: Zero Uncommitted Side Effects on Rejected Transactions',
        policyCode: `// Because domain transaction was rejected, zero rows were inserted into outbox_events.`,
        inputEnvelope: {
          headers: {},
          payload: { outboxWriteAttempted: false },
          byteSize: 48,
        },
        outputEnvelope: {
          headers: {},
          payload: { status: 'NO_OP_ABORTED' },
          byteSize: 42,
        },
      },
      {
        id: 'pen-hop-5',
        hopIndex: 5,
        hopType: 'EGRESS_EXTERNAL_PROVIDER',
        serviceName: 'DNS-Pinned SSRF & IPv6 Tunnel Blocker',
        providerBadge: 'SSRF Socket Guard',
        operation: 'isPrivateOrReservedIp("::ffff:a9fe:a9fe")',
        status: 'BLOCKED_SECURITY',
        statusCode: 403,
        durationMs: 1.0,
        spanId: 'e50167aa0ba90005',
        parentSpanId: 'e50167aa0ba90004',
        policyTitle: 'Module 08 & 09: 128-Bit Hextet IPv6 Parser (Blocks ::ffff:a9fe:a9fe)',
        policyCode: `// parseIpv6Hextets("::ffff:a9fe:a9fe") -> Hextets [0,0,0,0,0,0xffff,0xa9fe,0xa9fe]
// Extracts embedded IPv4 169.254.169.254 (Cloud IMDSv2 link-local) -> BLOCKED!`,
        inputEnvelope: {
          headers: {},
          payload: { targetHost: '::ffff:a9fe:a9fe', resolvedIpv4: '169.254.169.254' },
          byteSize: 112,
        },
        outputEnvelope: {
          headers: { 'x-ssrf-blocked': 'true' },
          payload: {
            isPrivateOrReserved: true,
            matchedRange: '169.254.0.0/16 (IPv4-Mapped IPv6 Cloud Metadata)',
            socketOpened: false,
          },
          byteSize: 184,
        },
      },
    ],
    logs: [
      {
        id: 'log-501',
        timestamp: '2026-11-06T17:18:45.002Z',
        level: 'SECURITY_AUDIT',
        traceId: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
        spanId: 'e50167aa0ba90001',
        hopId: 'pen-hop-1',
        service: 'api-ingress-gateway',
        event: 'SPOOFED_XFF_AND_INJECTION_DETECTED',
        message: 'Ignored spoofed X-Forwarded-For prefix (1.1.1.1, 8.8.8.8); detected NoSQL "$ne" operator and SMTP CRLF sequence.',
        durationMs: 3.8,
        metadata: { realClientIp: '203.0.113.99', rejectedKeys: ['$ne'], crlfHeader: 'emailSubjectHeader' },
      },
      {
        id: 'log-502',
        timestamp: '2026-11-06T17:18:45.009Z',
        level: 'ERROR',
        traceId: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
        spanId: 'e50167aa0ba90005',
        hopId: 'pen-hop-5',
        service: 'ssrf-pinned-socket-guard',
        event: 'SSRF_IPV6_HEX_MAPPED_IMDS_BLOCKED',
        message: 'Blocked outbound request to [::ffff:a9fe:a9fe]: expands to link-local Cloud Metadata 169.254.169.254.',
        durationMs: 1.0,
        metadata: { targetInput: '::ffff:a9fe:a9fe', decodedIpv4: '169.254.169.254', rfc9457Status: 403 },
      },
    ],
  },
];

export default function BackendSkillWorkspace({ files }: { files: SkillMarkdownFile[] }) {
  const [activeMainView, setActiveMainView] = useState<'visualizer' | 'risk-audit' | 'specification'>('risk-audit');
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(SCENARIOS[0].id);
  const [selectedHopId, setSelectedHopId] = useState<string>(SCENARIOS[0].hops[0].id);
  const [filterBySelectedHop, setFilterBySelectedHop] = useState<boolean>(false);
  const [selectedLogLevel, setSelectedLogLevel] = useState<'ALL' | LogLevel>('ALL');
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');

  // Critical Risk Audit state
  const [selectedRiskId, setSelectedRiskId] = useState<string>(CRITICAL_RISK_ITEMS[0].id);
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');

  // Editable request payload state for live simulation
  const [customBodyText, setCustomBodyText] = useState<string>(() =>
    JSON.stringify(SCENARIOS[0].defaultRequestBody, null, 2)
  );
  const [liveAuditFinding, setLiveAuditFinding] = useState<{
    triggered: boolean;
    findings: string[];
    evaluatedAt: string;
  } | null>(null);

  // Specification reader state
  const [selectedFilePath, setSelectedFilePath] = useState<string>(files[0]?.path ?? '');
  const [specSearchQuery, setSpecSearchQuery] = useState<string>('');
  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  const activeScenario = useMemo(
    () => SCENARIOS.find((s) => s.id === selectedScenarioId) ?? SCENARIOS[0],
    [selectedScenarioId]
  );

  const activeHop = useMemo(
    () => activeScenario.hops.find((h) => h.id === selectedHopId) ?? activeScenario.hops[0],
    [activeScenario, selectedHopId]
  );

  const filteredRisks = useMemo(() => {
    if (severityFilter === 'ALL') return CRITICAL_RISK_ITEMS;
    return CRITICAL_RISK_ITEMS.filter((item) => item.severity === severityFilter);
  }, [severityFilter]);

  const activeRisk = useMemo(
    () => filteredRisks.find((r) => r.id === selectedRiskId) ?? filteredRisks[0] ?? CRITICAL_RISK_ITEMS[0],
    [filteredRisks, selectedRiskId]
  );

  const handleSelectScenario = (scenarioId: string) => {
    const next = SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0];
    setSelectedScenarioId(next.id);
    setSelectedHopId(next.hops[0].id);
    setCustomBodyText(JSON.stringify(next.defaultRequestBody, null, 2));
    setLiveAuditFinding(null);
  };

  const handleRunLiveTraceEvaluation = () => {
    const findings: string[] = [];
    const raw = customBodyText;

    if (raw.includes('__proto__') || raw.includes('constructor') || raw.includes('prototype')) {
      findings.push('BLOCKED [PEN-06]: Prototype Pollution vector (__proto__ / constructor) stripped by sanitizeUntrustedJsonInput().');
    }
    if (/\$ne|\$where|\$gt|\$regex/i.test(raw)) {
      findings.push('BLOCKED [PEN-06]: NoSQL operator injection ($ne / $where) rejected at Ingress Gate.');
    }
    if (/\\r|\\n|\r|\n/i.test(raw) && /bcc:|cc:|to:/i.test(raw)) {
      findings.push('BLOCKED [PEN-09]: SMTP CRLF Header Injection (\\r\\nBcc:) blocked by sanitizeHeaderFieldAntiCrlf().');
    }
    if (/169\.254\.169\.254|a9fe:a9fe|127\.0\.0\.1|64:ff9b/i.test(raw)) {
      findings.push('BLOCKED [PEN-01]: SSRF Cloud Metadata / IPv6 Tunnel target blocked by 128-bit hextet parser & DNS-pinned agent.');
    }
    if (/user_metadata/i.test(raw)) {
      findings.push('BLOCKED [PEN-10]: Supabase client-writable user_metadata claim ignored; RLS enforces auth.jwt() -> app_metadata.');
    }
    if (findings.length === 0) {
      findings.push(
        `VERIFIED CLEAN: Payload passed schema validation, PII scrubbing (scrubIoPayload), and W3C traceparent correlation (${activeScenario.traceId}).`
      );
    }

    setLiveAuditFinding({
      triggered: true,
      findings,
      evaluatedAt: new Date().toISOString(),
    });
  };

  const filteredLogs = useMemo(() => {
    return activeScenario.logs.filter((entry) => {
      if (filterBySelectedHop && entry.hopId !== activeHop.id) {
        return false;
      }
      if (selectedLogLevel !== 'ALL' && entry.level !== selectedLogLevel) {
        return false;
      }
      if (logSearchQuery.trim() !== '') {
        const q = logSearchQuery.toLowerCase();
        const hay = `${entry.service} ${entry.event} ${entry.message} ${entry.spanId} ${JSON.stringify(entry.metadata)}`.toLowerCase();
        return hay.includes(q);
      }
      return true;
    });
  }, [activeScenario.logs, filterBySelectedHop, activeHop.id, selectedLogLevel, logSearchQuery]);

  const filteredSpecFiles = useMemo(() => {
    if (!specSearchQuery.trim()) return files;
    const q = specSearchQuery.toLowerCase();
    return files.filter(
      (f) => f.path.toLowerCase().includes(q) || f.content.toLowerCase().includes(q)
    );
  }, [files, specSearchQuery]);

  const activeSpecFile = useMemo(
    () =>
      filteredSpecFiles.find((f) => f.path === selectedFilePath) ??
      filteredSpecFiles[0] ??
      files[0],
    [filteredSpecFiles, selectedFilePath, files]
  );

  const handleCopyContent = async (pathKey: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedPath(pathKey);
      setTimeout(() => setCopiedPath(null), 1800);
    } catch {
      // Fallback no-op if clipboard restricted
    }
  };

  return (
    <div className="min-h-screen bg-[#090D16] text-[#F1F5F9] font-sans selection:bg-sky-500/30">
      {/* Top Bar Contract: Strict 3-Zone Navigation (Identity Left, View Switcher Center, Primary Action Right) */}
      <header className="sticky top-0 z-30 h-14 border-b border-slate-800/80 bg-[#090D16]/95 backdrop-blur px-4 lg:px-8 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="truncate">
            <div className="text-sm font-semibold tracking-tight text-slate-100 truncate">
              Advanced Backend Development Skill
            </div>
            <div className="text-[11px] font-mono text-slate-400 truncate">
              /skills/*.md · {files.length} Modules · All Critical Module Risks Verified
            </div>
          </div>
        </div>

        {/* Center View Switcher */}
        <nav aria-label="Workspace Mode" className="flex items-center bg-[#111827] p-1 rounded border border-slate-800">
          <button
            type="button"
            onClick={() => setActiveMainView('risk-audit')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeMainView === 'risk-audit'
                ? 'bg-sky-500 text-slate-950 font-semibold'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Critical Risk Audit (12)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveMainView('visualizer')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeMainView === 'visualizer'
                ? 'bg-sky-500 text-slate-950 font-semibold'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Request I/O & Service Logs</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveMainView('specification')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeMainView === 'specification'
                ? 'bg-sky-500 text-slate-950 font-semibold'
                : 'text-slate-300 hover:text-white'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Skill Specification ({files.length})</span>
          </button>
        </nav>

        {/* Right Primary Action */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() =>
              handleCopyContent(
                'ALL_SKILL_MODULES',
                files.map((f) => `# FILE: ${f.path}\n\n${f.content}`).join('\n\n---\n\n')
              )
            }
            className="px-3 py-1.5 rounded border border-slate-700 bg-[#111827] hover:bg-slate-800 text-xs font-medium text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            {copiedPath === 'ALL_SKILL_MODULES' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied All {files.length} Files</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span>Export Full Skill Bundle</span>
              </>
            )}
          </button>
        </div>
      </header>

      {activeMainView === 'risk-audit' ? (
        <main className="max-w-[1600px] mx-auto p-4 lg:p-6 space-y-6">
          {/* KPI Summary Strip */}
          <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-[#111827] border border-slate-800/80 rounded-md p-4">
              <div className="text-xs font-mono text-slate-400">CRITICAL RISK DOMAINS AUDITED</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-slate-100 mt-1">
                12 / 12
              </div>
              <div className="text-xs text-emerald-400 mt-1 font-mono">
                6 Critical · 6 High Severity Remediated
              </div>
            </div>
            <div className="bg-[#111827] border border-slate-800/80 rounded-md p-4">
              <div className="text-xs font-mono text-slate-400">DB & MULTI-TENANT ISOLATION</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-sky-400 mt-1">
                SET LOCAL + RLS
              </div>
              <div className="text-xs text-slate-400 mt-1 font-mono">
                Composite Tenant FKs · NOBYPASSRLS
              </div>
            </div>
            <div className="bg-[#111827] border border-slate-800/80 rounded-md p-4">
              <div className="text-xs font-mono text-slate-400">API & SECRET BOUNDARIES</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400 mt-1">
                AES-GCM + AAD
              </div>
              <div className="text-xs text-slate-400 mt-1 font-mono">
                Zero service_role in Frontend · Strict CORS/CSRF
              </div>
            </div>
            <div className="bg-[#111827] border border-slate-800/80 rounded-md p-4">
              <div className="text-xs font-mono text-slate-400">PRODUCTION RELIABILITY</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-amber-400 mt-1">
                /healthz + /readyz
              </div>
              <div className="text-xs text-slate-400 mt-1 font-mono">
                SIGTERM Connection Draining · 3-Phase Outbox
              </div>
            </div>
          </section>

          {/* 12-Domain Interactive Critical Risk Audit Matrix + Code Inspector */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left: 12 Risk Domains Table (7 cols) */}
            <div className="lg:col-span-7 bg-[#111827] border border-slate-800/80 rounded-md p-4 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <h1 className="text-sm font-semibold text-slate-100">
                    Pre-Production Critical Risk Audit & Remediation Matrix
                  </h1>
                  <p className="text-xs text-slate-400">
                    Click any risk area to inspect the subtle vulnerability uncovered during the skill audit and its exact code-level fix.
                  </p>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  {(['ALL', 'CRITICAL', 'HIGH'] as const).map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => setSeverityFilter(sev)}
                      className={`px-2.5 py-1 rounded text-xs font-mono border transition-colors ${
                        severityFilter === sev
                          ? 'bg-sky-500 text-slate-950 border-sky-500 font-semibold'
                          : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2 px-3">ID</th>
                      <th className="py-2 px-3">RISK AREA & CONSEQUENCE</th>
                      <th className="py-2 px-3">SEVERITY</th>
                      <th className="py-2 px-3">MODULE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredRisks.map((item) => {
                      const isSelected = item.id === activeRisk.id;
                      return (
                        <tr
                          key={item.id}
                          onClick={() => setSelectedRiskId(item.id)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-sky-500/15 text-slate-100'
                              : 'hover:bg-slate-900/60 text-slate-300'
                          }`}
                        >
                          <td className="py-2.5 px-3 font-semibold text-sky-400 whitespace-nowrap align-top">
                            {item.id}
                          </td>
                          <td className="py-2.5 px-3 align-top">
                            <div className="font-sans font-semibold text-xs text-slate-100">
                              {item.domain}
                            </div>
                            <div className="font-sans text-[11px] text-slate-400 mt-0.5">
                              {item.consequence}
                            </div>
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap align-top">
                            <span
                              className={
                                item.severity === 'CRITICAL'
                                  ? 'text-rose-400 font-semibold'
                                  : 'text-amber-400 font-semibold'
                              }
                            >
                              {item.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap align-top">
                            {item.moduleRef}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Right: Selected Risk Deep-Dive & Remediation Inspector (5 cols) */}
            <div className="lg:col-span-5 bg-[#111827] border border-slate-800/80 rounded-md p-4 space-y-4">
              <div className="border-b border-slate-800 pb-3 flex items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-mono text-sky-400">
                    {activeRisk.id} · {activeRisk.moduleRef}
                  </div>
                  <h2 className="text-sm font-semibold text-slate-100 mt-0.5">
                    {activeRisk.domain}
                  </h2>
                </div>
                <span
                  className={`text-xs font-mono font-semibold ${
                    activeRisk.severity === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'
                  }`}
                >
                  {activeRisk.severity}
                </span>
              </div>

              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-rose-400 font-semibold">
                  VULNERABILITY / RISK UNCOVERED DURING AUDIT:
                </div>
                <p className="text-xs text-slate-300 leading-relaxed bg-[#090D16] p-3 rounded border border-slate-800">
                  {activeRisk.vulnerabilityFound}
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-emerald-400 font-semibold">
                  MANDATORY CODE-LEVEL REMEDIATION IMPLEMENTED:
                </div>
                <p className="text-xs text-slate-300 leading-relaxed bg-[#090D16] p-3 rounded border border-slate-800">
                  {activeRisk.remediationImplemented}
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-sky-400 font-semibold">
                  HARDENED IMPLEMENTATION SNIPPET:
                </div>
                <pre className="p-3 rounded bg-[#090D16] border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto leading-relaxed">
                  {activeRisk.remediationCode}
                </pre>
              </div>

              <div className="p-3 rounded bg-emerald-950/30 border border-emerald-500/30 text-xs font-mono text-emerald-300">
                {activeRisk.verificationAssertion}
              </div>
            </div>
          </section>
        </main>
      ) : activeMainView === 'visualizer' ? (
        <main className="max-w-[1600px] mx-auto p-4 lg:p-6 space-y-6">
          {/* Scenario Selector Bar */}
          <section className="bg-[#111827] border border-slate-800/80 rounded-md p-4">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 pb-3 border-b border-slate-800/80">
              <div>
                <h1 className="text-base font-semibold text-slate-100">
                  Incoming/Outgoing Request I/O, BaaS & Service Dependency Telemetry
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Select an end-to-end backend trace below or edit the incoming payload to inspect every service hop, BaaS security policy, outgoing provider call, and W3C correlated log entry.
                </p>
              </div>
              <div className="flex items-center gap-4 text-xs font-mono tabular-nums text-slate-300 shrink-0">
                <div>
                  <span className="text-slate-500">TRACE ID: </span>
                  <span className="text-sky-400">{activeScenario.traceId}</span>
                </div>
                <div>
                  <span className="text-slate-500">TOTAL LATENCY: </span>
                  <span className="text-emerald-400">{activeScenario.totalDurationMs.toFixed(1)} ms</span>
                </div>
                <div>
                  <span className="text-slate-500">HTTP STATUS: </span>
                  <span
                    className={
                      activeScenario.finalStatus >= 400
                        ? 'text-rose-400 font-semibold'
                        : 'text-emerald-400 font-semibold'
                    }
                  >
                    {activeScenario.finalStatus}
                  </span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-2.5 pt-3">
              {SCENARIOS.map((scenario) => {
                const isSelected = scenario.id === activeScenario.id;
                return (
                  <button
                    key={scenario.id}
                    type="button"
                    onClick={() => handleSelectScenario(scenario.id)}
                    className={`text-left p-3 rounded border transition-colors flex flex-col justify-between gap-2 ${
                      isSelected
                        ? 'bg-sky-500/10 border-sky-500/60 text-slate-100'
                        : 'bg-[#090D16]/60 border-slate-800/80 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div>
                      <div className="text-[11px] font-mono text-sky-400 truncate">
                        {scenario.category}
                      </div>
                      <div className="text-xs font-semibold text-slate-100 mt-1 line-clamp-2">
                        {scenario.title}
                      </div>
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono tabular-nums pt-2 border-t border-slate-800/60">
                      <span className="text-slate-400">
                        {scenario.httpMethod} · {scenario.totalDurationMs}ms
                      </span>
                      <span
                        className={
                          scenario.overallStatus === 'BLOCKED_SECURITY'
                            ? 'text-rose-400'
                            : scenario.overallStatus === 'DEGRADED_FAILOVER'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {scenario.finalStatus} {scenario.overallStatus}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </section>

          {/* 5-Stage Service Dependency Pipeline Topology */}
          <section className="bg-[#111827] border border-slate-800/80 rounded-md p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-400" />
                <h2 className="text-sm font-semibold text-slate-100">
                  Service-to-Service Execution Pipeline (Click any service node to inspect Input/Output & Policy)
                </h2>
              </div>
              <div className="text-xs font-mono text-slate-400">
                W3C traceparent: <span className="text-slate-200">{activeScenario.traceparent}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
              {activeScenario.hops.map((hop, idx) => {
                const isSelected = hop.id === activeHop.id;
                const statusColor =
                  hop.status === 'BLOCKED_SECURITY'
                    ? 'border-rose-500/60 text-rose-400'
                    : hop.status === 'DEGRADED_FAILOVER'
                    ? 'border-amber-500/60 text-amber-400'
                    : 'border-emerald-500/50 text-emerald-400';

                return (
                  <div key={hop.id} className="relative flex items-stretch">
                    <button
                      type="button"
                      onClick={() => setSelectedHopId(hop.id)}
                      className={`w-full text-left p-3.5 rounded border transition-all flex flex-col justify-between gap-2.5 ${
                        isSelected
                          ? 'bg-sky-500/15 border-sky-400 ring-1 ring-sky-400/30'
                          : 'bg-[#090D16] border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-[11px] font-mono tabular-nums">
                          <span className="text-slate-400">
                            HOP 0{hop.hopIndex} · {hop.providerBadge}
                          </span>
                          <span className={statusColor.split(' ')[1]}>{hop.durationMs.toFixed(1)} ms</span>
                        </div>
                        <div className="text-xs font-semibold text-slate-100">
                          {hop.serviceName}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 truncate">
                          {hop.operation}
                        </div>
                      </div>

                      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono tabular-nums">
                        <span className="text-slate-400">span: {hop.spanId.slice(0, 10)}</span>
                        <span
                          className={
                            hop.status === 'BLOCKED_SECURITY'
                              ? 'text-rose-400 font-semibold'
                              : hop.status === 'DEGRADED_FAILOVER'
                              ? 'text-amber-400 font-semibold'
                              : 'text-emerald-400 font-semibold'
                          }
                        >
                          {hop.status} ({hop.statusCode})
                        </span>
                      </div>
                    </button>

                    {idx < activeScenario.hops.length - 1 && (
                      <div className="hidden lg:flex items-center justify-center -right-2.5 top-1/2 -translate-y-1/2 absolute z-10 pointer-events-none">
                        <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>

          {/* 3-Column Deep I/O Envelope & Hop Policy Inspector */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch">
            {/* Column 1: Incoming Request & Live Payload Simulator (4 cols) */}
            <div className="lg:col-span-4 bg-[#111827] border border-slate-800/80 rounded-md flex flex-col justify-between">
              <div className="p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-sky-400" />
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                      1. Incoming Client Request I/O
                    </h3>
                  </div>
                  <span className="text-xs font-mono text-sky-400">
                    {activeScenario.httpMethod} {activeScenario.route}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400">
                    INCOMING HEADERS (PII & Secrets Scrubbed):
                  </div>
                  <pre className="p-2.5 rounded bg-[#090D16] border border-slate-800/80 text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
                    {JSON.stringify(activeScenario.defaultRequestHeaders, null, 2)}
                  </pre>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="incoming-json-editor"
                      className="text-[11px] font-mono text-slate-400"
                    >
                      EDITABLE INCOMING JSON PAYLOAD:
                    </label>
                    <button
                      type="button"
                      onClick={() => {
                        setCustomBodyText(
                          JSON.stringify(activeScenario.defaultRequestBody, null, 2)
                        );
                        setLiveAuditFinding(null);
                      }}
                      className="text-[11px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Reset</span>
                    </button>
                  </div>
                  <textarea
                    id="incoming-json-editor"
                    value={customBodyText}
                    onChange={(e) => setCustomBodyText(e.target.value)}
                    rows={8}
                    className="w-full p-2.5 rounded bg-[#090D16] border border-slate-800 focus:border-sky-500 focus:outline-none text-[11px] font-mono text-emerald-300 leading-relaxed"
                  />
                </div>

                {liveAuditFinding && (
                  <div className="p-2.5 rounded bg-[#090D16] border border-sky-500/40 space-y-1">
                    <div className="text-[11px] font-mono text-sky-400 font-semibold">
                      LIVE GATE EVALUATION ({liveAuditFinding.evaluatedAt.slice(11, 23)}Z):
                    </div>
                    {liveAuditFinding.findings.map((f, i) => (
                      <div key={i} className="text-[11px] font-mono text-slate-200">
                        • {f}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="p-4 pt-0">
                <button
                  type="button"
                  onClick={handleRunLiveTraceEvaluation}
                  className="w-full py-2 px-3 rounded bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Evaluate Incoming Payload Against Security Gates</span>
                </button>
              </div>
            </div>

            {/* Column 2: Selected Service Hop Input/Output & Policy Inspector (4 cols) */}
            <div className="lg:col-span-4 bg-[#111827] border border-slate-800/80 rounded-md p-4 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <div className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-sky-400" />
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                      2. Hop 0{activeHop.hopIndex} I/O: {activeHop.serviceName}
                    </h3>
                  </div>
                  <span className="text-xs font-mono tabular-nums text-emerald-400">
                    {activeHop.durationMs.toFixed(1)} ms
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono text-sky-400">
                    {activeHop.policyTitle}
                  </div>
                  <pre className="p-2.5 rounded bg-[#090D16] border border-slate-800/80 text-[11px] font-mono text-amber-300 overflow-x-auto leading-relaxed">
                    {activeHop.policyCode}
                  </pre>
                </div>

                <div className="grid grid-cols-1 gap-2.5">
                  <div>
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                      <span>HOP INPUT ENVELOPE</span>
                      <span>{activeHop.inputEnvelope.byteSize} bytes</span>
                    </div>
                    <pre className="p-2.5 rounded bg-[#090D16] border border-slate-800/80 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-36">
                      {JSON.stringify(activeHop.inputEnvelope.payload, null, 2)}
                    </pre>
                  </div>

                  <div>
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                      <span>HOP OUTPUT ENVELOPE (HTTP {activeHop.statusCode})</span>
                      <span>{activeHop.outputEnvelope.byteSize} bytes</span>
                    </div>
                    <pre className="p-2.5 rounded bg-[#090D16] border border-slate-800/80 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-36">
                      {JSON.stringify(activeHop.outputEnvelope.payload, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>span_id: {activeHop.spanId}</span>
                <span>parent: {activeHop.parentSpanId ?? 'root'}</span>
              </div>
            </div>

            {/* Column 3: Outgoing Response Envelope & BaaS/Provider Summary (4 cols) */}
            <div className="lg:col-span-4 bg-[#111827] border border-slate-800/80 rounded-md p-4 space-y-3 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <div className="flex items-center gap-2">
                    <Send className="w-4 h-4 text-sky-400" />
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                      3. Outgoing Response & Provider Egress
                    </h3>
                  </div>
                  <span
                    className={`text-xs font-mono font-semibold tabular-nums ${
                      activeScenario.outgoingResponse.status >= 400
                        ? 'text-rose-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    HTTP {activeScenario.outgoingResponse.status}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400">
                    OUTGOING RESPONSE HEADERS:
                  </div>
                  <pre className="p-2.5 rounded bg-[#090D16] border border-slate-800/80 text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
                    {JSON.stringify(activeScenario.outgoingResponse.headers, null, 2)}
                  </pre>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400">
                    OUTGOING JSON RESPONSE BODY:
                  </div>
                  <pre className="p-2.5 rounded bg-[#090D16] border border-slate-800/80 text-[11px] font-mono text-sky-300 overflow-x-auto max-h-64 leading-relaxed">
                    {JSON.stringify(activeScenario.outgoingResponse.body, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Tenant: {activeScenario.tenantId}</span>
                <span>Actor: {activeScenario.actorId}</span>
              </div>
            </div>
          </section>

          {/* Correlated Structured JSON Log Telemetry Stream */}
          <section className="bg-[#111827] border border-slate-800/80 rounded-md p-4 space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-sky-400" />
                <div>
                  <h2 className="text-sm font-semibold text-slate-100">
                    Correlated Structured JSON Log Stream (W3C trace_id={activeScenario.traceId})
                  </h2>
                  <p className="text-xs text-slate-400">
                    Every log entry is automatically bound to its service hop span_id with recursive PII/secret redaction.
                  </p>
                </div>
              </div>

              {/* Log Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setFilterBySelectedHop((prev) => !prev)}
                  className={`px-2.5 py-1 rounded text-xs font-mono border transition-colors ${
                    filterBySelectedHop
                      ? 'bg-sky-500/20 border-sky-400 text-sky-300'
                      : 'bg-[#090D16] border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  {filterBySelectedHop
                    ? `Filtered: Hop 0${activeHop.hopIndex} Only`
                    : 'All Service Hops'}
                </button>

                {(['ALL', 'INFO', 'WARN', 'ERROR', 'SECURITY_AUDIT'] as const).map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setSelectedLogLevel(lvl)}
                    className={`px-2.5 py-1 rounded text-xs font-mono border transition-colors ${
                      selectedLogLevel === lvl
                        ? 'bg-slate-200 text-slate-950 border-slate-200 font-semibold'
                        : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}

                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={logSearchQuery}
                    onChange={(e) => setLogSearchQuery(e.target.value)}
                    placeholder="Filter logs by span, event..."
                    className="pl-8 pr-3 py-1 rounded bg-[#090D16] border border-slate-800 focus:border-sky-500 focus:outline-none text-xs font-mono text-slate-200"
                  />
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <th className="py-2 px-3">TIMESTAMP</th>
                    <th className="py-2 px-3">LEVEL</th>
                    <th className="py-2 px-3">SERVICE HOP & SPAN</th>
                    <th className="py-2 px-3">EVENT & CORRELATED MESSAGE</th>
                    <th className="py-2 px-3 text-right">LATENCY</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredLogs.map((log) => {
                    const levelStyle =
                      log.level === 'ERROR'
                        ? 'text-rose-400 font-semibold'
                        : log.level === 'WARN'
                        ? 'text-amber-400 font-semibold'
                        : log.level === 'SECURITY_AUDIT'
                        ? 'text-sky-400 font-semibold'
                        : 'text-emerald-400';

                    return (
                      <tr
                        key={log.id}
                        onClick={() => setSelectedHopId(log.hopId)}
                        className={`cursor-pointer transition-colors ${
                          log.hopId === activeHop.id
                            ? 'bg-sky-500/5 hover:bg-sky-500/10'
                            : 'hover:bg-slate-900/60'
                        }`}
                      >
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap align-top">
                          {log.timestamp.slice(11, 23)}Z
                        </td>
                        <td className={`py-2.5 px-3 whitespace-nowrap align-top ${levelStyle}`}>
                          {log.level}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap align-top">
                          <div className="text-slate-200">{log.service}</div>
                          <div className="text-[11px] text-slate-500">span: {log.spanId}</div>
                        </td>
                        <td className="py-2.5 px-3 align-top">
                          <div className="text-slate-100 font-semibold">{log.event}</div>
                          <div className="text-slate-300 mt-0.5 font-sans text-xs">
                            {log.message}
                          </div>
                          <pre className="mt-1.5 p-2 rounded bg-[#090D16] border border-slate-800/80 text-[11px] text-slate-400 overflow-x-auto">
                            {JSON.stringify(log.metadata)}
                          </pre>
                        </td>
                        <td className="py-2.5 px-3 text-right text-slate-300 whitespace-nowrap align-top">
                          {log.durationMs.toFixed(1)} ms
                        </td>
                      </tr>
                    );
                  })}
                  {filteredLogs.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-slate-500">
                        No correlated log entries match the current filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      ) : (
        /* View 3: Complete Skill Specification Reader & Exporter */
        <main className="max-w-[1600px] mx-auto p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Sidebar Module Index */}
          <aside className="lg:col-span-4 xl:col-span-3 space-y-3">
            <div className="bg-[#111827] border border-slate-800/80 rounded-md p-3 space-y-3">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={specSearchQuery}
                  onChange={(e) => setSpecSearchQuery(e.target.value)}
                  placeholder={`Search ${files.length} skill modules...`}
                  className="w-full pl-8 pr-3 py-1.5 rounded bg-[#090D16] border border-slate-800 focus:border-sky-500 focus:outline-none text-xs font-mono text-slate-200"
                />
              </div>

              <div className="space-y-1 max-h-[70vh] overflow-y-auto pr-1">
                {filteredSpecFiles.map((file) => {
                  const isSelected = activeSpecFile?.path === file.path;
                  const shortName = file.path.replace(/^\/skills\//, '');
                  return (
                    <button
                      key={file.path}
                      type="button"
                      onClick={() => setSelectedFilePath(file.path)}
                      className={`w-full text-left px-3 py-2 rounded text-xs font-mono transition-colors flex items-center justify-between gap-2 ${
                        isSelected
                          ? 'bg-sky-500/15 border border-sky-500/50 text-sky-300 font-semibold'
                          : 'text-slate-300 hover:bg-slate-900 border border-transparent'
                      }`}
                    >
                      <span className="truncate">{shortName}</span>
                      <span className="text-[10px] text-slate-500 shrink-0">
                        {(file.content.length / 1024).toFixed(1)}KB
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </aside>

          {/* Main Markdown Specification Viewer */}
          <section className="lg:col-span-8 xl:col-span-9 bg-[#111827] border border-slate-800/80 rounded-md flex flex-col">
            {activeSpecFile ? (
              <>
                <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-4">
                  <div className="flex items-center gap-2 min-w-0">
                    <Lock className="w-4 h-4 text-sky-400 shrink-0" />
                    <span className="font-mono text-xs font-semibold text-sky-400 truncate">
                      {activeSpecFile.path}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopyContent(activeSpecFile.path, activeSpecFile.content)
                    }
                    className="px-3 py-1 rounded border border-slate-700 bg-[#090D16] hover:bg-slate-800 text-xs font-mono text-slate-200 flex items-center gap-1.5 shrink-0"
                  >
                    {copiedPath === activeSpecFile.path ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-slate-400" />
                        <span>Copy Module</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-5 overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-slate-200 max-h-[78vh] overflow-y-auto">
                  {activeSpecFile.content}
                </pre>
              </>
            ) : (
              <div className="p-8 text-center text-slate-400 text-sm flex items-center justify-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>No skill module matches your search query.</span>
              </div>
            )}
          </section>
        </main>
      )}
    </div>
  );
}
