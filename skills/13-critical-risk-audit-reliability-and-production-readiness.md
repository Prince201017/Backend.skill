# Module 13: Critical Pre-Deployment Risk Audit, Database Constraints, API Boundary Guards & Production Reliability

This module provides the **Complete 12-Domain Critical Risk Audit Matrix** and production-grade TypeScript/SQL implementations for database composite foreign-key constraints, connection-pool-safe tenant transaction boundaries, frontend secret-leak prevention, CORS/CSRF/size/timeout API boundary guards, AAD-bound envelope encryption, `/healthz` + `/readyz` probes, graceful shutdown (`SIGTERM`/`SIGINT`), and dependency supply-chain verification.

---

## 1. The 15-Domain Critical Risk Audit Matrix (Pre-Production Gate)

| Risk Area | Potential Consequence | Severity | Vulnerability Found in Naive Implementations | Mandatory Remediation in This Skill |
| :--- | :--- | :--- | :--- | :--- |
| **1. Authentication** | Weak JWT/session implementation; forged tokens, 100-year TTLs, or stolen refresh token replay | **Critical** | Accepting `alg: "none"`, `RS256`->`HS256` confusion, unvalidated `kid`/`jku`, future `iat`, unbounded `exp - iat`, unbound sessions, or ignoring replayed refresh tokens. | `verifyJwtPenetrationSafe` (strict `alg`, alphanumeric `kid`, `iat`/`exp`/`nbf`, `maxTokenLifetimeSeconds`, `cnf.sidHash` session binding, `jti` revocation) + `rotateRefreshTokenWithReuseDetection` in `Module 02`. |
| **2. Authorization** | Users accessing other users' data (Horizontal BOLA/IDOR or Vertical privilege escalation) | **Critical** | Checking only `subject.tenantId === resource.tenantId` and role `'member'` without checking `resource.ownerId === subject.userId`. | `authorizeAction` in `Module 02` enforces both **Cross-Tenant Isolation** AND **Intra-Tenant Horizontal Ownership / ReBAC** for non-privileged roles, plus step-up MFA for sensitive mutations. |
| **3. Database Security & Constraints** | SQL injection, cross-tenant foreign-key references, leaked RLS session state, or `service_role` in frontend | **Critical** | String-interpolated `ORDER BY`, single-column `FOREIGN KEY (user_id)` allowing cross-tenant references, `SET` instead of `SET LOCAL` on pooled connections, or `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`. | 100% parameterized SQL + `resolveSafeOrderByClause`, composite foreign keys `FOREIGN KEY (tenant_id, user_id)`, `withTenantTransaction` (`SET LOCAL`), `NOBYPASSRLS` role, and `assertNoSecretsExposedToFrontendEnv`. |
| **4. Secrets Management** | API keys, DB credentials, or ciphertext transplanted across tenants | **Critical** | Hardcoded secrets, unrotated keys, or AES-GCM encryption without Additional Authenticated Data (`AAD`), allowing attackers to copy encrypted PII/keys into their own row. | KMS/Vault Envelope Encryption (`encryptWithTenantAad` / `decryptWithKeyRing`) binding `AAD = tenantId:resourceId:fieldName` with zero-downtime multi-version key rings (`v1`, `v2`). |
| **5. Input Validation** | Malformed/malicious payloads, memory exhaustion, Prototype Pollution, or Mass Assignment (BOPLA) | **High** | Calling `JSON.parse` before checking byte length, allowing unknown fields (`role: "admin"`), or skipping `NFKC` normalization. | `parseAndValidateJsonBodyStrict` (enforces `Content-Type`, hard `maxBodyBytes` cutoff, `sanitizeUntrustedJsonInput` stripping `__proto__`/`$`, and strict schema key allowlisting). |
| **6. Multi-Tenancy** | Cross-customer data leakage via shared Redis cache keys or pooled DB connections | **Critical** | Passing un-namespaced cache keys (`getOrComputeCachedSingleFlight(redis, "orders:summary")`) or leaking PostgreSQL session variables across pooled connections. | `getOrComputeCachedSingleFlight` (`Module 03`) mandates validated `tenantId` and `resourceKey` (`tenant:{tenantId}:{resourceKey}`), and `withTenantTransaction` enforces transaction-scoped `SET LOCAL`. |
| **7. File Uploads** | Malicious polyglot files, 17GB PNG decompression bombs, OOM crashes, or path traversal | **High** | Buffering files in RAM, checking only 8-byte PNG magic without checking `IHDR` dimensions (`65535x65535`), or concatenating unvalidated `tenantId` into storage paths. | `SecurityGateTransformStream` (`Module 05`) enforces `/^[a-zA-Z0-9_-]{1,64}$/` on `tenantId`, PNG `IHDR` dimension caps ($\le 8192\text{px}$, $\le 33.5\text{MP}$), 64KB bounded RAM, PDF `#XX`/null-byte deobfuscation, and ClamAV `zINSTREAM` scan. |
| **8. Rate Limiting** | API brute-force abuse, resource exhaustion, or Lua divide-by-zero crashes | **High** | Non-atomic `GET`/`SET` rate limiters, trusting spoofed leftmost `X-Forwarded-For`, or passing `refill_rate <= 0` to Lua. | Atomic Redis Lua Token Bucket (`Module 04`) with `refill_rate > 0` guard, right-to-left `extractTrustedClientIp`, and composite IP-prefix + Tenant/User buckets. |
| **9. Transactions & Outbox** | Duplicate payments, expired-lock fallthrough double charges, or poison-pill outbox head-of-line blocking | **Critical** | Falling through to `handler()` when `!lockRes.acquired` on an expired idempotency lock, holding DB locks across network I/O, or retrying a poison-pill outbox row forever. | `executeWithIdempotencyLock` (`Module 04` strict 409 on unacquired lock) + 3-Phase Outbox Relay with Phase 0 poison-pill quarantine (`dead_lettered_at` after `maxRelayAttempts` in `Module 03`). |
| **10. Error Handling** | Stack traces, SQL constraint names, or file paths leaked in 500 responses | **High** | Returning `res.status(500).json({ error: err.message, stack: err.stack })` to clients. | `toSafeProblemDetailsResponse` (`Module 04`) exposes only `OperationalAppError` fields and masks all internal/DB exceptions behind an opaque RFC 9457 `500` response correlated by `traceId`. |
| **11. Dependencies & Supply Chain** | Vulnerable or malicious postinstall scripts in npm packages | **High** | Unpinned ranges (`*` or wide `^`), running arbitrary `postinstall` scripts in CI, or skipping lockfile integrity checks. | Enforce `npm ci --ignore-scripts`, exact lockfile verification, automated OSV/`npm audit --audit-level=high`, and cryptographic package provenance checks. |
| **12. Testing & Production Reliability** | Untested concurrency paths, Half-Open circuit stampedes, or dropped requests on deploy | **High** | Allowing 500 concurrent requests in `CircuitBreaker` `HALF_OPEN` state, missing `/readyz` draining before pod termination, or conflating `/healthz` and `/readyz`. | `ProductionLifecycleCoordinator` (`SIGTERM` draining), `halfOpenMaxConcurrentProbes` in `CircuitBreaker`, and Testcontainers + CI Security Harness (`Module 09`). |
| **13. API Gateway & Header Forwarding** | `403` rollout outages, direct `*.run.app`/`*.gateway.dev` bypass, or forged `X-Apigateway-Api-Userinfo` | **Critical** | Using Compute Engine default SA, locking down Cloud Run before gateway config rollout, reading overwritten `Authorization` instead of `X-Apigateway-Api-Userinfo`, or trusting `X-Apigateway-Api-Userinfo` without verifying the gateway OIDC token. | Dedicated gateway SA (`roles/run.invoker`), 5-step zero-downtime lockdown, and `extractVerifiedApiGatewayUserInfo()` (`Module 02 & 14`). |
| **14. MCP Traffic Security & Quotas** | Unauthenticated `tools/list` schema exposure, agent HTTP header injection, or Service Control `HTTP 500` quota outage | **Critical** | Leaving `tools-list.security` empty (`{}`), exposing trust headers (`X-User-Id`, `X-Tenant-Id`) as OpenAPI `in: header` parameters on MCP tools, or renaming/removing a quota metric while older gateways still reference it. | `auditOpenApiGatewayAndMcpSecurity()` (`Module 14`) enforcing single-scheme `tools-list.security`, blocking MCP `in: header` identity parameters, and enforcing Path A additive dual-metric transitions. |
| **15. Business Logic & Ledger Invariants** | Illegal state transitions (`CANCELLED -> SHIPPED`), unbalanced journals, or Maker-Checker self-approval | **Critical** | Ad-hoc `UPDATE status`, single-sided balance mutations, or allowing the initiator (`Maker`) to approve their own high-value refund/payout (`Checker`). | `executeDomainStateTransition`, `validateBalancedDoubleEntryJournal` (`Module 01`), and `evaluateEnterpriseBusinessLogicPolicy` (`Module 14`). |

---

## 2. Database Security: Composite Foreign Keys, Explicit Transaction Boundaries & Frontend Secret Guard

### A. Relational Schema Integrity with Composite Multi-Tenant Foreign Keys
A single-column foreign key (`user_id REFERENCES users(id)`) allows an `orders` row belonging to `tenant_A` to reference a `user_id` belonging to `tenant_B`! Always include `tenant_id` in composite primary/unique keys and composite foreign keys:

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{2,64}$'),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE tenant_members (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL,
    role VARCHAR(24) NOT NULL CHECK (role IN ('owner', 'admin', 'finance', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE orders (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    customer_user_id UUID NOT NULL,
    currency_code CHAR(3) NOT NULL CHECK (currency_code ~ '^[A-Z]{3}$'),
    subtotal_minor BIGINT NOT NULL CHECK (subtotal_minor >= 0),
    discount_minor BIGINT NOT NULL DEFAULT 0 CHECK (discount_minor >= 0 AND discount_minor <= subtotal_minor),
    tax_minor BIGINT NOT NULL DEFAULT 0 CHECK (tax_minor >= 0),
    grand_total_minor BIGINT NOT NULL CHECK (grand_total_minor = subtotal_minor - discount_minor + tax_minor),
    status VARCHAR(24) NOT NULL CHECK (status IN ('PENDING', 'PAID', 'SHIPPED', 'REFUNDED', 'CANCELLED')),
    version INT NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, id),
    -- Composite Foreign Key guarantees customer_user_id belongs to the EXACT SAME tenant_id!
    CONSTRAINT fk_orders_tenant_member
        FOREIGN KEY (tenant_id, customer_user_id)
        REFERENCES tenant_members (tenant_id, user_id)
        ON DELETE RESTRICT
);

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

CREATE POLICY orders_tenant_isolation ON orders
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
```

### B. Connection-Pool-Safe Explicit Tenant Transaction Wrapper (`withTenantTransaction`)
Never execute `SET app.current_tenant_id = '...'` outside a transaction on a pooled connection (PgBouncer / `pg.Pool`), or the setting will bleed into the next request that checks out that connection! Always bind `SET LOCAL` inside an explicit `BEGIN ... COMMIT` block:

```typescript
export interface PooledDbClient {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[]
  ): Promise<{ rows: T[]; rowCount: number }>;
  release: () => void;
}

export interface DbConnectionPool {
  connect(): Promise<PooledDbClient>;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function withTenantTransaction<TResult>(params: {
  pool: DbConnectionPool;
  tenantId: string;
  actorUserId: string;
  isolationLevel?: 'READ COMMITTED' | 'REPEATABLE READ' | 'SERIALIZABLE';
  statementTimeoutMs?: number;
  fn: (client: PooledDbClient) => Promise<TResult>;
}): Promise<TResult> {
  if (!UUID_REGEX.test(params.tenantId)) {
    throw new Error('DB_SECURITY_VIOLATION: tenantId must be a valid UUID');
  }
  const isolation = params.isolationLevel ?? 'READ COMMITTED';
  const timeoutMs = Math.max(500, Math.min(30_000, params.statementTimeoutMs ?? 5_000));

  const client = await params.pool.connect();
  try {
    await client.query(`BEGIN ISOLATION LEVEL ${isolation}`);
    // SET LOCAL is strictly scoped to this transaction and automatically cleared on COMMIT/ROLLBACK!
    await client.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [params.tenantId]);
    await client.query(`SELECT set_config('app.current_user_id', $1, true)`, [params.actorUserId]);
    await client.query(`SELECT set_config('statement_timeout', $1, true)`, [`${timeoutMs}ms`]);

    const result = await params.fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Compile-time allowlist mapper for dynamic ORDER BY clauses (100% immune to SQL injection).
 */
export function resolveSafeOrderByClause<TAllowed extends string>(
  requestedSortColumn: string | undefined,
  requestedDirection: string | undefined,
  allowedColumnMap: Readonly<Record<TAllowed, string>>,
  defaultColumn: TAllowed
): string {
  const safeColKey =
    requestedSortColumn && Object.prototype.hasOwnProperty.call(allowedColumnMap, requestedSortColumn)
      ? (requestedSortColumn as TAllowed)
      : defaultColumn;
  const sqlIdentifier = allowedColumnMap[safeColKey];
  const dir = requestedDirection?.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
  return `${sqlIdentifier} ${dir}`;
}
```

### C. Boot-Time Frontend Bundle Secret Scanner (Blocking `service_role` & Private Keys in Client Env)
Run this guard at server startup and in CI builds to guarantee no privileged secret or `service_role` JWT is ever exposed via `NEXT_PUBLIC_*`, `VITE_*`, or `REACT_APP_*`:

```typescript
const PUBLIC_ENV_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'PUBLIC_'];
const FORBIDDEN_PUBLIC_NAME_PATTERNS = /(SERVICE_ROLE|SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|KMS_KEY|WEBHOOK_SECRET|PASS_PEPPER)/i;
const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  /^sk_(live|test)_[a-zA-Z0-9]+/,       // Stripe secret key
  /^whsec_[a-zA-Z0-9]+/,                // Webhook secret
  /^-----BEGIN [A-Z ]*PRIVATE KEY-----/, // PEM private key
  /^postgres(?:ql)?:\/\//i,             // PostgreSQL connection string
];

export function assertNoSecretsExposedToFrontendEnv(
  env: NodeJS.ProcessEnv = process.env
): { verified: true; checkedCount: number } {
  let checkedCount = 0;

  for (const [key, rawValue] of Object.entries(env)) {
    if (!rawValue) continue;
    const isClientExposed = PUBLIC_ENV_PREFIXES.some((prefix) => key.startsWith(prefix));
    if (!isClientExposed) continue;
    checkedCount++;

    if (FORBIDDEN_PUBLIC_NAME_PATTERNS.test(key)) {
      throw new Error(
        `CRITICAL_SECRET_LEAK_BLOCKED: Server secret variable "${key}" is prefixed for frontend exposure!`
      );
    }

    for (const pattern of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
      if (pattern.test(rawValue.trim())) {
        throw new Error(
          `CRITICAL_SECRET_LEAK_BLOCKED: Public env var "${key}" contains a private key, secret token, or DB URI!`
        );
      }
    }

    // Detect Supabase service_role JWT accidentally placed in NEXT_PUBLIC_SUPABASE_ANON_KEY
    if (rawValue.split('.').length === 3) {
      try {
        const payload = JSON.parse(
          Buffer.from(rawValue.split('.')[1], 'base64url').toString('utf8')
        ) as Record<string, unknown>;
        if (payload.role === 'service_role' || payload.role === 'supabase_admin') {
          throw new Error(
            `CRITICAL_SECRET_LEAK_BLOCKED: Public env var "${key}" contains a Supabase "${String(payload.role)}" JWT!`
          );
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith('CRITICAL_SECRET_LEAK_BLOCKED')) {
          throw err;
        }
      }
    }
  }

  return { verified: true, checkedCount };
}
```

---

## 3. Secrets Management: AAD-Bound AES-256-GCM Envelope Encryption & Key Rotation

Always bind `tenantId`, `resourceId`, and `fieldName` into the AES-256-GCM **Additional Authenticated Data (AAD)**. If an attacker with database access copies an encrypted API key or SSN from Tenant A's row into Tenant B's row, decryption fails cryptographically because the AAD does not match!

```typescript
import crypto from 'node:crypto';

export interface KeyRing {
  activeVersion: string; // e.g., 'v2'
  keysByVersion: Readonly<Record<string, Buffer>>; // 32-byte (256-bit) DEKs per version
}

export interface AadContext {
  tenantId: string;
  resourceType: string;
  resourceId: string;
  fieldName: string;
}

function buildCanonicalAadBuffer(ctx: AadContext): Buffer {
  return Buffer.from(
    `${ctx.tenantId}:${ctx.resourceType}:${ctx.resourceId}:${ctx.fieldName}`,
    'utf8'
  );
}

export function encryptWithTenantAad(
  plaintext: string,
  keyRing: KeyRing,
  aadContext: AadContext
): string {
  const key = keyRing.keysByVersion[keyRing.activeVersion];
  if (!key || key.byteLength !== 32) {
    throw new Error(`ENCRYPTION_ERROR: Missing or invalid 256-bit key for version "${keyRing.activeVersion}"`);
  }

  const iv = crypto.randomBytes(12); // 96-bit nonce for AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(buildCanonicalAadBuffer(aadContext));

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${keyRing.activeVersion}:${iv.toString('base64url')}:${authTag.toString('base64url')}:${encrypted.toString('base64url')}`;
}

export function decryptWithKeyRing(
  serializedCiphertext: string,
  keyRing: KeyRing,
  aadContext: AadContext
): { plaintext: string; needsReEncryption: boolean } {
  const parts = serializedCiphertext.split(':');
  if (parts.length !== 4) {
    throw new Error('DECRYPTION_FAILED: Malformed ciphertext envelope');
  }

  const [version, ivB64, tagB64, dataB64] = parts;
  const key = Object.prototype.hasOwnProperty.call(keyRing.keysByVersion, version)
    ? keyRing.keysByVersion[version]
    : undefined;

  if (!key || key.byteLength !== 32) {
    throw new Error(`DECRYPTION_FAILED: Unknown key version "${version}"`);
  }

  const iv = Buffer.from(ivB64, 'base64url');
  const authTag = Buffer.from(tagB64, 'base64url');
  const ciphertext = Buffer.from(dataB64, 'base64url');

  if (iv.byteLength !== 12 || authTag.byteLength !== 16) {
    throw new Error('DECRYPTION_FAILED: Invalid IV or GCM auth tag length');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAAD(buildCanonicalAadBuffer(aadContext));
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return {
    plaintext: decrypted.toString('utf8'),
    needsReEncryption: version !== keyRing.activeVersion,
  };
}
```

---

## 4. API Security: CORS Allowlist, CSRF Verifier & Request Size/Timeout Boundary

```typescript
import crypto from 'node:crypto';

/**
 * 1. Exact-Match CORS Allowlist Guard:
 * Never reflect arbitrary Origin headers when Access-Control-Allow-Credentials is true!
 */
export function evaluateCorsHeaders(params: {
  requestOrigin: string | undefined;
  allowedOrigins: ReadonlySet<string>;
  allowCredentials: boolean;
}): Record<string, string> {
  if (!params.requestOrigin) {
    return { Vary: 'Origin' };
  }
  if (!params.allowedOrigins.has(params.requestOrigin)) {
    return { Vary: 'Origin' };
  }

  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': params.requestOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Idempotency-Key, X-CSRF-Token, traceparent',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };

  if (params.allowCredentials) {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  return headers;
}

/**
 * 2. CSRF Defense-in-Depth for Cookie-Authenticated State-Mutating Requests:
 * Verifies Fetch Metadata (Sec-Fetch-Site), Exact Origin, and Session-Bound HMAC CSRF Token.
 */
export function verifyCsrfProtection(params: {
  httpMethod: string;
  secFetchSiteHeader?: string;
  originHeader?: string;
  allowedOrigins: ReadonlySet<string>;
  csrfTokenHeader?: string;
  sessionId: string;
  csrfHmacSecret: string;
}): { valid: boolean; reason?: string } {
  const method = params.httpMethod.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return { valid: true };
  }

  // Layer 1: Fetch Metadata header check
  if (params.secFetchSiteHeader && params.secFetchSiteHeader === 'cross-site') {
    return { valid: false, reason: 'CSRF_BLOCKED: Sec-Fetch-Site is cross-site' };
  }

  // Layer 2: Origin header check
  if (!params.originHeader || !params.allowedOrigins.has(params.originHeader)) {
    return { valid: false, reason: 'CSRF_BLOCKED: Missing or disallowed Origin header' };
  }

  // Layer 3: Session-bound cryptographic anti-CSRF token check
  if (!params.csrfTokenHeader) {
    return { valid: false, reason: 'CSRF_BLOCKED: Missing X-CSRF-Token header' };
  }

  const expectedHmac = crypto
    .createHmac('sha256', params.csrfHmacSecret)
    .update(params.sessionId, 'utf8')
    .digest();
  const providedBuf = Buffer.from(params.csrfTokenHeader, 'hex');

  if (
    expectedHmac.byteLength !== providedBuf.byteLength ||
    !crypto.timingSafeEqual(expectedHmac, providedBuf)
  ) {
    return { valid: false, reason: 'CSRF_BLOCKED: Invalid X-CSRF-Token signature' };
  }

  return { valid: true };
}

/**
 * 3. External Request Size Limit, Strict Field Allowlist (Anti-BOPLA) & Timeout Enforcer
 */
export function parseAndValidateJsonBodyStrict<TAllowedKey extends string>(params: {
  rawBodyBuffer: Buffer;
  contentTypeHeader: string | undefined;
  maxBodyBytes: number;
  allowedTopLevelKeys: ReadonlySet<TAllowedKey>;
}): Record<TAllowedKey, unknown> {
  if (!params.contentTypeHeader?.toLowerCase().includes('application/json')) {
    throw new Error('UNSUPPORTED_MEDIA_TYPE: Content-Type must be application/json');
  }
  if (params.rawBodyBuffer.byteLength > params.maxBodyBytes) {
    throw new Error(
      `PAYLOAD_TOO_LARGE: Request body (${params.rawBodyBuffer.byteLength}B) exceeds limit (${params.maxBodyBytes}B)`
    );
  }

  const parsed = JSON.parse(params.rawBodyBuffer.toString('utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('INVALID_PAYLOAD: Root JSON value must be an object');
  }

  const entries = Object.entries(parsed as Record<string, unknown>);
  const result = Object.create(null) as Record<TAllowedKey, unknown>;

  for (const [rawKey, val] of entries) {
    const key = rawKey.normalize('NFKC');
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error('PROTOTYPE_POLLUTION_BLOCKED');
    }
    if (!params.allowedTopLevelKeys.has(key as TAllowedKey)) {
      throw new Error(`MASS_ASSIGNMENT_BLOCKED: Unpermitted field "${key}"`);
    }
    result[key as TAllowedKey] = val;
  }

  return { ...result };
}
```

---

## 5. Production Reliability: `/healthz` vs. `/readyz` Probes & Graceful Shutdown Coordinator

Never conflate **Liveness (`/healthz`)** and **Readiness (`/readyz`)**:
- **`GET /healthz` (Liveness)**: Checks only that the Node.js event loop is responsive and not deadlocked. Never check external databases in `/healthz` (or a transient 3-second DB blip will cause Kubernetes to restart all pods simultaneously!).
- **`GET /readyz` (Readiness)**: Checks whether the pod is ready to receive traffic (`!isShuttingDown` AND PostgreSQL/Redis ping succeeds within `1500ms`). Immediately returns `503 Service Unavailable` when `SIGTERM` is received so the load balancer drains traffic before connections close.

```typescript
export class ProductionLifecycleCoordinator {
  private shuttingDown = false;
  private inFlightRequests = 0;
  private drainResolvers: Array<() => void> = [];

  public isShuttingDown(): boolean {
    return this.shuttingDown;
  }

  public onRequestStart(): boolean {
    if (this.shuttingDown) return false;
    this.inFlightRequests += 1;
    return true;
  }

  public onRequestEnd(): void {
    this.inFlightRequests = Math.max(0, this.inFlightRequests - 1);
    if (this.shuttingDown && this.inFlightRequests === 0) {
      for (const resolve of this.drainResolvers) resolve();
      this.drainResolvers = [];
    }
  }

  public async checkReadiness(deps: {
    pingPostgres: (signal: AbortSignal) => Promise<void>;
    pingRedis: (signal: AbortSignal) => Promise<void>;
  }): Promise<{ status: 200 | 503; body: Record<string, unknown> }> {
    if (this.shuttingDown) {
      return {
        status: 503,
        body: { ready: false, reason: 'POD_DRAINING_FOR_SHUTDOWN', inFlightRequests: this.inFlightRequests },
      };
    }

    try {
      const signal = AbortSignal.timeout(1500);
      await Promise.all([deps.pingPostgres(signal), deps.pingRedis(signal)]);
      return {
        status: 200,
        body: { ready: true, inFlightRequests: this.inFlightRequests },
      };
    } catch (err) {
      return {
        status: 503,
        body: {
          ready: false,
          reason: 'DEPENDENCY_UNAVAILABLE',
          detail: err instanceof Error ? err.message : 'Health check timeout',
        },
      };
    }
  }

  /**
   * Executes a zero-dropped-request graceful shutdown on SIGTERM / SIGINT:
   * 1. Marks readiness false (503 on /readyz) so ALB/Ingress stops routing new requests.
   * 2. Waits for in-flight HTTP requests and active worker leases to finish (up to drainTimeoutMs).
   * 3. Closes DB & Redis connection pools cleanly.
   */
  public async initiateGracefulShutdown(params: {
    drainTimeoutMs?: number;
    stopHttpServer: () => Promise<void>;
    stopQueueWorkers: () => Promise<void>;
    closeDatabasePools: () => Promise<void>;
  }): Promise<void> {
    if (this.shuttingDown) return;
    this.shuttingDown = true;

    const drainTimeoutMs = params.drainTimeoutMs ?? 15_000;
    if (this.inFlightRequests > 0) {
      await Promise.race([
        new Promise<void>((resolve) => this.drainResolvers.push(resolve)),
        new Promise<void>((resolve) => setTimeout(resolve, drainTimeoutMs)),
      ]);
    }

    await params.stopQueueWorkers();
    await params.stopHttpServer();
    await params.closeDatabasePools();
  }
}
```
