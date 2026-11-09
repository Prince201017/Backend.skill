# Module 13: Critical Risk Audit, Tenant Transaction Security & Production Readiness

## 1. Scope & Threat Model

This module remediates **CRITICAL 2.A & DEVIL-01 (Tenant Transaction Security — `withTenantTransaction()`, `tenant_members` Bootstrap Paradox, Role Bypass Verification, and Transaction-Bound Context Signing)** and **HIGH Production Readiness (Secret Scanning & Coordinated Graceful Shutdown)**.

### Trust Boundaries & Failure Modes
1. **Tenant Transaction Security (`withTenantTransaction()`)**:
   - *Vulnerabilities Fixed*:
     1. **UUID validation is not authorization**: Validating `UUID_V4_OR_V7_REGEX.test(tenantId)` only checks string syntax; an attacker can pass any valid tenant UUID they do not belong to.
     2. **Caller-provided tenant IDs are untrusted**: A header (`X-Tenant-Id`), path param, or request body `tenantId` is a *target hint*, never proof of membership.
     3. **Pre-authorization `set_config` injection**: Calling `SELECT set_config('app.current_tenant_id', $1, true)` *before* verifying active membership sets the PostgreSQL RLS session GUC to the victim tenant's ID, allowing subsequent queries in the transaction to read victim rows!
     4. **`tenant_members` Bootstrap Paradox & `BYPASSRLS` / `SUPERUSER` Check (`DEVIL-01`)**:
        - If `tenant_members` has RLS enabled, querying `tenant_members` before setting `app.current_user_id` fails to return the user's membership row. Setting `app.current_user_id` **after** cryptographic server identity verification (while keeping `app.current_tenant_id` unset until membership + permission checks succeed!) cleanly allows `tenant_members` RLS (`user_id = current_setting('app.current_user_id', true)::uuid`) to read only the authenticated user's membership row.
        - If the database connection uses a role with `rolsuper = true` or `rolbypassrls = true`, PostgreSQL silently bypasses all RLS policies. `verifyDatabaseRoleRlsEnforcement()` verifies at startup that the runtime role cannot bypass RLS.
        - Additionally, `withTenantTransaction()` binds a transaction-local HMAC (`app.current_tenant_mac`) when `gucHmacSecret` is configured, preventing mid-transaction `set_config('app.current_tenant_id', ...)` tampering if an application query suffers from SQL injection.

---

## 2. Remediated `withTenantTransaction()` Implementation (CRITICAL 2.A + DEVIL-01)

```typescript
// Executable TypeScript — Verified Server-Side Identity + Role RLS Verification + Post-Authorization RLS Context
import { createHmac, timingSafeEqual } from 'node:crypto';

export type TenantStatus = 'ACTIVE' | 'SUSPENDED' | 'DISABLED';
export type MembershipStatus = 'ACTIVE' | 'SUSPENDED' | 'DISABLED' | 'REVOKED';
export type TenantRole = 'OWNER' | 'ADMIN' | 'BILLING_ADMIN' | 'MEMBER' | 'READ_ONLY';
export type TenantPermission =
  | 'project:read'
  | 'project:write'
  | 'invoice:read'
  | 'invoice:pay'
  | 'ledger:write'
  | 'member:manage';

const ROLE_PERMISSION_MATRIX: Readonly<Record<TenantRole, readonly TenantPermission[]>> = {
  OWNER: ['project:read', 'project:write', 'invoice:read', 'invoice:pay', 'ledger:write', 'member:manage'],
  ADMIN: ['project:read', 'project:write', 'invoice:read', 'ledger:write', 'member:manage'],
  BILLING_ADMIN: ['project:read', 'invoice:read', 'invoice:pay', 'ledger:write'],
  MEMBER: ['project:read', 'project:write'],
  READ_ONLY: ['project:read'],
};

export interface VerifiedServerIdentity {
  readonly userId: string;
  readonly sessionId: string;
  readonly issuedAtSec: number;
  readonly expiresAtSec: number;
}

export interface VerifyServerIdentityOptions {
  readonly nowSec?: number;
  readonly maxClockSkewSec?: number;
  readonly maxAssertionLifetimeSec?: number;
  readonly isSessionRevoked?: (sessionId: string, userId: string) => boolean;
}

/**
 * Verifies an HMAC-SHA256 signed server session assertion (`DEVIL-19` Hardened).
 * Enforces signing secret strength (>= 32 chars), constant-time HMAC verification,
 * non-empty `userId` and `sessionId`, `issuedAtSec` clock-skew bounds, `expiresAtSec` expiry,
 * maximum assertion lifetime (`maxAssertionLifetimeSec`, default 3600s), and session revocation checks.
 */
export function verifyServerIdentityAssertion(
  assertionToken: string | undefined | null,
  signingSecret: string,
  nowSecOrOptions: number | VerifyServerIdentityOptions = Math.floor(Date.now() / 1000)
): VerifiedServerIdentity {
  if (!signingSecret || typeof signingSecret !== 'string' || signingSecret.trim().length < 32) {
    throw new Error('AUTH_SIGNING_SECRET_WEAK_OR_MISSING: signingSecret must be at least 32 characters');
  }
  const opts: VerifyServerIdentityOptions =
    typeof nowSecOrOptions === 'number' ? { nowSec: nowSecOrOptions } : nowSecOrOptions;
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const maxClockSkewSec = opts.maxClockSkewSec ?? 60;
  const maxAssertionLifetimeSec = opts.maxAssertionLifetimeSec ?? 3600;

  if (!assertionToken || typeof assertionToken !== 'string') {
    throw new Error('AUTH_IDENTITY_MISSING');
  }
  const parts = assertionToken.split('.');
  if (parts.length !== 2) {
    throw new Error('AUTH_IDENTITY_MALFORMED');
  }
  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) {
    throw new Error('AUTH_IDENTITY_MALFORMED');
  }
  const expectedSig = createHmac('sha256', signingSecret).update(payloadB64, 'utf8').digest();
  let providedSig: Buffer;
  try {
    providedSig = Buffer.from(sigB64, 'base64url');
  } catch {
    throw new Error('AUTH_IDENTITY_SIGNATURE_INVALID');
  }
  if (
    providedSig.length !== expectedSig.length ||
    !timingSafeEqual(providedSig, expectedSig)
  ) {
    throw new Error('AUTH_IDENTITY_SIGNATURE_MISMATCH');
  }

  let parsed: VerifiedServerIdentity;
  try {
    parsed = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as VerifiedServerIdentity;
  } catch {
    throw new Error('AUTH_IDENTITY_PAYLOAD_INVALID');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('AUTH_IDENTITY_PAYLOAD_INVALID');
  }
  if (!parsed.userId || typeof parsed.userId !== 'string' || parsed.userId.trim().length === 0) {
    throw new Error('AUTH_IDENTITY_USER_MISSING');
  }
  if (!parsed.sessionId || typeof parsed.sessionId !== 'string' || parsed.sessionId.trim().length === 0) {
    throw new Error('AUTH_IDENTITY_SESSION_MISSING');
  }
  if (
    typeof parsed.issuedAtSec !== 'number' ||
    !Number.isFinite(parsed.issuedAtSec) ||
    parsed.issuedAtSec > nowSec + maxClockSkewSec
  ) {
    throw new Error('AUTH_IDENTITY_ISSUED_IN_FUTURE_OR_INVALID');
  }
  if (
    typeof parsed.expiresAtSec !== 'number' ||
    !Number.isFinite(parsed.expiresAtSec) ||
    parsed.expiresAtSec <= nowSec - maxClockSkewSec
  ) {
    throw new Error('AUTH_IDENTITY_EXPIRED');
  }
  if (parsed.expiresAtSec < parsed.issuedAtSec) {
    throw new Error('AUTH_IDENTITY_INVALID_TIME_RANGE');
  }
  if (parsed.expiresAtSec - parsed.issuedAtSec > maxAssertionLifetimeSec) {
    throw new Error('AUTH_IDENTITY_LIFETIME_EXCEEDED');
  }
  if (opts.isSessionRevoked && opts.isSessionRevoked(parsed.sessionId, parsed.userId)) {
    throw new Error('AUTH_IDENTITY_SESSION_REVOKED');
  }
  return parsed;
}

export interface PooledDbClient {
  query<R = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<{ rows: R[]; rowCount: number }>;
  release(): void;
}

export interface DbConnectionPool {
  connect(): Promise<PooledDbClient>;
}

export interface AuthorizedTenantTxContext {
  readonly userId: string;
  readonly sessionId: string;
  readonly tenantId: string;
  readonly role: TenantRole;
  readonly permissions: readonly TenantPermission[];
}

const UUID_SYNTAX_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Startup & Pool Guard (DEVIL-01):
 * Verifies that the PostgreSQL connection role is NOT a superuser and does NOT have BYPASSRLS.
 * If either flag is true, PostgreSQL ignores all RLS policies even with FORCE ROW LEVEL SECURITY!
 */
export async function verifyDatabaseRoleRlsEnforcement(client: PooledDbClient): Promise<void> {
  const res = await client.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean }>(
    `SELECT rolname, rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname IN (current_user, session_user)`
  );
  if (!res.rows || res.rows.length === 0) {
    throw new Error('DB_ROLE_VERIFICATION_FAILED: Could not inspect current_user/session_user in pg_roles');
  }
  for (const role of res.rows) {
    if (role.rolsuper || role.rolbypassrls) {
      throw new Error(
        `DB_RLS_BYPASS_HAZARD: Runtime or session role "${role.rolname}" has rolsuper=${String(role.rolsuper)} or rolbypassrls=${String(role.rolbypassrls)}; RLS policies would be silently bypassed!`
      );
    }
  }
}

/**
 * Remediated withTenantTransaction() (`DEVIL-01`, `DEVIL-02`, `DEVIL-19` Hardened):
 * 1. Enforces mandatory `gucHmacSecret` (>= 32 chars) and verifies server-side identity assertion lifecycle.
 * 2. Validates UUID syntax only as an input hygiene filter (never as authorization).
 * 3. Starts transaction (`BEGIN`), obtains `txid_current()::text`, clears any stale `app.current_tenant_id` / `app.current_tenant_mac`,
 *    and sets ONLY `app.current_user_id` + `app.current_user_mac` (`HMAC(gucHmacSecret, "user:" + userId + ":" + txid)`).
 * 4. Queries authoritative membership (`FOR SHARE OF t, tm`) while `app.current_tenant_id` remains unset (`''`).
 * 5. Verifies active tenant status, active membership status, and required permission.
 * 6. Populates `app.current_tenant_id` and `app.current_tenant_mac` (`HMAC(gucHmacSecret, tenantId + ":" + txid)`) ONLY AFTER authorization.
 * 7. Runs all queries on `txClient` and guarantees `COMMIT`/`ROLLBACK` cleanup before pool release.
 */
export async function withTenantTransaction<T>(params: {
  pool: DbConnectionPool;
  identityAssertionToken: string | undefined | null;
  identitySigningSecret: string;
  requestedTenantId: string;
  requiredPermission: TenantPermission;
  gucHmacSecret: string;
  nowSec?: number;
  maxAssertionLifetimeSec?: number;
  isSessionRevoked?: (sessionId: string, userId: string) => boolean;
  work: (txClient: PooledDbClient, authContext: AuthorizedTenantTxContext) => Promise<T>;
}): Promise<T> {
  if (!params.gucHmacSecret || typeof params.gucHmacSecret !== 'string' || params.gucHmacSecret.trim().length < 32) {
    throw new Error('GUC_HMAC_SECRET_MISSING_OR_WEAK: gucHmacSecret (>= 32 chars) is mandatory for tenant transactions');
  }

  // Step 1: Authenticate user from verified server-side identity assertion
  const verifiedIdentity = verifyServerIdentityAssertion(
    params.identityAssertionToken,
    params.identitySigningSecret,
    {
      nowSec: params.nowSec,
      maxAssertionLifetimeSec: params.maxAssertionLifetimeSec,
      isSessionRevoked: params.isSessionRevoked,
    }
  );

  // Step 2: Input format check (hygiene only — does NOT establish authorization)
  if (!UUID_SYNTAX_REGEX.test(params.requestedTenantId)) {
    throw new Error('TENANT_ID_SYNTAX_INVALID');
  }

  const client = await params.pool.connect();
  try {
    await client.query('BEGIN');

    // Step 3a (DEVIL-01 & DEVIL-02): Bind context MACs to PostgreSQL's current transaction ID (txid_current()::text)
    const txidRes = await client.query<{ txid: string }>(`SELECT txid_current()::text AS txid`);
    const currentTxId = txidRes.rows[0]?.txid ?? '0';
    const userGucMac = createHmac('sha256', params.gucHmacSecret)
      .update(`user:${verifiedIdentity.userId}:${currentTxId}`, 'utf8')
      .digest('hex');

    // Clear any stale tenant context and set ONLY the verified user_id + user_mac so that
    // tenant_members FORCE ROW LEVEL SECURITY (security.verify_active_user_context(user_id))
    // permits reading this user's membership row BEFORE app.current_tenant_id is populated!
    await client.query(`SELECT set_config('app.current_tenant_id', '', true)`);
    await client.query(`SELECT set_config('app.current_tenant_mac', '', true)`);
    await client.query(`SELECT set_config('app.current_user_id', $1, true)`, [
      verifiedIdentity.userId,
    ]);
    await client.query(`SELECT set_config('app.current_user_mac', $1, true)`, [userGucMac]);

    // Step 3b: Query authoritative tenant + membership status inside the transaction (FOR SHARE lock)
    // CRITICAL: app.current_tenant_id is still empty ('') here!
    const membershipRes = await client.query<{
      tenant_id: string;
      tenant_status: TenantStatus;
      member_status: MembershipStatus;
      role: TenantRole;
    }>(
      `SELECT t.id AS tenant_id,
              t.status AS tenant_status,
              tm.status AS member_status,
              tm.role AS role
         FROM public.tenants t
         INNER JOIN public.tenant_members tm
           ON tm.tenant_id = t.id
        WHERE t.id = $1::uuid
          AND tm.user_id = $2::uuid
        FOR SHARE OF t, tm`,
      [params.requestedTenantId, verifiedIdentity.userId]
    );

    if (membershipRes.rowCount === 0 || !membershipRes.rows[0]) {
      throw new Error('TENANT_MEMBERSHIP_NOT_FOUND_OR_UNAUTHORIZED');
    }

    const row = membershipRes.rows[0];
    if (row.tenant_status !== 'ACTIVE') {
      throw new Error(`TENANT_NOT_ACTIVE:${row.tenant_status}`);
    }
    if (row.member_status !== 'ACTIVE') {
      throw new Error(`TENANT_MEMBERSHIP_NOT_ACTIVE:${row.member_status}`);
    }

    const grantedPermissions = ROLE_PERMISSION_MATRIX[row.role] ?? [];
    if (!grantedPermissions.includes(params.requiredPermission)) {
      throw new Error(
        `TENANT_PERMISSION_DENIED:role=${row.role}:required=${params.requiredPermission}`
      );
    }

    // Step 4: Establish transaction-local RLS tenant context + cryptographic MAC ONLY AFTER authorization succeeds
    const tenantGucMac = createHmac('sha256', params.gucHmacSecret)
      .update(`${row.tenant_id}:${currentTxId}`, 'utf8')
      .digest('hex');
    await client.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [
      row.tenant_id,
    ]);
    await client.query(`SELECT set_config('app.current_tenant_mac', $1, true)`, [tenantGucMac]);

    const authContext: AuthorizedTenantTxContext = {
      userId: verifiedIdentity.userId,
      sessionId: verifiedIdentity.sessionId,
      tenantId: row.tenant_id,
      role: row.role,
      permissions: grantedPermissions,
    };

    // Step 5: Execute all tenant database operations inside this authorized transaction
    const result = await params.work(client, authContext);

    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Preserve primary error
    }
    throw err;
  } finally {
    client.release();
  }
}
```

### Connection-Pool & Transaction-Context Behavior (PgBouncer / `node-postgres`)
- Because `set_config(setting_name, new_value, true)` sets `is_local = true`, PostgreSQL automatically resets `app.current_tenant_id` and `app.current_user_id` at the instant `COMMIT` or `ROLLBACK` completes.
- When using PgBouncer in `transaction` pooling mode, every call to `withTenantTransaction()` checks out a server connection for the entire `BEGIN ... COMMIT/ROLLBACK` block, preventing transaction multiplexing or GUC leakage between concurrent requests.
- **Defense-in-Depth RLS Policy**: PostgreSQL RLS policies must use `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid` so that if any query is accidentally executed outside `withTenantTransaction()`, `current_setting(..., true)` returns `''` -> `NULL`, and `tenant_id = NULL` evaluates to `FALSE` (fail-closed, zero rows returned).

---

## 3. High-Precision Release Artifact, Bundle & Environment Secret Scanner

```typescript
// Executable TypeScript — Unanchored Secret Scanner for Env Vars, Client Bundles & Source Maps
export interface SecretLeakFinding {
  sourceType: 'CLIENT_ENV_VAR' | 'FRONTEND_BUNDLE' | 'SOURCE_MAP';
  location: string;
  ruleId: string;
  description: string;
}

const UNANCHORED_SECRET_PATTERNS: ReadonlyArray<{
  ruleId: string;
  description: string;
  regex: RegExp;
}> = [
  {
    ruleId: 'STRIPE_LIVE_OR_TEST_SECRET',
    description: 'Stripe secret or restricted API key (sk_live_, sk_test_, rk_live_)',
    regex: /(?:sk_live_|sk_test_|rk_live_|whsec_)[0-9a-zA-Z]{10,}/,
  },
  {
    ruleId: 'PEM_PRIVATE_KEY',
    description: 'Embedded PEM private key block',
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  },
  {
    ruleId: 'AWS_ACCESS_KEY_ID',
    description: 'AWS IAM Access Key ID (AKIA / ASIA)',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    ruleId: 'DATABASE_CONNECTION_URI',
    description: 'Embedded PostgreSQL / Redis / MongoDB / AMQP / MySQL connection URI with credentials',
    regex: /\b(?:postgres(?:ql)?|redis(?:s)?|mongodb(?:\+srv)?|amqp(?:s)?|mysql):\/\/[^:\s"']+:[^@\s"']+@[^\s"']+/,
  },
  {
    ruleId: 'SUPABASE_SERVICE_ROLE_JWT',
    description: 'Supabase service_role JWT or secret key marker',
    regex: /"role"\s*:\s*"service_role"|SUPABASE_SERVICE_ROLE_KEY/,
  },
  {
    ruleId: 'GITHUB_OR_SLACK_TOKEN',
    description: 'GitHub PAT (ghp_, github_pat_) or Slack token (xoxb-, xoxp-)',
    regex: /\b(?:ghp_[0-9a-zA-Z]{20,}|github_pat_[0-9a-zA-Z_]{20,}|xox[bp]-[0-9a-zA-Z-]{15,})\b/,
  },
  {
    ruleId: 'GOOGLE_OR_AI_PROVIDER_API_KEY',
    description: 'Google Cloud / Firebase API key (AIza...) or OpenAI/Anthropic secret key (sk-proj-, sk-ant-)',
    regex: /\b(?:AIza[0-9A-Za-z_-]{35,}|sk-(?:proj|ant)-[0-9a-zA-Z_-]{20,})\b/,
  },
  {
    ruleId: 'EMBEDDED_BEARER_JWT',
    description: 'Hardcoded 3-part JWS/JWT bearer token (eyJ...)',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
];

const FORBIDDEN_CLIENT_ENV_NAME_REGEX =
  /(?:SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL|REDIS_URL|INTERNAL_KEY|SIGNING_KEY|WEBHOOK_SECRET|PASSWORD|API_KEY)/i;

export function scanReleaseArtifactsAndEnvForSecrets(params: {
  envVars: Readonly<Record<string, string | undefined>>;
  clientEnvPrefixes?: readonly string[];
  frontendArtifacts: ReadonlyArray<{
    filePath: string;
    isSourceMap?: boolean;
    content: string;
  }>;
}): SecretLeakFinding[] {
  const findings: SecretLeakFinding[] = [];
  const prefixes = params.clientEnvPrefixes ?? ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'PUBLIC_'];

  for (const [envName, envValue] of Object.entries(params.envVars)) {
    const isClientExposed = prefixes.some((prefix) => envName.startsWith(prefix));
    if (!isClientExposed) continue;

    if (FORBIDDEN_CLIENT_ENV_NAME_REGEX.test(envName)) {
      findings.push({
        sourceType: 'CLIENT_ENV_VAR',
        location: envName,
        ruleId: 'FORBIDDEN_CLIENT_ENV_NAME',
        description: `Client-exposed env variable "${envName}" contains a privileged secret keyword`,
      });
    }

    if (typeof envValue === 'string' && envValue.length > 0) {
      for (const detector of UNANCHORED_SECRET_PATTERNS) {
        if (detector.regex.test(envValue)) {
          findings.push({
            sourceType: 'CLIENT_ENV_VAR',
            location: envName,
            ruleId: detector.ruleId,
            description: detector.description,
          });
        }
      }
    }
  }

  for (const artifact of params.frontendArtifacts) {
    const isMap = Boolean(artifact.isSourceMap || artifact.filePath.endsWith('.map'));
    for (const detector of UNANCHORED_SECRET_PATTERNS) {
      if (detector.regex.test(artifact.content)) {
        findings.push({
          sourceType: isMap ? 'SOURCE_MAP' : 'FRONTEND_BUNDLE',
          location: artifact.filePath,
          ruleId: detector.ruleId,
          description: detector.description,
        });
      }
    }
  }

  return findings;
}
```

---

## 4. Coordinated Graceful Shutdown Lifecycle (`ProductionLifecycleCoordinator`)

> **Important Operational Reality**: Graceful shutdown reduces dropped requests during rolling deployments, but **cannot guarantee unconditional zero dropped requests** if in-flight requests or stuck transactions exceed the orchestrator's `terminationGracePeriodSeconds` (after which Kubernetes sends `SIGKILL`).

```typescript
// Executable TypeScript — 9-Step Coordinated Graceful Shutdown Manager
export interface ShutdownSubsystemHooks {
  markReadinessUnhealthy(): Promise<void> | void;
  stopAcceptingNewHttpRequestsAndDrain(timeoutMs: number): Promise<{ drainedCleanly: boolean; remainingConnections: number }>;
  closeActiveWebSocketsGoingAway(): Promise<number>; // Sends WS 1001 Going Away
  closeActiveSseStreams(): Promise<number>;
  pauseQueueWorkerAcquisition(): Promise<void>;
  drainOrCancelInFlightWorkersAndTasks(timeoutMs: number): Promise<{ completedCount: number; forceAbortedCount: number }>;
  flushTelemetryAndLogs(): Promise<void>;
  closeDatabaseAndCachePools(): Promise<void>;
}

export interface GracefulShutdownReport {
  readonly completedWithinGraceBudget: boolean;
  readonly stepsExecuted: string[];
  readonly remainingHttpConnections: number;
  readonly webSocketsClosed: number;
  readonly sseStreamsClosed: number;
  readonly workersForceAborted: number;
}

export async function executeCoordinatedGracefulShutdown(
  hooks: ShutdownSubsystemHooks,
  totalGraceBudgetMs = 25_000
): Promise<GracefulShutdownReport> {
  const stepsExecuted: string[] = [];
  const halfBudgetMs = Math.max(1_000, Math.floor(totalGraceBudgetMs * 0.45));

  // 1. Flip /health/ready to 503 so load balancers stop routing new traffic
  await hooks.markReadinessUnhealthy();
  stepsExecuted.push('READINESS_MARKED_UNHEALTHY');

  // 2. Pause background queue worker polling immediately so no new jobs start
  await hooks.pauseQueueWorkerAcquisition();
  stepsExecuted.push('QUEUE_WORKER_ACQUISITION_PAUSED');

  // 3. Notify WebSocket clients with 1001 Going Away and close SSE streams
  const [webSocketsClosed, sseStreamsClosed] = await Promise.all([
    hooks.closeActiveWebSocketsGoingAway(),
    hooks.closeActiveSseStreams(),
  ]);
  stepsExecuted.push('WEBSOCKETS_AND_SSE_CLOSED');

  // 4. Drain in-flight HTTP requests and active queue workers in parallel within budget
  const [httpDrain, workerDrain] = await Promise.all([
    hooks.stopAcceptingNewHttpRequestsAndDrain(halfBudgetMs),
    hooks.drainOrCancelInFlightWorkersAndTasks(halfBudgetMs),
  ]);
  stepsExecuted.push('HTTP_AND_WORKERS_DRAINED_OR_CANCELLED');

  // 5. Flush buffered OpenTelemetry spans and structured logs before closing pools
  await hooks.flushTelemetryAndLogs();
  stepsExecuted.push('TELEMETRY_FLUSHED');

  // 6. Close PostgreSQL and Redis connection pools last (after all workers & HTTP handlers finish)
  await hooks.closeDatabaseAndCachePools();
  stepsExecuted.push('DB_AND_CACHE_POOLS_CLOSED');

  const completedWithinGraceBudget =
    httpDrain.drainedCleanly && workerDrain.forceAbortedCount === 0;

  return {
    completedWithinGraceBudget,
    stepsExecuted,
    remainingHttpConnections: httpDrain.remainingConnections,
    webSocketsClosed,
    sseStreamsClosed,
    workersForceAborted: workerDrain.forceAbortedCount,
  };
}
```
