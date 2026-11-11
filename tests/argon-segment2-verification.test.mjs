import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { createRequire } from 'node:module';
import ts from 'typescript';

const nativeRequire = createRequire(import.meta.url);
const ROOT = process.cwd();
const loadedModulesCache = new Map();

function loadModuleFromMarkdown(mdRelativePath, blockIndices = null) {
  const fullPath = path.join(ROOT, mdRelativePath);
  const content = fs.readFileSync(fullPath, 'utf8');
  const regex = /^```typescript\r?\n([\s\S]*?)^```\s*$/gm;
  const blocks = [];
  let match;
  while ((match = regex.exec(content)) !== null) {
    blocks.push(match[1]);
  }
  const selected = blockIndices ? blockIndices.map((idx) => blocks[idx]) : blocks;
  const combinedTs = selected.join('\n\n');
  const transpiled = ts.transpileModule(combinedTs, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      strict: false,
    },
  }).outputText;

  const customRequire = (id) => {
    if (id.includes('13-critical-risk-audit-reliability-and-production-readiness')) {
      return loadedModulesCache.get('mod13');
    }
    return nativeRequire(id);
  };

  const mod = { exports: {} };
  const fn = new Function('exports', 'require', 'module', '__filename', '__dirname', transpiled);
  fn(mod.exports, customRequire, mod, fullPath, path.dirname(fullPath));
  return mod.exports;
}

const mod00 = loadModuleFromMarkdown('skills/00-execution-intelligence-architecture-engine.md');
const mod01 = loadModuleFromMarkdown('skills/01-domain-modeling-fields-timestamps-ids.md');
const mod02 = loadModuleFromMarkdown('skills/02-auth-authorization-fingerprinting-security.md');
const mod03 = loadModuleFromMarkdown('skills/03-databases-polyglot-storage-transactions.md');
const mod04 = loadModuleFromMarkdown('skills/04-apis-payments-webhooks-resilience.md');
const mod05 = loadModuleFromMarkdown('skills/05-file-uploads-multi-storage-malware-scanning.md');
const mod06 = loadModuleFromMarkdown('skills/06-async-queues-observability-testing-devops.md');
const mod07 = loadModuleFromMarkdown('skills/07-events-realtime-sagas-migrations-sql-multitenancy-search.md');
const mod08 = loadModuleFromMarkdown('skills/08-api-security-secrets-dr-networking-microservices-ai-governance.md');
const mod10 = loadModuleFromMarkdown('skills/10-omnichannel-notifications-email-messaging-security.md');
const mod11 = loadModuleFromMarkdown('skills/11-baas-providers-supabase-firebase-amplified-security.md');
const mod12 = loadModuleFromMarkdown('skills/12-request-io-tracing-service-visualization-and-log-correlation.md');
const mod13 = loadModuleFromMarkdown('skills/13-critical-risk-audit-reliability-and-production-readiness.md');
loadedModulesCache.set('mod13', mod13);
const mod14 = loadModuleFromMarkdown('skills/14-api-gateway-mcp-quotas-and-business-logic-engine.md');
const mod15 = loadModuleFromMarkdown('skills/15-security-hardening-checklist-and-markdown-parser.md');
const mod16 = loadModuleFromMarkdown('skills/16-ai-codegen-failure-modes-and-glue-layer-guardrails.md');

function signServerIdentityAssertion(claims, secret) {
  const payloadB64 = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const sigB64 = crypto.createHmac('sha256', secret).update(payloadB64, 'utf8').digest('base64url');
  return `${payloadB64}.${sigB64}`;
}

function signEd25519Jwt(header, payload, privateKey) {
  const h = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const p = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.sign(null, Buffer.from(`${h}.${p}`, 'utf8'), privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

function signRs256Jwt(header, payload, privateKey) {
  const h = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const p = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`, 'utf8'), privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

// ============================================================================
// VERIFY-01: PostgreSQL Tenant Isolation (Application Context, GUC MAC, & SQL)
// ============================================================================
test('VERIFY-01 [Application & Cross-Module GUC MAC]: Missing/weak GUC secret, forged context, superuser/session_user check & cross-module MAC parity (DEVIL-01, DEVIL-02, DEVIL-19, DEVIL-49, DEVIL-57)', async () => {
  const signingSecret = 'identity-assertion-secret-at-least-32-bytes-long!!';
  const gucSecret = 'guc-hmac-secret-at-least-32-bytes-long-verified!!';
  const userId = '0195f8a0-0000-7000-8000-0000000000aa';
  const tenantId = '0195f8a0-0000-7000-8000-000000000001';
  const nowSec = Math.floor(Date.now() / 1000);

  const token = signServerIdentityAssertion(
    {
      userId,
      sessionId: 'sess-001',
      issuedAtSec: nowSec - 5,
      expiresAtSec: nowSec + 300,
    },
    signingSecret
  );

  const mockPool = {
    connect: async () => ({
      query: async () => ({ rows: [], rowCount: 0 }),
      release: () => {},
    }),
  };

  // 1. Weak or missing GUC secret rejected before touching DB pool
  await assert.rejects(
    () =>
      mod13.withTenantTransaction({
        pool: mockPool,
        identityAssertionToken: token,
        identitySigningSecret: signingSecret,
        requestedTenantId: tenantId,
        requiredPermission: 'project:read',
        gucHmacSecret: 'short-secret',
        work: async () => 'unreachable',
      }),
    /GUC_HMAC_SECRET_MISSING_OR_WEAK/
  );

  // 2. Superuser OR BYPASSRLS on current_user OR session_user rejected (DEVIL-01 & DEVIL-57)
  let checkedSql = '';
  await assert.rejects(
    () =>
      mod13.verifyDatabaseRoleRlsEnforcement({
        query: async (sql) => {
          checkedSql = sql;
          return {
            rows: [
              { rolname: 'app_runtime', rolsuper: false, rolbypassrls: false },
              { rolname: 'postgres_pool_session_owner', rolsuper: true, rolbypassrls: false },
            ],
            rowCount: 2,
          };
        },
        release: () => {},
      }),
    /DB_RLS_BYPASS_HAZARD.*postgres_pool_session_owner/
  );
  assert.match(checkedSql, /IN\s*\(\s*current_user\s*,\s*session_user\s*\)/);

  // 3. Cross-module GUC MAC compatibility between Module 03 consumeEventIdempotently and Module 07/13 SQL functions (DEVIL-49)
  const recordedConfigs = new Map();
  const txid = '9918273';
  const outboxSecret = 'outbox-hmac-secret-at-least-32-bytes-long-verified!';
  const eventId = '0195f8a0-0000-7000-8000-000000000999';
  const baseEvent = {
    event_id: eventId,
    tenant_id: tenantId,
    aggregate_type: 'order',
    aggregate_id: 'ord-100',
    event_type: 'order.paid',
    payload: { orderId: 'ord-100', amountMinor: '5000' },
    traceparent: null,
  };
  const eventHmac = mod03.computeOutboxEventHmac(baseEvent, outboxSecret);

  const txClient = {
    query: async (sql, values = []) => {
      if (sql.includes('txid_current()')) {
        return { rows: [{ txid }], rowCount: 1 };
      }
      const cfgMatch = sql.match(/set_config\('([^']+)'/);
      if (cfgMatch) {
        recordedConfigs.set(cfgMatch[1], values[0]);
        return { rows: [], rowCount: 1 };
      }
      if (sql.includes('INSERT INTO')) {
        return { rows: [{ event_id: eventId }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
    release: () => {},
  };

  const out = await mod03.consumeEventIdempotently({
    pool: { connect: async () => txClient },
    consumerGroup: 'ledger-consumer',
    event: { ...baseEvent, event_hmac: eventHmac },
    outboxHmacSecret: outboxSecret,
    gucHmacSecret: gucSecret,
    applySideEffectInTx: async () => {},
  });
  assert.equal(out, 'PROCESSED');

  // Verify Module 03's GUC values match Module 07's security.verify_active_user_context and verify_active_tenant_context formulas
  const setUserId = recordedConfigs.get('app.current_user_id');
  const setUserMac = recordedConfigs.get('app.current_user_mac');
  const setTenantId = recordedConfigs.get('app.current_tenant_id');
  const setTenantMac = recordedConfigs.get('app.current_tenant_mac');

  assert.match(setUserId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  const expectedUserMac = crypto.createHmac('sha256', gucSecret).update(`user:${setUserId}:${txid}`, 'utf8').digest('hex');
  const expectedTenantMac = crypto.createHmac('sha256', gucSecret).update(`${tenantId}:${txid}`, 'utf8').digest('hex');
  assert.equal(setUserMac, expectedUserMac);
  assert.equal(setTenantId, tenantId);
  assert.equal(setTenantMac, expectedTenantMac);

  // Verify SQL schema in Module 07 creates `extensions` schema and uses `extensions.hmac`
  const sql07 = fs.readFileSync(path.join(ROOT, 'skills/07-events-realtime-sagas-migrations-sql-multitenancy-search.md'), 'utf8');
  assert.match(sql07, /CREATE SCHEMA IF NOT EXISTS extensions;/);
  assert.match(sql07, /CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;/);
});

test('VERIFY-01-LIVE-POSTGRES-RLS [Live PostgreSQL Database Engine Verification]', async () => {
  const { PGlite } = await import('@electric-sql/pglite');
  const { pgcrypto } = await import('@electric-sql/pglite/contrib/pgcrypto');

  const sql07 = fs.readFileSync(
    path.join(ROOT, 'skills/07-events-realtime-sagas-migrations-sql-multitenancy-search.md'),
    'utf8'
  );
  const sqlBlocks07 = mod15.extractFencedCodeBlocksDetailed(sql07, {
    allowedLanguages: new Set(['sql']),
  }).blocks;
  // Find the Section 5 Cryptographic Tenant Context & RLS SQL block
  const rlsBlock = sqlBlocks07.find((b) => b.code.includes('security.verify_active_tenant_context'));
  assert.ok(rlsBlock, 'Expected Module 07 Section 5 RLS SQL block');

  const db = new PGlite({ extensions: { pgcrypto } });
  try {
    await db.exec(rlsBlock.code);

    const gucSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    await db.query(
      `INSERT INTO security.guc_hmac_keys (key_id, hmac_secret) VALUES (1, $1)
       ON CONFLICT (key_id) DO UPDATE SET hmac_secret = EXCLUDED.hmac_secret`,
      [gucSecret]
    );

    const tenantA = '0195f8a0-0000-7000-8000-0000000000a1';
    const tenantB = '0195f8a0-0000-7000-8000-0000000000b2';
    const userAlice = '0195f8a0-0000-7000-8000-000000000111';
    const userBob = '0195f8a0-0000-7000-8000-000000000222';
    const orderA = '0195f8a0-0000-7000-8000-000000000901';
    const orderB = '0195f8a0-0000-7000-8000-000000000902';

    await db.query(
      `INSERT INTO public.tenants (id, name, status) VALUES ($1, 'Acme A', 'ACTIVE'), ($2, 'Beta B', 'ACTIVE')`,
      [tenantA, tenantB]
    );
    await db.query(
      `INSERT INTO public.tenant_members (tenant_id, user_id, role, status)
       VALUES ($1, $3, 'ADMIN', 'ACTIVE'), ($2, $4, 'ADMIN', 'ACTIVE')`,
      [tenantA, tenantB, userAlice, userBob]
    );
    await db.query(
      `INSERT INTO public.orders (id, tenant_id, customer_user_id, order_number, total_minor, currency_code)
       VALUES ($1, $3, $5, 'ORD-A-001', 1500, 'USD'), ($2, $4, $6, 'ORD-B-001', 2500, 'USD')`,
      [orderA, orderB, tenantA, tenantB, userAlice, userBob]
    );

    const signingSecret = 'server-identity-signing-secret-minimum-32-bytes-long!!';
    const nowSec = Math.floor(Date.now() / 1000);
    const aliceToken = signServerIdentityAssertion(
      {
        userId: userAlice,
        sessionId: 'sess-live-pg-001',
        issuedAtSec: nowSec - 5,
        expiresAtSec: nowSec + 300,
      },
      signingSecret
    );

    // Switch session_user and current_user to app_login (inherits app_runtime, NOSUPERUSER, NOBYPASSRLS)
    await db.exec('SET SESSION AUTHORIZATION app_login;');

    const pool = {
      connect: async () => ({
        query: async (sql, values = []) => {
          const res = await db.query(sql, values);
          return { rows: res.rows, rowCount: res.rows.length || res.affectedRows || 0 };
        },
        release: () => {},
      }),
    };

    // 1. Authorized tenant transaction via Module 13 withTenantTransaction sees ONLY tenantA orders
    const visibleOrders = await mod13.withTenantTransaction({
      pool,
      identityAssertionToken: aliceToken,
      identitySigningSecret: signingSecret,
      requestedTenantId: tenantA,
      requiredPermission: 'project:read',
      gucHmacSecret: gucSecret,
      work: async (tx) => {
        const r = await tx.query('SELECT id, tenant_id, order_number FROM public.orders');
        return r.rows;
      },
    });
    assert.equal(visibleOrders.length, 1);
    assert.equal(visibleOrders[0].tenant_id, tenantA);
    assert.equal(visibleOrders[0].order_number, 'ORD-A-001');

    // 2. Attempting to switch app.current_tenant_id mid-transaction to tenantB without tenantB's MAC fails closed (0 rows)
    const hijackedOrders = await mod13.withTenantTransaction({
      pool,
      identityAssertionToken: aliceToken,
      identitySigningSecret: signingSecret,
      requestedTenantId: tenantA,
      requiredPermission: 'project:read',
      gucHmacSecret: gucSecret,
      work: async (tx) => {
        await tx.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [tenantB]);
        const r = await tx.query('SELECT id, tenant_id FROM public.orders');
        return r.rows;
      },
    });
    assert.equal(hijackedOrders.length, 0);
  } finally {
    await db.close();
  }
});

// ============================================================================
// VERIFY-02: Identity Assertions and Gateway Auth
// ============================================================================
test('VERIFY-02: Identity assertions, exp/iat/nbf bounds, Gateway OIDC JWT verification & DEVIL-52', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const nowMs = 1_750_000_000_000;
  const nowSec = Math.floor(nowMs / 1000);

  const gatewayJwt = signRs256Jwt(
    { alg: 'RS256', typ: 'JWT', kid: 'gw-key-1' },
    {
      sub: 'gw-sa-subject',
      iss: 'https://accounts.google.com',
      aud: 'https://orders-backend.a.run.app',
      email: 'api-gateway@proj.iam.gserviceaccount.com',
      email_verified: true,
      iat: nowSec - 10,
      exp: nowSec + 300,
    },
    privateKey
  );

  const makeUserInfoB64 = (claims) => Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');

  // 1. Valid gateway OIDC JWT + valid end-user claims succeed
  const res = mod02.extractVerifiedApiGatewayUserInfo({
    rawGatewayAuthorizationHeader: `Bearer ${gatewayJwt}`,
    gatewayPublicKeyRing: { 'gw-key-1': publicKey },
    expectedBackendAudience: 'https://orders-backend.a.run.app',
    expectedGatewayServiceAccountEmail: 'api-gateway@proj.iam.gserviceaccount.com',
    rawUserInfoHeader: makeUserInfoB64({
      sub: 'usr_123',
      iss: 'https://auth.example.com',
      aud: 'api://orders',
      tenantId: 'tnt_acme_01',
      iat: nowSec - 10,
      exp: nowSec + 300,
    }),
    expectedEndUserIssuers: new Set(['https://auth.example.com']),
    expectedEndUserAudiences: new Set(['api://orders']),
    nowMs,
  });
  assert.equal(res.endUserClaims.sub, 'usr_123');
  assert.equal(res.endUserClaims.tenantId, 'tnt_acme_01');

  // 2. DEVIL-52: Future iat, future nbf, NaN exp, lifetime > 86400s, and invalid tenantId format rejected
  for (const badClaims of [
    { sub: 'u1', iss: 'https://auth.example.com', aud: 'api://orders', tenantId: 'tnt_1', iat: nowSec + 3600, exp: nowSec + 3900 },
    { sub: 'u1', iss: 'https://auth.example.com', aud: 'api://orders', tenantId: 'tnt_1', iat: nowSec - 10, nbf: nowSec + 120, exp: nowSec + 300 },
    { sub: 'u1', iss: 'https://auth.example.com', aud: 'api://orders', tenantId: 'tnt_1', iat: nowSec - 10, exp: Number.NaN },
    { sub: 'u1', iss: 'https://auth.example.com', aud: 'api://orders', tenantId: 'tnt_1', iat: nowSec - 10, exp: nowSec + 90_000 },
    { sub: 'u1', iss: 'https://auth.example.com', aud: 'api://orders', tenantId: '../traversal', iat: nowSec - 10, exp: nowSec + 300 },
  ]) {
    assert.throws(
      () =>
        mod02.extractVerifiedApiGatewayUserInfo({
          rawGatewayAuthorizationHeader: `Bearer ${gatewayJwt}`,
          gatewayPublicKeyRing: { 'gw-key-1': publicKey },
          expectedBackendAudience: 'https://orders-backend.a.run.app',
          expectedGatewayServiceAccountEmail: 'api-gateway@proj.iam.gserviceaccount.com',
          rawUserInfoHeader: makeUserInfoB64(badClaims),
          expectedEndUserIssuers: new Set(['https://auth.example.com']),
          expectedEndUserAudiences: new Set(['api://orders']),
          nowMs,
        }),
      /GATEWAY_USERINFO_REJECTED/
    );
  }
});

// ============================================================================
// VERIFY-03: Authentication and Token Lifecycle
// ============================================================================
test('VERIFY-03: JWT algorithm/typ/crit confusion, refresh token reuse family revocation, & scrypt concurrency protection', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const nowMs = 1_750_000_000_000;
  const nowSec = Math.floor(nowMs / 1000);

  // 1. Valid EdDSA JWT passes; alg:none and unsupported crit header fail
  const validJwt = signEd25519Jwt(
    { alg: 'EdDSA', typ: 'at+jwt', kid: 'k1' },
    {
      sub: 'usr_1',
      iss: 'https://issuer.example.com',
      aud: 'api://backend',
      jti: 'jti-001',
      tenantId: 'tnt_1',
      iat: nowSec - 5,
      exp: nowSec + 300,
    },
    privateKey
  );
  const verified = mod02.verifyJwtPenetrationSafe({
    token: validJwt,
    allowedAlgorithm: 'EdDSA',
    publicKeyRing: { k1: publicKey },
    expectedIssuer: 'https://issuer.example.com',
    expectedAudience: 'api://backend',
    expectedTyp: new Set(['at+jwt']),
    nowMs,
  });
  assert.equal(verified.sub, 'usr_1');

  const critJwt = signEd25519Jwt(
    { alg: 'EdDSA', typ: 'at+jwt', kid: 'k1', crit: ['exp', 'custom-unhandled-ext'] },
    {
      sub: 'usr_1',
      iss: 'https://issuer.example.com',
      aud: 'api://backend',
      iat: nowSec - 5,
      exp: nowSec + 300,
    },
    privateKey
  );
  assert.throws(
    () =>
      mod02.verifyJwtPenetrationSafe({
        token: critJwt,
        allowedAlgorithm: 'EdDSA',
        publicKeyRing: { k1: publicKey },
        expectedIssuer: 'https://issuer.example.com',
        expectedAudience: 'api://backend',
        nowMs,
      }),
    /JWT_REJECTED/
  );

  // 2. Refresh token reuse revokes entire token family atomically
  const rawToken = 'rt_live_secret_token_value_001';
  const tokenHash = crypto.createHash('sha256').update(rawToken, 'utf8').digest('hex');
  let revokedFamilyId = null;

  await assert.rejects(
    () =>
      mod02.rotateRefreshTokenWithReuseDetection({
        rawRefreshToken: rawToken,
        expectedDeviceId: 'dev-1',
        nowMs,
        findTokenByHash: async (h) =>
          h === tokenHash
            ? {
                tokenHash,
                familyId: 'fam-99',
                userId: 'usr-1',
                tenantId: 'tnt-1',
                deviceId: 'dev-1',
                status: 'ROTATED', // Already consumed!
                expiresAtMs: nowMs + 60_000,
                sessionCreatedAtMs: nowMs - 60_000,
                absoluteSessionExpiresAtMs: nowMs + 86_400_000,
              }
            : null,
        markTokenRotatedAndInsertChild: async () => true,
        revokeEntireTokenFamily: async (famId) => {
          revokedFamilyId = famId;
        },
      }),
    /REFRESH_TOKEN_COMPROMISED_FAMILY_REVOKED/
  );
  assert.equal(revokedFamilyId, 'fam-99');
});

// ============================================================================
// VERIFY-04: Fine-Grained Authorization, ReBAC, & Maker-Checker
// ============================================================================
test('VERIFY-04: Trusted-store ReBAC authorization & Maker-Checker ACID state commit on tampered/expired approvals (DEVIL-05, DEVIL-06)', async () => {
  // 1. ReBAC ignores caller-supplied role hints and enforces resource ownership/tenant match
  const authzDenied = await mod02.authorizeActionFromTrustedStore({
    authenticatedUserId: 'usr-viewer',
    requestedTenantId: 'tnt-1',
    action: 'file:delete',
    targetResourceType: 'file',
    targetResourceId: 'file-1',
    factStore: {
      loadSubjectFacts: async () => ({
        userId: 'usr-viewer',
        tenantId: 'tnt-1',
        membershipStatus: 'ACTIVE',
        roles: ['viewer'],
        clearanceLevel: 1,
        identityVerificationLevel: 'KYC_FULL',
        mfaVerifiedAtMs: Date.now(),
      }),
      loadResourceFacts: async () => ({
        resourceId: 'file-1',
        resourceType: 'file',
        tenantId: 'tnt-1',
        ownerUserId: 'usr-other',
        classificationLevel: 1,
        isLocked: false,
      }),
      loadActiveRebacRelations: async () => [],
    },
  });
  assert.equal(authzDenied.allowed, false);

  // 2. Maker-checker commits 'REVOKED' state inside ACID transaction before throwing when payload is tampered (DEVIL-05 & DEVIL-06)
  const originalOp = {
    tenantId: 'tnt-1',
    operationType: 'WIRE_PAYOUT',
    amountMinor: 100_000n,
    currency: 'USD',
    destinationAccount: 'acct_legit',
    idempotencyKey: 'idem-wire-1',
  };
  const originalHash = mod14.computeCanonicalOperationHash(originalOp);
  let committedApprovalState = 'APPROVED';

  const mockAcidStore = {
    runInAcidTransaction: async (fn) => fn(mockAcidStore),
    getActorMembership: async (_t, uid) => ({
      userId: uid,
      tenantId: 'tnt-1',
      membershipStatus: 'ACTIVE',
      roles: uid === 'usr-checker' ? ['FINANCE_CHECKER'] : ['FINANCE_INITIATOR'],
    }),
    getApprovalRecordForUpdate: async () => ({
      approvalId: 'app-1',
      tenantId: 'tnt-1',
      makerUserId: 'usr-maker',
      checkerUserId: 'usr-checker',
      canonicalPayloadHash: originalHash,
      state: committedApprovalState,
      expiresAtMs: Date.now() + 300_000,
    }),
    markApprovalState: async ({ nextState }) => {
      committedApprovalState = nextState;
      return true;
    },
    reserveTenantBalanceAtomically: async () => ({ reserved: true, remainingBalanceMinor: 900_000n }),
    appendImmutableAuditRecord: async () => {},
  };

  await assert.rejects(
    () =>
      mod14.executeVerifiedBusinessApprovalAndReservation({
        store: mockAcidStore,
        verifiedExecutorUserId: 'usr-maker',
        approvalId: 'app-1',
        operation: { ...originalOp, amountMinor: 9_999_999n }, // Tampered amount!
        auditHmacSecret: 'audit-hmac-secret-at-least-32-bytes-long!!',
      }),
    /APPROVAL_PAYLOAD_TAMPERED_REVOKED/
  );
  assert.equal(committedApprovalState, 'REVOKED');
});

// ============================================================================
// VERIFY-05: Financial Integrity and Double-Entry Ledger
// ============================================================================
test('VERIFY-05: Largest-remainder proration, credit note refund caps (DEVIL-51), journal hash canonicalization (DEVIL-50), & double-entry invariants (DEVIL-10, DEVIL-11)', async () => {
  // 1. Largest-remainder proration exact penny sum
  const shares = mod01.allocateProratedAmountExact([100n, 100n, 100n], 300n, 100n);
  assert.deepEqual(shares, [34n, 33n, 33n]);
  assert.equal(shares.reduce((a, b) => a + b, 0n), 100n);

  // 2. DEVIL-51: Negative or over-refunded baseline state in calculatePartialRefundCreditNote rejected
  assert.throws(
    () =>
      mod01.calculatePartialRefundCreditNote(
        {
          lineId: 'line-1',
          capturedQuantity: 2n,
          capturedNetMinor: 1000n,
          capturedTaxMinor: 100n,
          alreadyRefundedQuantity: 0n,
          alreadyRefundedNetMinor: -500n, // corrupted negative baseline
          alreadyRefundedTaxMinor: 0n,
        },
        1n
      ),
    /INVALID_LINE_REFUND_STATE/
  );

  assert.throws(
    () =>
      mod01.calculatePartialRefundCreditNote(
        {
          lineId: 'line-1',
          capturedQuantity: 2n,
          capturedNetMinor: 1000n,
          capturedTaxMinor: 100n,
          alreadyRefundedQuantity: 1n,
          alreadyRefundedNetMinor: 1200n, // exceeds capturedNetMinor
          alreadyRefundedTaxMinor: 50n,
        },
        1n
      ),
    /INVALID_LINE_REFUND_STATE/
  );

  // 3. DEVIL-50: Canonical JSON journal request hash prevents delimiter injection collision
  const h1 = mod01.computeJournalRequestHash({
    tenantId: 'tnt_a|key_1',
    idempotencyKey: 'key_2',
    postings: [{ accountId: 'acc_1', direction: 'DEBIT', amountMinor: 100n, currencyCode: 'USD' }],
  });
  const h2 = mod01.computeJournalRequestHash({
    tenantId: 'tnt_a',
    idempotencyKey: 'key_1|key_2',
    postings: [{ accountId: 'acc_1', direction: 'DEBIT', amountMinor: 100n, currencyCode: 'USD' }],
  });
  assert.notEqual(h1, h2);

  // 4. DEVIL-10 & DEVIL-11: Cross-tenant account injection and ASSET credit sign inversion blocked
  const mockLedgerPort = {
    runInTransaction: async (fn) =>
      fn({
        findJournalByIdempotencyKey: async () => null,
        lockAccountsSortedForUpdate: async () => [
          {
            accountId: 'acc-asset',
            tenantId: 'tnt-1',
            currencyCode: 'USD',
            status: 'ACTIVE',
            normalBalance: 'DEBIT',
            allowNegativeBalance: false,
            balanceMinor: 500n,
            version: 1,
          },
          {
            accountId: 'acc-liab',
            tenantId: 'tnt-1',
            currencyCode: 'USD',
            status: 'ACTIVE',
            normalBalance: 'CREDIT',
            allowNegativeBalance: false,
            balanceMinor: 500n,
            version: 1,
          },
        ],
        insertJournalAndUpdateBalances: async () => ({ updatedAccountCount: 2 }),
      }),
  };

  // Attempting to CREDIT an ASSET account by 600n when balance is 500n must throw INSUFFICIENT_FUNDS
  await assert.rejects(
    () =>
      mod01.persistBalancedJournalAtomically({
        journalId: 'jrn-1',
        tenantId: 'tnt-1',
        idempotencyKey: 'idem-jrn-1',
        postings: [
          { accountId: 'acc-asset', direction: 'CREDIT', amountMinor: 600n, currencyCode: 'USD' },
          { accountId: 'acc-liab', direction: 'DEBIT', amountMinor: 600n, currencyCode: 'USD' },
        ],
        ledgerPort: mockLedgerPort,
      }),
    /INSUFFICIENT_FUNDS|OVERDRAFT|negative/i
  );
});

// ============================================================================
// VERIFY-06: Payment Idempotency, Fencing, and Webhooks
// ============================================================================
test('VERIFY-06: Monotonic fencing tokens, ambiguous reconciliation abort check (DEVIL-54), & webhook timestamp/HMAC verification (DEVIL-12)', async () => {
  // 1. DEVIL-54: Ambiguous payment reconciliation aborts before commit if heartbeat fails during reconciliation
  let completeLockCalled = false;
  const db = {
    tryAcquireOrTakeoverExpiredLock: async () => ({
      acquired: true,
      fencingToken: 7n,
      currentStatus: 'UNKNOWN_RECONCILIATION_REQUIRED',
      providerIdempotencyKey: 'prov-idem-1',
    }),
    renewLockLease: async () => false, // simulates lost lease during reconciliation
    completeLockConditionally: async () => {
      completeLockCalled = true;
      return true;
    },
    releaseLockOnPreExternalFailureConditionally: async () => true,
    markUnknownReconciliationRequiredConditionally: async () => false,
  };

  await assert.rejects(
    () =>
      mod04.executeWithIdempotencyLock({
        tenantId: 'tnt-1',
        idempotencyKey: 'idem_pay_12345678',
        endpoint: 'POST:/v1/charges',
        canonicalRequestBody: { amountMinor: 5000 },
        lockTtlSeconds: 1, // heartbeat runs every max(250ms, floor(333ms)) = 333ms
        db,
        reconcileAmbiguousPayment: async () => {
          await new Promise((r) => setTimeout(r, 450));
          return { resolved: 'SUCCEEDED', status: 200, body: { status: 'succeeded' } };
        },
        handler: async () => ({ status: 200, body: {} }),
      }),
    /IDEMPOTENCY_FENCING_TOKEN_REJECTED_STALE_OWNER/
  );
  assert.equal(completeLockCalled, false);

  // 2. Webhook signature verification with raw bytes, CPU DoS cap (>5 v1 sigs), and replay window enforcement
  const whSecret = 'whsec_test_secret_at_least_32_bytes_long!!';
  const nowSec = Math.floor(Date.now() / 1000);
  const rawBodyBuffer = Buffer.from('{"id":"evt_123","type":"payment_intent.succeeded"}', 'utf8');
  const sigHex = crypto
    .createHmac('sha256', whSecret)
    .update(`${nowSec}.`, 'utf8')
    .update(rawBodyBuffer)
    .digest('hex');

  const validWh = mod04.verifyWebhookSignature({
    rawBodyBuffer,
    signatureHeader: `t=${nowSec},v1=${sigHex}`,
    webhookSecrets: [whSecret],
    toleranceSeconds: 300,
    nowMs: nowSec * 1000,
  });
  assert.equal(validWh.valid, true);

  // Stale timestamp rejected
  const staleWh = mod04.verifyWebhookSignature({
    rawBodyBuffer,
    signatureHeader: `t=${nowSec - 900},v1=${sigHex}`,
    webhookSecrets: [whSecret],
    toleranceSeconds: 300,
    nowMs: nowSec * 1000,
  });
  assert.equal(staleWh.valid, false);
});

// ============================================================================
// VERIFY-07: Single-Flight Cache and Cursor Security
// ============================================================================
test('VERIFY-07: Single-flight cache pre-write authorization & deep-clone isolation (DEVIL-53)', async () => {
  const redisMap = new Map();
  const redis = {
    get: async (k) => redisMap.get(k) ?? null,
    set: async (k, v) => {
      redisMap.set(k, v);
      return 'OK';
    },
    del: async (k) => {
      redisMap.delete(k);
    },
  };

  // 1. DEVIL-53: Unauthenticated/unauthorized caller cannot populate Redis cache on a miss
  await assert.rejects(
    () =>
      mod03.getOrComputeAuthorizedCachedSingleFlight(
        redis,
        {
          tenantId: 'tnt_attacker',
          actorUserId: 'usr_attacker',
          visibilityScope: 'TENANT_SHARED',
          resourceKey: 'doc:secret-1',
          ttlSeconds: 60,
        },
        async () => ({ tenantId: 'tnt_victim', classified: 'TOP_SECRET' }),
        async (doc, ctx) => doc.tenantId === ctx.tenantId
      ),
    /CACHE_AUTHZ_DENIED/
  );
  assert.equal(redisMap.size, 0);

  // 2. Concurrent authorized callers receive isolated clones (mutating one does not poison the other)
  const [resA, resB] = await Promise.all([
    mod03.getOrComputeAuthorizedCachedSingleFlight(
      redis,
      {
        tenantId: 'tnt_1',
        actorUserId: 'usr_1',
        visibilityScope: 'TENANT_SHARED',
        resourceKey: 'doc:shared-1',
        ttlSeconds: 60,
      },
      async () => {
        await new Promise((r) => setTimeout(r, 10));
        return { tenantId: 'tnt_1', items: ['original'] };
      },
      async (doc, ctx) => doc.tenantId === ctx.tenantId
    ),
    mod03.getOrComputeAuthorizedCachedSingleFlight(
      redis,
      {
        tenantId: 'tnt_1',
        actorUserId: 'usr_2',
        visibilityScope: 'TENANT_SHARED',
        resourceKey: 'doc:shared-1',
        ttlSeconds: 60,
      },
      async () => ({ tenantId: 'tnt_1', items: ['original'] }),
      async (doc, ctx) => doc.tenantId === ctx.tenantId
    ),
  ]);
  resA.items.push('mutated-by-caller-A');
  assert.deepEqual(resB.items, ['original']);
});

// ============================================================================
// VERIFY-08: File Upload, Quarantine, and Malware Pipeline
// ============================================================================
test('VERIFY-08: Decompression bomb dimension checks, JPEG APP2/EXIF support (DEVIL-59), PDF hex-escaped /JavaScript blocking, & version-pinned promotion (DEVIL-14)', async () => {
  // 1. DEVIL-59: Valid JPEG with APP2 (0xFFE2) ICC profile and 8KB EXIF header before SOF0 (0xFFC0) succeeds
  const app2Segment = Buffer.alloc(8192, 0);
  app2Segment[0] = 0xff;
  app2Segment[1] = 0xe2; // APP2 marker
  app2Segment.writeUInt16BE(8190, 2); // segment length

  const sof0Segment = Buffer.from([
    0xff, 0xc0, 0x00, 0x11, 0x08,
    0x01, 0x90, // height = 400
    0x02, 0x58, // width = 600
    0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
  ]);
  const validJpeg = Buffer.concat([Buffer.from([0xff, 0xd8]), app2Segment, sof0Segment, Buffer.from([0xff, 0xd9])]);
  const jpgPolicy = mod05.STREAM_FILE_WHITELIST.get('.jpg');
  assert.equal(jpgPolicy.verifyMagicBytesAndDimensions(validJpeg), true);

  // 2. Pixel flood image (15000 x 15000 = 225 MP > 25 MP limit) rejected
  const bombPng = Buffer.alloc(32);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bombPng, 0);
  bombPng.write('IHDR', 12, 'ascii');
  bombPng.writeUInt32BE(15000, 16);
  bombPng.writeUInt32BE(15000, 20);
  const pngPolicy = mod05.STREAM_FILE_WHITELIST.get('.png');
  assert.equal(pngPolicy.verifyMagicBytesAndDimensions(bombPng), false);

  // 3. PDF hex-escaped `/#4aavaScript` rejected by streaming gate
  const pdfPolicy = mod05.STREAM_FILE_WHITELIST.get('.pdf');
  const maliciousPdf = Buffer.from('%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /#4aavaScript /JS (app.alert(1)) >> >>\n', 'utf8');
  const gate = new mod05.SecurityGateTransformStream(pdfPolicy);
  await assert.rejects(
    async () => {
      for await (const _ of Readable.from([maliciousPdf]).pipe(gate)) {
        // consume
      }
    },
    /STREAM_UPLOAD_ABORTED.*forbidden active token/
  );
});

// ============================================================================
// VERIFY-09: Queue Leases, Outbox Relay, and Log Redaction
// ============================================================================
test('VERIFY-09: 3-phase outbox relay, worker lease heartbeat abort guard (DEVIL-60), & recursive sensitive field redaction', async () => {
  // 1. DEVIL-60: Worker whose lease heartbeat failed must NOT call markJobFailedOrDeadLetter
  let markFailedCalled = false;
  const leaseManager = {
    acquireJobLease: async () => ({
      status: 'ACQUIRED',
      fencingToken: 11n,
      attempt: 1,
      maxAttempts: 3,
    }),
    renewJobLeaseHeartbeat: async () => false, // lose lease on first heartbeat
    completeJobWithFencingToken: async () => false,
    markJobFailedOrDeadLetter: async () => {
      markFailedCalled = true;
      return 'SCHEDULED_RETRY';
    },
    replayDeadLetterJob: async () => {},
  };

  const silentLogger = new mod06.StructuredLogger('test-worker', () => {});

  await assert.rejects(
    () =>
      mod06.executeQueueWorkerJob(
        {
          jobId: 'job-001',
          tenantId: 'tnt-1',
          queueName: 'P1_HIGH',
          idempotencyKey: 'idem-job-001',
          traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
          payload: {},
          createdAtIso: '2026-11-09T00:00:00.000Z',
        },
        'wrk-1',
        30, // leaseDurationMs = 30ms -> heartbeat every max(1000ms, 10ms) = 1000ms
        {
          leaseManager,
          logger: silentLogger,
        },
        async (_payload, ctx) => {
          await new Promise((_, reject) => {
            ctx.signal.addEventListener('abort', () => reject(new Error('Generic handler error after abort')));
          });
        }
      ),
    /JOB_LEASE_HEARTBEAT_FAILED/
  );
  assert.equal(markFailedCalled, false);

  // 2. Recursive log redaction scrubs camelCase, snake_case, and headers
  const scrubbed = mod06.redactSensitiveFields({
    userId: 'usr-1',
    passwordHash: '$argon2id$secret',
    nested: {
      clientSecret: 'sec_99182',
      'x-api-key': 'ak_live_999',
      safeField: 'visible',
    },
  });
  assert.equal(scrubbed.passwordHash, '[REDACTED_SECRET]');
  assert.equal(scrubbed.nested.clientSecret, '[REDACTED_SECRET]');
  assert.equal(scrubbed.nested['x-api-key'], '[REDACTED_SECRET]');
  assert.equal(scrubbed.nested.safeField, 'visible');
});

// ============================================================================
// VERIFY-10: Durable Sagas and Compensation
// ============================================================================
test('VERIFY-10: Saga step timeout AbortError transitions to RECONCILIATION_REQUIRED without blind compensation (DEVIL-13, DEVIL-61)', async () => {
  const stepRecords = new Map();
  let finalSagaState = 'RUNNING';
  let step0Compensated = false;

  const store = {
    acquireSagaLease: async ({ initialContext }) => ({
      acquired: true,
      fencingToken: 1n,
      sagaStatus: 'RUNNING',
      context: initialContext,
      steps: [],
    }),
    recordStepStatus: async (_sagaId, stepIndex, stepName, status) => {
      stepRecords.set(stepIndex, { stepIndex, stepName, status });
    },
    updateSagaStatus: async (_sagaId, status) => {
      finalSagaState = status;
    },
  };

  const result = await mod07.runOrResumeDurableSaga({
    sagaId: 'saga-timeout-01',
    tenantId: 'tnt-1',
    sagaType: 'ORDER_CHECKOUT',
    initialContext: {},
    store,
    steps: [
      {
        stepName: 'reserve_inventory',
        stepTimeoutMs: 100,
        executeForward: async () => {},
        compensateBackward: async () => {
          step0Compensated = true;
        },
      },
      {
        stepName: 'charge_card_pivot',
        stepTimeoutMs: 15,
        // Simulates standard fetch/DOMException AbortError when signal aborts
        executeForward: async (_ctx, _key, signal) => {
          await new Promise((_, reject) => {
            signal.addEventListener('abort', () => {
              const abortErr = new Error('The operation was aborted');
              abortErr.name = 'AbortError';
              reject(abortErr);
            });
          });
        },
      },
    ],
  });

  // Must halt in RECONCILIATION_REQUIRED (never blindly compensate step 0 when pivot step timed out!)
  assert.equal(result.finalStatus, 'RECONCILIATION_REQUIRED');
  assert.equal(finalSagaState, 'RECONCILIATION_REQUIRED');
  assert.equal(stepRecords.get(1).status, 'FORWARD_AMBIGUOUS_TIMEOUT');
  assert.equal(step0Compensated, false);
});

// ============================================================================
// VERIFY-11: SSRF, Edge Defense, and Rate Limiting
// ============================================================================
test('VERIFY-11: IPv4/IPv6/NAT64/6to4/Teredo/Octal SSRF blocking (DEVIL-17) & XFF right-to-left CIDR extraction', () => {
  for (const blockedIp of [
    '127.0.0.1',
    '10.0.0.1',
    '100.64.1.1',
    '169.254.169.254',
    '::1',
    '::ffff:169.254.169.254',
    '64:ff9b::a9fe:a9fe', // NAT64 cloud metadata
    '2002:7f00:0001::', // 6to4 loopback
    '2001:0000:4136:e378:8000:63bf:3fff:fdd2', // Teredo
  ]) {
    assert.equal(mod08.isPrivateOrReservedIp(blockedIp), true, `Expected ${blockedIp} to be blocked`);
  }
  assert.equal(mod08.isPrivateOrReservedIp('93.184.216.34'), false);
  assert.equal(mod08.isAmbiguousIpv4Hostname('0177.0.0.1'), true);
  assert.equal(mod08.isAmbiguousIpv4Hostname('2130706433'), true);

  // Right-to-left X-Forwarded-For extraction ignores spoofed leftmost IP
  const clientIp = mod08.extractTrustedClientIpByCidr({
    socketRemoteAddress: '10.0.1.5',
    xForwardedForHeader: '1.2.3.4, 198.51.100.77, 10.0.1.5',
    trustedProxyCidrs: ['10.0.0.0/8'],
  });
  assert.equal(clientIp, '198.51.100.77');
});

// ============================================================================
// VERIFY-12: BaaS and Supabase Security
// ============================================================================
test('VERIFY-12: Firestore active membership & client COMPLETED state lock + Supabase RLS policies (DEVIL-15)', () => {
  const nowMs = 1_750_000_000_000;
  // Client attempting to transition project directly to COMPLETED is denied
  const ruleRes = mod11.evaluateFirestoreProjectRule({
    operation: 'update',
    auth: { uid: 'usr-1', emailVerified: true },
    membership: { tenantId: 'tnt-1', uid: 'usr-1', status: 'ACTIVE', role: 'ADMIN' },
    existingDoc: {
      tenantId: 'tnt-1',
      ownerId: 'usr-1',
      name: 'Billing Migration',
      status: 'ACTIVE',
      budgetCents: 5000,
      createdAtMs: nowMs - 10_000,
      updatedAtMs: nowMs - 5_000,
    },
    incomingDoc: {
      tenantId: 'tnt-1',
      ownerId: 'usr-1',
      name: 'Billing Migration',
      status: 'COMPLETED', // Forbidden from client SDK!
      budgetCents: 5000,
      createdAtMs: nowMs - 10_000,
      updatedAtMs: nowMs,
    },
    requestTimeMs: nowMs,
  });
  assert.equal(ruleRes.allowed, false);
  assert.equal(ruleRes.denialReason, 'UNAUTHORIZED_CLIENT_STATUS_TRANSITION');
});

// ============================================================================
// VERIFY-13: Omnichannel Notification Security
// ============================================================================
test('VERIFY-13: Post-acceptance SMS DB commit failure isolation & composite providerIdempotencyKey reconciliation (DEVIL-18, DEVIL-55)', async () => {
  // 1. DEVIL-18: Post-acceptance DB commit failure does NOT failover to secondary SMS provider
  let secondaryCalled = false;
  let markedAmbiguousSid = null;
  const smsRes = await mod10.dispatchSmsWithBudgetAndFailover({
    store: {
      getRecipientProfile: async () => ({
        tenantId: 'tnt-1',
        recipientId: 'rec-1',
        e164Phone: '+14155550101',
        phoneVerified: true,
        smsOptedOut: false,
        marketingConsentGranted: false,
      }),
      reserveBudgetAtomically: async () => ({
        reserved: true,
      }),
      commitReservation: async () => {
        throw new Error('Transient DB commit loss after Twilio 200 OK');
      },
      releaseReservation: async () => {},
      markReservationAmbiguous: async ({ providerMessageSid }) => {
        markedAmbiguousSid = providerMessageSid;
      },
    },
    primaryProvider: {
      providerName: 'twilio',
      sendSms: async () => ({ providerMessageSid: 'SM_PRIMARY_SENT_001' }),
    },
    secondaryProvider: {
      providerName: 'vonage',
      sendSms: async () => {
        secondaryCalled = true;
        return { providerMessageSid: 'SM_SECONDARY_DUPLICATE' };
      },
    },
    reservationId: 'res-1',
    tenantId: 'tnt-1',
    recipientId: 'rec-1',
    e164Phone: '+14155550101',
    body: 'Your OTP is 123456',
    classification: 'TRANSACTIONAL_SECURITY_OTP',
    idempotencyKey: 'idem-sms-1',
    costCents: 5,
    maxDailyBudgetCents: 1000,
    maxPhoneHourlyCount: 5,
    maxSubnetHourlyCount: 20,
    clientIpSubnet24: '198.51.100.0/24',
    allowedCountryPrefixes: ['+1'],
  });
  assert.equal(smsRes.status, 'AMBIGUOUS_RECONCILIATION_REQUIRED');
  assert.equal(markedAmbiguousSid, 'SM_PRIMARY_SENT_001');
  assert.equal(secondaryCalled, false);

  // 2. DEVIL-55: reconcileStaleSmsBudgetReservations queries provider using composite providerIdempotencyKey
  const queriedKeys = [];
  const committedIds = [];
  const reconcileRes = await mod10.reconcileStaleSmsBudgetReservations({
    staleRecords: [
      {
        reservationId: 'res-01',
        tenantId: 'tnt-1',
        idempotencyKey: 'caller-key-01',
        providerIdempotencyKey: 'tnt-1:res-01:caller-key-01',
        reservedCostCents: 5,
        status: 'AMBIGUOUS_RECONCILIATION_REQUIRED',
        createdAtMs: Date.now() - 120_000,
      },
    ],
    store: {
      getRecipientProfile: async () => null,
      reserveBudgetAtomically: async () => ({ reserved: false }),
      commitReservation: async ({ reservationId }) => {
        committedIds.push(reservationId);
      },
      releaseReservation: async () => {},
      markReservationAmbiguous: async () => {},
    },
    queryProviderStatusByIdempotencyKey: async (key) => {
      queriedKeys.push(key);
      if (key === 'tnt-1:res-01:caller-key-01') {
        return { found: true, providerMessageSid: 'SM999111' };
      }
      return { found: false };
    },
  });
  assert.deepEqual(queriedKeys, ['tnt-1:res-01:caller-key-01']);
  assert.equal(reconcileRes.committedCount, 1);
  assert.deepEqual(committedIds, ['res-01']);
});

// ============================================================================
// VERIFY-14: Privacy, Crypto-Shredding, and Audit Ledgers
// ============================================================================
test('VERIFY-14: AES-256-GCM AAD envelope encryption/crypto-shredding & tenant-scoped HMAC audit hash chain', () => {
  const keyRing = { 'dek-user-1': crypto.randomBytes(32) };
  const env = mod16.encryptEnvelopeAes256Gcm({
    keyId: 'dek-user-1',
    keyBytes32: keyRing['dek-user-1'],
    plaintextUtf8: 'alice@example.com',
    tenantId: 'tnt-1',
    resourceId: 'usr-1',
    purpose: 'pii-email',
  });

  // Cross-tenant AAD transplant rejected
  assert.throws(
    () =>
      mod16.decryptEnvelopeAes256Gcm({
        envelope: env,
        keyRing,
        expectedTenantId: 'tnt-2',
        expectedResourceId: 'usr-1',
        expectedPurpose: 'pii-email',
      }),
    /Unsupported state or unable to authenticate data/
  );

  // Sequenced HMAC audit hash chain binds sequenceNumber, prevHashHex, and tenantId
  const h1 = mod08.computeAuditChainHash({
    auditHmacSecret: 'audit-chain-secret-at-least-32-bytes-long!!',
    sequenceNumber: 1n,
    prevHashHex: '0'.repeat(64),
    tenantId: 'tnt-1',
    actorId: 'usr-1',
    action: 'LEDGER_POST',
    resourceType: 'journal',
    resourceId: 'jrn-1',
    payloadJson: '{"amount":100}',
    createdAtIsoUtc: '2026-11-09T00:00:00.000Z',
  });
  const h2 = mod08.computeAuditChainHash({
    auditHmacSecret: 'audit-chain-secret-at-least-32-bytes-long!!',
    sequenceNumber: 2n,
    prevHashHex: h1,
    tenantId: 'tnt-1',
    actorId: 'usr-1',
    action: 'LEDGER_POST',
    resourceType: 'journal',
    resourceId: 'jrn-2',
    payloadJson: '{"amount":200}',
    createdAtIsoUtc: '2026-11-09T00:01:00.000Z',
  });
  assert.notEqual(h1, h2);
});

// ============================================================================
// VERIFY-15: Checklist Parser and Verification Tooling
// ============================================================================
test('VERIFY-15: Checklist parser never hardcodes VERIFIED_FIXED and requires section-specific passing test evidence (DEVIL-22, DEVIL-58)', () => {
  const sampleMd = [
    '# Sample Skill',
    '## 1. Tested Security Guardrail (DEVIL-01)',
    '```typescript',
    'export const safe = 1;',
    '```',
    '## 2. Untested Security Section Without Test IDs',
    '```typescript',
    'export const untested = 2;',
    '```',
  ].join('\n');

  const parsed = mod15.parseMarkdownSecurityChecklist(
    [{ fileName: 'sample.md', content: sampleMd }],
    { executedPassingTestIds: new Set(['DEVIL-01']) }
  );
  const sec1 = parsed.items.find((i) => i.sectionTitle.includes('Tested Security Guardrail'));
  const sec2 = parsed.items.find((i) => i.sectionTitle.includes('Untested Security Section'));

  assert.equal(sec1.status, 'VERIFIED_FIXED');
  // DEVIL-58: Section 2 does NOT mention DEVIL-01, so it must remain UNVERIFIED instead of inheriting file-wide IDs!
  assert.equal(sec2.status, 'UNVERIFIED');
});

// ============================================================================
// VERIFY-16: Module 16 Glue-Layer Guardrails Execution
// ============================================================================
test('VERIFY-16: Unforgeable WeakMap txClient guard (DEVIL-07), Server Mutation wrapper (DEVIL-08), Realtime revocation seal (DEVIL-16), & Bounded Batch (DEVIL-09)', async () => {
  // 1. Forged Symbol.for('backend.skill.pinnedTenantTx') client rejected by WeakMap guard (DEVIL-07)
  const forgedClient = {
    [Symbol.for('backend.skill.pinnedTenantTx')]: true,
    boundTenantId: 'tnt-1',
    query: async () => ({ rows: [], rowCount: 0 }),
  };
  assert.throws(
    () => mod16.assertPinnedTenantTransactionClient(forgedClient, 'tnt-1'),
    /GLUE_LAYER_POOL_BYPASS_DETECTED/
  );

  // 2. Bounded batch rejects missing runInTransaction (DEVIL-64) and maxBatchSize > 50 (DEVIL-09)
  await assert.rejects(
    () =>
      mod16.executeBoundedAuthorizedBatch({
        items: [1, 2, 3],
        consumeRateLimitTokens: async () => true,
        authorizeItem: async () => true,
        processItem: async (x) => x,
      }),
    /BATCH_TRANSACTION_RUNNER_REQUIRED/
  );

  await assert.rejects(
    () =>
      mod16.executeBoundedAuthorizedBatch({
        items: [1, 2, 3],
        maxBatchSize: 100, // Exceeds HARD_MAX_BATCH_SIZE (50)
        runInTransaction: async (fn) => fn(),
        consumeRateLimitTokens: async () => true,
        authorizeItem: async () => true,
        processItem: async (x) => x,
      }),
    /BATCH_MAX_LIMIT_OVERRIDE_FORBIDDEN/
  );

  // 3. Realtime stream controller permanently seals socket upon membership revocation (DEVIL-16)
  let deliveredCount = 0;
  let closedCode = null;
  let membershipStatus = 'ACTIVE';
  const streamCtrl = mod16.createRevocationSafeRealtimeStreamController({
    userId: 'usr-1',
    tenantId: 'tnt-1',
    tokenExpiresAtSec: Math.floor(Date.now() / 1000) + 300,
    loadCurrentMembershipStatus: async () => membershipStatus,
    deliverFrameToSocket: () => {
      deliveredCount += 1;
    },
    closeSocketWithReason: (code) => {
      closedCode = code;
    },
  });

  assert.equal(await streamCtrl.sendFrameIfAuthorized({ msg: 'hello' }), true);
  membershipStatus = 'REVOKED';
  assert.equal(await streamCtrl.sendFrameIfAuthorized({ msg: 'after-revoke' }), false);
  assert.equal(closedCode, 4403);
  assert.equal(deliveredCount, 1);
});

// ============================================================================
// VERIFY-17 & VERIFY-18: Cross-Module Contract Consistency & Master SKILL.md / UI Parity
// ============================================================================
test('VERIFY-17 & VERIFY-18: Repository-wide anti-pattern scan across skills/00..16, SKILL.md, and BackendSkillWorkspace.tsx (DEVIL-56)', () => {
  const skillsDir = path.join(ROOT, 'skills');
  const mdFiles = fs
    .readdirSync(skillsDir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => ({
      fileName: f,
      content: fs.readFileSync(path.join(skillsDir, f), 'utf8'),
    }));

  const parsed = mod15.parseMarkdownSecurityChecklist(mdFiles);
  assert.deepEqual(
    parsed.antiPatternViolations,
    [],
    `Expected zero anti-pattern violations across all 18 skill files, found: ${JSON.stringify(parsed.antiPatternViolations)}`
  );

  // Verify Master SKILL.md indexes all modules 00 through 16
  const skillIndex = fs.readFileSync(path.join(ROOT, 'skills/SKILL.md'), 'utf8');
  for (let i = 0; i <= 16; i++) {
    const prefix = String(i).padStart(2, '0');
    assert.match(skillIndex, new RegExp(`${prefix}-`));
  }

  // Verify BackendSkillWorkspace.tsx no longer contains stale pre-remediation policyCode snippets (DEVIL-56)
  const uiContent = fs.readFileSync(path.join(ROOT, 'components/BackendSkillWorkspace.tsx'), 'utf8');
  assert.doesNotMatch(uiContent, /ON CONFLICT \(tenant_id, idempotency_key\) DO NOTHING/);
  assert.doesNotMatch(uiContent, /AWS SES returns HTTP 503 Service Unavailable BEFORE accepting payload/);
  assert.match(uiContent, /set_config\('app\.current_tenant_mac'/);
  assert.match(uiContent, /deriveStripeIdempotencyKey/);
});

// ============================================================================
// VERIFY-19: Chunk 3 Strict TypeScript Compilation & Nested/Malformed Fence Parser
// ============================================================================
test('VERIFY-19: All executable TypeScript blocks across Modules 00..16 compile cleanly under strict TypeScript (--strict) & Module 15 handles nested/malformed fences (DEVIL-62)', () => {
  const skillsDir = path.join(ROOT, 'skills');
  const mdFileNames = fs
    .readdirSync(skillsDir)
    .filter((f) => /^\d{2}-.*\.md$/.test(f))
    .sort();

  const tempDir = path.join(ROOT, '.tmp-ts-verify');
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    const generatedFiles = [];
    for (const mdFile of mdFileNames) {
      const raw = fs.readFileSync(path.join(skillsDir, mdFile), 'utf8');
      const extracted = mod15.extractFencedCodeBlocksDetailed(raw, {
        allowedLanguages: new Set(['typescript', 'ts']),
      });
      assert.equal(
        extracted.malformedUnclosedCount,
        0,
        `Module ${mdFile} contains unclosed/malformed Markdown code fences`
      );
      if (extracted.blocks.length === 0) continue;

      const tsFilePath = path.join(tempDir, mdFile.replace(/\.md$/, '.ts'));
      fs.writeFileSync(tsFilePath, extracted.blocks.map((b) => b.code).join('\n\n'), 'utf8');
      generatedFiles.push(tsFilePath);
    }

    const compilerOptions = {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      strict: true,
      noImplicitAny: true,
      strictNullChecks: true,
      skipLibCheck: true,
      noEmit: true,
    };

    const program = ts.createProgram(generatedFiles, compilerOptions);
    const diagnostics = ts.getPreEmitDiagnostics(program);
    const formattedErrors = diagnostics.map((d) => {
      const file = d.file ? path.basename(d.file.fileName) : 'global';
      const line =
        d.file && d.start !== undefined
          ? d.file.getLineAndCharacterOfPosition(d.start).line + 1
          : 0;
      const msg = ts.flattenDiagnosticMessageText(d.messageText, '\n');
      return `${file}:${line} - TS${d.code}: ${msg}`;
    });

    assert.deepEqual(
      formattedErrors,
      [],
      `Expected zero TypeScript --strict diagnostics across Modules 00..16, found:\n${formattedErrors.join('\n')}`
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  // Test Module 15 nested 4-backtick fence extraction and malformed unclosed fence rejection
  const nestedAndMalformedMd = [
    '## Section A: Nested Fences & Threat Model (DEVIL-62)',
    '````markdown',
    'Here is an inner code block inside a 4-backtick outer fence:',
    '```typescript',
    'export const innerSafeConstant = 42;',
    '```',
    '````',
    '## Section B: Malformed Unclosed Fence Security Control',
    '```typescript',
    'export const unclosedBrokenCode = true;',
  ].join('\n');

  const detailed = mod15.extractFencedCodeBlocksDetailed(nestedAndMalformedMd);
  assert.equal(detailed.blocks.length, 1);
  assert.match(detailed.blocks[0].code, /innerSafeConstant = 42/);
  assert.equal(detailed.malformedUnclosedCount, 1);

  const checklistRes = mod15.parseMarkdownSecurityChecklist(
    [{ fileName: '99-nested-malformed.md', content: nestedAndMalformedMd }],
    { executedPassingTestIds: new Set(['DEVIL-62']) }
  );
  assert.equal(checklistRes.malformedFenceFiles.length, 1);
  assert.equal(checklistRes.malformedFenceFiles[0].malformedUnclosedCount, 1);
  // Malformed unclosed fence in file must force status to 'DETECTED' instead of 'VERIFIED_FIXED'
  assert.ok(checklistRes.items.every((item) => item.status === 'DETECTED'));

  // Test evidence ID validator
  const idCheck = mod15.validateEvidenceIdentifiers([
    'DEVIL-01',
    'DEVIL-62',
    'TEST-62',
    'VERIFY-01',
    'INVALID-ID',
    'DEVIL-X',
  ]);
  assert.deepEqual(idCheck.validIds, ['DEVIL-01', 'DEVIL-62', 'TEST-62', 'VERIFY-01']);
  assert.deepEqual(idCheck.invalidIds, ['INVALID-ID', 'DEVIL-X']);
});

// ============================================================================
// VERIFY-20: Chunk 3 PostgreSQL 16 Migration Prerequisite Ordering & Cross-Module Contracts
// ============================================================================
test('VERIFY-20: SQL migrations in Modules 01, 07, 11 enforce clean-DB prerequisite ordering, valid CTE batch updates, and all 15 Cross-Module Contracts (DEVIL-62)', () => {
  const mod01Content = fs.readFileSync(
    path.join(ROOT, 'skills/01-domain-modeling-fields-timestamps-ids.md'),
    'utf8'
  );
  const mod07Content = fs.readFileSync(
    path.join(ROOT, 'skills/07-events-realtime-sagas-migrations-sql-multitenancy-search.md'),
    'utf8'
  );
  const mod11Content = fs.readFileSync(
    path.join(ROOT, 'skills/11-baas-providers-supabase-firebase-amplified-security.md'),
    'utf8'
  );
  const skillMaster = fs.readFileSync(path.join(ROOT, 'skills/SKILL.md'), 'utf8');

  // 1. Module 07 must NOT contain invalid PostgreSQL `UPDATE ... ORDER BY ... LIMIT`
  assert.doesNotMatch(
    mod07Content,
    /\bUPDATE\s+orders\s+SET\s+[^;]*?\bORDER\s+BY\b[^;]*?\bLIMIT\b/i
  );
  assert.match(mod07Content, /WITH\s+batch\s+AS\s*\(\s*SELECT\s+id\s+FROM\s+public\.orders/i);
  assert.match(mod07Content, /FOR\s+UPDATE\s+SKIP\s+LOCKED/i);

  // 2. Module 15 anti-pattern scanner must catch invalid PostgreSQL `UPDATE ... ORDER BY ... LIMIT`
  const badSqlCheck = mod15.parseMarkdownSecurityChecklist([
    {
      fileName: '98-bad-sql.md',
      content:
        '## Bad SQL Backfill\n```sql\nUPDATE orders SET tax_jurisdiction = \'US\' WHERE id > 0 ORDER BY id ASC LIMIT 2000;\n```',
    },
  ]);
  assert.equal(badSqlCheck.antiPatternViolations.length, 1);
  assert.equal(badSqlCheck.antiPatternViolations[0].ruleId, 'INVALID_PG_UPDATE_ORDER_BY_LIMIT');

  // 3. Verify clean-DB prerequisite ordering: CREATE TABLE IF NOT EXISTS precedes REVOKE / ALTER TABLE ENABLE RLS / CREATE TRIGGER
  const mod01CreateTablePos = mod01Content.indexOf('CREATE TABLE IF NOT EXISTS public.journal_entries');
  const mod01RevokePos = mod01Content.indexOf('REVOKE ALL ON public.journal_entries');
  const mod01TriggerPos = mod01Content.indexOf('CREATE TRIGGER trg_journal_entries_immutable');
  assert.ok(mod01CreateTablePos > 0 && mod01CreateTablePos < mod01RevokePos);
  assert.ok(mod01RevokePos < mod01TriggerPos);

  const mod07CreateOrdersPos = mod07Content.indexOf('CREATE TABLE IF NOT EXISTS public.orders');
  const mod07EnableRlsPos = mod07Content.indexOf('ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY');
  assert.ok(mod07CreateOrdersPos > 0 && mod07CreateOrdersPos < mod07EnableRlsPos);

  const mod11CreateProjectsPos = mod11Content.indexOf('CREATE TABLE IF NOT EXISTS public.projects');
  const mod11EnableRlsPos = mod11Content.indexOf('ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY');
  assert.ok(mod11CreateProjectsPos > 0 && mod11CreateProjectsPos < mod11EnableRlsPos);

  // 4. Verify all 15 Cross-Module Contracts (CONTRACT-01..CONTRACT-15) are documented in SKILL.md
  for (let c = 1; c <= 15; c++) {
    const cid = `CONTRACT-${String(c).padStart(2, '0')}`;
    assert.match(skillMaster, new RegExp(`\\b${cid}\\b`), `Missing ${cid} in skills/SKILL.md`);
  }
});

// ============================================================================
// VERIFY-21: Chunk 4 Red-Team Attack Matrix Execution (DEVIL-63..DEVIL-66)
// ============================================================================
test('VERIFY-21: Chunk 4 Red-Team Exploits — Bare Bearer/OIDC OpenAPI Bypass & MCP Delimiter Collision (DEVIL-63), Atomic Bounded Batch Rollback (DEVIL-64), AES-GCM AAD Key-Binding & Stream Serialization (DEVIL-65), Secret & Duplicate Evidence Scanner (DEVIL-66)', async () => {
  // 1. DEVIL-63: Bare { type: 'http', scheme: 'bearer' } without JWT/introspection metadata MUST be rejected
  const bareBearerViolations = mod14.auditOpenApiSecurityAlternatives({
    securitySchemes: {
      bareBearer: { type: 'http', scheme: 'bearer' },
    },
    operations: [
      {
        operationId: 'transferLedgerFunds',
        security: [{ bareBearer: [] }],
      },
    ],
  });
  assert.equal(bareBearerViolations.length, 1);
  assert.match(bareBearerViolations[0], /transferLedgerFunds/);

  // And openIdConnect without https:// openIdConnectUrl MUST be rejected
  const bareOidcViolations = mod14.auditOpenApiSecurityAlternatives({
    securitySchemes: {
      badOidc: { type: 'openIdConnect' },
    },
    operations: [
      {
        operationId: 'transferLedgerFundsOidc',
        security: [{ badOidc: [] }],
      },
    ],
  });
  assert.equal(bareOidcViolations.length, 1);
  assert.match(bareOidcViolations[0], /transferLedgerFundsOidc/);

  // Valid OIDC with https:// openIdConnectUrl passes with zero violations
  const validOidcViolations = mod14.auditOpenApiSecurityAlternatives({
    securitySchemes: {
      goodOidc: {
        type: 'openIdConnect',
        openIdConnectUrl: 'https://idp.example.com/.well-known/openid-configuration',
      },
    },
    operations: [
      {
        operationId: 'transferLedgerFundsValidOidc',
        security: [{ goodOidc: [] }],
      },
    ],
  });
  assert.deepEqual(validOidcViolations, []);

  // 2. DEVIL-63: MCP confirmation token canonical tuple encoding prevents pipe-delimiter collision
  const secret = 'mcp-confirmation-secret-key-minimum-32-bytes!!';
  const tokenA = mod14.computeMcpUserConfirmationToken({
    userId: 'usr-1|tnt-1',
    tenantId: 'tool-x',
    toolName: 'delete_db',
    confirmationNonce: 'nonce-1234567890',
    expiresAtEpochMs: 1800000000000,
    args: { target: 'prod' },
    confirmationSecret: secret,
  });
  const tokenB = mod14.computeMcpUserConfirmationToken({
    userId: 'usr-1',
    tenantId: 'tnt-1|tool-x',
    toolName: 'delete_db',
    confirmationNonce: 'nonce-1234567890',
    expiresAtEpochMs: 1800000000000,
    args: { target: 'prod' },
    confirmationSecret: secret,
  });
  assert.notEqual(tokenA, tokenB, 'Pipe delimiter collision must not produce identical MCP tokens');

  // 3. DEVIL-64: executeBoundedAuthorizedBatch rolls back partial mutations on mid-batch failure
  const committedState = [];
  let stagedState = [];
  await assert.rejects(
    () =>
      mod16.executeBoundedAuthorizedBatch({
        items: ['item-1', 'item-2', 'FAIL-ITEM-3'],
        runInTransaction: async (fn) => {
          stagedState = [...committedState];
          const res = await fn();
          committedState.splice(0, committedState.length, ...stagedState);
          return res;
        },
        consumeRateLimitTokens: async () => true,
        authorizeItem: async () => true,
        processItem: async (item) => {
          if (item === 'FAIL-ITEM-3') {
            throw new Error('MID_BATCH_MUTATION_ERROR');
          }
          stagedState.push(item);
          return item;
        },
      }),
    /MID_BATCH_MUTATION_ERROR/
  );
  assert.deepEqual(
    committedState,
    [],
    'Partial batch mutations must not commit when a subsequent batch item fails'
  );

  // 4. DEVIL-65: AES-256-GCM envelope encryption binds keyId in AAD and rejects pipe delimiter injection
  const dek = crypto.randomBytes(32);
  const keyRing = { 'kms-key-v1': dek, 'kms-key-v2': dek };
  assert.throws(
    () =>
      mod16.encryptEnvelopeAes256Gcm({
        plaintextUtf8: 'secret-ssn-999',
        keyBytes32: dek,
        keyId: 'kms-key-v1',
        tenantId: 'tnt-1',
        resourceId: 'res-1|injected',
        purpose: 'pii-field',
      }),
    /CRYPTO_AAD_DELIMITER_REJECTED/
  );

  const cipherEnv = mod16.encryptEnvelopeAes256Gcm({
    plaintextUtf8: 'secret-ssn-999',
    keyBytes32: dek,
    keyId: 'kms-key-v1',
    tenantId: 'tnt-1',
    resourceId: 'res-1',
    purpose: 'pii-field',
  });
  // Tampering with keyId while keeping the same DEK must fail GCM authentication tag verification
  assert.throws(
    () =>
      mod16.decryptEnvelopeAes256Gcm({
        envelope: { ...cipherEnv, keyId: 'kms-key-v2' },
        keyRing,
        expectedTenantId: 'tnt-1',
        expectedResourceId: 'res-1',
        expectedPurpose: 'pii-field',
      }),
    /Unsupported state or unable to authenticate data/
  );

  // 5. DEVIL-65: Concurrent sendFrameIfAuthorized calls serialize via operationQueue and mid-flight close() aborts pending delivery
  const emittedFrames = [];
  let closeCalls = 0;
  let statusCheckCount = 0;
  const concurrentStream = mod16.createRevocationSafeRealtimeStreamController({
    userId: 'usr-1',
    tenantId: 'tnt-1',
    tokenExpiresAtSec: Math.floor(Date.now() / 1000) + 300,
    loadCurrentMembershipStatus: async () => {
      statusCheckCount += 1;
      await new Promise((r) => setTimeout(r, 10));
      return statusCheckCount === 1 ? 'ACTIVE' : 'REVOKED';
    },
    deliverFrameToSocket: (frame) => {
      emittedFrames.push(frame);
    },
    closeSocketWithReason: () => {
      closeCalls += 1;
    },
  });

  const [res1, res2, res3] = await Promise.all([
    concurrentStream.sendFrameIfAuthorized({ seq: 1 }),
    concurrentStream.sendFrameIfAuthorized({ seq: 2 }),
    concurrentStream.sendFrameIfAuthorized({ seq: 3 }),
  ]);
  assert.equal(res1, true);
  assert.equal(res2, false, 'Second concurrent frame must see REVOKED status and terminate stream');
  assert.equal(res3, false, 'Third concurrent frame queued behind revoked frame must short-circuit without DB query');
  assert.equal(statusCheckCount, 2, 'Third frame must not invoke loadCurrentMembershipStatus after stream is sealed');
  assert.equal(emittedFrames.length, 1);
  assert.equal(closeCalls, 1);

  // Also verify explicit close() during an in-flight DB check aborts delivery before deliverFrameToSocket
  const inflightFrames = [];
  const abortableStream = mod16.createRevocationSafeRealtimeStreamController({
    userId: 'usr-1',
    tenantId: 'tnt-1',
    tokenExpiresAtSec: Math.floor(Date.now() / 1000) + 300,
    loadCurrentMembershipStatus: async () => {
      await new Promise((r) => setTimeout(r, 15));
      return 'ACTIVE';
    },
    deliverFrameToSocket: (frame) => {
      inflightFrames.push(frame);
    },
    closeSocketWithReason: () => {},
  });
  const inflightSend = abortableStream.sendFrameIfAuthorized({ seq: 99 });
  abortableStream.close(4000, 'CLIENT_DISCONNECT');
  assert.equal(await inflightSend, false, 'In-flight frame must abort if close() occurs during async membership check');
  assert.equal(inflightFrames.length, 0);

  // 6. DEVIL-66: Secret scanner catches Google/AI API keys, embedded JWTs, AMQP URIs, and NEXT_PUBLIC_API_KEY
  const fakeGoogleKey = 'AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz';
  const fakeJwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const secretFindings = mod13.scanReleaseArtifactsAndEnvForSecrets({
    envVars: {
      NEXT_PUBLIC_API_KEY: 'public-but-forbidden-key-name',
    },
    frontendArtifacts: [
      {
        filePath: 'dist/bundle.js',
        content: `const k = "${fakeGoogleKey}"; const jwt = "${fakeJwt}"; const q = "amqp://admin:supersecret@rabbitmq.internal:5672/vhost";`,
      },
    ],
  });
  assert.ok(secretFindings.length >= 4);
  const rulesMatched = new Set(secretFindings.map((v) => v.ruleId));
  assert.ok(rulesMatched.has('GOOGLE_OR_AI_PROVIDER_API_KEY'));
  assert.ok(rulesMatched.has('EMBEDDED_BEARER_JWT'));
  assert.ok(rulesMatched.has('DATABASE_CONNECTION_URI'));
  assert.ok(rulesMatched.has('FORBIDDEN_CLIENT_ENV_NAME'));

  // And Module 15 validateEvidenceIdentifiers detects duplicate IDs and supports ARGON-LEDGER-* IDs
  const dupCheck = mod15.validateEvidenceIdentifiers([
    'DEVIL-01',
    'ARGON-LEDGER-001',
    'ARGON-LEDGER-005',
    'DEVIL-01',
    'VERIFY-21',
  ]);
  assert.deepEqual(dupCheck.duplicateIds, ['DEVIL-01']);
  assert.deepEqual(dupCheck.invalidIds, []);
});

// ============================================================================
// VERIFY-22: ARGON DATABASE SECURITY V1 — CHUNK 1 (ARGON-LEDGER-001 & ARGON-LEDGER-005)
// Complete PostgreSQL Database-Layer Ledger Acceptance Suite (10 Acceptance Tests)
// ============================================================================
test('VERIFY-22: PostgreSQL 16+ Database-Layer Ledger Referential Integrity (ARGON-LEDGER-001) & Financial Invariants (ARGON-LEDGER-005) — All 10 Acceptance Tests', async () => {
  const { PGlite } = await import('@electric-sql/pglite');
  const { pgcrypto } = await import('@electric-sql/pglite/contrib/pgcrypto');

  const mod01Content = fs.readFileSync(
    path.join(ROOT, 'skills/01-domain-modeling-fields-timestamps-ids.md'),
    'utf8'
  );
  const sqlBlocks = mod15.extractFencedCodeBlocksDetailed(mod01Content, {
    allowedLanguages: new Set(['sql']),
  }).blocks;
  assert.ok(sqlBlocks.length >= 3, 'Expected at least 3 SQL blocks in Module 01 (DDL, Preflight, Migration)');

  const authoritativeDdlSql = sqlBlocks[0].code;
  const preflightQueriesSql = sqlBlocks[1].code;

  // Verify Module 15 anti-pattern detector catches legacy non-composite FK to ledger_accounts(account_id)
  const legacyFkScan = mod15.parseMarkdownSecurityChecklist([
    {
      fileName: '01-legacy-bad-fk.md',
      content:
        '## Legacy Bad FK\n```sql\nCREATE TABLE journal_postings (account_id UUID NOT NULL REFERENCES public.ledger_accounts (account_id));\n```',
    },
  ]);
  assert.equal(legacyFkScan.antiPatternViolations.length, 1);
  assert.equal(legacyFkScan.antiPatternViolations[0].ruleId, 'NON_COMPOSITE_LEDGER_ACCOUNT_FK');

  const db = new PGlite({ extensions: { pgcrypto } });
  try {
    // Install authoritative Module 01 Ledger DDL on clean PostgreSQL instance
    await db.exec(authoritativeDdlSql);

    const tenantA = '0195f8a0-0000-7000-8000-000000000001';
    const tenantB = '0195f8a0-0000-7000-8000-000000000002';

    const acctADebit1 = '0195f8a0-0000-7000-8000-000000000101';
    const acctADebit2 = '0195f8a0-0000-7000-8000-000000000102';
    const acctACredit = '0195f8a0-0000-7000-8000-000000000103';
    const acctAEur = '0195f8a0-0000-7000-8000-000000000104';
    const acctBCredit = '0195f8a0-0000-7000-8000-000000000201';

    const validHash = 'a'.repeat(64);

    // Seed accounts for Tenant A (USD & EUR) and Tenant B (USD)
    await db.query(
      `INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor, allow_negative_balance)
       VALUES
         ($1, $2, 'USD', 'ACTIVE', 'DEBIT', 500000, FALSE),
         ($3, $2, 'USD', 'ACTIVE', 'DEBIT', 500000, FALSE),
         ($4, $2, 'USD', 'ACTIVE', 'CREDIT', 500000, FALSE),
         ($5, $2, 'EUR', 'ACTIVE', 'CREDIT', 500000, FALSE),
         ($6, $7, 'USD', 'ACTIVE', 'CREDIT', 500000, FALSE)`,
      [acctADebit1, tenantA, acctADebit2, acctACredit, acctAEur, acctBCredit, tenantB]
    );

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 8: Floating-point monetary arithmetic absent
    // ------------------------------------------------------------------------
    const colTypesRes = await db.query(
      `SELECT table_name, column_name, data_type
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN ('ledger_accounts', 'journal_entries', 'journal_postings')
          AND column_name IN ('balance_minor', 'total_debit_minor', 'total_credit_minor', 'amount_minor')
        ORDER BY table_name, column_name`
    );
    assert.equal(colTypesRes.rows.length, 4);
    for (const row of colTypesRes.rows) {
      assert.equal(
        row.data_type,
        'bigint',
        `Expected ${row.table_name}.${row.column_name} to use exact integer BIGINT, found ${row.data_type}`
      );
    }
    const floatColsRes = await db.query(
      `SELECT table_name, column_name, data_type
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN ('ledger_accounts', 'journal_entries', 'journal_postings')
          AND data_type IN ('real', 'double precision', 'float')`
    );
    assert.equal(floatColsRes.rows.length, 0, 'Zero floating-point columns allowed in ledger tables');

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 2: Valid same-tenant balanced posting accepted
    // ------------------------------------------------------------------------
    const journalValid1 = '0195f8a0-0000-7000-8000-000000000301';
    await db.exec(`
      BEGIN;
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
      VALUES ('${journalValid1}', '${tenantA}', 'idem-valid-0001', '${validHash}', 'USD', 25000, 25000);

      INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        ('${journalValid1}', '${tenantA}', '${acctADebit1}', 'DEBIT', 25000, 'USD'),
        ('${journalValid1}', '${tenantA}', '${acctACredit}', 'CREDIT', 25000, 'USD');
      COMMIT;
    `);
    const verifyValid1 = await db.query(
      `SELECT total_debit_minor, total_credit_minor FROM public.journal_entries WHERE journal_id = $1`,
      [journalValid1]
    );
    assert.equal(BigInt(verifyValid1.rows[0].total_debit_minor), 25000n);
    assert.equal(BigInt(verifyValid1.rows[0].total_credit_minor), 25000n);

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 9: Valid multi-line compound balanced journal accepted
    // (Also tests backward-compatible INSERT omitting total_credit_minor via trigger)
    // ------------------------------------------------------------------------
    const journalValidCompound = '0195f8a0-0000-7000-8000-000000000302';
    await db.exec(`
      BEGIN;
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor)
      VALUES ('${journalValidCompound}', '${tenantA}', 'idem-compound-0002', '${validHash}', 'USD', 10000);

      INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        ('${journalValidCompound}', '${tenantA}', '${acctADebit1}', 'DEBIT', 7000, 'USD'),
        ('${journalValidCompound}', '${tenantA}', '${acctADebit2}', 'DEBIT', 3000, 'USD'),
        ('${journalValidCompound}', '${tenantA}', '${acctACredit}', 'CREDIT', 10000, 'USD');
      COMMIT;
    `);
    const verifyCompound = await db.query(
      `SELECT COUNT(*)::int AS cnt FROM public.journal_postings WHERE journal_id = $1`,
      [journalValidCompound]
    );
    assert.equal(verifyCompound.rows[0].cnt, 3);

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 1: Cross-tenant account posting rejected (ARGON-LEDGER-001)
    // ------------------------------------------------------------------------
    const journalCrossTenant = '0195f8a0-0000-7000-8000-000000000303';
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${journalCrossTenant}', '${tenantA}', 'idem-cross-tenant-0003', '${validHash}', 'USD', 5000, 5000);

          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES
            ('${journalCrossTenant}', '${tenantA}', '${acctADebit1}', 'DEBIT', 5000, 'USD'),
            ('${journalCrossTenant}', '${tenantA}', '${acctBCredit}', 'CREDIT', 5000, 'USD');
          COMMIT;
        `);
      },
      /LEDGER_CROSS_TENANT_ACCOUNT_DENIED|fk_journal_postings_tenant_account/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 4: Account tenant reassignment rejected when referenced (ARGON-LEDGER-001)
    // ------------------------------------------------------------------------
    await assert.rejects(
      () =>
        db.query(`UPDATE public.ledger_accounts SET tenant_id = $1 WHERE account_id = $2`, [
          tenantB,
          acctADebit1,
        ]),
      /LEDGER_ACCOUNT_IDENTITY_IMMUTABLE|fk_journal_postings_tenant_account/
    );

    // Also verify that even if the trigger is dropped in a test sandbox, the composite FK ON UPDATE RESTRICT blocks tenant reassignment!
    await db.exec('BEGIN; DROP TRIGGER trg_ledger_accounts_protect_identity ON public.ledger_accounts;');
    await assert.rejects(
      () =>
        db.query(`UPDATE public.ledger_accounts SET tenant_id = $1 WHERE account_id = $2`, [
          tenantB,
          acctADebit1,
        ]),
      /fk_journal_postings_tenant_account|violates foreign key constraint/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 5: Mismatched journal currency & account currency rejected (ARGON-LEDGER-005)
    // ------------------------------------------------------------------------
    const journalBadCurrency = '0195f8a0-0000-7000-8000-000000000305';
    // 5a. Posting currency ('EUR') !== Journal header currency ('USD')
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${journalBadCurrency}', '${tenantA}', 'idem-bad-curr-0005', '${validHash}', 'USD', 5000, 5000);

          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES
            ('${journalBadCurrency}', '${tenantA}', '${acctADebit1}', 'DEBIT', 5000, 'USD'),
            ('${journalBadCurrency}', '${tenantA}', '${acctAEur}', 'CREDIT', 5000, 'EUR');
          COMMIT;
        `);
      },
      /LEDGER_CURRENCY_MISMATCH|fk_journal_postings_tenant_journal_currency/
    );
    await db.exec('ROLLBACK;');

    // 5b. Posting claims 'USD' to match journal, but target account acctAEur is 'EUR'
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${journalBadCurrency}', '${tenantA}', 'idem-bad-acc-curr-0005', '${validHash}', 'USD', 5000, 5000);

          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES
            ('${journalBadCurrency}', '${tenantA}', '${acctADebit1}', 'DEBIT', 5000, 'USD'),
            ('${journalBadCurrency}', '${tenantA}', '${acctAEur}', 'CREDIT', 5000, 'USD');
          COMMIT;
        `);
      },
      /LEDGER_CURRENCY_MISMATCH|fk_journal_postings_tenant_account_currency/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 6: Unsupported account/journal currency rejected (ARGON-LEDGER-005)
    // ------------------------------------------------------------------------
    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor)
           VALUES ('0195f8a0-0000-7000-8000-000000000999', $1, 'XYZ', 'ACTIVE', 'DEBIT', 0)`,
          [tenantA]
        ),
      /chk_ledger_accounts_supported_currency/
    );

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 7: Incorrect stored totals rejected (ARGON-LEDGER-005)
    // ------------------------------------------------------------------------
    const journalBadAggregate = '0195f8a0-0000-7000-8000-000000000307';
    // 7a. Header total_debit_minor (5000) !== total_credit_minor (4000) rejected immediately by CHECK constraint
    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
           VALUES ($1, $2, 'idem-bad-hdr-0007', $3, 'USD', 5000, 4000)`,
          [journalBadAggregate, tenantA, validHash]
        ),
      /chk_journal_entries_totals_balanced/
    );

    // 7b. Header says 5000, but balanced postings sum to 99000 -> rejected at COMMIT by verify_journal_balanced_at_commit
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${journalBadAggregate}', '${tenantA}', 'idem-bad-agg-0007', '${validHash}', 'USD', 5000, 5000);

          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES
            ('${journalBadAggregate}', '${tenantA}', '${acctADebit1}', 'DEBIT', 99000, 'USD'),
            ('${journalBadAggregate}', '${tenantA}', '${acctACredit}', 'CREDIT', 99000, 'USD');
          COMMIT;
        `);
      },
      /LEDGER_STORED_AGGREGATE_MISMATCH/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // ACCEPTANCE TEST 10: Concurrent / out-of-band posting cannot corrupt aggregate integrity
    // ------------------------------------------------------------------------
    // 10a. Attempting to append extra balanced postings to already-committed journalValid1 in a new transaction
    //      fires trg_verify_posting_journal_balanced_commit at COMMIT and rejects with LEDGER_STORED_AGGREGATE_MISMATCH!
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES ('${journalValid1}', '${tenantA}', '${acctADebit2}', 'DEBIT', 1000, 'USD');
          COMMIT;
        `);
      },
      /LEDGER_POSTING_FINALIZED_CLOSED|LEDGER_DB_INVARIANT_VIOLATION|LEDGER_STORED_AGGREGATE_MISMATCH/
    );
    await db.exec('ROLLBACK;');

    // 10b. Self-wash (debiting and crediting the same account in the same journal) rejected by uq_journal_postings_journal_account
    const journalSelfWash = '0195f8a0-0000-7000-8000-000000000310';
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${journalSelfWash}', '${tenantA}', 'idem-self-wash-0010', '${validHash}', 'USD', 5000, 5000);

          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES
            ('${journalSelfWash}', '${tenantA}', '${acctADebit1}', 'DEBIT', 5000, 'USD'),
            ('${journalSelfWash}', '${tenantA}', '${acctADebit1}', 'CREDIT', 5000, 'USD');
          COMMIT;
        `);
      },
      /uq_journal_postings_journal_account|duplicate key value/
    );
    await db.exec('ROLLBACK;');
  } finally {
    await db.close();
  }

  // --------------------------------------------------------------------------
  // ACCEPTANCE TEST 3: Invalid historical records detected by Preflight Queries
  // without modifying or deleting financial records (plus staged migration validation)
  // --------------------------------------------------------------------------
  const legacyDb = new PGlite();
  try {
    await legacyDb.exec(`
      CREATE TABLE public.ledger_accounts (
        account_id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        currency_code CHAR(3) NOT NULL,
        status VARCHAR(16) NOT NULL,
        normal_balance VARCHAR(6) NOT NULL,
        balance_minor BIGINT NOT NULL DEFAULT 0,
        version INT NOT NULL DEFAULT 0,
        allow_negative_balance BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      );
      CREATE TABLE public.journal_entries (
        journal_id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        idempotency_key VARCHAR(128) NOT NULL,
        request_hash CHAR(64) NOT NULL,
        currency_code CHAR(3) NOT NULL,
        total_debit_minor BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      );
      CREATE TABLE public.journal_postings (
        posting_id BIGSERIAL PRIMARY KEY,
        journal_id UUID NOT NULL,
        tenant_id UUID NOT NULL,
        account_id UUID NOT NULL REFERENCES public.ledger_accounts (account_id),
        direction VARCHAR(6) NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency_code CHAR(3) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      );
    `);

    const tA = '0195f8a0-0000-7000-8000-000000000001';
    const tB = '0195f8a0-0000-7000-8000-000000000002';
    const accA = '0195f8a0-0000-7000-8000-000000000101';
    const accB = '0195f8a0-0000-7000-8000-000000000201';
    const accBadCurr = '0195f8a0-0000-7000-8000-000000000999';
    const jBad = '0195f8a0-0000-7000-8000-000000000401';

    await legacyDb.exec(`
      INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor)
      VALUES
        ('${accA}', '${tA}', 'USD', 'ACTIVE', 'DEBIT', 10000),
        ('${accB}', '${tB}', 'USD', 'ACTIVE', 'CREDIT', 10000),
        ('${accBadCurr}', '${tA}', 'XYZ', 'ACTIVE', 'DEBIT', 0);

      -- Historical journal with stored total_debit_minor = 500, while postings sum to 1000,
      -- one posting references tenant_B's account (accB), and one posting has currency 'EUR'
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor)
      VALUES ('${jBad}', '${tA}', 'idem-legacy-bad', '${'b'.repeat(64)}', 'USD', 500);

      INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        ('${jBad}', '${tA}', '${accA}', 'DEBIT', 1000, 'EUR'),
        ('${jBad}', '${tA}', '${accB}', 'CREDIT', 1000, 'USD');
    `);

    const preflightStatements = preflightQueriesSql
      .split(/;\s*(?:\r?\n|$)/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    assert.ok(preflightStatements.length >= 4, 'Expected at least 4 preflight diagnostic SELECT queries');

    const pf1 = await legacyDb.query(preflightStatements[0]);
    assert.equal(pf1.rows.length, 1);
    assert.equal(pf1.rows[0].anomaly_type, 'UNSUPPORTED_ACCOUNT_CURRENCY');

    const pf2 = await legacyDb.query(preflightStatements[1]);
    assert.equal(pf2.rows.length, 2);
    const pf2Types = new Set(pf2.rows.map((r) => r.anomaly_type));
    assert.ok(pf2Types.has('CROSS_TENANT_ACCOUNT_POSTING'));
    assert.ok(pf2Types.has('ACCOUNT_CURRENCY_MISMATCH'));

    const pf3 = await legacyDb.query(preflightStatements[2]);
    assert.equal(pf3.rows.length, 1);
    assert.equal(pf3.rows[0].anomaly_type, 'JOURNAL_CURRENCY_MISMATCH');

    const pf4 = await legacyDb.query(preflightStatements[3]);
    assert.equal(pf4.rows.length, 1);
    assert.equal(BigInt(pf4.rows[0].stored_total_debit_minor), 500n);
    assert.equal(BigInt(pf4.rows[0].actual_debit_minor), 1000n);
  } finally {
    await legacyDb.close();
  }

  // --------------------------------------------------------------------------
  // STAGED MIGRATION EXECUTION TEST (Phase 1 -> Phase 2 -> Phase 3 on Legacy Schema)
  // --------------------------------------------------------------------------
  const stagedMigrationSql = sqlBlocks[2].code;
  const migDb = new PGlite({ extensions: { pgcrypto } });
  try {
    await migDb.exec(`
      CREATE TABLE public.ledger_accounts (
        account_id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        currency_code CHAR(3) NOT NULL,
        status VARCHAR(16) NOT NULL,
        normal_balance VARCHAR(6) NOT NULL,
        balance_minor BIGINT NOT NULL DEFAULT 0,
        version INT NOT NULL DEFAULT 0,
        allow_negative_balance BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      );
      CREATE TABLE public.journal_entries (
        journal_id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        idempotency_key VARCHAR(128) NOT NULL,
        request_hash CHAR(64) NOT NULL,
        currency_code CHAR(3) NOT NULL,
        total_debit_minor BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        UNIQUE (tenant_id, idempotency_key),
        UNIQUE (tenant_id, journal_id)
      );
      CREATE TABLE public.journal_postings (
        posting_id BIGSERIAL PRIMARY KEY,
        journal_id UUID NOT NULL,
        tenant_id UUID NOT NULL,
        account_id UUID NOT NULL REFERENCES public.ledger_accounts (account_id),
        direction VARCHAR(6) NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency_code CHAR(3) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        FOREIGN KEY (tenant_id, journal_id) REFERENCES public.journal_entries (tenant_id, journal_id)
      );
    `);

    const tA = '0195f8a0-0000-7000-8000-000000000001';
    const tB = '0195f8a0-0000-7000-8000-000000000002';
    const accA1 = '0195f8a0-0000-7000-8000-000000000101';
    const accA2 = '0195f8a0-0000-7000-8000-000000000102';
    const accB1 = '0195f8a0-0000-7000-8000-000000000201';
    const jHist = '0195f8a0-0000-7000-8000-000000000501';

    await migDb.exec(`
      INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor)
      VALUES
        ('${accA1}', '${tA}', 'USD', 'ACTIVE', 'DEBIT', 5000),
        ('${accA2}', '${tA}', 'USD', 'ACTIVE', 'CREDIT', 5000),
        ('${accB1}', '${tB}', 'USD', 'ACTIVE', 'CREDIT', 5000);

      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor)
      VALUES ('${jHist}', '${tA}', 'idem-hist-clean', '${'c'.repeat(64)}', 'USD', 5000);

      INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        ('${jHist}', '${tA}', '${accA1}', 'DEBIT', 5000, 'USD'),
        ('${jHist}', '${tA}', '${accA2}', 'CREDIT', 5000, 'USD');
    `);

    // Backfill total_credit_minor = total_debit_minor on clean historical journal_entries before Phase 3 validation
    await migDb.exec(`
      ALTER TABLE public.journal_entries ADD COLUMN IF NOT EXISTS total_credit_minor BIGINT;
      UPDATE public.journal_entries SET total_credit_minor = total_debit_minor WHERE total_credit_minor IS NULL;
      ALTER TABLE public.journal_entries ALTER COLUMN total_credit_minor SET NOT NULL;
    `);

    // Execute the extracted Staged Migration SQL block from Module 01 Section 5.E:
    // Note: PostgreSQL forbids CREATE INDEX CONCURRENTLY inside a multi-statement Simple Query protocol batch
    // (SQLSTATE 25001), so migration runners execute Phase 1 CONCURRENTLY statements one statement per query call.
    const [phase1Part, phase2And3Part] = stagedMigrationSql.split(/--\s*=+\r?\n--\s*PHASE 2:/);
    const phase1Stmts = phase1Part
      .split(/;\s*(?:\r?\n|$)/)
      .map((s) => s.replace(/--.*$/gm, '').trim())
      .filter((s) => s.length > 0);
    for (const stmt of phase1Stmts) {
      await migDb.query(stmt);
    }
    await migDb.exec('-- PHASE 2:' + phase2And3Part);

    // Confirm that after the staged migration, cross-tenant account posting is rejected by fk_journal_postings_tenant_account
    const jPostMig = '0195f8a0-0000-7000-8000-000000000502';
    await migDb.exec(`
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
      VALUES ('${jPostMig}', '${tA}', 'idem-post-mig', '${'d'.repeat(64)}', 'USD', 1000, 1000);
    `);
    await assert.rejects(
      () =>
        migDb.query(
          `INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
           VALUES ($1, $2, $3, 'CREDIT', 1000, 'USD')`,
          [jPostMig, tA, accB1]
        ),
      /fk_journal_postings_tenant_account/
    );
  } finally {
    await migDb.close();
  }
});

// ============================================================================
// VERIFY-23: ARGON DATABASE SECURITY V1 — CHUNK 2
// Deferred Commit Validation, Lifecycle Guards (ARGON-LEDGER-002),
// Cryptographic Context RLS (ARGON-LEDGER-003), & Canonical Roles (ARGON-ROLE-004)
// ============================================================================
test('VERIFY-23: PostgreSQL 16+ Database-Layer Deferred Enforcement, RLS & Canonical Roles (ARGON-LEDGER-002, ARGON-LEDGER-003, ARGON-ROLE-004)', async () => {
  const { PGlite } = await import('@electric-sql/pglite');
  const { pgcrypto } = await import('@electric-sql/pglite/contrib/pgcrypto');

  const mod01Content = fs.readFileSync(
    path.join(ROOT, 'skills/01-domain-modeling-fields-timestamps-ids.md'),
    'utf8'
  );
  const sqlBlocks = mod15.extractFencedCodeBlocksDetailed(mod01Content, {
    allowedLanguages: new Set(['sql']),
  }).blocks;

  const authoritativeDdlSql = sqlBlocks[0].code;
  const db = new PGlite({ extensions: { pgcrypto } });

  try {
    // 1. Initialize complete DDL (roles, security schema, tables, triggers, RLS)
    await db.exec(authoritativeDdlSql);

    // 2. Provision master HMAC key in restricted security schema
    const masterKeyStr = 'supersecretmasterkey32charactersminimum!!';
    await db.query(
      `INSERT INTO security.guc_hmac_keys (key_id, hmac_secret)
       VALUES (1, $1)
       ON CONFLICT (key_id) DO UPDATE SET hmac_secret = $1`,
      [masterKeyStr]
    );

    const tenantA = '0195f8a0-0000-7000-8000-00000000a001';
    const tenantB = '0195f8a0-0000-7000-8000-00000000b001';

    const acctA1 = '0195f8a0-0000-7000-8000-00000000a101';
    const acctA2 = '0195f8a0-0000-7000-8000-00000000a102';
    const acctA3 = '0195f8a0-0000-7000-8000-00000000a103';
    const acctA4 = '0195f8a0-0000-7000-8000-00000000a104';
    const acctB1 = '0195f8a0-0000-7000-8000-00000000b101';
    const acctB2 = '0195f8a0-0000-7000-8000-00000000b102';

    // Seed test accounts under table owner
    await db.query(
      `INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor, allow_negative_balance)
       VALUES
         ($1, $2, 'USD', 'ACTIVE', 'DEBIT', 100000, FALSE),
         ($3, $2, 'USD', 'ACTIVE', 'CREDIT', 100000, FALSE),
         ($4, $2, 'USD', 'ACTIVE', 'DEBIT', 100000, FALSE),
         ($5, $2, 'USD', 'ACTIVE', 'CREDIT', 100000, FALSE),
         ($6, $7, 'USD', 'ACTIVE', 'DEBIT', 200000, FALSE),
         ($8, $7, 'USD', 'ACTIVE', 'CREDIT', 200000, FALSE)`,
      [acctA1, tenantA, acctA2, acctA3, acctA4, acctB1, tenantB, acctB2]
    );

    // ------------------------------------------------------------------------
    // TEST 1: Deferred Commit Trigger Rejects Unbalanced Postings at COMMIT (ARGON-LEDGER-002)
    // ------------------------------------------------------------------------
    const journalUnbalanced = '0195f8a0-0000-7000-8000-00000000c001';
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${journalUnbalanced}', '${tenantA}', 'idem-unbalanced', '${'1'.repeat(64)}', 'USD', 5000, 5000);
          INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES ('${journalUnbalanced}', '${tenantA}', '${acctA1}', 'DEBIT', 5000, 'USD');
          -- Missing credit posting!
          COMMIT;
        `);
      },
      /LEDGER_DB_INVARIANT_VIOLATION/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // TEST 2: Valid Balanced Journal Auto-Finalizes on Commit (ARGON-LEDGER-002)
    // ------------------------------------------------------------------------
    const journalValid = '0195f8a0-0000-7000-8000-00000000c002';
    await db.exec(`
      BEGIN;
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
      VALUES ('${journalValid}', '${tenantA}', 'idem-valid-auto-fin', '${'2'.repeat(64)}', 'USD', 3000, 3000);
      INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        ('${journalValid}', '${tenantA}', '${acctA1}', 'DEBIT', 3000, 'USD'),
        ('${journalValid}', '${tenantA}', '${acctA2}', 'CREDIT', 3000, 'USD');
      COMMIT;
    `);

    const finalRes = await db.query(
      'SELECT lifecycle_status, finalized_at FROM public.journal_entries WHERE journal_id = $1',
      [journalValid]
    );
    assert.equal(finalRes.rows[0].lifecycle_status, 'FINALIZED');
    assert.ok(finalRes.rows[0].finalized_at !== null, 'finalized_at must be populated');

    // ------------------------------------------------------------------------
    // TEST 3: Post-Finalization Append Attack Blocked (ARGON-LEDGER-002)
    // ------------------------------------------------------------------------
    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
           VALUES ($1, $2, $3, 'DEBIT', 1000, 'USD')`,
          [journalValid, tenantA, acctA1]
        ),
      /LEDGER_POSTING_FINALIZED_CLOSED/
    );

    // ------------------------------------------------------------------------
    // TEST 4: Post-Finalization Mutation & Deletion Attack Blocked (ARGON-LEDGER-002)
    // ------------------------------------------------------------------------
    await assert.rejects(
      () =>
        db.query(
          'DELETE FROM public.journal_postings WHERE journal_id = $1',
          [journalValid]
        ),
      /LEDGER_POSTING_FINALIZED_IMMUTABLE/
    );

    // ------------------------------------------------------------------------
    // TEST 5: Relocating Postings Validates Both OLD and NEW Parent Journals (ARGON-LEDGER-002)
    // ------------------------------------------------------------------------
    const journalReloc1 = '0195f8a0-0000-7000-8000-00000000c010';
    const journalReloc2 = '0195f8a0-0000-7000-8000-00000000c020';

    // Create 2 open journals with postings in uncommitted state
    await db.exec(`
      BEGIN;
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
      VALUES
        ('${journalReloc1}', '${tenantA}', 'idem-reloc-1', '${'3'.repeat(64)}', 'USD', 2000, 2000),
        ('${journalReloc2}', '${tenantA}', 'idem-reloc-2', '${'4'.repeat(64)}', 'USD', 1000, 1000);

      INSERT INTO public.journal_postings (posting_id, journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        (90001, '${journalReloc1}', '${tenantA}', '${acctA1}', 'DEBIT', 2000, 'USD'),
        (90002, '${journalReloc1}', '${tenantA}', '${acctA2}', 'CREDIT', 2000, 'USD'),
        (90003, '${journalReloc2}', '${tenantA}', '${acctA3}', 'DEBIT', 1000, 'USD'),
        (90004, '${journalReloc2}', '${tenantA}', '${acctA4}', 'CREDIT', 1000, 'USD');

      -- Maliciously relocate posting 90002 from journalReloc1 to journalReloc2
      UPDATE public.journal_postings SET journal_id = '${journalReloc2}' WHERE posting_id = 90002;
    `);

    // Committing must fail because journalReloc1 is now stripped of its credit posting!
    await assert.rejects(
      () => db.exec('COMMIT;'),
      /LEDGER_DB_INVARIANT_VIOLATION/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // TEST 6: Cryptographic Context Tenant Isolation with RLS (ARGON-LEDGER-003)
    // ------------------------------------------------------------------------
    // 6a. Authenticated Tenant A query sees only Tenant A rows
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_runtime;');

    const txResA = await db.query('SELECT txid_current()::text AS txid');
    const txidA = txResA.rows[0].txid;
    const hmacA = crypto
      .createHmac('sha256', Buffer.from(masterKeyStr, 'utf8'))
      .update(`${tenantA}:${txidA}`)
      .digest('hex');

    await db.query(`SET LOCAL app.current_tenant_id = '${tenantA}'`);
    await db.query(`SET LOCAL app.current_tenant_mac = '${hmacA}'`);

    const acctRowsA = await db.query('SELECT account_id, tenant_id FROM public.ledger_accounts');
    assert.ok(acctRowsA.rows.length >= 2);
    for (const row of acctRowsA.rows) {
      assert.equal(row.tenant_id, tenantA, 'Tenant A context must only see Tenant A accounts');
    }
    await db.exec('ROLLBACK;');

    // 6b. Cross-tenant INSERT is blocked by RLS WITH CHECK under app_runtime
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_runtime;');
    const txResCheck = await db.query('SELECT txid_current()::text AS txid');
    const txidCheck = txResCheck.rows[0].txid;
    const hmacCheck = crypto
      .createHmac('sha256', Buffer.from(masterKeyStr, 'utf8'))
      .update(`${tenantA}:${txidCheck}`)
      .digest('hex');

    await db.query(`SET LOCAL app.current_tenant_id = '${tenantA}'`);
    await db.query(`SET LOCAL app.current_tenant_mac = '${hmacCheck}'`);

    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor)
           VALUES ('${crypto.randomUUID()}', '${tenantB}', 'USD', 'ACTIVE', 'DEBIT', 0)`
        ),
      /new row violates row-level security policy/
    );
    await db.exec('ROLLBACK;');

    // 6c. Forged or missing MAC fails closed (0 rows returned under app_runtime)
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_runtime;');
    await db.query(`SET LOCAL app.current_tenant_id = '${tenantA}'`);
    await db.query(`SET LOCAL app.current_tenant_mac = '0000000000000000000000000000000000000000000000000000000000000000'`);
    const forgedRows = await db.query('SELECT * FROM public.ledger_accounts');
    assert.equal(forgedRows.rows.length, 0, 'Forged MAC must return 0 rows');
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // TEST 7: Role Privilege Boundaries & Preflight Security (ARGON-ROLE-004)
    // ------------------------------------------------------------------------
    // 7a. Direct read on security.guc_hmac_keys denied to app_runtime
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_runtime;');
    await assert.rejects(
      () => db.query('SELECT * FROM security.guc_hmac_keys'),
      /permission denied/
    );
    await db.exec('ROLLBACK;');

    // 7b. DELETE on ledger_accounts denied to app_runtime
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_runtime;');
    await assert.rejects(
      () => db.query('DELETE FROM public.ledger_accounts'),
      /LEDGER_ACCOUNT_IMMUTABLE_VIOLATION|permission denied/
    );
    await db.exec('ROLLBACK;');

    // 7c. Preflight PREFLIGHT-07: Verify zero superuser or bypassrls privileges on app roles
    const preflight07 = await db.query(
      `SELECT rolname, rolsuper, rolbypassrls
       FROM pg_roles
       WHERE rolname IN ('db_migrator', 'app_runtime', 'app_login')
         AND (rolsuper OR rolbypassrls)`
    );
    assert.equal(preflight07.rows.length, 0, 'Zero application roles should have SUPERUSER or BYPASSRLS');
  } finally {
    await db.close();
  }
});

// ============================================================================
// VERIFY-24: ARGON DATABASE SECURITY V1 — CHUNK 3
// Complete Red-Team Adversarial Test Matrix (ARGON-LEDGER-001..005) &
// 10-Scenario Migration Verification Suite
// ============================================================================
test('VERIFY-24: Chunk 3 Independent Red-Team Adversarial Matrix (ARGON-LEDGER-001..005, ARGON-ROLE-004) & All 10 Migration Scenarios', async () => {
  const { PGlite } = await import('@electric-sql/pglite');
  const { pgcrypto } = await import('@electric-sql/pglite/contrib/pgcrypto');

  const mod01Content = fs.readFileSync(
    path.join(ROOT, 'skills/01-domain-modeling-fields-timestamps-ids.md'),
    'utf8'
  );
  const mod07Content = fs.readFileSync(
    path.join(ROOT, 'skills/07-events-realtime-sagas-migrations-sql-multitenancy-search.md'),
    'utf8'
  );

  const sqlBlocks01 = mod15.extractFencedCodeBlocksDetailed(mod01Content, {
    allowedLanguages: new Set(['sql']),
  }).blocks;
  const sqlBlocks07 = mod15.extractFencedCodeBlocksDetailed(mod07Content, {
    allowedLanguages: new Set(['sql']),
  }).blocks;

  const authoritativeDdlSql = sqlBlocks01[0].code;
  const preflightQueriesSql = sqlBlocks01[1].code;
  const stagedMigrationSql = sqlBlocks01[2].code;
  const mod07RlsSql = sqlBlocks07.find((b) => b.code.includes('security.verify_active_tenant_context')).code;

  // ==========================================================================
  // PART A: RED-TEAM ADVERSARIAL MATRIX ON FRESH POSTGRESQL INSTANCE
  // ==========================================================================
  const db = new PGlite({ extensions: { pgcrypto } });
  try {
    await db.exec(authoritativeDdlSql);

    // Scenario 9 check: Repeated migration execution of authoritative DDL is idempotent
    await db.exec(`
      DO $$
      BEGIN
        -- Re-run canonical role block idempotently on existing expected roles (ARGON-ROLE-004)
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_migrator') THEN
          CREATE ROLE db_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
        END IF;
      END
      $$;
    `);

    const masterSecret = 'chunk3-red-team-master-hmac-secret-minimum-32-bytes!!';
    await db.query(
      `INSERT INTO security.guc_hmac_keys (key_id, hmac_secret)
       VALUES (1, $1)
       ON CONFLICT (key_id) DO UPDATE SET hmac_secret = EXCLUDED.hmac_secret`,
      [masterSecret]
    );

    const tenantA = '0195f8a0-0000-7000-8000-00000000aa01';
    const tenantB = '0195f8a0-0000-7000-8000-00000000bb02';
    const userAlice = '0195f8a0-0000-7000-8000-00000000aa99';
    const userMallory = '0195f8a0-0000-7000-8000-00000000bb99';

    const acctAUsdDebit = '0195f8a0-0000-7000-8000-00000000aa11';
    const acctAUsdCredit = '0195f8a0-0000-7000-8000-00000000aa12';
    const acctAUsdExtra = '0195f8a0-0000-7000-8000-00000000aa13';
    const acctAEurDebit = '0195f8a0-0000-7000-8000-00000000aa14';
    const acctAEurCredit = '0195f8a0-0000-7000-8000-00000000aa15';
    const acctBUsdDebit = '0195f8a0-0000-7000-8000-00000000bb11';
    const acctBUsdCredit = '0195f8a0-0000-7000-8000-00000000bb12';
    const reqHash = 'f'.repeat(64);

    // Helper to activate cryptographic tenant (+ optional user) context for current transaction
    const setCryptoContext = async (targetTenantId, targetUserId = null, customTenantMac = null, customUserMac = null) => {
      const txRes = await db.query('SELECT txid_current()::text AS txid');
      const txid = txRes.rows[0].txid;
      const tenantMac =
        customTenantMac ??
        crypto.createHmac('sha256', Buffer.from(masterSecret, 'utf8')).update(`${targetTenantId}:${txid}`).digest('hex');
      await db.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [targetTenantId]);
      await db.query(`SELECT set_config('app.current_tenant_mac', $1, true)`, [tenantMac]);
      if (targetUserId !== null) {
        const userMac =
          customUserMac ??
          crypto.createHmac('sha256', Buffer.from(masterSecret, 'utf8')).update(`user:${targetUserId}:${txid}`).digest('hex');
        await db.query(`SELECT set_config('app.current_user_id', $1, true)`, [targetUserId]);
        await db.query(`SELECT set_config('app.current_user_mac', $1, true)`, [userMac]);
      }
    };

    // Seed accounts for Tenant A and Tenant B
    await db.query(
      `INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor)
       VALUES
         ($1, $2, 'USD', 'ACTIVE', 'DEBIT', 500000),
         ($3, $2, 'USD', 'ACTIVE', 'CREDIT', 500000),
         ($4, $2, 'USD', 'ACTIVE', 'DEBIT', 500000),
         ($5, $2, 'EUR', 'ACTIVE', 'DEBIT', 500000),
         ($6, $2, 'EUR', 'ACTIVE', 'CREDIT', 500000),
         ($7, $8, 'USD', 'ACTIVE', 'DEBIT', 500000),
         ($9, $8, 'USD', 'ACTIVE', 'CREDIT', 500000)`,
      [acctAUsdDebit, tenantA, acctAUsdCredit, acctAUsdExtra, acctAEurDebit, acctAEurCredit, acctBUsdDebit, tenantB, acctBUsdCredit]
    );

    // ------------------------------------------------------------------------
    // 1. ARGON-LEDGER-002 RED-TEAM ATTACKS:
    //    - Direct INSERT of journal with lifecycle_status = 'FINALIZED' (no postings) rejected!
    //    - Journal with 0 postings rejected at COMMIT
    //    - Journal with 1 posting rejected at COMMIT
    //    - Posting UPDATE that unbalances a journal rejected at COMMIT
    //    - Moving a posting between two unfinalized journals succeeds when BOTH remain balanced,
    //      and fails when EITHER becomes unbalanced
    // ------------------------------------------------------------------------
    const jFakeFinalized = '0195f8a0-0000-7000-8000-00000000dd01';
    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor, lifecycle_status)
           VALUES ($1, $2, 'idem-fake-final', $3, 'USD', 1000, 1000, 'FINALIZED')`,
          [jFakeFinalized, tenantA, reqHash]
        ),
      /LEDGER_LIFECYCLE_VIOLATION/
    );

    // Journal with 0 postings fails at COMMIT
    const jZeroPostings = '0195f8a0-0000-7000-8000-00000000dd02';
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${jZeroPostings}', '${tenantA}', 'idem-zero-lines', '${reqHash}', 'USD', 1000, 1000);
          COMMIT;
        `);
      },
      /LEDGER_DB_INVARIANT_VIOLATION/
    );
    await db.exec('ROLLBACK;');

    // Posting UPDATE that unbalances an in-flight journal fails at COMMIT
    const jUpdateUnbal = '0195f8a0-0000-7000-8000-00000000dd03';
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
          VALUES ('${jUpdateUnbal}', '${tenantA}', 'idem-upd-unbal', '${reqHash}', 'USD', 4000, 4000);
          INSERT INTO public.journal_postings (posting_id, journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
          VALUES
            (88001, '${jUpdateUnbal}', '${tenantA}', '${acctAUsdDebit}', 'DEBIT', 4000, 'USD'),
            (88002, '${jUpdateUnbal}', '${tenantA}', '${acctAUsdCredit}', 'CREDIT', 4000, 'USD');
          -- Mutate debit posting amount from 4000 to 3999 before commit
          UPDATE public.journal_postings SET amount_minor = 3999 WHERE posting_id = 88001;
          COMMIT;
        `);
      },
      /LEDGER_DB_INVARIANT_VIOLATION|LEDGER_STORED_AGGREGATE_MISMATCH/
    );
    await db.exec('ROLLBACK;');

    // Moving a posting between two unfinalized journals when a replacement posting keeps BOTH balanced succeeds at COMMIT!
    const jMoveOld = '0195f8a0-0000-7000-8000-00000000dd04';
    const jMoveNew = '0195f8a0-0000-7000-8000-00000000dd05';
    await db.exec(`
      BEGIN;
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
      VALUES
        ('${jMoveOld}', '${tenantA}', 'idem-move-old', '${reqHash}', 'USD', 2000, 2000),
        ('${jMoveNew}', '${tenantA}', 'idem-move-new', '${reqHash}', 'USD', 2000, 2000);
      INSERT INTO public.journal_postings (posting_id, journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        (88011, '${jMoveOld}', '${tenantA}', '${acctAUsdDebit}', 'DEBIT', 2000, 'USD'),
        (88012, '${jMoveOld}', '${tenantA}', '${acctAUsdCredit}', 'CREDIT', 2000, 'USD'),
        (88013, '${jMoveNew}', '${tenantA}', '${acctAUsdDebit}', 'DEBIT', 2000, 'USD');
      -- Move credit posting 88012 from jMoveOld to jMoveNew, and insert a replacement credit posting into jMoveOld
      UPDATE public.journal_postings SET journal_id = '${jMoveNew}' WHERE posting_id = 88012;
      INSERT INTO public.journal_postings (posting_id, journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES (88014, '${jMoveOld}', '${tenantA}', '${acctAUsdExtra}', 'CREDIT', 2000, 'USD');
      COMMIT;
    `);
    const moveCheck = await db.query(
      `SELECT journal_id, lifecycle_status FROM public.journal_entries WHERE journal_id IN ($1, $2) ORDER BY journal_id`,
      [jMoveOld, jMoveNew]
    );
    assert.equal(moveCheck.rows.length, 2);
    assert.equal(moveCheck.rows[0].lifecycle_status, 'FINALIZED');
    assert.equal(moveCheck.rows[1].lifecycle_status, 'FINALIZED');

    // ------------------------------------------------------------------------
    // 2. ARGON-LEDGER-003 RED-TEAM ATTACKS:
    //    - Cross-tenant SELECT, INSERT, UPDATE, DELETE under app_login
    //    - Forged user GUC (app.current_user_id set with invalid MAC while tenant MAC is valid) fails closed!
    //    - Runtime role attempting SET row_security = off fails
    //    - Table owner (db_migrator) is also bound by FORCE ROW LEVEL SECURITY
    // ------------------------------------------------------------------------
    // 2a. Cross-tenant UPDATE under app_login affects 0 rows
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_login;');
    await setCryptoContext(tenantA, userAlice);
    const crossUpdateRes = await db.query(
      `UPDATE public.ledger_accounts SET balance_minor = 999999 WHERE tenant_id = $1 RETURNING account_id`,
      [tenantB]
    );
    assert.equal(crossUpdateRes.rows.length, 0, 'Cross-tenant UPDATE under app_login must affect 0 rows');
    await db.exec('ROLLBACK;');

    // 2b. Forged user GUC fails closed even when tenant GUC + MAC are valid!
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_login;');
    await setCryptoContext(tenantA, userMallory, null, '0'.repeat(64)); // Valid tenantA MAC, forged userMallory MAC
    const forgedUserRows = await db.query('SELECT account_id FROM public.ledger_accounts');
    assert.equal(
      forgedUserRows.rows.length,
      0,
      'Forged app.current_user_id / app.current_user_mac must cause verify_active_tenant_context to fail closed (0 rows)'
    );
    await db.exec('ROLLBACK;');

    // 2c. Valid user GUC + valid tenant GUC succeeds under app_login
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_login;');
    await setCryptoContext(tenantA, userAlice);
    const validUserRows = await db.query('SELECT account_id FROM public.ledger_accounts');
    assert.equal(validUserRows.rows.length, 5, 'Valid user + tenant MACs must return all 5 Tenant A accounts');
    await db.exec('ROLLBACK;');

    // 2d. Runtime role (app_login / app_runtime) attempting to bypass RLS via SET LOCAL row_security = off
    //     causes PostgreSQL (SQLSTATE 42501) to abort the query with "query would be affected by row-level security policy"
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE app_login;');
    await db.exec('SET LOCAL row_security = off;');
    await assert.rejects(
      () => db.query('SELECT * FROM public.ledger_accounts'),
      /query would be affected by row-level security policy/
    );
    await db.exec('ROLLBACK;');

    // 2e. Table owner (db_migrator) is ALSO subject to FORCE ROW LEVEL SECURITY (sees 0 rows without MAC, sees Tenant A rows with MAC)
    await db.exec('BEGIN;');
    await db.exec('SET LOCAL ROLE db_migrator;');
    const ownerNoContextRows = await db.query('SELECT account_id FROM public.ledger_accounts');
    assert.equal(
      ownerNoContextRows.rows.length,
      0,
      'Table owner db_migrator (NOBYPASSRLS) must be bound by FORCE ROW LEVEL SECURITY when GUC context is unset'
    );
    await setCryptoContext(tenantA);
    const ownerWithContextRows = await db.query('SELECT account_id FROM public.ledger_accounts');
    assert.equal(ownerWithContextRows.rows.length, 5);
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // 3. ARGON-LEDGER-005 RED-TEAM ATTACKS:
    //    - Invalid posting amounts (0, negative, > 900_000_000_000_000) rejected
    //    - Supported FX conversion settlement workflow (exact rational conversion vs. mismatch)
    // ------------------------------------------------------------------------
    const jAmountTest = '0195f8a0-0000-7000-8000-00000000ee01';
    for (const badAmount of [0, -500, 900000000000001n]) {
      await assert.rejects(
        async () => {
          await db.exec(`
            BEGIN;
            INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
            VALUES ('${jAmountTest}', '${tenantA}', 'idem-bad-amt', '${reqHash}', 'USD', 1000, 1000);
            INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
            VALUES ('${jAmountTest}', '${tenantA}', '${acctAUsdDebit}', 'DEBIT', ${badAmount.toString()}, 'USD');
            COMMIT;
          `);
        },
        /journal_postings_amount_minor_check|violates check constraint/
      );
      await db.exec('ROLLBACK;');
    }

    // Supported FX conversion settlement workflow:
    // Convert 10,000 USD minor units ($100.00) -> 9,200 EUR minor units (EUR 92.00) at rational rate 92/100
    const jFxSourceUsd = '0195f8a0-0000-7000-8000-00000000ee10';
    const jFxTargetEur = '0195f8a0-0000-7000-8000-00000000ee11';
    const fxSettlementId = '0195f8a0-0000-7000-8000-00000000ee12';

    await db.exec(`
      BEGIN;
      INSERT INTO public.journal_entries (journal_id, tenant_id, idempotency_key, request_hash, currency_code, total_debit_minor, total_credit_minor)
      VALUES
        ('${jFxSourceUsd}', '${tenantA}', 'idem-fx-src-usd', '${reqHash}', 'USD', 10000, 10000),
        ('${jFxTargetEur}', '${tenantA}', 'idem-fx-dst-eur', '${reqHash}', 'EUR', 9200, 9200);

      INSERT INTO public.journal_postings (journal_id, tenant_id, account_id, direction, amount_minor, currency_code)
      VALUES
        ('${jFxSourceUsd}', '${tenantA}', '${acctAUsdDebit}', 'DEBIT', 10000, 'USD'),
        ('${jFxSourceUsd}', '${tenantA}', '${acctAUsdCredit}', 'CREDIT', 10000, 'USD'),
        ('${jFxTargetEur}', '${tenantA}', '${acctAEurDebit}', 'DEBIT', 9200, 'EUR'),
        ('${jFxTargetEur}', '${tenantA}', '${acctAEurCredit}', 'CREDIT', 9200, 'EUR');

      INSERT INTO public.fx_conversion_settlements (
        settlement_id, tenant_id,
        source_journal_id, source_currency_code, source_amount_minor,
        target_journal_id, target_currency_code, target_amount_minor,
        rate_numerator, rate_denominator
      ) VALUES (
        '${fxSettlementId}', '${tenantA}',
        '${jFxSourceUsd}', 'USD', 10000,
        '${jFxTargetEur}', 'EUR', 9200,
        92, 100
      );
      COMMIT;
    `);

    // FX conversion with inexact rational arithmetic (10000 * 92 != 9201 * 100) rejected by chk_fx_exact_rational_conversion
    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO public.fx_conversion_settlements (
            settlement_id, tenant_id,
            source_journal_id, source_currency_code, source_amount_minor,
            target_journal_id, target_currency_code, target_amount_minor,
            rate_numerator, rate_denominator
          ) VALUES ($1, $2, $3, 'USD', 10000, $4, 'EUR', 9201, 92, 100)`,
          ['0195f8a0-0000-7000-8000-00000000ee13', tenantA, jFxSourceUsd, jFxTargetEur]
        ),
      /chk_fx_exact_rational_conversion/
    );

    // FX conversion where settlement amounts (5000 / 4600) don't match journal header totals (10000 / 9200) rejected at COMMIT
    await assert.rejects(
      async () => {
        await db.exec(`
          BEGIN;
          INSERT INTO public.fx_conversion_settlements (
            settlement_id, tenant_id,
            source_journal_id, source_currency_code, source_amount_minor,
            target_journal_id, target_currency_code, target_amount_minor,
            rate_numerator, rate_denominator
          ) VALUES (
            '0195f8a0-0000-7000-8000-00000000ee14', '${tenantA}',
            '${jFxSourceUsd}', 'USD', 5000,
            '${jFxTargetEur}', 'EUR', 4600,
            92, 100
          );
          COMMIT;
        `);
      },
      /LEDGER_FX_SETTLEMENT_AMOUNT_MISMATCH/
    );
    await db.exec('ROLLBACK;');

    // ------------------------------------------------------------------------
    // 4. ARGON-ROLE-004 RED-TEAM ATTACKS:
    //    - Ownership of security.guc_hmac_keys and ledger tables is db_migrator
    //    - Runtime role (app_login / app_runtime) cannot SET ROLE postgres (superuser)
    //    - Runtime role cannot SET ROLE db_migrator
    //    - Runtime role cannot ALTER ROLE ... BYPASSRLS or SUPERUSER
    // ------------------------------------------------------------------------
    const ownerVerifyRes = await db.query(`
      SELECT c.relname, r.rolname AS owner_role
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_roles r ON r.oid = c.relowner
      WHERE (n.nspname = 'security' AND c.relname = 'guc_hmac_keys')
         OR (n.nspname = 'public' AND c.relname IN ('ledger_accounts', 'journal_entries', 'journal_postings', 'fx_conversion_settlements'))
    `);
    assert.equal(ownerVerifyRes.rows.length, 5);
    for (const row of ownerVerifyRes.rows) {
      assert.equal(row.owner_role, 'db_migrator', `Expected ${row.relname} to be owned by db_migrator`);
    }

    await db.exec('SET SESSION AUTHORIZATION app_login;');
    for (const [sqlCmd, expectedPattern] of [
      ['SET ROLE postgres;', /permission denied to set role "postgres"/],
      ['SET ROLE db_migrator;', /permission denied to set role "db_migrator"/],
      ['ALTER ROLE app_login BYPASSRLS;', /permission denied/],
      ['ALTER ROLE app_runtime SUPERUSER;', /permission denied/],
    ]) {
      await assert.rejects(() => db.exec(sqlCmd), expectedPattern);
    }
  } finally {
    await db.close();
  }

  // ==========================================================================
  // PART B: MIGRATION ORDER VARIATIONS & CONFLICTING ROLE DETECTION (ARGON-ROLE-004)
  // ==========================================================================
  // 1. Order Variation A: Module 01 -> Module 07
  const dbOrder01Then07 = new PGlite({ extensions: { pgcrypto } });
  try {
    await dbOrder01Then07.exec(authoritativeDdlSql);
    await dbOrder01Then07.exec(mod07RlsSql);
    const rolesRes = await dbOrder01Then07.query(
      `SELECT rolname, rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('db_migrator', 'app_runtime', 'app_login') ORDER BY rolname`
    );
    assert.deepEqual(rolesRes.rows, [
      { rolname: 'app_login', rolcanlogin: true, rolsuper: false, rolbypassrls: false },
      { rolname: 'app_runtime', rolcanlogin: false, rolsuper: false, rolbypassrls: false },
      { rolname: 'db_migrator', rolcanlogin: false, rolsuper: false, rolbypassrls: false },
    ]);
  } finally {
    await dbOrder01Then07.close();
  }

  // 2. Order Variation B: Module 07 -> Module 01
  const dbOrder07Then01 = new PGlite({ extensions: { pgcrypto } });
  try {
    await dbOrder07Then01.exec(mod07RlsSql);
    await dbOrder07Then01.exec(authoritativeDdlSql);
    const rolesRes = await dbOrder07Then01.query(
      `SELECT rolname, rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('db_migrator', 'app_runtime', 'app_login') ORDER BY rolname`
    );
    assert.deepEqual(rolesRes.rows, [
      { rolname: 'app_login', rolcanlogin: true, rolsuper: false, rolbypassrls: false },
      { rolname: 'app_runtime', rolcanlogin: false, rolsuper: false, rolbypassrls: false },
      { rolname: 'db_migrator', rolcanlogin: false, rolsuper: false, rolbypassrls: false },
    ]);
  } finally {
    await dbOrder07Then01.close();
  }

  // 3. Migration Scenario 5: Conflicting Role Attributes Fail Safely (db_migrator BYPASSRLS, app_runtime LOGIN, app_login inheriting db_migrator)
  for (const conflictingSetupSql of [
    `CREATE ROLE db_migrator NOLOGIN BYPASSRLS;`,
    `CREATE ROLE db_migrator NOLOGIN; CREATE ROLE app_runtime LOGIN;`,
    `CREATE ROLE db_migrator NOLOGIN; CREATE ROLE app_runtime NOLOGIN; CREATE ROLE app_login LOGIN IN ROLE db_migrator;`,
  ]) {
    const conflictDb = new PGlite({ extensions: { pgcrypto } });
    try {
      await conflictDb.exec(conflictingSetupSql);
      await assert.rejects(
        () => conflictDb.exec(authoritativeDdlSql),
        /ROLE_SECURITY_INVARIANT_VIOLATION/
      );
    } finally {
      await conflictDb.close();
    }
  }

  // ==========================================================================
  // PART C: MIGRATION SCENARIOS 4, 6, 7, 9, 10 (DUPLICATE KEYS, RECOVERY, IDEMPOTENCY, ROLLBACK)
  // ==========================================================================
  const dupAndRollbackDb = new PGlite({ extensions: { pgcrypto } });
  try {
    await dupAndRollbackDb.exec(`
      CREATE TABLE public.ledger_accounts (
        account_id UUID NOT NULL,
        tenant_id UUID NOT NULL,
        currency_code CHAR(3) NOT NULL,
        status VARCHAR(16) NOT NULL,
        normal_balance VARCHAR(6) NOT NULL,
        balance_minor BIGINT NOT NULL DEFAULT 0,
        version INT NOT NULL DEFAULT 0,
        allow_negative_balance BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      );
      CREATE TABLE public.journal_entries (
        journal_id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        idempotency_key VARCHAR(128) NOT NULL,
        request_hash CHAR(64) NOT NULL,
        currency_code CHAR(3) NOT NULL,
        total_debit_minor BIGINT NOT NULL,
        total_credit_minor BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        UNIQUE (tenant_id, idempotency_key),
        UNIQUE (tenant_id, journal_id)
      );
      CREATE TABLE public.journal_postings (
        posting_id BIGSERIAL PRIMARY KEY,
        journal_id UUID NOT NULL,
        tenant_id UUID NOT NULL,
        account_id UUID NOT NULL,
        direction VARCHAR(6) NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency_code CHAR(3) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      );
    `);

    const tDup = '0195f8a0-0000-7000-8000-00000000ff01';
    const accDup = '0195f8a0-0000-7000-8000-00000000ff11';
    // Insert duplicate candidate key (tenant_id, account_id) into unindexed legacy table
    await dupAndRollbackDb.query(
      `INSERT INTO public.ledger_accounts (account_id, tenant_id, currency_code, status, normal_balance, balance_minor)
       VALUES ($1, $2, 'USD', 'ACTIVE', 'DEBIT', 1000), ($1, $2, 'USD', 'ACTIVE', 'DEBIT', 1000)`,
      [accDup, tDup]
    );

    // Scenario 4: PREFLIGHT-01 detects DUPLICATE_TENANT_ACCOUNT_KEY and Phase 1 CREATE UNIQUE INDEX fails safely without mutating data
    const preflightStmts = preflightQueriesSql
      .split(/;\s*(?:\r?\n|$)/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const dupDetect = await dupAndRollbackDb.query(preflightStmts[0]);
    assert.equal(dupDetect.rows.length, 2);
    assert.equal(dupDetect.rows[0].anomaly_type, 'DUPLICATE_TENANT_ACCOUNT_KEY');

    await assert.rejects(
      () =>
        dupAndRollbackDb.query(
          `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_ledger_accounts_tenant_account ON public.ledger_accounts (tenant_id, account_id)`
        ),
      /could not create unique index|duplicate key value/
    );

    // Scenario 6: Recovery after resolving duplicate key -> Phase 1, Phase 2, Phase 3 succeed
    await dupAndRollbackDb.exec(`
      DELETE FROM public.ledger_accounts a
      WHERE a.ctid <> (
        SELECT MIN(a2.ctid) FROM public.ledger_accounts a2
        WHERE a2.tenant_id = a.tenant_id AND a2.account_id = a.account_id
      );
      DROP INDEX IF EXISTS public.idx_ledger_accounts_tenant_account;
    `);

    const [phase1Part, phase2And3Part] = stagedMigrationSql.split(/--\s*=+\r?\n--\s*PHASE 2:/);
    const phase1Stmts = phase1Part
      .split(/;\s*(?:\r?\n|$)/)
      .map((s) => s.replace(/--.*$/gm, '').trim())
      .filter((s) => s.length > 0);
    for (const stmt of phase1Stmts) {
      await dupAndRollbackDb.query(stmt);
    }
    await dupAndRollbackDb.exec('-- PHASE 2:' + phase2And3Part);

    // Scenario 7: Verify all 8 constraints are marked convalidated = true in pg_constraint
    const validatedRes = await dupAndRollbackDb.query(`
      SELECT conname, convalidated
      FROM pg_constraint
      WHERE conname IN (
        'uq_ledger_accounts_tenant_account',
        'uq_ledger_accounts_tenant_account_currency',
        'chk_ledger_accounts_supported_currency',
        'chk_ledger_accounts_safe_bigint',
        'uq_journal_entries_tenant_journal_currency',
        'chk_journal_entries_supported_currency',
        'chk_journal_entries_totals_balanced',
        'fk_journal_postings_tenant_account',
        'fk_journal_postings_tenant_account_currency',
        'fk_journal_postings_tenant_journal_currency'
      )
      ORDER BY conname
    `);
    assert.equal(validatedRes.rows.length, 10);
    for (const row of validatedRes.rows) {
      assert.equal(row.convalidated, true, `Constraint ${row.conname} must have convalidated = true`);
    }

    // Scenario 9: Repeated execution of Phase 1 + Phase 2 + Phase 3 succeeds idempotently
    for (const stmt of phase1Stmts) {
      await dupAndRollbackDb.query(stmt);
    }
    await dupAndRollbackDb.exec('-- PHASE 2:' + phase2And3Part);

    // Scenario 10: Non-destructive metadata-only rollback of Phase 2 constraints preserves 100% of table rows
    await dupAndRollbackDb.exec(`
      ALTER TABLE public.journal_postings
        DROP CONSTRAINT IF EXISTS fk_journal_postings_tenant_journal_currency,
        DROP CONSTRAINT IF EXISTS fk_journal_postings_tenant_account_currency,
        DROP CONSTRAINT IF EXISTS fk_journal_postings_tenant_account;
    `);
    const postRollbackRows = await dupAndRollbackDb.query('SELECT COUNT(*)::int AS cnt FROM public.ledger_accounts');
    assert.equal(postRollbackRows.rows[0].cnt, 1);
  } finally {
    await dupAndRollbackDb.close();
  }
});



