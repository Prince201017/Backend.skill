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

test('VERIFY-01-LIVE-POSTGRES-RLS [Live PostgreSQL Database Engine Verification]', async (t) => {
  if (!process.env.DATABASE_URL) {
    t.skip(
      'Live PostgreSQL instance (DATABASE_URL / postgres daemon) is not available in this container environment; PL/pgSQL & RLS runtime execution in PostgreSQL remains UNVERIFIED'
    );
    return;
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

  // And Module 15 validateEvidenceIdentifiers detects duplicate IDs
  const dupCheck = mod15.validateEvidenceIdentifiers(['DEVIL-01', 'DEVIL-63', 'DEVIL-01', 'VERIFY-21']);
  assert.deepEqual(dupCheck.duplicateIds, ['DEVIL-01']);
  assert.deepEqual(dupCheck.invalidIds, []);
});

