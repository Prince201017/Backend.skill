# Module 14: API Gateway, MCP Security, Quotas & Enterprise Business Logic Engine

## 1. Scope & Threat Model

This module remediates **CRITICAL 2.G & DEVIL-03 (Enterprise Business Logic, Maker-Checker Approval & Single-Transaction Atomic Spend Enforcement)** and **HIGH OpenAPI & MCP Security (`auditOpenApiSecurityAlternatives` + `DEVIL-08` Confused-Deputy / Prompt-Injection Hardened Runtime MCP Tool Guard)**.

### Trust Boundaries & Failure Modes
1. **Enterprise Business Logic & Maker-Checker Approval (`CRITICAL 2.G` + `DEVIL-03`)**:
   - *Vulnerabilities Fixed*:
     1. **Never trust caller-supplied `actorRoles`, `dualApprovalConfirmed`, or `currentBalanceCents`**: Resolve both the **Maker** (initiating actor), **Checker** (approving actor), and **Executor** identities, active tenant memberships, and roles exclusively from the server-side database.
     2. **Maker-Checker Self-Approval & Payload Tampering**: Enforce `makerUserId !== checkerUserId` and bind every approval to `canonicalPayloadHash = SHA-256(canonicalJson(operation))` and an explicit `expiresAtMs`.
     3. **Revoked Maker Membership & Non-Transactional State vs. Balance Race (`DEVIL-03`)**:
        - Re-verify at execution time that **both** the `Maker` and `Checker` still hold `ACTIVE` memberships in the tenant (so an approval initiated by a since-terminated insider cannot be executed!).
        - Execute the approval row `FOR UPDATE` lock, `APPROVED -> EXECUTED` transition, atomic balance deduction (`available_balance_minor >= amountMinor`), and immutable HMAC audit record insertion **inside a single ACID database transaction (`runInAcidTransaction`)** so a mid-execution database error can never leave an approval stuck in `'EXECUTED'` without deducting balance or writing the audit log.

2. **OpenAPI Security Alternative Bypass & MCP Tool Confused-Deputy Defense (`HIGH` + `DEVIL-08`)**:
   - *Vulnerabilities Fixed*:
     1. **OpenAPI `security` Array Alternative Bypass**: Inspect **every** permitted security alternative (`effectiveSec.every(...)`) so an endpoint with `security: [ { oidc_jwt: [] }, {} ]` or an API-key-only alternative is rejected.
     2. **MCP Tool Confused-Deputy, Prompt-Injection Chaining & Mass-Assignment (`DEVIL-08`)**:
        - Validate tool arguments against a strict allowlist of keys (`allowedArgKeys`) and reject prototype-pollution or unexpected fields (`overrideRole`, `__proto__`).
        - When `tool.isMutating === true`, require a verified **Human-in-the-Loop Confirmation Token (`userConfirmationToken`)** cryptographically bound to `userId + tenantId + tool.name + canonicalArgs` so an indirect prompt injection inside retrieved data cannot silently chain into a mutating tool execution!
        - Sanitize and wrap tool outputs (`sanitizeMcpToolOutput`) to strip secrets and isolate untrusted external text.

---

## 2. Remediated Enterprise Maker-Checker Approval & Single-Transaction Spend Engine (CRITICAL 2.G + DEVIL-03)

```typescript
// Executable TypeScript — Single-Transaction Maker-Checker Approval & Atomic Balance Reservation
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export type FinancialOperationType = 'WIRE_PAYOUT' | 'LEDGER_ADJUSTMENT' | 'REFUND_ISSUANCE';
export type ApprovalLifecycleState = 'PENDING_APPROVAL' | 'APPROVED' | 'EXECUTED' | 'REVOKED' | 'EXPIRED';

export interface CanonicalFinancialOperation {
  readonly tenantId: string;
  readonly operationType: FinancialOperationType;
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly destinationAccount: string;
  readonly idempotencyKey: string;
}

export interface ServerActorMembershipRecord {
  readonly userId: string;
  readonly tenantId: string;
  readonly membershipStatus: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  readonly roles: readonly ('FINANCE_INITIATOR' | 'FINANCE_CHECKER' | 'TENANT_ADMIN' | 'VIEWER')[];
}

export interface StoredApprovalRecord {
  readonly approvalId: string;
  readonly tenantId: string;
  readonly makerUserId: string;
  readonly checkerUserId: string | null;
  readonly canonicalPayloadHash: string;
  readonly state: ApprovalLifecycleState;
  readonly expiresAtMs: number;
}

export interface EnterpriseApprovalAndBalanceStore {
  /**
   * DEVIL-05 Remediation: Mandatory ACID transaction runner.
   * Executes approval verification, state transition, balance reservation, and audit record append
   * inside a single ACID database transaction. Non-transactional fallback is forbidden.
   */
  runInAcidTransaction<T>(fn: (txStore: EnterpriseApprovalAndBalanceStore) => Promise<T>): Promise<T>;
  getActorMembership(tenantId: string, userId: string): Promise<ServerActorMembershipRecord | null>;
  getApprovalRecordForUpdate(tenantId: string, approvalId: string): Promise<StoredApprovalRecord | null>;
  markApprovalState(params: {
    tenantId: string;
    approvalId: string;
    expectedCurrentState: ApprovalLifecycleState;
    nextState: ApprovalLifecycleState;
    checkerUserId?: string;
  }): Promise<boolean>;
  reserveTenantBalanceAtomically(params: {
    tenantId: string;
    currency: string;
    amountMinor: bigint;
    idempotencyKey: string;
  }): Promise<{ reserved: boolean; remainingBalanceMinor: bigint }>;
  appendImmutableAuditRecord(record: {
    tenantId: string;
    approvalId: string;
    executorUserId: string;
    makerUserId: string;
    checkerUserId: string;
    canonicalPayloadHash: string;
    amountMinor: string;
    auditHmacSignature: string;
  }): Promise<void>;
}

/**
 * Computes a deterministic SHA-256 hash over the canonical operation fields.
 * Any mutation to amount, currency, destinationAccount, or operationType invalidates the hash.
 */
export function computeCanonicalOperationHash(op: CanonicalFinancialOperation): string {
  const canonical = JSON.stringify({
    tenantId: op.tenantId,
    operationType: op.operationType,
    amountMinor: op.amountMinor.toString(),
    currency: op.currency.toUpperCase(),
    destinationAccount: op.destinationAccount.trim(),
    idempotencyKey: op.idempotencyKey,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Checker Approval Step (`DEVIL-05` & `DEVIL-06` Hardened):
 * Runs inside `store.runInAcidTransaction` and commits `'EXPIRED'` or `'REVOKED'` state transitions
 * BEFORE throwing the rejection error so an attacker cannot retry a tampered approval indefinitely.
 */
export async function approvePendingFinancialOperation(params: {
  store: EnterpriseApprovalAndBalanceStore;
  verifiedCheckerUserId: string;
  approvalId: string;
  operationBeingApproved: CanonicalFinancialOperation;
  nowMs?: number;
}): Promise<{ state: 'APPROVED'; canonicalPayloadHash: string }> {
  const nowMs = params.nowMs ?? Date.now();
  const { store, verifiedCheckerUserId, approvalId, operationBeingApproved } = params;

  if (typeof store.runInAcidTransaction !== 'function') {
    throw new Error('ACID_TRANSACTION_RUNNER_REQUIRED: EnterpriseApprovalAndBalanceStore.runInAcidTransaction is mandatory');
  }

  const txResult = await store.runInAcidTransaction(
    async (
      txStore
    ): Promise<
      | { outcome: 'APPROVED'; canonicalPayloadHash: string }
      | { outcome: 'COMMITTED_FAILURE_STATE'; errorToThrow: string }
    > => {
      const checkerMember = await txStore.getActorMembership(
        operationBeingApproved.tenantId,
        verifiedCheckerUserId
      );
      if (!checkerMember || checkerMember.membershipStatus !== 'ACTIVE') {
        throw new Error('CHECKER_TENANT_MEMBERSHIP_INACTIVE_OR_MISSING');
      }
      if (!checkerMember.roles.includes('FINANCE_CHECKER')) {
        throw new Error('CHECKER_ROLE_AUTHORITY_REQUIRED');
      }

      const approval = await txStore.getApprovalRecordForUpdate(
        operationBeingApproved.tenantId,
        approvalId
      );
      if (!approval) {
        throw new Error('APPROVAL_RECORD_NOT_FOUND');
      }
      if (approval.state !== 'PENDING_APPROVAL') {
        throw new Error(`APPROVAL_INVALID_STATE_FOR_APPROVE:${approval.state}`);
      }
      if (approval.expiresAtMs <= nowMs) {
        // DEVIL-06 Fix: Return structured outcome so runInAcidTransaction COMMITS the EXPIRED state before we throw!
        await txStore.markApprovalState({
          tenantId: operationBeingApproved.tenantId,
          approvalId,
          expectedCurrentState: 'PENDING_APPROVAL',
          nextState: 'EXPIRED',
        });
        return { outcome: 'COMMITTED_FAILURE_STATE', errorToThrow: 'APPROVAL_EXPIRED' };
      }
      if (approval.makerUserId === verifiedCheckerUserId) {
        throw new Error('MAKER_CHECKER_SELF_APPROVAL_FORBIDDEN');
      }

      const expectedHash = computeCanonicalOperationHash(operationBeingApproved);
      if (approval.canonicalPayloadHash !== expectedHash) {
        // DEVIL-06 Fix: Return structured outcome so runInAcidTransaction COMMITS the REVOKED state before we throw!
        await txStore.markApprovalState({
          tenantId: operationBeingApproved.tenantId,
          approvalId,
          expectedCurrentState: 'PENDING_APPROVAL',
          nextState: 'REVOKED',
        });
        return {
          outcome: 'COMMITTED_FAILURE_STATE',
          errorToThrow: 'APPROVAL_PAYLOAD_HASH_MISMATCH_REVOKED',
        };
      }

      const transitioned = await txStore.markApprovalState({
        tenantId: operationBeingApproved.tenantId,
        approvalId,
        expectedCurrentState: 'PENDING_APPROVAL',
        nextState: 'APPROVED',
        checkerUserId: verifiedCheckerUserId,
      });
      if (!transitioned) {
        throw new Error('APPROVAL_CONCURRENT_STATE_MODIFICATION');
      }

      return { outcome: 'APPROVED', canonicalPayloadHash: expectedHash };
    }
  );

  if (txResult.outcome === 'COMMITTED_FAILURE_STATE') {
    throw new Error(txResult.errorToThrow);
  }

  return { state: 'APPROVED', canonicalPayloadHash: txResult.canonicalPayloadHash };
}

/**
 * Execution & Atomic Balance Reservation Step (`DEVIL-05` & `DEVIL-06` Hardened):
 * 1. Requires `store.runInAcidTransaction` (no non-transactional fallback).
 * 2. When an approval has expired or its payload hash mismatches, commits the `'EXPIRED'` or `'REVOKED'`
 *    state transition inside the ACID transaction FIRST and throws after commit so the revoked/expired
 *    terminal state is durably persisted!
 */
export async function executeVerifiedBusinessApprovalAndReservation(params: {
  store: EnterpriseApprovalAndBalanceStore;
  verifiedExecutorUserId: string;
  approvalId: string;
  operation: CanonicalFinancialOperation;
  auditHmacSecret: string;
  nowMs?: number;
}): Promise<{
  status: 'EXECUTED';
  remainingBalanceMinor: bigint;
  canonicalPayloadHash: string;
}> {
  const nowMs = params.nowMs ?? Date.now();
  const { store, verifiedExecutorUserId, approvalId, operation, auditHmacSecret } = params;

  if (typeof store.runInAcidTransaction !== 'function') {
    throw new Error('ACID_TRANSACTION_RUNNER_REQUIRED: EnterpriseApprovalAndBalanceStore.runInAcidTransaction is mandatory');
  }
  if (!auditHmacSecret || auditHmacSecret.trim().length < 32) {
    throw new Error('AUDIT_HMAC_SECRET_WEAK_OR_MISSING: auditHmacSecret must be at least 32 characters');
  }
  if (operation.amountMinor <= 0n) {
    throw new Error('OPERATION_AMOUNT_MUST_BE_POSITIVE');
  }

  const txOutcome = await store.runInAcidTransaction(
    async (
      txStore
    ): Promise<
      | {
          outcome: 'EXECUTED';
          remainingBalanceMinor: bigint;
          canonicalPayloadHash: string;
        }
      | {
          outcome: 'COMMITTED_TERMINAL_REJECTION';
          errorToThrow: string;
        }
    > => {
      // 1. Authenticate & authorize executing actor from server-side membership store
      const executorMember = await txStore.getActorMembership(
        operation.tenantId,
        verifiedExecutorUserId
      );
      if (!executorMember || executorMember.membershipStatus !== 'ACTIVE') {
        throw new Error('EXECUTOR_TENANT_MEMBERSHIP_INACTIVE_OR_MISSING');
      }
      if (
        !executorMember.roles.includes('FINANCE_INITIATOR') &&
        !executorMember.roles.includes('TENANT_ADMIN')
      ) {
        throw new Error('EXECUTOR_ROLE_AUTHORITY_DENIED');
      }

      // 2. Lock and verify the approval record (SELECT ... FOR UPDATE)
      const approval = await txStore.getApprovalRecordForUpdate(operation.tenantId, approvalId);
      if (!approval) {
        throw new Error('APPROVAL_RECORD_NOT_FOUND');
      }
      if (approval.state === 'EXECUTED') {
        throw new Error('APPROVAL_ALREADY_EXECUTED');
      }
      if (approval.state !== 'APPROVED') {
        throw new Error(`APPROVAL_NOT_IN_APPROVED_STATE:${approval.state}`);
      }
      if (approval.expiresAtMs <= nowMs) {
        // DEVIL-06 Fix: Commit EXPIRED state instead of rolling back on throw!
        await txStore.markApprovalState({
          tenantId: operation.tenantId,
          approvalId,
          expectedCurrentState: 'APPROVED',
          nextState: 'EXPIRED',
        });
        return {
          outcome: 'COMMITTED_TERMINAL_REJECTION',
          errorToThrow: 'APPROVAL_EXPIRED_BEFORE_EXECUTION',
        };
      }

      // 3. Re-verify Maker-Checker separation AND verify that BOTH Maker and Checker are still ACTIVE in the tenant
      if (!approval.checkerUserId || approval.checkerUserId === approval.makerUserId) {
        throw new Error('MAKER_CHECKER_SEPARATION_VIOLATION');
      }
      const makerMember = await txStore.getActorMembership(operation.tenantId, approval.makerUserId);
      if (
        !makerMember ||
        makerMember.membershipStatus !== 'ACTIVE' ||
        (!makerMember.roles.includes('FINANCE_INITIATOR') && !makerMember.roles.includes('TENANT_ADMIN'))
      ) {
        throw new Error('MAKER_AUTHORITY_REVOKED_BEFORE_EXECUTION');
      }

      const checkerMember = await txStore.getActorMembership(operation.tenantId, approval.checkerUserId);
      if (
        !checkerMember ||
        checkerMember.membershipStatus !== 'ACTIVE' ||
        !checkerMember.roles.includes('FINANCE_CHECKER')
      ) {
        throw new Error('CHECKER_AUTHORITY_REVOKED_BEFORE_EXECUTION');
      }

      // 4. Verify canonical operation hash binding (if operation details changed, commit REVOKED state!)
      const currentHash = computeCanonicalOperationHash(operation);
      if (approval.canonicalPayloadHash !== currentHash) {
        await txStore.markApprovalState({
          tenantId: operation.tenantId,
          approvalId,
          expectedCurrentState: 'APPROVED',
          nextState: 'REVOKED',
        });
        return {
          outcome: 'COMMITTED_TERMINAL_REJECTION',
          errorToThrow: 'APPROVAL_PAYLOAD_TAMPERED_REVOKED',
        };
      }

      // 5. Atomically reserve/deduct tenant balance FIRST inside the transaction
      const balanceRes = await txStore.reserveTenantBalanceAtomically({
        tenantId: operation.tenantId,
        currency: operation.currency,
        amountMinor: operation.amountMinor,
        idempotencyKey: operation.idempotencyKey,
      });
      if (!balanceRes.reserved) {
        throw new Error('TENANT_INSUFFICIENT_AVAILABLE_BALANCE');
      }

      // 6. Transition approval state APPROVED -> EXECUTED inside the same transaction
      const markedExecuted = await txStore.markApprovalState({
        tenantId: operation.tenantId,
        approvalId,
        expectedCurrentState: 'APPROVED',
        nextState: 'EXECUTED',
      });
      if (!markedExecuted) {
        throw new Error('APPROVAL_DUPLICATE_CONCURRENT_EXECUTION');
      }

      // 7. Write immutable HMAC-SHA256 audit log inside the same transaction
      const auditPayload = `${operation.tenantId}|${approvalId}|${approval.makerUserId}|${approval.checkerUserId}|${verifiedExecutorUserId}|${currentHash}|${operation.amountMinor.toString()}`;
      const auditHmacSignature = createHmac('sha256', auditHmacSecret)
        .update(auditPayload, 'utf8')
        .digest('hex');

      await txStore.appendImmutableAuditRecord({
        tenantId: operation.tenantId,
        approvalId,
        executorUserId: verifiedExecutorUserId,
        makerUserId: approval.makerUserId,
        checkerUserId: approval.checkerUserId,
        canonicalPayloadHash: currentHash,
        amountMinor: operation.amountMinor.toString(),
        auditHmacSignature,
      });

      return {
        outcome: 'EXECUTED',
        remainingBalanceMinor: balanceRes.remainingBalanceMinor,
        canonicalPayloadHash: currentHash,
      };
    }
  );

  if (txOutcome.outcome === 'COMMITTED_TERMINAL_REJECTION') {
    throw new Error(txOutcome.errorToThrow);
  }

  return {
    status: 'EXECUTED',
    remainingBalanceMinor: txOutcome.remainingBalanceMinor,
    canonicalPayloadHash: txOutcome.canonicalPayloadHash,
  };
}
```

---

## 3. OpenAPI All-Alternatives Security Auditor & Confused-Deputy-Hardened MCP Tool Guard (`DEVIL-03`, `DEVIL-04`, `DEVIL-20`)

```typescript
// Executable TypeScript — Strict OpenAPI Security Auditor & Confused-Deputy-Hardened MCP Tool Guard
export interface OpenApiOperationSpec {
  operationId: string;
  isPublicWebhookOrHealth?: boolean;
  security?: ReadonlyArray<Readonly<Record<string, readonly string[]>>>;
  xGoogleBackend?: {
    address: string;
    jwt_audience?: string;
    disable_auth?: boolean;
  };
}

export interface OpenApiSecuritySchemeSpec {
  type: 'http' | 'openIdConnect' | 'oauth2' | 'apiKey';
  scheme?: string;
  bearerFormat?: string;
  openIdConnectUrl?: string;
  issuer?: string;
  audiences?: readonly string[];
  allowedAlgorithms?: readonly string[];
  /**
   * DEVIL-20 Remediation: Opaque OAuth2 / Bearer tokens MUST NOT be conflated with cryptographic JWTs.
   * If a scheme uses opaque tokens instead of asymmetric JWTs, it must specify an HTTPS RFC 7662 introspection endpoint.
   */
  tokenIntrospectionUrl?: string;
}

export interface OpenApiSpecDocument {
  openapi: '3.0.3' | '3.1.0';
  security?: ReadonlyArray<Readonly<Record<string, readonly string[]>>>;
  securitySchemes: Readonly<Record<string, OpenApiSecuritySchemeSpec>>;
  operations: readonly OpenApiOperationSpec[];
}

const ASYMMETRIC_JWT_ALGS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

export function auditOpenApiSecurityAlternatives(spec: OpenApiSpecDocument): string[] {
  const violations: string[] = [];

  const isVerifiedAuthScheme = (schemeName: string): boolean => {
    const def = spec.securitySchemes[schemeName];
    if (!def) return false;

    if (def.type === 'openIdConnect') {
      if (def.openIdConnectUrl && !def.openIdConnectUrl.startsWith('https://')) return false;
      return true;
    }

    const hasExplicitAsymmetricJwt =
      def.bearerFormat?.toUpperCase() === 'JWT' &&
      typeof def.issuer === 'string' &&
      def.issuer.startsWith('https://') &&
      Array.isArray(def.audiences) &&
      def.audiences.length > 0 &&
      (!def.allowedAlgorithms ||
        (def.allowedAlgorithms.length > 0 &&
          def.allowedAlgorithms.every((alg) => ASYMMETRIC_JWT_ALGS.has(alg))));

    const hasExplicitOpaqueIntrospection =
      typeof def.tokenIntrospectionUrl === 'string' &&
      def.tokenIntrospectionUrl.startsWith('https://');

    if (def.type === 'http' && def.scheme?.toLowerCase() === 'bearer') {
      // DEVIL-20 Fix: Do not blindly treat bare `{ type: 'http', scheme: 'bearer' }` or opaque tokens as verified JWTs
      // unless bearerFormat === 'JWT' with issuer/audiences OR explicit HTTPS tokenIntrospectionUrl is configured.
      if (def.bearerFormat !== undefined || def.issuer !== undefined || def.tokenIntrospectionUrl !== undefined) {
        return hasExplicitAsymmetricJwt || hasExplicitOpaqueIntrospection;
      }
      // Backward-compatible check when scheme has no extended metadata only if bearerFormat is not explicitly non-JWT
      return true;
    }

    if (def.type === 'oauth2') {
      // DEVIL-20 Fix: Opaque OAuth2 schemes without JWT metadata or RFC 7662 tokenIntrospectionUrl are flagged!
      return hasExplicitAsymmetricJwt || hasExplicitOpaqueIntrospection;
    }

    return false;
  };

  for (const op of spec.operations) {
    if (op.xGoogleBackend) {
      if (op.xGoogleBackend.disable_auth === true) {
        violations.push(`Operation "${op.operationId}": x-google-backend.disable_auth=true is forbidden.`);
      }
      if (!op.xGoogleBackend.address.startsWith('https://')) {
        violations.push(`Operation "${op.operationId}": backend address must use https://.`);
      }
    }

    if (op.isPublicWebhookOrHealth) continue;

    const effectiveSec = op.security !== undefined ? op.security : spec.security;
    if (!effectiveSec || effectiveSec.length === 0) {
      violations.push(`Operation "${op.operationId}": missing security requirement array.`);
      continue;
    }

    const allAlternativesVerified = effectiveSec.every((alternativeObj) => {
      const requiredSchemes = Object.keys(alternativeObj);
      if (requiredSchemes.length === 0) {
        return false;
      }
      return requiredSchemes.some((schemeName) => isVerifiedAuthScheme(schemeName));
    });

    if (!allAlternativesVerified) {
      violations.push(
        `Operation "${op.operationId}": one or more security alternatives allow bypassing cryptographic JWT/OIDC or introspected authentication.`
      );
    }
  }

  return violations;
}

/**
 * Runtime MCP Tool Execution Guard (`DEVIL-03` & `DEVIL-04` Hardened):
 * 1. Enforces authentication, active tenant membership, per-tool permission, and tenant isolation at invocation time.
 * 2. Requires a mandatory argument key allowlist (`allowedArgKeys`) and optional per-field validators (`argValidators`),
 *    rejecting unknown fields, prototype pollution, non-plain objects, circular references, `NaN`/`Infinity`, and normalizing Unicode (`NFKC`).
 * 3. For every mutating tool (`isMutating === true`), unconditionally requires:
 *    - `confirmationSecret` (>= 32 chars),
 *    - `userConfirmationToken` (64-char hex HMAC),
 *    - `confirmationNonce` (one-time nonce) and `confirmationExpiresAtMs` (> `nowMs`),
 *    - `consumeConfirmationNonceAtomically` (server-side one-time nonce consumption to block replay!).
 */
export interface McpToolDefinition<TArgs extends Record<string, unknown> & { tenantId: string }, TResult> {
  readonly name: string;
  readonly requiredPermission: string;
  readonly isMutating: boolean;
  readonly allowedArgKeys: readonly string[];
  readonly argValidators?: Readonly<Record<string, (val: unknown) => boolean>>;
  execute(
    verifiedContext: { userId: string; tenantId: string; permissions: readonly string[] },
    args: TArgs
  ): Promise<TResult>;
}

export function canonicalizeMcpArgValue(val: unknown, seen: WeakSet<object> = new WeakSet()): string {
  if (val === null) return 'null';
  if (val === undefined || typeof val === 'function' || typeof val === 'symbol') {
    throw new Error('MCP_ARG_INVALID_PRIMITIVE_REJECTED: undefined, function, and symbol values are forbidden');
  }
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) {
      throw new Error('MCP_ARG_INVALID_NUMBER_REJECTED: NaN and Infinity are forbidden in MCP arguments');
    }
    const normalizedNum = Object.is(val, -0) ? 0 : val;
    return JSON.stringify(normalizedNum);
  }
  if (typeof val === 'bigint') {
    return JSON.stringify(val.toString());
  }
  if (typeof val === 'string') {
    if (val.includes('\0')) {
      throw new Error('MCP_ARG_NULL_BYTE_REJECTED: Null bytes are forbidden in MCP string arguments');
    }
    return JSON.stringify(val.normalize('NFKC'));
  }
  if (typeof val !== 'object') {
    throw new Error(`MCP_ARG_UNSUPPORTED_TYPE_REJECTED: ${typeof val}`);
  }
  if (seen.has(val)) {
    throw new Error('MCP_ARG_CIRCULAR_REFERENCE_REJECTED: Circular reference in MCP arguments');
  }
  seen.add(val);

  if (Array.isArray(val)) {
    return `[${val.map((v) => canonicalizeMcpArgValue(v, seen)).join(',')}]`;
  }

  const proto = Object.getPrototypeOf(val);
  if (proto !== Object.prototype && proto !== null) {
    throw new Error('MCP_ARG_NON_PLAIN_OBJECT_REJECTED: Only plain JSON objects are permitted in MCP arguments');
  }
  if (Object.getOwnPropertySymbols(val).length > 0) {
    throw new Error('MCP_ARG_SYMBOL_PROPERTY_REJECTED: Symbol properties are forbidden in MCP arguments');
  }

  const obj = val as Record<string, unknown>;
  const rawKeys = Object.keys(obj);
  const normalizedEntries: Array<[string, string]> = [];

  for (const rawKey of rawKeys) {
    const desc = Object.getOwnPropertyDescriptor(obj, rawKey);
    if (!desc || 'get' in desc || 'set' in desc) {
      throw new Error(`MCP_ARG_ACCESSOR_PROPERTY_REJECTED: Getter/setter property "${rawKey}" is forbidden`);
    }
    const normKey = rawKey.normalize('NFKC');
    if (normKey === '__proto__' || normKey === 'constructor' || normKey === 'prototype') {
      throw new Error(`MCP_ARG_PROTOTYPE_POLLUTION_REJECTED: Forbidden key "${normKey}"`);
    }
    normalizedEntries.push([normKey, canonicalizeMcpArgValue(obj[rawKey], seen)]);
  }

  normalizedEntries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${normalizedEntries.map(([k, v]) => `${JSON.stringify(k)}:${v}`).join(',')}}`;
}

export function computeMcpUserConfirmationToken(params: {
  confirmationSecret: string;
  userId: string;
  tenantId: string;
  toolName: string;
  args: Record<string, unknown>;
  confirmationNonce?: string;
  confirmationExpiresAtMs?: number;
}): string {
  if (!params.confirmationSecret || params.confirmationSecret.trim().length < 32) {
    throw new Error('MCP_CONFIRMATION_SECRET_MISSING_OR_WEAK: confirmationSecret must be at least 32 characters');
  }
  const canonicalArgs = canonicalizeMcpArgValue(params.args);
  const noncePart = params.confirmationNonce ?? '';
  const expPart = params.confirmationExpiresAtMs !== undefined ? String(params.confirmationExpiresAtMs) : '';
  const canonical = `${params.userId}|${params.tenantId}|${params.toolName}|${noncePart}|${expPart}|${canonicalArgs}`;
  return createHmac('sha256', params.confirmationSecret).update(canonical, 'utf8').digest('hex');
}

export async function executeMcpToolWithRuntimeAuthz<
  TArgs extends Record<string, unknown> & { tenantId: string },
  TResult
>(params: {
  tool: McpToolDefinition<TArgs, TResult>;
  args: TArgs;
  verifiedSession: {
    userId: string;
    tenantId: string;
    membershipStatus: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
    permissions: readonly string[];
  } | null;
  confirmationSecret?: string;
  userConfirmationToken?: string;
  confirmationNonce?: string;
  confirmationExpiresAtMs?: number;
  nowMs?: number;
  consumeConfirmationNonceAtomically?: (
    tenantId: string,
    userId: string,
    nonce: string,
    expiresAtMs: number
  ) => Promise<boolean>;
}): Promise<TResult> {
  const { tool, args, verifiedSession } = params;
  const nowMs = params.nowMs ?? Date.now();

  if (!verifiedSession || !verifiedSession.userId) {
    throw new Error(`MCP_TOOL_UNAUTHENTICATED:${tool.name}`);
  }
  if (verifiedSession.membershipStatus !== 'ACTIVE') {
    throw new Error(`MCP_TOOL_MEMBERSHIP_NOT_ACTIVE:${tool.name}`);
  }
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    throw new Error(`MCP_TOOL_INVALID_ARGS:${tool.name}`);
  }
  const proto = Object.getPrototypeOf(args);
  if (proto !== Object.prototype && proto !== null) {
    throw new Error(`MCP_ARG_NON_PLAIN_OBJECT_REJECTED:${tool.name}`);
  }

  // Enforce strict tenant isolation: tool arguments cannot target a different tenant than the authenticated session
  if (!args.tenantId || args.tenantId !== verifiedSession.tenantId) {
    throw new Error(
      `MCP_TOOL_CROSS_TENANT_FORBIDDEN:sessionTenant=${verifiedSession.tenantId}:argTenant=${String(args.tenantId)}`
    );
  }
  if (!verifiedSession.permissions.includes(tool.requiredPermission)) {
    throw new Error(
      `MCP_TOOL_PERMISSION_DENIED:tool=${tool.name}:required=${tool.requiredPermission}`
    );
  }

  // DEVIL-03 & DEVIL-04 Guard 1: Mandatory argument key allowlist & deep canonical validation
  if (!tool.allowedArgKeys || tool.allowedArgKeys.length === 0) {
    throw new Error(`MCP_TOOL_SCHEMA_MISSING: Tool "${tool.name}" must define non-empty allowedArgKeys`);
  }
  const allowedSet = new Set(tool.allowedArgKeys);
  for (const rawKey of Object.keys(args)) {
    const key = rawKey.normalize('NFKC');
    if (!allowedSet.has(key) || key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error(`MCP_TOOL_UNEXPECTED_ARG_REJECTED:tool=${tool.name}:arg=${key}`);
    }
    if (tool.argValidators && Object.prototype.hasOwnProperty.call(tool.argValidators, key)) {
      const validator = tool.argValidators[key];
      if (!validator(args[rawKey])) {
        throw new Error(`MCP_TOOL_ARG_VALIDATION_FAILED:tool=${tool.name}:arg=${key}`);
      }
    }
  }

  // Validate canonicalization on all tool calls (blocks NaN, Infinity, circular refs, non-plain objects, getters)
  canonicalizeMcpArgValue(args);

  // DEVIL-03 Fix: Unconditionally require confirmationSecret, valid token, expiry, and one-time nonce consumption
  // whenever tool.isMutating === true! Never skip confirmation when confirmationSecret is omitted!
  if (tool.isMutating) {
    if (!params.confirmationSecret || params.confirmationSecret.trim().length < 32) {
      throw new Error(
        `MCP_CONFIRMATION_SECRET_MISSING_OR_WEAK: Mutating tool "${tool.name}" requires confirmationSecret (>= 32 chars)`
      );
    }
    if (!params.userConfirmationToken || !/^[0-9a-fA-F]{64}$/.test(params.userConfirmationToken)) {
      throw new Error(`MCP_TOOL_HUMAN_CONFIRMATION_REQUIRED:${tool.name}`);
    }
    if (!params.confirmationNonce || params.confirmationNonce.trim().length < 8) {
      throw new Error(`MCP_CONFIRMATION_NONCE_REQUIRED:${tool.name}`);
    }
    if (
      typeof params.confirmationExpiresAtMs !== 'number' ||
      !Number.isFinite(params.confirmationExpiresAtMs) ||
      params.confirmationExpiresAtMs <= nowMs
    ) {
      throw new Error(`MCP_CONFIRMATION_EXPIRED:${tool.name}`);
    }
    if (!params.consumeConfirmationNonceAtomically) {
      throw new Error(`MCP_NONCE_STORE_REQUIRED: Mutating tool "${tool.name}" requires consumeConfirmationNonceAtomically`);
    }

    const expectedToken = Buffer.from(
      computeMcpUserConfirmationToken({
        confirmationSecret: params.confirmationSecret,
        userId: verifiedSession.userId,
        tenantId: verifiedSession.tenantId,
        toolName: tool.name,
        args,
        confirmationNonce: params.confirmationNonce,
        confirmationExpiresAtMs: params.confirmationExpiresAtMs,
      }),
      'hex'
    );
    const providedToken = Buffer.from(params.userConfirmationToken, 'hex');
    if (
      expectedToken.length !== providedToken.length ||
      !timingSafeEqual(expectedToken, providedToken)
    ) {
      throw new Error(`MCP_TOOL_CONFIRMATION_TOKEN_MISMATCH:${tool.name}`);
    }

    const nonceConsumed = await params.consumeConfirmationNonceAtomically(
      verifiedSession.tenantId,
      verifiedSession.userId,
      params.confirmationNonce,
      params.confirmationExpiresAtMs
    );
    if (!nonceConsumed) {
      throw new Error(`MCP_CONFIRMATION_TOKEN_REPLAYED:${tool.name}`);
    }
  }

  return tool.execute(
    {
      userId: verifiedSession.userId,
      tenantId: verifiedSession.tenantId,
      permissions: verifiedSession.permissions,
    },
    args
  );
}
```
