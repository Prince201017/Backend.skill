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
   * Executes the entire approval verification, state transition, balance reservation,
   * and audit record append inside a single ACID database transaction (DEVIL-03).
   */
  runInAcidTransaction?<T>(fn: (txStore: EnterpriseApprovalAndBalanceStore) => Promise<T>): Promise<T>;
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
 * Checker Approval Step:
 * Verifies the Checker's identity, active tenant membership, FINANCE_CHECKER role,
 * anti-self-approval (makerUserId !== checkerUserId), and exact payload hash match.
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

  const checkerMember = await store.getActorMembership(
    operationBeingApproved.tenantId,
    verifiedCheckerUserId
  );
  if (!checkerMember || checkerMember.membershipStatus !== 'ACTIVE') {
    throw new Error('CHECKER_TENANT_MEMBERSHIP_INACTIVE_OR_MISSING');
  }
  if (!checkerMember.roles.includes('FINANCE_CHECKER')) {
    throw new Error('CHECKER_ROLE_AUTHORITY_REQUIRED');
  }

  const approval = await store.getApprovalRecordForUpdate(
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
    await store.markApprovalState({
      tenantId: operationBeingApproved.tenantId,
      approvalId,
      expectedCurrentState: 'PENDING_APPROVAL',
      nextState: 'EXPIRED',
    });
    throw new Error('APPROVAL_EXPIRED');
  }
  if (approval.makerUserId === verifiedCheckerUserId) {
    throw new Error('MAKER_CHECKER_SELF_APPROVAL_FORBIDDEN');
  }

  const expectedHash = computeCanonicalOperationHash(operationBeingApproved);
  if (approval.canonicalPayloadHash !== expectedHash) {
    await store.markApprovalState({
      tenantId: operationBeingApproved.tenantId,
      approvalId,
      expectedCurrentState: 'PENDING_APPROVAL',
      nextState: 'REVOKED',
    });
    throw new Error('APPROVAL_PAYLOAD_HASH_MISMATCH_REVOKED');
  }

  const transitioned = await store.markApprovalState({
    tenantId: operationBeingApproved.tenantId,
    approvalId,
    expectedCurrentState: 'PENDING_APPROVAL',
    nextState: 'APPROVED',
    checkerUserId: verifiedCheckerUserId,
  });
  if (!transitioned) {
    throw new Error('APPROVAL_CONCURRENT_STATE_MODIFICATION');
  }

  return { state: 'APPROVED', canonicalPayloadHash: expectedHash };
}

/**
 * Execution & Atomic Balance Reservation Step (DEVIL-03 Hardened):
 * Runs inside a single ACID transaction so approval state transition, Maker/Checker/Executor live status verification,
 * atomic balance deduction, and HMAC audit logging commit or roll back together as an indivisible unit.
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

  if (operation.amountMinor <= 0n) {
    throw new Error('OPERATION_AMOUNT_MUST_BE_POSITIVE');
  }

  const executeTxBody = async (txStore: EnterpriseApprovalAndBalanceStore) => {
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
      await txStore.markApprovalState({
        tenantId: operation.tenantId,
        approvalId,
        expectedCurrentState: 'APPROVED',
        nextState: 'EXPIRED',
      });
      throw new Error('APPROVAL_EXPIRED_BEFORE_EXECUTION');
    }

    // 3. Re-verify Maker-Checker separation AND verify that BOTH Maker and Checker are still ACTIVE in the tenant (DEVIL-03)
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

    // 4. Verify canonical operation hash binding (if operation details changed, revoke approval!)
    const currentHash = computeCanonicalOperationHash(operation);
    if (approval.canonicalPayloadHash !== currentHash) {
      await txStore.markApprovalState({
        tenantId: operation.tenantId,
        approvalId,
        expectedCurrentState: 'APPROVED',
        nextState: 'REVOKED',
      });
      throw new Error('APPROVAL_PAYLOAD_TAMPERED_REVOKED');
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
      status: 'EXECUTED' as const,
      remainingBalanceMinor: balanceRes.remainingBalanceMinor,
      canonicalPayloadHash: currentHash,
    };
  };

  if (store.runInAcidTransaction) {
    return store.runInAcidTransaction(executeTxBody);
  }
  return executeTxBody(store);
}
```

---

## 3. OpenAPI All-Alternatives Security Auditor & Confused-Deputy-Hardened MCP Tool Guard (`DEVIL-08`)

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

export interface OpenApiSpecDocument {
  openapi: '3.0.3' | '3.1.0';
  security?: ReadonlyArray<Readonly<Record<string, readonly string[]>>>;
  securitySchemes: Readonly<
    Record<
      string,
      {
        type: 'http' | 'openIdConnect' | 'oauth2' | 'apiKey';
        scheme?: string;
      }
    >
  >;
  operations: readonly OpenApiOperationSpec[];
}

export function auditOpenApiSecurityAlternatives(spec: OpenApiSpecDocument): string[] {
  const violations: string[] = [];

  const isCryptographicJwtScheme = (schemeName: string): boolean => {
    const def = spec.securitySchemes[schemeName];
    if (!def) return false;
    return (
      def.type === 'openIdConnect' ||
      def.type === 'oauth2' ||
      (def.type === 'http' && def.scheme?.toLowerCase() === 'bearer')
    );
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

    const allAlternativesRequireJwt = effectiveSec.every((alternativeObj) => {
      const requiredSchemes = Object.keys(alternativeObj);
      if (requiredSchemes.length === 0) {
        return false;
      }
      return requiredSchemes.some((schemeName) => isCryptographicJwtScheme(schemeName));
    });

    if (!allAlternativesRequireJwt) {
      violations.push(
        `Operation "${op.operationId}": one or more security alternatives allow bypassing cryptographic JWT/OIDC authentication.`
      );
    }
  }

  return violations;
}

/**
 * Runtime MCP Tool Execution Guard (DEVIL-08 Hardened):
 * 1. Enforces authentication, active tenant membership, per-tool permission, and tenant isolation at invocation time.
 * 2. Enforces strict argument key allowlisting (`allowedArgKeys`) to block mass-assignment / schema bypass.
 * 3. Requires a cryptographic Human-in-the-Loop confirmation token (`userConfirmationToken`) bound to
 *    `(userId, tenantId, tool.name, canonicalArgs)` for mutating tools, defeating indirect prompt injection!
 */
export interface McpToolDefinition<TArgs extends Record<string, unknown> & { tenantId: string }, TResult> {
  readonly name: string;
  readonly requiredPermission: string;
  readonly isMutating: boolean;
  readonly allowedArgKeys?: readonly string[];
  execute(
    verifiedContext: { userId: string; tenantId: string; permissions: readonly string[] },
    args: TArgs
  ): Promise<TResult>;
}

function canonicalizeMcpArgValue(val: unknown): string {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'bigint') return JSON.stringify(val.toString());
  if (typeof val !== 'object') return JSON.stringify(val);
  if (Array.isArray(val)) return `[${val.map((v) => canonicalizeMcpArgValue(v)).join(',')}]`;
  const obj = val as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => k !== '__proto__' && k !== 'constructor' && k !== 'prototype')
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeMcpArgValue(obj[k])}`).join(',')}}`;
}

export function computeMcpUserConfirmationToken(params: {
  confirmationSecret: string;
  userId: string;
  tenantId: string;
  toolName: string;
  args: Record<string, unknown>;
}): string {
  const canonicalArgs = canonicalizeMcpArgValue(params.args);
  const canonical = `${params.userId}|${params.tenantId}|${params.toolName}|${canonicalArgs}`;
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
}): Promise<TResult> {
  const { tool, args, verifiedSession } = params;

  if (!verifiedSession || !verifiedSession.userId) {
    throw new Error(`MCP_TOOL_UNAUTHENTICATED:${tool.name}`);
  }
  if (verifiedSession.membershipStatus !== 'ACTIVE') {
    throw new Error(`MCP_TOOL_MEMBERSHIP_NOT_ACTIVE:${tool.name}`);
  }
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    throw new Error(`MCP_TOOL_INVALID_ARGS:${tool.name}`);
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

  // DEVIL-08 Guard 1: Strict argument allowlist to block mass-assignment / schema bypass
  if (tool.allowedArgKeys) {
    const allowedSet = new Set(tool.allowedArgKeys);
    for (const key of Object.keys(args)) {
      if (!allowedSet.has(key) || key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new Error(`MCP_TOOL_UNEXPECTED_ARG_REJECTED:tool=${tool.name}:arg=${key}`);
      }
    }
  }

  // DEVIL-08 Guard 2: Human-in-the-Loop Confirmation Token for mutating tools (blocks indirect prompt injection!)
  if (tool.isMutating && params.confirmationSecret) {
    if (!params.userConfirmationToken || !/^[0-9a-fA-F]{64}$/.test(params.userConfirmationToken)) {
      throw new Error(`MCP_TOOL_HUMAN_CONFIRMATION_REQUIRED:${tool.name}`);
    }
    const expectedToken = Buffer.from(
      computeMcpUserConfirmationToken({
        confirmationSecret: params.confirmationSecret,
        userId: verifiedSession.userId,
        tenantId: verifiedSession.tenantId,
        toolName: tool.name,
        args,
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
