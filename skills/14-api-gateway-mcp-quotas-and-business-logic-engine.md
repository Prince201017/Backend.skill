# Module 14: API Gateway, MCP Security, Quotas & Enterprise Business Logic Engine

## 1. Scope & Threat Model

This module remediates **CRITICAL 2.G (Enterprise Business Logic, Maker-Checker Approval & Atomic Spend Enforcement)** and **HIGH OpenAPI & MCP Security (`auditOpenApiGatewayAndMcpSecurity` + Runtime MCP Tool Authorization)**.

### Trust Boundaries & Failure Modes
1. **Enterprise Business Logic & Maker-Checker Approval (`CRITICAL 2.G`)**:
   - *Vulnerabilities Fixed*:
     1. **Never trust caller-supplied `actorRoles`, `dualApprovalConfirmed`, or `currentBalanceCents`**: In the legacy `evaluateEnterpriseBusinessLogicPolicy(input)`, the caller passed `actorRoles: ['FINANCE_APPROVER']`, `dualApprovalConfirmed: true`, and `currentBalanceCents: 500_000` in the request payload, allowing any authenticated caller to forge their role, spoof dual approval, and bypass balance checks.
     2. **Maker-Checker Self-Approval & Payload Tampering**: Even when a second user ID is recorded, if the approval record is not cryptographically bound to the canonical hash of the operation parameters (`tenantId`, `operationType`, `amountMinor`, `currency`, `destinationAccount`), an attacker can obtain approval for a $100 transfer and execute a $100,000 transfer using the same `approvalId`.
     3. **Non-Atomic Balance Check vs. Deduction (TOCTOU)**: Checking `currentBalanceCents >= amountCents` in application memory without an atomic database reservation (`UPDATE ... SET available_balance_minor = available_balance_minor - $1 WHERE available_balance_minor >= $1`) allows parallel requests to overdraft the tenant's account.
   - *Enforcement*:
     - Resolve both the **Maker** (initiating actor) and **Checker** (approving actor) identities, active tenant memberships, and roles exclusively from the server-side database.
     - Enforce `makerUserId !== checkerUserId` (strict anti-self-approval).
     - Bind every approval to `canonicalPayloadHash = SHA-256(canonicalJson(operation))` and an explicit `expiresAtMs`; if the execution payload differs by a single byte or the approval has expired, reject immediately.
     - Enforce the approval state machine (`PENDING_APPROVAL -> APPROVED -> EXECUTED`) with atomic conditional state transition so an approval can never be executed twice.
     - Atomically deduct/reserve the tenant's balance inside the same database transaction as the approval execution.

2. **OpenAPI Security Alternative Bypass & MCP Tool Runtime Enforcement (`HIGH`)**:
   - *Vulnerabilities Fixed*:
     1. **OpenAPI `security` Array Alternative Bypass**: In OpenAPI 3.x, `security: [ { google_id_token: [] }, { api_key_only: [] } ]` means **either** security requirement object suffices (logical OR). Checking `effectiveSec.some(...)` falsely passes an endpoint that allows an unauthenticated `{}` or API-key-only alternative alongside a JWT requirement! Every permitted security alternative (`effectiveSec.every(...)`) must require a verified JWT/OIDC scheme.
     2. **MCP Tool Registration vs. Runtime Authorization**: Checking `requiresUserAuth: true` only in a static linter does not protect runtime tool invocations. Every MCP tool execution (`executeMcpToolWithRuntimeAuthz`) must verify the caller's server-side identity, active tenant membership, per-tool permission, and tenant-scoped arguments at execution time.

---

## 2. Remediated Enterprise Maker-Checker Approval & Atomic Spend Engine (CRITICAL 2.G)

```typescript
// Executable TypeScript — Server-Verified Maker-Checker Approval & Atomic Balance Reservation
import { createHash, createHmac } from 'node:crypto';

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
 * Execution & Atomic Balance Reservation Step:
 * 1. Verifies the initiating/executing actor's identity, active membership, and FINANCE_INITIATOR role.
 * 2. Verifies the approval record is in 'APPROVED' state, not expired, has distinct Maker and Checker,
 *    and matches the exact canonical SHA-256 operation payload hash.
 * 3. Atomically transitions approval state 'APPROVED' -> 'EXECUTED' (blocking duplicate execution).
 * 4. Atomically reserves/deducts tenant balance (`available_balance_minor >= amountMinor`).
 * 5. Writes an HMAC-signed immutable audit trail.
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

  // 1. Authenticate & authorize executing actor from server-side membership store
  const executorMember = await store.getActorMembership(
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

  // 2. Lock and verify the approval record
  const approval = await store.getApprovalRecordForUpdate(operation.tenantId, approvalId);
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
    await store.markApprovalState({
      tenantId: operation.tenantId,
      approvalId,
      expectedCurrentState: 'APPROVED',
      nextState: 'EXPIRED',
    });
    throw new Error('APPROVAL_EXPIRED_BEFORE_EXECUTION');
  }

  // 3. Re-verify Maker-Checker separation and Maker/Checker active status
  if (!approval.checkerUserId || approval.checkerUserId === approval.makerUserId) {
    throw new Error('MAKER_CHECKER_SEPARATION_VIOLATION');
  }
  const checkerMember = await store.getActorMembership(operation.tenantId, approval.checkerUserId);
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
    await store.markApprovalState({
      tenantId: operation.tenantId,
      approvalId,
      expectedCurrentState: 'APPROVED',
      nextState: 'REVOKED',
    });
    throw new Error('APPROVAL_PAYLOAD_TAMPERED_REVOKED');
  }

  // 5. Transition approval state APPROVED -> EXECUTED before/within atomic balance reservation
  const markedExecuted = await store.markApprovalState({
    tenantId: operation.tenantId,
    approvalId,
    expectedCurrentState: 'APPROVED',
    nextState: 'EXECUTED',
  });
  if (!markedExecuted) {
    throw new Error('APPROVAL_DUPLICATE_CONCURRENT_EXECUTION');
  }

  // 6. Atomically reserve/deduct tenant balance in the database
  const balanceRes = await store.reserveTenantBalanceAtomically({
    tenantId: operation.tenantId,
    currency: operation.currency,
    amountMinor: operation.amountMinor,
    idempotencyKey: operation.idempotencyKey,
  });
  if (!balanceRes.reserved) {
    // Rollback approval state if atomic balance deduction failed
    await store.markApprovalState({
      tenantId: operation.tenantId,
      approvalId,
      expectedCurrentState: 'EXECUTED',
      nextState: 'APPROVED',
    });
    throw new Error('TENANT_INSUFFICIENT_AVAILABLE_BALANCE');
  }

  // 7. Write immutable HMAC-SHA256 audit log
  const auditPayload = `${operation.tenantId}|${approvalId}|${approval.makerUserId}|${approval.checkerUserId}|${verifiedExecutorUserId}|${currentHash}|${operation.amountMinor.toString()}`;
  const auditHmacSignature = createHmac('sha256', auditHmacSecret)
    .update(auditPayload, 'utf8')
    .digest('hex');

  await store.appendImmutableAuditRecord({
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
    status: 'EXECUTED',
    remainingBalanceMinor: balanceRes.remainingBalanceMinor,
    canonicalPayloadHash: currentHash,
  };
}
```

---

## 3. OpenAPI All-Alternatives Security Auditor & Runtime MCP Tool Authorization Guard

```typescript
// Executable TypeScript — Strict OpenAPI Security Auditor (Inspects Every Alternative) & Runtime MCP Guard
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

/**
 * Remediated OpenAPI Security Auditor:
 * Inspects EVERY permitted security alternative (`effectiveSec.every(...)`) on each private operation.
 * If an operation specifies `security: [ { oidc_jwt: [] }, { api_key_only: [] } ]` or `security: [ { oidc_jwt: [] }, {} ]`,
 * the second alternative allows bypassing JWT authentication and is deterministically flagged!
 */
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
      if (!op.xGoogleBackend. address.startsWith('https://')) {
        violations.push(`Operation "${op.operationId}": backend address must use https://.`);
      }
    }

    if (op.isPublicWebhookOrHealth) continue;

    const effectiveSec = op.security !== undefined ? op.security : spec.security;
    if (!effectiveSec || effectiveSec.length === 0) {
      violations.push(`Operation "${op.operationId}": missing security requirement array.`);
      continue;
    }

    // EVERY alternative in the OpenAPI `security` array (logical OR between objects)
    // must require at least one cryptographic JWT/OIDC scheme (logical AND within each object).
    const allAlternativesRequireJwt = effectiveSec.every((alternativeObj) => {
      const requiredSchemes = Object.keys(alternativeObj);
      if (requiredSchemes.length === 0) {
        // An empty `{}` object in OpenAPI `security` makes authentication optional!
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
 * Runtime MCP Tool Execution Guard:
 * Enforces authentication, active tenant membership, per-tool permission, and tenant isolation at invocation time.
 */
export interface McpToolDefinition<TArgs extends { tenantId: string }, TResult> {
  readonly name: string;
  readonly requiredPermission: string;
  readonly isMutating: boolean;
  execute(
    verifiedContext: { userId: string; tenantId: string; permissions: readonly string[] },
    args: TArgs
  ): Promise<TResult>;
}

export async function executeMcpToolWithRuntimeAuthz<
  TArgs extends { tenantId: string },
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
}): Promise<TResult> {
  const { tool, args, verifiedSession } = params;

  if (!verifiedSession || !verifiedSession.userId) {
    throw new Error(`MCP_TOOL_UNAUTHENTICATED:${tool.name}`);
  }
  if (verifiedSession.membershipStatus !== 'ACTIVE') {
    throw new Error(`MCP_TOOL_MEMBERSHIP_NOT_ACTIVE:${tool.name}`);
  }
  // Enforce strict tenant isolation: tool arguments cannot target a different tenant than the authenticated session
  if (!args.tenantId || args.tenantId !== verifiedSession.tenantId) {
    throw new Error(
      `MCP_TOOL_CROSS_TENANT_FORBIDDEN:sessionTenant=${verifiedSession.tenantId}:argTenant=${args.tenantId}`
    );
  }
  if (!verifiedSession.permissions.includes(tool.requiredPermission)) {
    throw new Error(
      `MCP_TOOL_PERMISSION_DENIED:tool=${tool.name}:required=${tool.requiredPermission}`
    );
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
