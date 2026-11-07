# Module 02: Identity Verification, Authentication, Session Management, ReBAC Authorization & Gateway Identity

This module defines the strict separation between **Identity Verification**, **Authentication**, **Session Management**, and **Authorization**, remediates ReBAC owner-escalation and caller-supplied relationship vulnerabilities, enforces absolute session lifetimes on refresh token rotation, and cryptographically verifies API Gateway OIDC assertions before reading forwarded `X-Apigateway-Api-Userinfo` headers.

---

## 1. Threat Model, Trust Boundaries & Failure Behavior

| Security Control | Threat / Exploit Vector | Trust Boundary & Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **RBAC + ReBAC Authorization (`authorizeActionFromTrustedStore`)** | 1) Caller supplies `relationship: "owner"` or `roles: ["admin"]` in request JSON.<br>2) A boolean `hasExplicitRebacRelation` (`relationship === 'owner'`) bypasses role checks, letting an order owner execute `ledger:export`, `order:refund`, or `member:invite`.<br>3) Revoked/expired sharing relationships remain cached. | Server-side policy engine querying authoritative `AuthorizationFactStore` (PostgreSQL). | Default-deny (`allowed: false`). Requires **both** role permission AND (tenant-wide scope role OR active action-specific ReBAC tuple). |
| **Refresh Token Rotation (`rotateRefreshTokenWithReuseDetection`)** | 1) Rolling 14-day TTL allows stolen or automated refresh loops to renew a session indefinitely forever.<br>2) Replay of a rotated token indicates token theft. | Auth token persistence boundary (`auth_refresh_tokens` table). | Rejects if `nowMs >= absoluteSessionExpiresAtMs`; revokes entire `familyId` on rotated token reuse or concurrent race. |
| **API Gateway Identity (`extractVerifiedApiGatewayUserInfo`)** | Passing a boolean `gatewayOidcVerified: true` or trusting `X-Apigateway-Api-Userinfo` without verifying the Gateway OIDC JWT allows attackers to spoof any user identity. | Backend ingress middleware (verifying TCP peer + `Authorization: Bearer <oidc_jwt>` signature). | Rejects with `GATEWAY_OIDC_VERIFICATION_FAILED` before reading `X-Apigateway-Api-Userinfo`. |

---

## 2. Separating Device Registration, Session Binding, Hardware Auth & Risk Evaluation

Browser characteristics, IP addresses, ASNs, and TLS fingerprints are **probabilistic risk signals, NOT deterministic device identities**.

### RFC-Compliant IPv4 (`/24`) & IPv6 (`/48`) Canonical Prefix Extractor
```typescript
import net from 'node:net';

export function extractCanonicalNetworkPrefix(rawIp: string): string {
  const ip = rawIp.trim();
  const version = net.isIP(ip);

  if (version === 4) {
    const octets = ip.split('.').map(Number);
    return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }

  if (version === 6) {
    let normalizedIp = ip;
    if (normalizedIp.includes('.')) {
      const lastColon = normalizedIp.lastIndexOf(':');
      const ipv4Part = normalizedIp.slice(lastColon + 1);
      const octets = ipv4Part.split('.').map(Number);
      const hexHigh = ((octets[0] << 8) | octets[1]).toString(16);
      const hexLow = ((octets[2] << 8) | octets[3]).toString(16);
      normalizedIp = `${normalizedIp.slice(0, lastColon)}:${hexHigh}:${hexLow}`;
    }

    const halves = normalizedIp.split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    const missingHextets = 8 - (left.length + right.length);
    const fullHextets = [
      ...left,
      ...Array(Math.max(0, missingHextets)).fill('0000'),
      ...right,
    ].map((h) => h.padStart(4, '0').toLowerCase());

    return `${fullHextets[0]}:${fullHextets[1]}:${fullHextets[2]}::/48`;
  }

  throw new Error(`Invalid IP address format: ${rawIp}`);
}
```

### Risk-Based Authentication (RBA) Engine
```typescript
export type RiskDecision =
  | 'ALLOW'
  | 'STEP_UP_MFA_REQUIRED'
  | 'HARDWARE_KEY_REQUIRED'
  | 'REAUTHENTICATE_SESSION';

export interface SessionRiskContext {
  sessionBoundCookieValid: boolean;
  isRegisteredDevice: boolean;
  hardwareAttested: boolean;
  baselineIpPrefix: string;
  currentIpPrefix: string;
  baselineAsn?: number;
  currentAsn?: number;
  impossibleTravelDetected: boolean;
  behavioralScrapingScore: number; // 0..100
  isSensitiveAction: boolean;
}

export function evaluateSessionRisk(ctx: SessionRiskContext): {
  riskScore: number;
  decision: RiskDecision;
  reasons: string[];
} {
  const reasons: string[] = [];
  let score = 0;

  if (!ctx.sessionBoundCookieValid) {
    return {
      riskScore: 100,
      decision: 'REAUTHENTICATE_SESSION',
      reasons: ['MISSING_OR_INVALID_SESSION_BINDING_PROOF'],
    };
  }

  if (ctx.baselineIpPrefix !== ctx.currentIpPrefix) {
    score += 15;
    reasons.push('IP_PREFIX_CHANGED');
  }
  if (ctx.baselineAsn && ctx.currentAsn && ctx.baselineAsn !== ctx.currentAsn) {
    score += 20;
    reasons.push('ASN_NETWORK_CHANGED');
  }
  if (ctx.impossibleTravelDetected) {
    score += 45;
    reasons.push('IMPOSSIBLE_GEO_VELOCITY');
  }
  if (!ctx.isRegisteredDevice) {
    score += 20;
    reasons.push('UNREGISTERED_DEVICE');
  }
  if (ctx.behavioralScrapingScore >= 50) {
    score += 35;
    reasons.push('ABNORMAL_REQUEST_VELOCITY');
  }
  if (ctx.hardwareAttested) {
    score = Math.max(0, score - 25);
  }

  const finalScore = Math.min(100, score);
  if (finalScore >= 75) {
    return { riskScore: finalScore, decision: 'REAUTHENTICATE_SESSION', reasons };
  }
  if (finalScore >= 50 && ctx.isSensitiveAction) {
    return { riskScore: finalScore, decision: 'HARDWARE_KEY_REQUIRED', reasons };
  }
  if (finalScore >= 35 || (ctx.isSensitiveAction && !ctx.hardwareAttested)) {
    return { riskScore: finalScore, decision: 'STEP_UP_MFA_REQUIRED', reasons };
  }
  return { riskScore: finalScore, decision: 'ALLOW', reasons };
}
```

---

## 3. Remediated Authorization Engine: Action-Specific RBAC + Trusted Server-Side ReBAC (`authorizeActionFromTrustedStore`)

### Critical Security Rules for RBAC + ReBAC Composition
1. **Never Trust Caller-Provided Roles or Relationships**: `roles`, `ownerId`, and ReBAC `relationship` tuples MUST be loaded on the server from `AuthorizationFactStore` (PostgreSQL), never passed in from client request bodies or unverified headers.
2. **An `'owner'` Relationship Never Grants Universal Action Authority**:
   - Being the creator/`'owner'` of an `order` allows reading that order (`order:read`) or cancelling one's own draft (`order:cancel_own_draft`), **ONLY IF** the user's tenant role also grants that action.
   - An `'owner'` relationship on an `order` or `file` **NEVER** authorizes privileged financial or tenant-management actions such as `'order:refund'`, `'ledger:export'`, or `'member:invite'`.
3. **Conjunctive (AND) Evaluation**:
   - **Step 1 (Tenant Membership & Status)**: Subject must hold an `ACTIVE` membership in `targetTenantId` (suspended/revoked/missing memberships fail closed).
   - **Step 2 (Role Action Permission)**: Subject's verified tenant role(s) must grant `action` in `ROLE_PERMISSIONS`. (A ReBAC relationship can **never** grant an action that the subject's tenant role does not permit!)
   - **Step 3 (Resource Instance Scoping / BOLA)**: For resource-targeted actions, the subject must **either** hold a role listed in `TENANT_WIDE_ACTION_ROLES[action]` (e.g., `'finance'` for `'order:refund'` across the tenant) **or** hold an `ACTIVE`, non-revoked, non-expired ReBAC relationship on that exact `resourceId` that is explicitly mapped to `(resourceType, relation) -> action` in `REBAC_ACTION_POLICY`.

```typescript
export type TenantRole = 'owner' | 'admin' | 'finance' | 'member' | 'viewer';

export type Permission =
  | 'order:read'
  | 'order:create'
  | 'order:cancel_own_draft'
  | 'order:refund'
  | 'file:read'
  | 'file:upload'
  | 'file:delete'
  | 'member:invite'
  | 'ledger:export';

export type ResourceType = 'order' | 'file' | 'ledger' | 'tenant_membership';
export type RebacRelation = 'owner' | 'editor' | 'viewer';

export interface VerifiedSubjectFacts {
  userId: string;
  tenantId: string;
  membershipStatus: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  roles: readonly TenantRole[];
  mfaVerifiedAtMs?: number;
  identityVerificationLevel: 'NONE' | 'EMAIL_VERIFIED' | 'KYC_FULL';
  clearanceLevel: number;
}

export interface VerifiedResourceFacts {
  resourceId: string;
  resourceType: ResourceType;
  tenantId: string;
  ownerUserId?: string;
  amountMinor?: bigint;
  classificationLevel?: number;
  isLocked?: boolean;
}

export interface VerifiedRebacTuple {
  tenantId: string;
  resourceType: ResourceType;
  resourceId: string;
  subjectUserId: string;
  relation: RebacRelation;
  status: 'ACTIVE' | 'REVOKED';
  expiresAtMs?: number;
}

export interface AuthorizationFactStore {
  loadSubjectFacts(tenantId: string, userId: string): Promise<VerifiedSubjectFacts | null>;
  loadResourceFacts(resourceType: ResourceType, resourceId: string): Promise<VerifiedResourceFacts | null>;
  loadActiveRebacRelations(params: {
    tenantId: string;
    resourceType: ResourceType;
    resourceId: string;
    subjectUserId: string;
  }): Promise<readonly VerifiedRebacTuple[]>;
}

// 1. Role-to-Permission Matrix (What actions a role is ever allowed to perform)
const ROLE_PERMISSIONS: Readonly<Record<TenantRole, ReadonlySet<Permission>>> = {
  owner: new Set([
    'order:read',
    'order:create',
    'order:cancel_own_draft',
    'order:refund',
    'file:read',
    'file:upload',
    'file:delete',
    'member:invite',
    'ledger:export',
  ]),
  admin: new Set([
    'order:read',
    'order:create',
    'order:cancel_own_draft',
    'order:refund',
    'file:read',
    'file:upload',
    'file:delete',
    'member:invite',
  ]),
  finance: new Set(['order:read', 'order:refund', 'ledger:export']),
  member: new Set(['order:read', 'order:create', 'order:cancel_own_draft', 'file:read', 'file:upload', 'file:delete']),
  viewer: new Set(['order:read', 'file:read']),
};

// 2. Roles that have tenant-wide scope for a given action (do not require personal ReBAC tuple on the target instance)
const TENANT_WIDE_ACTION_ROLES: Readonly<Record<Permission, ReadonlySet<TenantRole>>> = {
  'order:read': new Set(['owner', 'admin', 'finance']),
  'order:create': new Set(['owner', 'admin', 'member']),
  'order:cancel_own_draft': new Set(['owner', 'admin']),
  'order:refund': new Set(['owner', 'admin', 'finance']),
  'file:read': new Set(['owner', 'admin']),
  'file:upload': new Set(['owner', 'admin', 'member']),
  'file:delete': new Set(['owner', 'admin']),
  'member:invite': new Set(['owner', 'admin']),
  'ledger:export': new Set(['owner', 'finance']),
};

// 3. Explicit Action-to-Relationship Policy Matrix:
// Defines which ReBAC relationships on which resource types can satisfy instance scoping.
// Notice: 'order:refund', 'ledger:export', and 'member:invite' are NEVER granted by resource 'owner' relationships!
const REBAC_ACTION_POLICY: Readonly<
  Record<ResourceType, Readonly<Record<RebacRelation, ReadonlySet<Permission>>>>
> = {
  order: {
    owner: new Set(['order:read', 'order:cancel_own_draft']),
    editor: new Set(['order:read']),
    viewer: new Set(['order:read']),
  },
  file: {
    owner: new Set(['file:read', 'file:delete']),
    editor: new Set(['file:read']),
    viewer: new Set(['file:read']),
  },
  ledger: {
    owner: new Set([]), // Ledger exports require explicit 'owner' or 'finance' tenant role, never ReBAC
    editor: new Set([]),
    viewer: new Set([]),
  },
  tenant_membership: {
    owner: new Set([]), // Member invitations require 'owner' or 'admin' tenant role, never ReBAC
    editor: new Set([]),
    viewer: new Set([]),
  },
};

export async function authorizeActionFromTrustedStore(params: {
  authenticatedUserId: string;
  requestedTenantId: string;
  action: Permission;
  targetResourceType: ResourceType;
  targetResourceId: string;
  factStore: AuthorizationFactStore;
  nowMs?: number;
}): Promise<{
  allowed: boolean;
  reason:
    | 'ALLOWED'
    | 'SUBJECT_NOT_IN_TENANT'
    | 'MEMBERSHIP_NOT_ACTIVE'
    | 'RESOURCE_NOT_FOUND'
    | 'CROSS_TENANT_ACCESS_DENIED'
    | 'ROLE_PERMISSION_DENIED'
    | 'BOLA_RELATIONSHIP_SCOPE_DENIED'
    | 'RESOURCE_IS_LOCKED'
    | 'CLEARANCE_LEVEL_TOO_LOW'
    | 'KYC_IDENTITY_VERIFICATION_REQUIRED'
    | 'STEP_UP_MFA_REQUIRED';
}> {
  const nowMs = params.nowMs ?? Date.now();

  // 1. Load verified subject membership & roles from trusted store
  const subject = await params.factStore.loadSubjectFacts(
    params.requestedTenantId,
    params.authenticatedUserId
  );
  if (!subject) {
    return { allowed: false, reason: 'SUBJECT_NOT_IN_TENANT' };
  }
  if (subject.membershipStatus !== 'ACTIVE') {
    return { allowed: false, reason: 'MEMBERSHIP_NOT_ACTIVE' };
  }

  // 2. Load verified resource facts from trusted store
  const resource = await params.factStore.loadResourceFacts(
    params.targetResourceType,
    params.targetResourceId
  );
  if (!resource) {
    return { allowed: false, reason: 'RESOURCE_NOT_FOUND' };
  }

  // 3. Enforce strict tenant boundary (Cross-Tenant BOLA guard)
  if (subject.tenantId !== resource.tenantId || resource.tenantId !== params.requestedTenantId) {
    return { allowed: false, reason: 'CROSS_TENANT_ACCESS_DENIED' };
  }

  // 4. Enforce Role Permission FIRST (ReBAC ownership NEVER bypasses ROLE_PERMISSIONS!)
  const hasRolePermission = subject.roles.some((r) => ROLE_PERMISSIONS[r]?.has(params.action));
  if (!hasRolePermission) {
    return { allowed: false, reason: 'ROLE_PERMISSION_DENIED' };
  }

  // 5. Enforce Target Resource Scoping (Tenant-wide role OR active, action-specific ReBAC relationship)
  const hasTenantWideScope = subject.roles.some((r) =>
    TENANT_WIDE_ACTION_ROLES[params.action]?.has(r)
  );

  if (!hasTenantWideScope) {
    const tuples = await params.factStore.loadActiveRebacRelations({
      tenantId: resource.tenantId,
      resourceType: resource.resourceType,
      resourceId: resource.resourceId,
      subjectUserId: subject.userId,
    });

    const allowedRelationsForAction = REBAC_ACTION_POLICY[resource.resourceType];
    const hasValidRebacForAction = tuples.some((tuple) => {
      if (tuple.status !== 'ACTIVE') return false;
      if (tuple.tenantId !== resource.tenantId) return false;
      if (tuple.expiresAtMs !== undefined && nowMs >= tuple.expiresAtMs) return false;
      return allowedRelationsForAction?.[tuple.relation]?.has(params.action) ?? false;
    });

    // Also check direct authoritative ownerUserId on the resource record using the 'owner' relation policy
    const isDirectResourceOwnerAllowed =
      resource.ownerUserId !== undefined &&
      resource.ownerUserId === subject.userId &&
      (allowedRelationsForAction?.owner?.has(params.action) ?? false);

    if (!hasValidRebacForAction && !isDirectResourceOwnerAllowed) {
      return { allowed: false, reason: 'BOLA_RELATIONSHIP_SCOPE_DENIED' };
    }
  }

  // 6. Enforce ABAC resource state & classification gates
  if (
    resource.isLocked &&
    params.action !== 'order:read' &&
    params.action !== 'file:read' &&
    params.action !== 'ledger:export'
  ) {
    return { allowed: false, reason: 'RESOURCE_IS_LOCKED' };
  }
  if (
    resource.classificationLevel !== undefined &&
    subject.clearanceLevel < resource.classificationLevel
  ) {
    return { allowed: false, reason: 'CLEARANCE_LEVEL_TOO_LOW' };
  }

  // 7. Enforce Identity Verification (KYC) for financial refunds and ledger exports
  if (
    (params.action === 'order:refund' || params.action === 'ledger:export') &&
    subject.identityVerificationLevel !== 'KYC_FULL'
  ) {
    return { allowed: false, reason: 'KYC_IDENTITY_VERIFICATION_REQUIRED' };
  }

  // 8. Enforce fresh Step-Up MFA (within 5 minutes) for sensitive operations
  const requiresFreshMfa =
    params.action === 'ledger:export' ||
    params.action === 'member:invite' ||
    (params.action === 'order:refund' && (resource.amountMinor ?? 0n) >= 100_000n);

  if (requiresFreshMfa) {
    const fiveMinutesAgo = nowMs - 5 * 60 * 1000;
    if (!subject.mfaVerifiedAtMs || subject.mfaVerifiedAtMs < fiveMinutesAgo) {
      return { allowed: false, reason: 'STEP_UP_MFA_REQUIRED' };
    }
  }

  return { allowed: true, reason: 'ALLOWED' };
}
```

---

## 4. Penetration-Hardened Credential, JWT, Refresh Token Family & Gateway Identity Verification

### A. Timing-Safe Login Verification with Threadpool Starvation Semaphore
```typescript
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(crypto.scrypt);

export interface PasswordHashRecord {
  saltHex: string;
  derivedKeyHex: string;
}

const DUMMY_SALT_HEX = crypto.randomBytes(16).toString('hex');
const DUMMY_DERIVED_HEX = crypto
  .scryptSync('dummy-penetration-defense-secret', Buffer.from(DUMMY_SALT_HEX, 'hex'), 64)
  .toString('hex');

let activeScryptWorkers = 0;
const DEFAULT_MAX_CONCURRENT_SCRYPT = 8;

export async function verifyPasswordTimingSafe(
  candidatePassword: string,
  userHashRecord: PasswordHashRecord | null,
  maxConcurrentHashes = DEFAULT_MAX_CONCURRENT_SCRYPT
): Promise<boolean> {
  // Defeat libuv threadpool starvation DoS: shed load before queuing unbounded scrypt jobs
  if (activeScryptWorkers >= maxConcurrentHashes) {
    throw new Error('AUTH_HASH_CONCURRENCY_LIMIT_EXCEEDED: Too many concurrent password verifications');
  }

  const normalizedPassword = candidatePassword.normalize('NFKC');
  if (Buffer.byteLength(normalizedPassword, 'utf8') > 1024) {
    return false;
  }

  const targetSaltHex = userHashRecord ? userHashRecord.saltHex : DUMMY_SALT_HEX;
  const targetKeyHex = userHashRecord ? userHashRecord.derivedKeyHex : DUMMY_DERIVED_HEX;
  if (!/^[0-9a-fA-F]{32,128}$/.test(targetSaltHex) || !/^[0-9a-fA-F]{128}$/.test(targetKeyHex)) {
    throw new Error('AUTH_INVALID_STORED_HASH_FORMAT');
  }

  activeScryptWorkers += 1;
  try {
    const derivedBuffer = (await scryptAsync(
      normalizedPassword,
      Buffer.from(targetSaltHex, 'hex'),
      64
    )) as Buffer;

    const expectedBuffer = Buffer.from(targetKeyHex, 'hex');
    if (derivedBuffer.length !== expectedBuffer.length) {
      return false;
    }

    const hashesMatch = crypto.timingSafeEqual(derivedBuffer, expectedBuffer);
    return userHashRecord !== null && hashesMatch;
  } finally {
    activeScryptWorkers = Math.max(0, activeScryptWorkers - 1);
  }
}
```

### B. Penetration-Hardened JWT Verifier (`verifyJwtPenetrationSafe`)
```typescript
export interface HardenedJwtVerifyOptions {
  token: string;
  allowedAlgorithm: 'EdDSA' | 'RS256';
  publicKeyRing: Readonly<Record<string, crypto.KeyObject>>;
  expectedIssuer: string;
  expectedAudience: string;
  expectedTyp?: ReadonlySet<string>; // RFC 8725 §3.11 explicit typing (prevents cross-JWT confusion)
  expectedSessionBindingCookie?: string;
  maxTokenLifetimeSeconds?: number;
  isJtiRevoked?: (jti: string) => boolean;
  clockToleranceSeconds?: number;
  requireTenantIdClaim?: boolean;
  nowMs?: number;
}

export interface VerifiedJwtClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat: number;
  jti?: string;
  tenantId?: string;
  email?: string;
  email_verified?: boolean;
  cnf?: { 'x5t#S256'?: string; jkt?: string; sidHash?: string };
}

export function verifyJwtPenetrationSafe(opts: HardenedJwtVerifyOptions): VerifiedJwtClaims {
  if (!opts.token || opts.token.length > 8192) {
    throw new Error('JWT_REJECTED: Token missing or exceeds 8KB maximum size');
  }
  const parts = opts.token.split('.');
  if (parts.length !== 3) {
    throw new Error('JWT_REJECTED: Token must have exactly 3 segments');
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  if (!signatureB64 || signatureB64.length === 0) {
    throw new Error('JWT_REJECTED: Empty signature (alg:none attack blocked)');
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    throw new Error('JWT_REJECTED: Malformed JWT header JSON');
  }

  if (header.alg !== opts.allowedAlgorithm) {
    throw new Error(`JWT_REJECTED: Disallowed algorithm "${String(header.alg)}"`);
  }
  if ('jku' in header || 'x5u' in header || 'jwk' in header || 'x5c' in header) {
    throw new Error('JWT_REJECTED: Dynamic key headers (jku/x5u/jwk/x5c) are forbidden');
  }
  // RFC 7515 §4.1.11: Reject any JWT containing unrecognized Critical ('crit') header parameters
  if ('crit' in header) {
    throw new Error('JWT_REJECTED: Unsupported critical (crit) header extension');
  }
  // RFC 8725 §3.11: Explicit JWT 'typ' verification to block cross-token confusion (e.g. refresh_token as access_token)
  if (opts.expectedTyp) {
    const rawTyp = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
    const normalizedAllowed = new Set(Array.from(opts.expectedTyp).map((t) => t.toLowerCase()));
    if (!normalizedAllowed.has(rawTyp)) {
      throw new Error(`JWT_REJECTED: Unexpected token typ "${String(header.typ)}"`);
    }
  }

  const kid = header.kid;
  if (typeof kid !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(kid)) {
    throw new Error('JWT_REJECTED: Invalid or missing kid header');
  }
  const publicKey = Object.prototype.hasOwnProperty.call(opts.publicKeyRing, kid)
    ? opts.publicKeyRing[kid]
    : undefined;
  if (!publicKey || publicKey.type !== 'public') {
    throw new Error('JWT_REJECTED: Unknown or non-asymmetric verification key');
  }

  const signedInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const signatureBytes = Buffer.from(signatureB64, 'base64url');
  const verifyAlgo = opts.allowedAlgorithm === 'EdDSA' ? null : 'RSA-SHA256';
  const signatureValid = crypto.verify(verifyAlgo, signedInput, publicKey, signatureBytes);
  if (!signatureValid) {
    throw new Error('JWT_REJECTED: Cryptographic signature verification failed');
  }

  let claims: VerifiedJwtClaims;
  try {
    claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as VerifiedJwtClaims;
  } catch {
    throw new Error('JWT_REJECTED: Malformed JWT payload JSON');
  }

  const nowSec = Math.floor((opts.nowMs ?? Date.now()) / 1000);
  const leeway = opts.clockToleranceSeconds ?? 15;
  const maxLifetimeSec = opts.maxTokenLifetimeSeconds ?? 3600;

  if (claims.iss !== opts.expectedIssuer) {
    throw new Error('JWT_REJECTED: Issuer mismatch');
  }
  const audMatch = Array.isArray(claims.aud)
    ? claims.aud.includes(opts.expectedAudience)
    : claims.aud === opts.expectedAudience;
  if (!audMatch) {
    throw new Error('JWT_REJECTED: Audience mismatch');
  }
  if (typeof claims.exp !== 'number' || nowSec >= claims.exp + leeway) {
    throw new Error('JWT_REJECTED: Token has expired');
  }
  if (typeof claims.iat !== 'number' || claims.iat > nowSec + leeway) {
    throw new Error('JWT_REJECTED: Token iat is in the future');
  }
  if (claims.exp <= claims.iat || claims.exp - claims.iat > maxLifetimeSec) {
    throw new Error(`JWT_REJECTED: Token lifetime exceeds maximum allowed TTL (${maxLifetimeSec}s)`);
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || nowSec + leeway < claims.nbf)) {
    throw new Error('JWT_REJECTED: Token is not yet valid (nbf)');
  }
  if (!claims.sub) {
    throw new Error('JWT_REJECTED: Missing required sub claim');
  }
  if (opts.requireTenantIdClaim !== false && (!claims.jti || !claims.tenantId)) {
    throw new Error('JWT_REJECTED: Missing required jti or tenantId claim');
  }
  if (claims.jti && opts.isJtiRevoked && opts.isJtiRevoked(claims.jti)) {
    throw new Error('JWT_REJECTED: Token jti has been revoked');
  }

  if (opts.expectedSessionBindingCookie !== undefined) {
    const expectedSidHash = crypto
      .createHash('sha256')
      .update(opts.expectedSessionBindingCookie, 'utf8')
      .digest('hex');
    if (!claims.cnf?.sidHash || claims.cnf.sidHash !== expectedSidHash) {
      throw new Error('JWT_REJECTED: Session binding cookie hash mismatch');
    }
  }

  return claims;
}
```

### C. Refresh Token Rotation with Absolute Session Lifetime, Family Reuse Detection & Device Binding
A rolling 14-day refresh expiry alone allows an active session (or an attacker who stole a session before MFA policy changes) to renew indefinitely forever.
- **Mandatory Fix**: Store `sessionCreatedAtMs` and `absoluteSessionExpiresAtMs` (e.g., 30 days from initial login) on the token family. Clamp every rotated child token's `expiresAtMs` to `Math.min(nowMs + rollingTtlMs, existing.absoluteSessionExpiresAtMs)` and reject rotation once `nowMs >= existing.absoluteSessionExpiresAtMs`.

```typescript
export interface RefreshTokenRecord {
  tokenHash: string;
  familyId: string;
  userId: string;
  tenantId: string;
  deviceId: string;
  status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  expiresAtMs: number;
  sessionCreatedAtMs: number;
  absoluteSessionExpiresAtMs: number; // Hard ceiling (e.g. sessionCreatedAtMs + 30 days)
}

export async function rotateRefreshTokenWithReuseDetection(params: {
  rawRefreshToken: string;
  expectedDeviceId: string;
  rollingTtlMs?: number; // Default 14 days
  nowMs?: number;
  findTokenByHash: (tokenHash: string) => Promise<RefreshTokenRecord | null>;
  markTokenRotatedAndInsertChild: (oldHash: string, newRecord: RefreshTokenRecord) => Promise<boolean>;
  revokeEntireTokenFamily: (familyId: string, reason: string) => Promise<void>;
}): Promise<{
  newRawRefreshToken: string;
  familyId: string;
  userId: string;
  tenantId: string;
  expiresAtMs: number;
  absoluteSessionExpiresAtMs: number;
}> {
  const nowMs = params.nowMs ?? Date.now();
  const rollingTtlMs = params.rollingTtlMs ?? 14 * 24 * 60 * 60 * 1000;
  const tokenHash = crypto.createHash('sha256').update(params.rawRefreshToken, 'utf8').digest('hex');
  const existing = await params.findTokenByHash(tokenHash);

  if (!existing) {
    throw new Error('REFRESH_TOKEN_INVALID');
  }

  // 1. Reuse detection: if token was already rotated or revoked, revoke the entire token family immediately!
  if (existing.status === 'ROTATED' || existing.status === 'REVOKED') {
    await params.revokeEntireTokenFamily(existing.familyId, 'REFRESH_TOKEN_REUSE_DETECTED');
    throw new Error('REFRESH_TOKEN_COMPROMISED_FAMILY_REVOKED');
  }

  // 2. Device binding verification
  if (existing.deviceId !== params.expectedDeviceId) {
    await params.revokeEntireTokenFamily(existing.familyId, 'REFRESH_TOKEN_DEVICE_MISMATCH');
    throw new Error('REFRESH_TOKEN_DEVICE_MISMATCH_FAMILY_REVOKED');
  }

  // 3. Enforce BOTH rolling expiry AND hard absolute session lifetime!
  if (nowMs >= existing.expiresAtMs) {
    throw new Error('REFRESH_TOKEN_EXPIRED');
  }
  if (nowMs >= existing.absoluteSessionExpiresAtMs) {
    await params.revokeEntireTokenFamily(existing.familyId, 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED');
    throw new Error('SESSION_ABSOLUTE_LIFETIME_EXCEEDED_REAUTH_REQUIRED');
  }

  // Clamp child token expiry so rolling renewals can NEVER extend past absoluteSessionExpiresAtMs
  const nextExpiresAtMs = Math.min(nowMs + rollingTtlMs, existing.absoluteSessionExpiresAtMs);
  const newRawRefreshToken = crypto.randomBytes(32).toString('base64url');
  const newTokenHash = crypto.createHash('sha256').update(newRawRefreshToken, 'utf8').digest('hex');

  const updated = await params.markTokenRotatedAndInsertChild(tokenHash, {
    tokenHash: newTokenHash,
    familyId: existing.familyId,
    userId: existing.userId,
    tenantId: existing.tenantId,
    deviceId: existing.deviceId,
    status: 'ACTIVE',
    expiresAtMs: nextExpiresAtMs,
    sessionCreatedAtMs: existing.sessionCreatedAtMs,
    absoluteSessionExpiresAtMs: existing.absoluteSessionExpiresAtMs,
  });

  if (!updated) {
    // Concurrent refresh race on the same token -> revoke entire family
    await params.revokeEntireTokenFamily(existing.familyId, 'CONCURRENT_REFRESH_RACE');
    throw new Error('REFRESH_TOKEN_COMPROMISED_FAMILY_REVOKED');
  }

  return {
    newRawRefreshToken,
    familyId: existing.familyId,
    userId: existing.userId,
    tenantId: existing.tenantId,
    expiresAtMs: nextExpiresAtMs,
    absoluteSessionExpiresAtMs: existing.absoluteSessionExpiresAtMs,
  };
}
```

### D. Cryptographic API Gateway OIDC Verification & `X-Apigateway-Api-Userinfo` Claim Extractor
**Critical Vulnerability Remediated**: A caller-provided boolean (`gatewayOidcVerified: boolean`) is **NOT** proof of gateway identity. The backend must cryptographically verify the `Authorization: Bearer <gateway_oidc_jwt>` token attached by API Gateway against Google's signing keys (`RS256`), verify `iss === 'https://accounts.google.com'`, `aud === expectedBackendAudience`, `email === expectedGatewayServiceAccountEmail`, and `email_verified === true` **before** decoding `X-Apigateway-Api-Userinfo`.

```typescript
export interface ApiGatewayUserInfoClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  email?: string;
  tenantId?: string;
}

export function extractVerifiedApiGatewayUserInfo(params: {
  rawGatewayAuthorizationHeader: string | undefined; // "Bearer <gateway_oidc_id_token>"
  gatewayPublicKeyRing: Readonly<Record<string, crypto.KeyObject>>;
  expectedGatewayIssuer?: string; // Defaults to 'https://accounts.google.com'
  expectedBackendAudience: string; // e.g. 'https://orders-backend-xyz.a.run.app'
  expectedGatewayServiceAccountEmail: string;
  rawUserInfoHeader: string | undefined;
  expectedEndUserIssuers: ReadonlySet<string>;
  expectedEndUserAudiences: ReadonlySet<string>;
  nowMs?: number;
}): {
  verifiedGatewayServiceAccount: string;
  endUserClaims: ApiGatewayUserInfoClaims;
} {
  // 1. Extract and cryptographically verify the API Gateway OIDC Bearer token
  if (
    !params.rawGatewayAuthorizationHeader ||
    !params.rawGatewayAuthorizationHeader.startsWith('Bearer ')
  ) {
    throw new Error('GATEWAY_OIDC_MISSING: Missing Authorization Bearer token from API Gateway');
  }
  const gatewayOidcToken = params.rawGatewayAuthorizationHeader.slice('Bearer '.length).trim();

  const gatewayClaims = verifyJwtPenetrationSafe({
    token: gatewayOidcToken,
    allowedAlgorithm: 'RS256',
    publicKeyRing: params.gatewayPublicKeyRing,
    expectedIssuer: params.expectedGatewayIssuer ?? 'https://accounts.google.com',
    expectedAudience: params.expectedBackendAudience,
    requireTenantIdClaim: false,
    nowMs: params.nowMs,
  });

  if (
    gatewayClaims.email !== params.expectedGatewayServiceAccountEmail ||
    gatewayClaims.email_verified !== true
  ) {
    throw new Error(
      `GATEWAY_OIDC_IDENTITY_MISMATCH: Token email "${String(gatewayClaims.email)}" does not match expected gateway service account "${params.expectedGatewayServiceAccountEmail}"`
    );
  }

  // 2. Only AFTER the gateway OIDC assertion is cryptographically verified, decode X-Apigateway-Api-Userinfo
  if (!params.rawUserInfoHeader || params.rawUserInfoHeader.length > 8192) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Missing or oversized X-Apigateway-Api-Userinfo header');
  }

  const normalizedB64 = params.rawUserInfoHeader.trim();
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(normalizedB64)) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Invalid base64url encoding');
  }
  const padLen = (4 - (normalizedB64.length % 4)) % 4;
  const paddedB64 = normalizedB64 + '='.repeat(padLen);

  let endUserClaims: ApiGatewayUserInfoClaims;
  try {
    endUserClaims = JSON.parse(
      Buffer.from(paddedB64, 'base64url').toString('utf8')
    ) as ApiGatewayUserInfoClaims;
  } catch {
    throw new Error('GATEWAY_USERINFO_REJECTED: Malformed JSON payload in X-Apigateway-Api-Userinfo');
  }

  if (!endUserClaims.sub || !endUserClaims.iss || !params.expectedEndUserIssuers.has(endUserClaims.iss)) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Missing sub or untrusted issuer in userinfo claims');
  }

  const audList = Array.isArray(endUserClaims.aud) ? endUserClaims.aud : [endUserClaims.aud];
  if (!audList.some((a) => typeof a === 'string' && params.expectedEndUserAudiences.has(a))) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Audience mismatch in userinfo claims');
  }

  const nowSec = Math.floor((params.nowMs ?? Date.now()) / 1000);
  if (typeof endUserClaims.exp !== 'number' || nowSec >= endUserClaims.exp + 15) {
    throw new Error('GATEWAY_USERINFO_REJECTED: End-user JWT in X-Apigateway-Api-Userinfo has expired');
  }

  return {
    verifiedGatewayServiceAccount: gatewayClaims.email,
    endUserClaims,
  };
}
```

---

## 5. Verification & Test Requirements

1. **ReBAC Owner Privilege Escalation Tests (`TEST-03`, `TEST-04`)**:
   - Resource `'owner'` with `'member'` role attempting `'ledger:export'` -> rejected with `ROLE_PERMISSION_DENIED`.
   - Resource `'owner'` with `'member'` role attempting `'member:invite'` -> rejected with `ROLE_PERMISSION_DENIED`.
   - Resource `'owner'` with `'member'` role attempting `'order:refund'` -> rejected with `ROLE_PERMISSION_DENIED`.
   - Member with revoked ReBAC tuple (`status: 'REVOKED'`) or expired ReBAC tuple attempting `'order:read'` on another user's order -> rejected with `BOLA_RELATIONSHIP_SCOPE_DENIED`.
2. **Refresh Token Reuse, Concurrent Race & Absolute Lifetime Tests (`TEST-07`, `TEST-08`)**:
   - Replaying an already-rotated token revokes the entire `familyId`.
   - Concurrent refresh calls on the same token trigger `CONCURRENT_REFRESH_RACE` family revocation.
   - Refresh attempt after `absoluteSessionExpiresAtMs` fails with `SESSION_ABSOLUTE_LIFETIME_EXCEEDED_REAUTH_REQUIRED`.
3. **Gateway Identity Spoofing Test (`TEST-26`)**:
   - Forged `X-Apigateway-Api-Userinfo` header sent with a missing, invalidly signed, or wrong-service-account `Authorization: Bearer` OIDC token is rejected before inspecting `X-Apigateway-Api-Userinfo`.

### Authoritative References
- **RFC 8725 — JSON Web Token Best Current Practices**: https://datatracker.ietf.org/doc/html/rfc8725
- **RFC 9700 — OAuth 2.0 Security Best Current Practice (Refresh Token Rotation)**: https://datatracker.ietf.org/doc/html/rfc9700
- **Google Cloud API Gateway — Authenticating Between Services (OIDC)**: https://cloud.google.com/api-gateway/docs/authenticating-service-to-service
