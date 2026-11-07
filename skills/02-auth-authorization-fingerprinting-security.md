# Module 02: Identity Verification, Authentication, Session Management, Authorization & Risk-Based Security

This reference defines the strict separation between **Identity Verification**, **Authentication**, **Session Management**, and **Authorization**, and separates **Session Binding**, **Device Registration**, **Hardware-Backed Authentication**, **Risk-Based Authentication (RBA)**, and **Behavioral Anomaly Detection**.

---

## 1. The 4-Pillar Security Architecture Separation

Never conflate authentication, session management, identity proofing, and authorization:

1. **Identity Verification (Proofing / KYC / KYB)**:
   - Verifies that an account corresponds to a real-world person or legal entity (email/phone ownership proof, government ID verification, business registry check, sanctions/AML screening).
   - Stored in `identity_verifications (user_id, level, provider, verified_at, expires_at, status)`.
2. **Authentication (AuthN)**:
   - Verifies credential ownership at a point in time (Argon2id password, FIDO2/WebAuthn Passkey assertion, OIDC federated assertion, TOTP/HOTP second factor).
   - Produces an authentication event with explicit `amr` (Authentication Methods References: `['pwd', 'mfa', 'hwk']`) and `acr` (Authentication Context Class Reference).
3. **Session Management**:
   - Governs the post-authentication lifecycle: session binding (`__Host-sid`), refresh token rotation with family reuse detection, idle timeout (e.g., 30 mins of inactivity), absolute timeout (e.g., 14 days), and immediate server-side revocation on logout/password change.
4. **Authorization (AuthZ)**:
   - Evaluates whether the authenticated subject is permitted to perform a specific `action` on a specific `resource` within a specific `environment` (BOLA tenant scoping + RBAC + ABAC + ReBAC).

---

## 2. Separating Device Registration, Session Binding, Hardware Auth & Risk Evaluation

Browser characteristics, IP addresses, ASNs, and TLS fingerprints are **probabilistic risk signals, NOT deterministic device identities** (they change legitimately across VPNs, mobile handoffs, CGNAT, and browser upgrades, and can be spoofed).

### Architectural Separation of the 5 Device & Risk Controls
1. **Session Binding**: Cryptographic binding between an active session/access token and a secret held by the client (`__Host-sid` `HttpOnly; Secure; SameSite=Strict` cookie or RFC 9449 DPoP proof-of-possession key).
2. **Device Registration**: Explicit enrollment of a known device in `registered_devices` after strong authentication (MFA/Passkey), issuing a cryptographic device certificate or WebCrypto non-extractable keypair.
3. **Hardware-Backed Authentication**: FIDO2 / WebAuthn Passkeys, Apple App Attest / DeviceCheck, Android Play Integrity API, or mTLS client certificates stored in Secure Enclave / TPM.
4. **Risk-Based Authentication (RBA)**: Evaluates network, geo-velocity, device-registration state, and transport signals into a risk decision (`ALLOW`, `CHALLENGE_MFA`, `CHALLENGE_PASSKEY`, `LOCK_SESSION_FOR_REAUTH`). **Never automatically terminate a user's account solely on a fingerprint mismatch.**
5. **Behavioral Anomaly Detection**: Tracks session-level velocity (e.g., rapid sequential scraping of 200 records, mass export attempts, abnormal API mutation cadence).

### RFC-Compliant IPv4 (`/24`) & IPv6 (`/48`) Canonical Prefix Extractor
Never use naive `.split(':')` on IPv6 addresses (which fails on `::` zero-compression such as `2001:db8::1` or IPv4-mapped `::ffff:192.0.2.1`). Expand IPv6 into its canonical 8 hextets first:

```typescript
import net from 'node:net';

/**
 * Expands any valid IPv4 or IPv6 address (including compressed '::' and IPv4-mapped addresses)
 * into a canonical network prefix (/24 for IPv4, /48 for IPv6).
 */
export function extractCanonicalNetworkPrefix(rawIp: string): string {
  const ip = rawIp.trim();
  const version = net.isIP(ip);

  if (version === 4) {
    const octets = ip.split('.').map(Number);
    return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }

  if (version === 6) {
    // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:192.0.2.128)
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

    // /48 prefix = first 3 hextets (48 bits)
    return `${fullHextets[0]}:${fullHextets[1]}:${fullHextets[2]}::/48`;
  }

  throw new Error(`Invalid IP address format: ${rawIp}`);
}
```

### Risk-Based Authentication (RBA) & Behavioral Evaluation Engine
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

  // 1. Session binding check (cryptographic cookie proof)
  if (!ctx.sessionBoundCookieValid) {
    return {
      riskScore: 100,
      decision: 'REAUTHENTICATE_SESSION',
      reasons: ['MISSING_OR_INVALID_SESSION_BINDING_PROOF'],
    };
  }

  // 2. Network & Geo-velocity signals (treated as probabilistic risk, never instant ban)
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

  // 3. Behavioral anomaly signal
  if (ctx.behavioralScrapingScore >= 50) {
    score += 35;
    reasons.push('ABNORMAL_REQUEST_VELOCITY');
  }

  // 4. Hardware attestation reduces risk
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

## 3. Authenticated Authorization Engine (RBAC + ABAC + ReBAC)

```typescript
export type Permission =
  | 'order:read'
  | 'order:create'
  | 'order:refund'
  | 'file:upload'
  | 'file:delete'
  | 'member:invite'
  | 'ledger:export';

export interface AuthSubject {
  userId: string;
  tenantId: string;
  roles: ('owner' | 'admin' | 'finance' | 'member' | 'viewer')[];
  mfaVerifiedAt?: number;
  identityVerificationLevel: 'NONE' | 'EMAIL_VERIFIED' | 'KYC_FULL';
  clearanceLevel: number;
}

export interface ResourceContext {
  type: 'order' | 'file' | 'ledger';
  id: string;
  tenantId: string;
  ownerId?: string;
  relationship?: 'owner' | 'editor' | 'viewer' | 'none'; // ReBAC graph relation
  amountMinor?: bigint;
  classificationLevel?: number;
  isLocked?: boolean;
}

const ROLE_PERMISSIONS: Record<AuthSubject['roles'][number], Permission[]> = {
  owner: ['order:read', 'order:create', 'order:refund', 'file:upload', 'file:delete', 'member:invite', 'ledger:export'],
  admin: ['order:read', 'order:create', 'order:refund', 'file:upload', 'file:delete', 'member:invite'],
  finance: ['order:read', 'order:refund', 'ledger:export'],
  member: ['order:read', 'order:create', 'file:upload'],
  viewer: ['order:read'],
};

export function authorizeAction(
  subject: AuthSubject,
  action: Permission,
  resource: ResourceContext
): { allowed: boolean; reason?: string } {
  // 1. Mandatory Multi-Tenant Isolation (BOLA / IDOR protection)
  if (subject.tenantId !== resource.tenantId) {
    return { allowed: false, reason: 'CROSS_TENANT_ACCESS_DENIED' };
  }

  // 2. Intra-Tenant Horizontal BOLA / IDOR Guard:
  // Non-privileged roles ('member', 'viewer') may only access resources they own or have an explicit ReBAC relation to.
  const isTenantPrivileged = subject.roles.some((r) => r === 'owner' || r === 'admin' || r === 'finance');
  const isResourceOwner = resource.ownerId !== undefined && resource.ownerId === subject.userId;
  const hasExplicitRebacRelation =
    resource.relationship === 'owner' ||
    (action === 'order:read' && (resource.relationship === 'editor' || resource.relationship === 'viewer'));

  if (!isTenantPrivileged && action !== 'order:create' && action !== 'file:upload') {
    if (!isResourceOwner && !hasExplicitRebacRelation) {
      return { allowed: false, reason: 'BOLA_HORIZONTAL_OWNERSHIP_DENIED' };
    }
  }

  // 3. RBAC + ReBAC Permission Check
  const hasRolePerm = subject.roles.some((r) => ROLE_PERMISSIONS[r]?.includes(action));

  if (!hasRolePerm && !hasExplicitRebacRelation) {
    return { allowed: false, reason: 'INSUFFICIENT_PERMISSION' };
  }

  // 4. Identity Verification Gate for financial exports/refunds
  if ((action === 'order:refund' || action === 'ledger:export') && subject.identityVerificationLevel !== 'KYC_FULL') {
    return { allowed: false, reason: 'KYC_IDENTITY_VERIFICATION_REQUIRED' };
  }

  // 5. ABAC Contextual Policy Rules
  if (resource.isLocked && action !== 'order:read') {
    return { allowed: false, reason: 'RESOURCE_IS_LOCKED' };
  }
  if (resource.classificationLevel !== undefined && subject.clearanceLevel < resource.classificationLevel) {
    return { allowed: false, reason: 'CLEARANCE_LEVEL_TOO_LOW' };
  }

  // 6. Step-Up MFA enforcement for high-value refunds (> $1,000.00 = 100_000 cents) or ledger exports
  const requiresFreshMfa =
    action === 'ledger:export' ||
    (action === 'order:refund' && (resource.amountMinor ?? 0n) >= 100_000n);

  if (requiresFreshMfa) {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    if (!subject.mfaVerifiedAt || subject.mfaVerifiedAt < fiveMinutesAgo) {
      return { allowed: false, reason: 'STEP_UP_MFA_REQUIRED' };
    }
  }

  return { allowed: true };
}
```

---

## 4. Penetration-Hardened Credential, Refresh Token Family & JWT Verification

### A. Timing-Safe Login Verification (Defeating Account Enumeration Oracles)
During penetration testing, attackers measure response latency on `POST /api/v1/auth/login` to distinguish valid emails (`~120ms` Argon2id/scrypt CPU work) from non-existent emails (`~1ms` early return).
- **Mandatory Rule**: Always execute a real KDF verification against a precomputed `DUMMY_PASSWORD_HASH` when `user === null` so both code paths perform identical CPU work and return the exact same generic error message.

```typescript
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(crypto.scrypt);

export interface PasswordHashRecord {
  saltHex: string;
  derivedKeyHex: string;
}

// Precomputed at server boot so non-existent user lookups consume identical CPU cycles
const DUMMY_SALT_HEX = crypto.randomBytes(16).toString('hex');
const DUMMY_DERIVED_HEX = crypto.scryptSync('dummy-penetration-defense-secret', Buffer.from(DUMMY_SALT_HEX, 'hex'), 64).toString('hex');

export async function verifyPasswordTimingSafe(
  candidatePassword: string,
  userHashRecord: PasswordHashRecord | null
): Promise<boolean> {
  // Always normalize Unicode (NFKC) and cap password byte length (<= 1024 bytes) to prevent DoS
  const normalizedPassword = candidatePassword.normalize('NFKC');
  if (Buffer.byteLength(normalizedPassword, 'utf8') > 1024) {
    return false;
  }

  const targetSaltHex = userHashRecord ? userHashRecord.saltHex : DUMMY_SALT_HEX;
  const targetKeyHex = userHashRecord ? userHashRecord.derivedKeyHex : DUMMY_DERIVED_HEX;

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
  // Only return true if the user actually existed AND the hash matched
  return userHashRecord !== null && hashesMatch;
}
```

### B. Penetration-Hardened JWT Verifier (Defeating `alg: none`, Algorithm Confusion & `kid` Injection)
Penetration testers routinely exploit JWT implementations via:
1. **`alg: "none"`**: Stripping the signature and setting `"alg": "none"`.
2. **Algorithm Confusion (`RS256` -> `HS256`)**: Signing a forged token using the server's public RSA/ECDSA key as a symmetric HMAC secret.
3. **`kid` Path Traversal / SQLi & `jku`/`x5u` SSRF**: Injecting `"kid": "../../../../dev/null"` or `"jku": "https://attacker.com/jwks.json"`.

```typescript
export interface HardenedJwtVerifyOptions {
  token: string;
  allowedAlgorithm: 'EdDSA' | 'RS256';
  publicKeyRing: Readonly<Record<string, crypto.KeyObject>>; // Keyed by strict kid
  expectedIssuer: string;
  expectedAudience: string;
  expectedSessionBindingCookie?: string; // Optional __Host-sid value to verify cnf.sidHash
  maxTokenLifetimeSeconds?: number;      // Default 3600s (1 hour) — blocks perpetual/100-year access tokens
  isJtiRevoked?: (jti: string) => boolean;
  clockToleranceSeconds?: number;
}

export interface VerifiedJwtClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  iat: number;
  jti: string;
  tenantId: string;
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
    const headerJson = Buffer.from(headerB64, 'base64url').toString('utf8');
    header = JSON.parse(headerJson) as Record<string, unknown>;
  } catch {
    throw new Error('JWT_REJECTED: Malformed JWT header JSON');
  }

  // 1. Strict Algorithm Pinning (blocks alg:none and RS256->HS256 confusion)
  if (header.alg !== opts.allowedAlgorithm) {
    throw new Error(`JWT_REJECTED: Disallowed algorithm "${String(header.alg)}"`);
  }

  // 2. Forbid external key-fetching headers (blocks jku/x5u SSRF and embedded jwk forgery)
  if ('jku' in header || 'x5u' in header || 'jwk' in header || 'x5c' in header) {
    throw new Error('JWT_REJECTED: Dynamic key headers (jku/x5u/jwk/x5c) are forbidden');
  }

  // 3. Validate 'kid' against strict alphanumeric allowlist before key-ring lookup
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

  // 4. Verify cryptographic signature before inspecting payload claims
  const signedInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const signatureBytes = Buffer.from(signatureB64, 'base64url');
  const verifyAlgo = opts.allowedAlgorithm === 'EdDSA' ? null : 'RSA-SHA256';
  const signatureValid = crypto.verify(verifyAlgo, signedInput, publicKey, signatureBytes);
  if (!signatureValid) {
    throw new Error('JWT_REJECTED: Cryptographic signature verification failed');
  }

  // 5. Parse and validate standard temporal & identity claims
  let claims: VerifiedJwtClaims;
  try {
    claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as VerifiedJwtClaims;
  } catch {
    throw new Error('JWT_REJECTED: Malformed JWT payload JSON');
  }

  const nowSec = Math.floor(Date.now() / 1000);
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
  if (!claims.sub || !claims.jti || !claims.tenantId) {
    throw new Error('JWT_REJECTED: Missing required sub, jti, or tenantId claim');
  }
  if (opts.isJtiRevoked && opts.isJtiRevoked(claims.jti)) {
    throw new Error('JWT_REJECTED: Token jti has been revoked');
  }

  // 6. Optional Cryptographic Session Binding Cookie Verification (__Host-sid)
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

### C. Refresh Token Rotation with Token-Family Reuse Detection
When a refresh token is rotated, store its `family_id` (`session_id`) and `replaced_by_token_hash`. If an already-rotated refresh token is presented again (indicating either the attacker or the legitimate user replayed a stolen token), **immediately revoke the entire `family_id` session**:

```typescript
export interface RefreshTokenRecord {
  tokenHash: string;
  familyId: string;
  userId: string;
  tenantId: string;
  status: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  expiresAtMs: number;
}

export async function rotateRefreshTokenWithReuseDetection(params: {
  rawRefreshToken: string;
  findTokenByHash: (tokenHash: string) => Promise<RefreshTokenRecord | null>;
  markTokenRotatedAndInsertChild: (oldHash: string, newRecord: RefreshTokenRecord) => Promise<boolean>;
  revokeEntireTokenFamily: (familyId: string, reason: string) => Promise<void>;
}): Promise<{ newRawRefreshToken: string; familyId: string; userId: string; tenantId: string }> {
  const tokenHash = crypto.createHash('sha256').update(params.rawRefreshToken, 'utf8').digest('hex');
  const existing = await params.findTokenByHash(tokenHash);

  if (!existing) {
    throw new Error('REFRESH_TOKEN_INVALID');
  }

  // CRITICAL: If token was ALREADY rotated, a token theft replay occurred -> Revoke whole family!
  if (existing.status === 'ROTATED' || existing.status === 'REVOKED') {
    await params.revokeEntireTokenFamily(existing.familyId, 'REFRESH_TOKEN_REUSE_DETECTED');
    throw new Error('REFRESH_TOKEN_COMPROMISED_FAMILY_REVOKED');
  }

  if (Date.now() >= existing.expiresAtMs) {
    throw new Error('REFRESH_TOKEN_EXPIRED');
  }

  const newRawRefreshToken = crypto.randomBytes(32).toString('base64url');
  const newTokenHash = crypto.createHash('sha256').update(newRawRefreshToken, 'utf8').digest('hex');

  const updated = await params.markTokenRotatedAndInsertChild(tokenHash, {
    tokenHash: newTokenHash,
    familyId: existing.familyId,
    userId: existing.userId,
    tenantId: existing.tenantId,
    status: 'ACTIVE',
    expiresAtMs: Date.now() + 14 * 24 * 60 * 60 * 1000,
  });

  if (!updated) {
    // Concurrent race on the same refresh token -> treat as reuse and revoke family
    await params.revokeEntireTokenFamily(existing.familyId, 'CONCURRENT_REFRESH_RACE');
    throw new Error('REFRESH_TOKEN_COMPROMISED_FAMILY_REVOKED');
  }

  return {
    newRawRefreshToken,
    familyId: existing.familyId,
    userId: existing.userId,
    tenantId: existing.tenantId,
  };
}
```

### D. API Gateway Header Override & `X-Apigateway-Api-Userinfo` Claim Extractor
When Google Cloud API Gateway routes a request to a backend with backend authentication enabled (`x-google-backend`), API Gateway **overrides the `Authorization` header** with the gateway's own OIDC service account ID token and places the verified client JWT payload in `X-Apigateway-Api-Userinfo`.
- **Critical Vulnerability to Prevent**: Never read `X-Apigateway-Api-Userinfo` unless the backend has first verified that the request arrived from the authenticated API Gateway service account (`gatewayOidcVerified === true`), or an attacker reaching the backend directly could forge `X-Apigateway-Api-Userinfo`!

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
  gatewayOidcVerified: boolean;
  gatewayServiceAccountEmail: string;
  expectedGatewayServiceAccountEmail: string;
  rawUserInfoHeader: string | undefined;
  expectedIssuers: ReadonlySet<string>;
  expectedAudiences: ReadonlySet<string>;
}): ApiGatewayUserInfoClaims {
  // 1. Mandatory Gateway OIDC Service Account Proof (blocks direct X-Apigateway-Api-Userinfo spoofing)
  if (
    !params.gatewayOidcVerified ||
    params.gatewayServiceAccountEmail !== params.expectedGatewayServiceAccountEmail
  ) {
    throw new Error('GATEWAY_AUTH_BYPASS_BLOCKED: Request lacks verified API Gateway OIDC service account identity');
  }

  if (!params.rawUserInfoHeader || params.rawUserInfoHeader.length > 8192) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Missing or oversized X-Apigateway-Api-Userinfo header');
  }

  // 2. Restore standard base64url '=' padding if required and decode JSON claims
  const normalizedB64 = params.rawUserInfoHeader.trim();
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(normalizedB64)) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Invalid base64url encoding');
  }
  const padLen = (4 - (normalizedB64.length % 4)) % 4;
  const paddedB64 = normalizedB64 + '='.repeat(padLen);

  let claims: ApiGatewayUserInfoClaims;
  try {
    claims = JSON.parse(Buffer.from(paddedB64, 'base64url').toString('utf8')) as ApiGatewayUserInfoClaims;
  } catch {
    throw new Error('GATEWAY_USERINFO_REJECTED: Malformed JSON payload in X-Apigateway-Api-Userinfo');
  }

  if (!claims.sub || !claims.iss || !params.expectedIssuers.has(claims.iss)) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Missing sub or untrusted issuer in userinfo claims');
  }

  const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audList.some((a) => typeof a === 'string' && params.expectedAudiences.has(a))) {
    throw new Error('GATEWAY_USERINFO_REJECTED: Audience mismatch in userinfo claims');
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || nowSec >= claims.exp + 15) {
    throw new Error('GATEWAY_USERINFO_REJECTED: End-user JWT in X-Apigateway-Api-Userinfo has expired');
  }

  return claims;
}
```


