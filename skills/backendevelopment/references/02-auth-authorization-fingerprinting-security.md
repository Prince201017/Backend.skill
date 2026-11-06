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

  // 2. RBAC + ReBAC Check
  const hasRolePerm = subject.roles.some((r) => ROLE_PERMISSIONS[r]?.includes(action));
  const hasRebacOverride =
    action === 'order:read' &&
    (resource.relationship === 'owner' || resource.relationship === 'editor' || resource.relationship === 'viewer');

  if (!hasRolePerm && !hasRebacOverride) {
    return { allowed: false, reason: 'INSUFFICIENT_PERMISSION' };
  }

  // 3. Identity Verification Gate for financial exports/refunds
  if ((action === 'order:refund' || action === 'ledger:export') && subject.identityVerificationLevel !== 'KYC_FULL') {
    return { allowed: false, reason: 'KYC_IDENTITY_VERIFICATION_REQUIRED' };
  }

  // 4. ABAC Contextual Policy Rules
  if (resource.isLocked && action !== 'order:read') {
    return { allowed: false, reason: 'RESOURCE_IS_LOCKED' };
  }
  if (resource.classificationLevel !== undefined && subject.clearanceLevel < resource.classificationLevel) {
    return { allowed: false, reason: 'CLEARANCE_LEVEL_TOO_LOW' };
  }

  // 5. Step-Up MFA enforcement for high-value refunds (> $1,000.00 = 100_000 cents) or ledger exports
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
