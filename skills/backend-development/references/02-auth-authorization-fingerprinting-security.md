# Module 02: Authentication, Authenticated Authorization, Fingerprinting & Security Hardening

This reference covers complete authentication flows, token rotation, multi-model authorization (RBAC, ABAC, ReBAC), request/device fingerprinting, and defense-in-depth security controls.

---

## 1. Authentication & Refresh Token Reuse Detection

### Database Schema for Token Families & Device Sessions
```sql
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id UUID NOT NULL,
    refresh_token_hash CHAR(64) NOT NULL UNIQUE, -- SHA-256 of opaque refresh token
    is_rotated BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ NULL,
    revocation_reason VARCHAR(64) NULL,
    -- Contextual Fingerprint Binding
    device_fingerprint_hash CHAR(64) NOT NULL,
    ip_prefix CIDR NOT NULL,
    asn INTEGER NULL,
    user_agent TEXT NOT NULL,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX idx_auth_sessions_user_active ON auth_sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_family ON auth_sessions(token_family_id);
```

### Refresh Token Rotation Protocol
1. Client sends `POST /api/v1/auth/refresh` with `__Host-refresh_token` and `__Host-device_fp` cookies.
2. Backend hashes `__Host-refresh_token` with SHA-256 and queries `auth_sessions`.
3. **Reuse Detection**: If `is_rotated = TRUE`, an attacker (or stolen token) is replaying an old token! Immediately execute:
   ```sql
   UPDATE auth_sessions
   SET revoked_at = clock_timestamp(), revocation_reason = 'TOKEN_REUSE_DETECTED'
   WHERE token_family_id = $1 AND revoked_at IS NULL;
   ```
   Force re-authentication across that token family and emit a `SECURITY_ALERT` log.
4. **Fingerprint Verification**: Verify that the request's `device_fingerprint_hash` matches the session's bound hash.
5. **Rotate**: Mark current row `is_rotated = TRUE` and insert a new `auth_sessions` row sharing the same `token_family_id`.

---

## 2. Request & Device Fingerprinting Engine

```typescript
import crypto from 'node:crypto';

export interface RequestFingerprintSignals {
  userAgent: string;
  secChUa: string;
  secChUaPlatform: string;
  acceptLanguage: string;
  tlsJa4Fingerprint?: string; // Injected by Cloudflare / Envoy / Nginx ingress
  clientIp: string;
  asn?: string;
  deviceCookieSecret: string; // Value of HttpOnly __Host-fp cookie
}

/**
 * Normalizes IPv4 to /24 subnet and IPv6 to /48 subnet so mobile carrier tower switches
 * within the same region do not falsely invalidate sessions, while cross-network theft does.
 */
export function extractIpPrefix(ip: string): string {
  if (ip.includes(':')) {
    return ip.split(':').slice(0, 3).join(':') + '::/48';
  }
  return ip.split('.').slice(0, 3).join('.') + '.0/24';
}

export function computeContextualFingerprint(
  signals: RequestFingerprintSignals,
  serverPepper: string
): {
  strictHash: string;
  softDriftScore: (previous: RequestFingerprintSignals) => number;
} {
  const canonical = [
    signals.userAgent.trim(),
    signals.secChUa.trim(),
    signals.secChUaPlatform.trim(),
    signals.tlsJa4Fingerprint ?? 'no-ja4',
    signals.deviceCookieSecret,
  ].join('|');

  const strictHash = crypto
    .createHmac('sha256', serverPepper)
    .update(canonical)
    .digest('hex');

  return {
    strictHash,
    softDriftScore: (prev: RequestFingerprintSignals) => {
      let riskScore = 0; // 0 = identical, 100 = critical anomaly
      if (prev.deviceCookieSecret !== signals.deviceCookieSecret) riskScore += 70;
      if (prev.secChUaPlatform !== signals.secChUaPlatform) riskScore += 50;
      if (prev.tlsJa4Fingerprint && signals.tlsJa4Fingerprint && prev.tlsJa4Fingerprint !== signals.tlsJa4Fingerprint) {
        riskScore += 35;
      }
      if (prev.asn && signals.asn && prev.asn !== signals.asn) riskScore += 25;
      if (extractIpPrefix(prev.clientIp) !== extractIpPrefix(signals.clientIp)) riskScore += 15;
      return Math.min(100, riskScore);
    },
  };
}
```

---

## 3. Authenticated Authorization Engine (RBAC + ABAC + ReBAC)

Never write ad-hoc `if (user.isAdmin)` checks scattered across controllers. Centralize policy evaluation in a Policy Decision Point (PDP).

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
  mfaVerifiedAt?: number; // Unix ms
  clearanceLevel: number;
}

export interface ResourceContext {
  type: 'order' | 'file' | 'ledger';
  id: string;
  tenantId: string;
  ownerId?: string;
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

  // 2. RBAC Check
  const hasRolePerm = subject.roles.some((r) => ROLE_PERMISSIONS[r]?.includes(action));
  if (!hasRolePerm) {
    return { allowed: false, reason: 'INSUFFICIENT_ROLE_PERMISSION' };
  }

  // 3. ABAC Contextual Policy Rules
  if (resource.isLocked && action !== 'order:read') {
    return { allowed: false, reason: 'RESOURCE_IS_LOCKED' };
  }

  if (
    resource.classificationLevel !== undefined &&
    subject.clearanceLevel < resource.classificationLevel
  ) {
    return { allowed: false, reason: 'CLEARANCE_LEVEL_TOO_LOW' };
  }

  // Step-Up MFA enforcement for high-value refunds (> $1,000.00 = 100_000 cents) or ledger exports
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

## 4. Transport Security, Input Validation & Data Encryption (AES-256-GCM Envelope Encryption)

### Mandatory HTTP Security Headers
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### Field-Level Authenticated Encryption (AES-256-GCM) for PII / Secrets at Rest
Never use unauthenticated `AES-CBC`. Always use `AES-256-GCM` with a unique 96-bit IV per encryption and key rotation version tags:

```typescript
import crypto from 'node:crypto';

export function encryptSensitiveField(
  plaintext: string,
  masterKey32Bytes: Buffer,
  keyVersion: string,
  associatedDataContext: string // e.g., `${tenantId}:${userId}:ssn` (prevents ciphertext swapping between rows!)
): string {
  const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey32Bytes, iv);
  cipher.setAAD(Buffer.from(associatedDataContext, 'utf8'));

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 128-bit authentication tag

  return `${keyVersion}:${iv.toString('base64url')}:${authTag.toString('base64url')}:${encrypted.toString('base64url')}`;
}

export function decryptSensitiveField(
  packedCiphertext: string,
  keyRing: Record<string, Buffer>,
  associatedDataContext: string
): string {
  const [keyVersion, ivB64, tagB64, dataB64] = packedCiphertext.split(':');
  const key = keyRing[keyVersion];
  if (!key) throw new Error(`Unknown encryption key version: ${keyVersion}`);

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivB64, 'base64url')
  );
  decipher.setAAD(Buffer.from(associatedDataContext, 'utf8'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64url')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}
```
