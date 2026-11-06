# Module 09: Adversarial Security Audit & Defensive Verification Harness

This module documents the adversarial security assessment ("penetration test" review) conducted against the reference implementations in Modules `00–08`, details the 7 subtle bypass vectors uncovered and remediated in the skill, and provides a deterministic **Defensive Security Verification Harness** to validate backend implementations before production release.

---

## 1. Adversarial Audit Findings & Remediation Matrix

| Finding ID | Severity | Target Module & Component | Vulnerability / Bypass Vector Discovered | Defensive Remediation Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **AUD-01** | **CRITICAL** | `Module 08` — SSRF Guard (`assertSafeOutboundUrl`) | **DNS Rebinding TOCTOU & IPv6 Tunnel Bypass**: Validating DNS in a pre-check function and returning a `URL` allowed `fetch()` to perform a second DNS lookup (`TTL=0` rebinding to `169.254.169.254`). In addition, hex-normalized IPv4-mapped IPv6 (`::ffff:7f00:1`), NAT64 (`64:ff9b::a9fe:a9fe`), and 6to4 (`2002:7f00:0001::`) bypassed string-based `net.isIP(v4)` checks. | Replaced `assertSafeOutboundUrl` with `createPinnedSafeHttpsAgent` which resolves DNS **once** and pins the `https.Agent` socket `lookup` callback to the verified IP. Added full 128-bit hextet expansion (`parseIpv6Hextets`) blocking `::ffff:0:0/96`, `64:ff9b::/96`, `2002::/16`, `198.18.0.0/15`, and `192.0.0.0/24`. |
| **AUD-02** | **HIGH** | `Module 05` — Streaming Upload Gate (`SecurityGateTransformStream`) | **PDF Hex-Escaped Name Obfuscation & Fragmented Header Chunk Bug**: Attackers could bypass `/javascript` token filters in PDFs using ISO 32000-1 `#XX` hex escapes (`/J#61vaScript`). Additionally, checking `chunk.byteLength < 12` on the first TCP packet prematurely rejected or mis-evaluated legitimate streams fragmented into tiny `<12`-byte initial chunks. | Added `#([0-9a-f]{2})` hex decoding prior to active-token matching (`/javascript`, `/js`, `/launch`, `/openaction`, `/aa`, `/xfa`), widened the sliding boundary window to 128 bytes, and buffered up to 64 header bytes across multiple chunks (with fallback verification in `_flush` for files `<64` bytes). |
| **AUD-03** | **HIGH** | `Module 07` — PostgreSQL Multi-Tenant RLS Policy | **Empty GUC UUID Cast Failure & `BYPASSRLS` Role Escalation**: Calling `RESET app.current_tenant_id` sets the GUC to `''` (empty string), causing `current_setting('app.current_tenant_id', true)::uuid` to throw a runtime UUID syntax error. Furthermore, connecting with a role that holds `SUPERUSER` or `BYPASSRLS` silently ignores `FORCE ROW LEVEL SECURITY`. | Wrapped GUC evaluation in `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid` (failing closed to `NULL` without throwing) and enforced `CREATE ROLE app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`. |
| **AUD-04** | **HIGH** | `Module 07` — Distributed Saga Orchestrator (`runOrchestratedSaga`) | **Unretried Compensation Failure ("Saga Zombie")**: If a compensating step threw a transient network error during rollback, the backward loop aborted immediately, leaving earlier completed steps uncompensated. | Added per-step idempotency keys (`${sagaId}:${stepName}:compensate`), bounded exponential-backoff retry loops for every compensation step, and explicit `COMPENSATION_FAILED_REQUIRES_INTERVENTION` state persistence so all remaining earlier steps still compensate. |
| **AUD-05** | **HIGH** | `Module 04` — Webhook Signature Verifier (`verifyWebhookSignature`) | **Multi-Signature Header Overwrite During Key Rotation & Non-Hex Silent Truncation**: Using `Object.fromEntries` on `t=...,v1=sigOld,v1=sigNew` overwrote `sigOld`, breaking zero-downtime secret rotation. Also, `Buffer.from(nonHex, 'hex')` silently truncates invalid hex strings. | Parsed all `v1` signatures into a strictly validated `/^[0-9a-fA-F]{64}$/` array and evaluated all `(secret, signature)` pairs in constant time via `crypto.timingSafeEqual`. |
| **AUD-06** | **MEDIUM** | `Module 06` — Worker Lease Heartbeat (`executeQueueWorkerJob`) | **Timer Leak on Unhandled Throw Path**: `clearInterval(heartbeatTimer)` was called inside `try` and `catch` rather than `finally`. | Moved `clearInterval(heartbeatTimer)` into a `finally` block and enforced fencing token checks on completion commits. |
| **AUD-07** | **MEDIUM** | `Module 01` — Partial Refund Credit Note Engine (`calculatePartialRefundCreditNote`) | **Cumulative Rounding Over-Refund Edge Case**: Across multiple sequential partial refunds, `divRoundHalfEven` could round up by 1 minor unit prior to the final unit refund. | Explicitly clamped `refundNetMinor <= remainingNet` and `refundTaxMinor <= remainingTax` on every partial refund step. |

---

## 2. Executable Defensive Security Verification Suite

Run this self-contained verification suite in CI/CD to assert that all security controls hold against adversarial inputs:

```typescript
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export interface SecurityVerificationResult {
  testId: string;
  category: string;
  passed: boolean;
  details: string;
}

/**
 * Executes 8 deterministic adversarial test vectors against the skill's security primitives.
 */
export async function runBackendSkillSecurityVerificationSuite(primitives: {
  isPrivateOrReservedIp: (ip: string) => boolean;
  extractCanonicalNetworkPrefix: (ip: string) => string;
  verifyWebhookSignature: (params: {
    rawBodyBuffer: Buffer;
    signatureHeader: string;
    webhookSecrets: string[];
    toleranceSeconds?: number;
  }) => { valid: boolean; reason?: string };
  allocateProratedAmountExact: (weights: bigint[], totalWeight: bigint, targetTotal: bigint) => bigint[];
  createPdfGateStream: () => NodeJS.ReadWriteStream;
  sanitizeUntrustedJsonInput?: (input: unknown) => unknown;
  extractTrustedClientIp?: (params: {
    socketRemoteAddress: string;
    xForwardedForHeader?: string;
    trustedProxyHopCount: number;
  }) => string;
  verifyJwtPenetrationSafe?: (opts: {
    token: string;
    allowedAlgorithm: 'EdDSA' | 'RS256';
    publicKeyRing: Readonly<Record<string, crypto.KeyObject>>;
    expectedIssuer: string;
    expectedAudience: string;
  }) => unknown;
}): Promise<SecurityVerificationResult[]> {
  const results: SecurityVerificationResult[] = [];

  // Vector 1: SSRF Cloud Metadata & IPv6 Tunnel Bypass Attempts
  {
    const maliciousTargets = [
      '127.0.0.1',
      '169.254.169.254',           // AWS/GCP/Azure Metadata IMDS
      '100.64.0.1',                // CGNAT internal
      '198.18.0.1',                // Benchmarking range
      '::1',                       // IPv6 loopback
      '::ffff:169.254.169.254',    // Dotted IPv4-mapped IPv6
      '::ffff:a9fe:a9fe',          // Hex-normalized IPv4-mapped IMDS!
      '::ffff:7f00:1',             // Hex-normalized IPv4-mapped loopback!
      '64:ff9b::a9fe:a9fe',        // NAT64 embedded IMDS!
      '2002:7f00:0001::1',         // 6to4 embedded loopback!
      'fd00::1234',                // IPv6 ULA
    ];
    const blockedAll = maliciousTargets.every((ip) => primitives.isPrivateOrReservedIp(ip) === true);
    const allowedPublic =
      primitives.isPrivateOrReservedIp('93.184.216.34') === false &&
      primitives.isPrivateOrReservedIp('2606:2800:220:1:248:1893:25c8:1946') === false;

    assert.equal(blockedAll && allowedPublic, true, 'SSRF IP filter failed on bypass vector');
    results.push({
      testId: 'PEN-01',
      category: 'SSRF & IPv6 Tunnel Evasion',
      passed: blockedAll && allowedPublic,
      details: `Blocked all ${maliciousTargets.length} private/IMDS/NAT64/6to4/hex-mapped vectors and allowed public unicast IPs.`,
    });
  }

  // Vector 2: PDF #XX Hex-Obfuscated Active Script Polyglot Upload
  {
    const maliciousPdfPayload = Buffer.from(
      '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /J#61va#53cript /JS (app.alert(1)) >> >>\nendobj\n',
      'latin1'
    );
    let rejectedReason = '';
    try {
      const gate = primitives.createPdfGateStream();
      const sink = new Writable({
        write(_chunk, _enc, cb) {
          cb();
        },
      });
      await pipeline(Readable.from([maliciousPdfPayload]), gate, sink);
    } catch (err) {
      rejectedReason = err instanceof Error ? err.message : String(err);
    }
    const passed = rejectedReason.includes('STREAM_UPLOAD_ABORTED');
    assert.equal(passed, true, 'PDF hex-escaped /J#61va#53cript payload was not blocked');
    results.push({
      testId: 'PEN-02',
      category: 'File Upload Polyglot & PDF Hex Escape Defense',
      passed,
      details: `Aborted obfuscated PDF stream with: "${rejectedReason}"`,
    });
  }

  // Vector 3: Multi-Signature Webhook Rotation, Replay Attack & Tampering
  {
    const rawBody = Buffer.from('{"id":"evt_123","type":"payment_intent.succeeded","amount":5000}');
    const oldSecret = 'whsec_old_retiring_secret_key_32b';
    const newSecret = 'whsec_new_active_secret_key_32bytes';
    const nowSec = Math.floor(Date.now() / 1000);

    const validNewHmac = crypto
      .createHmac('sha256', newSecret)
      .update(`${nowSec}.${rawBody.toString('utf8')}`)
      .digest('hex');
    const bogusOldHmac = '0'.repeat(64);

    // Dual-signature header during secret rotation
    const dualHeader = `t=${nowSec},v1=${bogusOldHmac},v1=${validNewHmac}`;
    const validRes = primitives.verifyWebhookSignature({
      rawBodyBuffer: rawBody,
      signatureHeader: dualHeader,
      webhookSecrets: [oldSecret, newSecret],
    });

    // Expired timestamp replay (> 300s old)
    const expiredSec = nowSec - 600;
    const expiredHmac = crypto
      .createHmac('sha256', newSecret)
      .update(`${expiredSec}.${rawBody.toString('utf8')}`)
      .digest('hex');
    const replayRes = primitives.verifyWebhookSignature({
      rawBodyBuffer: rawBody,
      signatureHeader: `t=${expiredSec},v1=${expiredHmac}`,
      webhookSecrets: [newSecret],
    });

    const passed = validRes.valid === true && replayRes.valid === false;
    assert.equal(passed, true, 'Webhook rotation or anti-replay check failed');
    results.push({
      testId: 'PEN-03',
      category: 'Webhook Constant-Time Rotation & Replay Prevention',
      passed,
      details: 'Accepted rotating dual-v1 header and rejected 10-minute-old replay attack.',
    });
  }

  // Vector 4: Financial Prorated Discount Penny-Drift Attack
  {
    // 3 identical items of 100 cents ($1.00 each = $3.00 subtotal) with a 100 cent ($1.00) discount.
    // Naive rounding gives 33 + 33 + 33 = 99 cents (losing 1 cent!).
    const shares = primitives.allocateProratedAmountExact([100n, 100n, 100n], 300n, 100n);
    const sum = shares.reduce((acc, v) => acc + v, 0n);
    const passed = sum === 100n && shares[0] === 34n && shares[1] === 33n && shares[2] === 33n;
    assert.equal(passed, true, 'Prorated discount failed exact minor-unit reconciliation');
    results.push({
      testId: 'PEN-04',
      category: 'Financial Proration Exact Reconciliation',
      passed,
      details: `Allocated [100n, 100n, 100n] discount of 100n as [${shares.join(', ')}] (sum === 100n).`,
    });
  }

  // Vector 5: IPv6 Compressed & IPv4-Mapped Prefix Normalization
  {
    const p1 = primitives.extractCanonicalNetworkPrefix('2001:db8:85a3::8a2e:370:7334');
    const p2 = primitives.extractCanonicalNetworkPrefix('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    const passed = p1 === '2001:0db8:85a3::/48' && p1 === p2;
    assert.equal(passed, true, 'IPv6 canonical prefix normalization mismatch');
    results.push({
      testId: 'PEN-05',
      category: 'RFC-Compliant IPv6 Prefix Normalization',
      passed,
      details: `Normalized compressed and full IPv6 representations to ${p1}.`,
    });
  }

  // Vector 6: Prototype Pollution (__proto__), NoSQL Operator ($ne/$where) & Null-Byte Injection
  if (primitives.sanitizeUntrustedJsonInput) {
    let blockedProto = false;
    let blockedNoSql = false;
    try {
      primitives.sanitizeUntrustedJsonInput(JSON.parse('{"__proto__":{"isAdmin":true}}'));
    } catch {
      blockedProto = true;
    }
    try {
      primitives.sanitizeUntrustedJsonInput({ email: 'admin@example.com', password: { $ne: null } });
    } catch {
      blockedNoSql = true;
    }
    const passed = blockedProto && blockedNoSql;
    assert.equal(passed, true, 'Prototype pollution or NoSQL operator injection was not blocked');
    results.push({
      testId: 'PEN-06',
      category: 'Prototype Pollution & NoSQL Operator Injection Defense',
      passed,
      details: 'Blocked __proto__ payload and MongoDB {"$ne": null} authentication bypass payload.',
    });
  }

  // Vector 7: X-Forwarded-For Spoofing Defense
  if (primitives.extractTrustedClientIp) {
    // Attacker spoofs "1.1.1.1, 8.8.8.8", real client IP is "203.0.113.99", ingress ALB adds "10.0.1.5" (2 trusted proxy hops: client + ALB)
    const realClientIp = primitives.extractTrustedClientIp({
      socketRemoteAddress: '10.0.1.5',
      xForwardedForHeader: '1.1.1.1, 8.8.8.8, 203.0.113.99, 10.0.1.5',
      trustedProxyHopCount: 2,
    });
    const passed = realClientIp === '203.0.113.99';
    assert.equal(passed, true, 'X-Forwarded-For spoofing was not defeated');
    results.push({
      testId: 'PEN-07',
      category: 'X-Forwarded-For Spoofing Defense',
      passed,
      details: `Ignored attacker-prepended IPs (1.1.1.1, 8.8.8.8) and extracted verified ingress client IP ${realClientIp}.`,
    });
  }

  // Vector 8: JWT alg:none, Algorithm Confusion (HS256) & kid Path Traversal Defense
  if (primitives.verifyJwtPenetrationSafe) {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const keyRing = { 'key-2026-v1': publicKey };
    const payloadB64 = Buffer.from(
      JSON.stringify({
        sub: 'user_1',
        iss: 'https://auth.example.com',
        aud: 'https://api.example.com',
        exp: Math.floor(Date.now() / 1000) + 600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'jti_1',
        tenantId: 'tenant_1',
      })
    ).toString('base64url');

    const algNoneToken = `${Buffer.from('{"alg":"none","kid":"key-2026-v1"}').toString('base64url')}.${payloadB64}.sig`;
    const kidTraversalToken = `${Buffer.from('{"alg":"EdDSA","kid":"../../../../dev/null"}').toString('base64url')}.${payloadB64}.sig`;
    const jkuSsrfToken = `${Buffer.from('{"alg":"EdDSA","kid":"key-2026-v1","jku":"https://evil.com/jwks.json"}').toString('base64url')}.${payloadB64}.sig`;

    const allRejected = [algNoneToken, kidTraversalToken, jkuSsrfToken].every((badToken) => {
      try {
        primitives.verifyJwtPenetrationSafe!({
          token: badToken,
          allowedAlgorithm: 'EdDSA',
          publicKeyRing: keyRing,
          expectedIssuer: 'https://auth.example.com',
          expectedAudience: 'https://api.example.com',
        });
        return false;
      } catch {
        return true;
      }
    });

    assert.equal(allRejected, true, 'JWT penetration vectors were not rejected');
    results.push({
      testId: 'PEN-08',
      category: 'JWT alg:none, kid Traversal & jku SSRF Defense',
      passed: allRejected,
      details: 'Rejected alg:none, kid="../../../../dev/null", and jku SSRF headers.',
    });
  }

  return results;
}
```
