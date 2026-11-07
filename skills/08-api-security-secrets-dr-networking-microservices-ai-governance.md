# Module 08: Deep API Security, Secrets Management, Disaster Recovery, Networking, Microservices, AI Infrastructure & Data Governance

This reference covers the remaining 7 enterprise architecture domains: API threat defense (SSRF, CSRF, XSS, CORS, SQLi, BOLA), KMS/Vault secrets management, PITR disaster recovery, infrastructure networking, microservices architecture, AI backend infrastructure, and data governance.

---

## 1. Deep API Security (SSRF, CSRF, XSS, CORS, SQLi & BOLA/BOPLA)

### Server-Side Request Forgery (SSRF) Defense
Whenever the backend fetches a user-supplied URL (webhooks, avatar URL import, link previews, OIDC discovery):
1. **Never pass raw user URLs directly to `fetch()`**.
2. **Parse & Restrict Protocol/Port**: Allow only `https:` (or `http:` if explicitly required) on standard ports (`443`, `80`).
3. **Custom DNS Resolution + Private/Metadata IP Blocklist (Anti-DNS-Rebinding)**: Resolve the hostname to its IP address(es) **once**, verify that **every** resolved IP is a public routable unicast address, and connect directly to that verified IP with `redirect: 'error'` (or re-validate every redirect hop).

```typescript
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';

function isReservedIpv4Octets(a: number, b: number, c: number, _d: number): boolean {
  if (a === 0 || a === 10 || a === 127) return true;                     // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
  if (a === 169 && b === 254) return true;                               // 169.254.0.0/16 (Cloud IMDS!)
  if (a === 172 && b >= 16 && b <= 31) return true;                      // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                               // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true;                     // 100.64.0.0/10 (CGNAT)
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;         // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1)
  if (a === 198 && (b === 18 || b === 19)) return true;                  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && b === 51 && c === 100) return true;                   // 198.51.100.0/24 (TEST-NET-2)
  if (a === 203 && b === 0 && c === 113) return true;                    // 203.0.113.0/24 (TEST-NET-3)
  if (a >= 224) return true;                                             // Multicast (224/4) & Reserved (240/4)
  return false;
}

/**
 * Expands any valid IPv6 string (including '::' and dotted-quad suffixes) into 8 16-bit numbers.
 */
function parseIpv6Hextets(ip: string): number[] | null {
  let normalized = ip.toLowerCase();
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    const v4Part = normalized.slice(lastColon + 1);
    if (net.isIP(v4Part) !== 4) return null;
    const [o0, o1, o2, o3] = v4Part.split('.').map(Number);
    const hHigh = ((o0 << 8) | o1).toString(16);
    const hLow = ((o2 << 8) | o3).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${hHigh}:${hLow}`;
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  const full = [...left, ...Array(missing).fill('0'), ...right];
  if (full.length !== 8) return null;
  return full.map((h) => parseInt(h, 16));
}

/**
 * Checks whether an IPv4 or IPv6 address belongs to loopback, link-local,
 * cloud metadata (169.254.169.254), RFC 1918, CGNAT, ULA, NAT64, 6to4, or hex IPv4-mapped ranges.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b, c, d] = ip.split('.').map(Number);
    return isReservedIpv4Octets(a, b, c, d);
  }
  if (version === 6) {
    const h = parseIpv6Hextets(ip);
    if (!h) return true;

    const isAllZeroPrefix = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0;
    // :: (Unspecified) or ::1 (Loopback)
    if (isAllZeroPrefix && h[5] === 0 && h[6] === 0 && (h[7] === 0 || h[7] === 1)) return true;

    // IPv4-mapped (::ffff:0:0/96) or IPv4-compatible (::0:0/96) — handles both dotted-quad and hex (::ffff:7f00:1)
    if (isAllZeroPrefix && (h[5] === 0xffff || h[5] === 0)) {
      return isReservedIpv4Octets(h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff);
    }

    // NAT64 Well-Known Prefix (64:ff9b::/96) embedding IPv4 in h[6..7]
    if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) {
      return isReservedIpv4Octets(h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff);
    }

    // 6to4 Prefix (2002::/16) embedding IPv4 in h[1..2]
    if (h[0] === 0x2002) {
      return isReservedIpv4Octets(h[1] >> 8, h[1] & 0xff, h[2] >> 8, h[2] & 0xff);
    }

    if ((h[0] & 0xffc0) === 0xfe80) return true; // Link-local fe80::/10
    if ((h[0] & 0xfe00) === 0xfc00) return true; // Unique Local fc00::/7
    if (h[0] === 0x2001 && h[1] === 0x0db8) return true; // Documentation 2001:db8::/32
    if ((h[0] & 0xff00) === 0xff00) return true; // Multicast ff00::/8
    return false;
  }
  return true;
}

/**
 * Resolves DNS ONCE, validates all returned IPs against the SSRF blocklist,
 * and returns a pinned https.Agent that connects directly to the verified IP
 * to completely defeat DNS Rebinding (TTL=0 TOCTOU) attacks.
 */
export async function createPinnedSafeHttpsAgent(rawUrl: string): Promise<{
  parsedUrl: URL;
  pinnedIp: string;
  pinnedFamily: 4 | 6;
  agent: https.Agent;
}> {
  const parsedUrl = new URL(rawUrl);
  if (parsedUrl.protocol !== 'https:') {
    throw new Error('SSRF_BLOCKED: Only https:// URLs are permitted');
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error('SSRF_BLOCKED: URL credentials are forbidden');
  }
  if (parsedUrl.port && parsedUrl.port !== '443') {
    throw new Error(`SSRF_BLOCKED: Non-standard outbound port ${parsedUrl.port} is forbidden`);
  }

  const records = await dns.lookup(parsedUrl.hostname, { all: true, verbatim: true });
  if (records.length === 0) {
    throw new Error('SSRF_BLOCKED: Hostname did not resolve');
  }
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error(`SSRF_BLOCKED: Hostname resolved to restricted IP ${rec.address}`);
    }
  }

  const pinnedIp = records[0].address;
  const pinnedFamily = records[0].family as 4 | 6;

  // Pin socket lookup to the already-validated IP so a second DNS lookup never occurs!
  const agent = new https.Agent({
    keepAlive: false,
    lookup: (_hostname, _options, callback) => {
      callback(null, pinnedIp, pinnedFamily);
    },
  });

  return { parsedUrl, pinnedIp, pinnedFamily, agent };
}
```

### CSRF, CORS, XSS, SQLi, NoSQLi, Prototype Pollution, Host Poisoning & GraphQL Amplification Defenses

```typescript
/**
 * 1. Anti-Prototype-Pollution & JSON Bomb / Depth Sanitizer:
 * Blocks "__proto__", "constructor", "prototype", deeply nested JSON bombs, and MongoDB "$" operator injection.
 */
const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function sanitizeUntrustedJsonInput(
  input: unknown,
  options: { maxDepth?: number; maxKeysPerObject?: number; forbidDollarKeys?: boolean } = {},
  currentDepth = 0
): unknown {
  const maxDepth = options.maxDepth ?? 12;
  const maxKeys = options.maxKeysPerObject ?? 250;
  const forbidDollar = options.forbidDollarKeys ?? true;

  if (currentDepth > maxDepth) {
    throw new Error(`PAYLOAD_REJECTED: JSON nesting depth exceeds maximum of ${maxDepth}`);
  }

  if (input === null || input === undefined) return input;
  if (typeof input === 'string') {
    // Normalize Unicode (NFKC) BEFORE downstream validation to defeat fullwidth/homoglyph bypasses
    if (input.includes('\0')) throw new Error('PAYLOAD_REJECTED: Null byte in string');
    return input.normalize('NFKC');
  }
  if (typeof input !== 'object') return input;

  if (Array.isArray(input)) {
    if (input.length > 1000) {
      throw new Error('PAYLOAD_REJECTED: Array length exceeds maximum bound');
    }
    return input.map((item) => sanitizeUntrustedJsonInput(item, options, currentDepth + 1));
  }

  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length > maxKeys) {
    throw new Error(`PAYLOAD_REJECTED: Object key count exceeds maximum of ${maxKeys}`);
  }

  const cleanObj: Record<string, unknown> = Object.create(null);
  for (const [rawKey, value] of entries) {
    const key = rawKey.normalize('NFKC');
    if (FORBIDDEN_OBJECT_KEYS.has(key)) {
      throw new Error(`PAYLOAD_REJECTED: Prototype pollution key "${key}" is forbidden`);
    }
    if (forbidDollar && (key.startsWith('$') || key.includes('.'))) {
      throw new Error(`PAYLOAD_REJECTED: NoSQL operator or dotted key "${key}" is forbidden`);
    }
    cleanObj[key] = sanitizeUntrustedJsonInput(value, options, currentDepth + 1);
  }
  return { ...cleanObj };
}

/**
 * 2. SQL LIKE Wildcard Escaper:
 * Prevents attackers from injecting "%" or "_" wildcards into search strings to cause pathological table scans.
 */
export function escapeSqlLikePattern(rawSearch: string): string {
  return rawSearch
    .normalize('NFKC')
    .replace(/[\\%_]/g, (match) => `\\${match}`);
}

/**
 * 3. Trusted Reverse-Proxy Client IP Extractor (Defeats X-Forwarded-For Spoofing):
 * Never read the leftmost IP in X-Forwarded-For (which is attacker-controlled!).
 * Walk right-to-left skipping exactly `trustedProxyCount` hops added by your own ingress load balancers.
 */
export function extractTrustedClientIp(params: {
  socketRemoteAddress: string;
  xForwardedForHeader?: string;
  trustedProxyHopCount: number;
}): string {
  if (params.trustedProxyHopCount <= 0 || !params.xForwardedForHeader) {
    return params.socketRemoteAddress;
  }
  const chain = params.xForwardedForHeader
    .split(',')
    .map((ip) => ip.trim())
    .filter((ip) => net.isIP(ip) !== 0);

  if (chain.length === 0) {
    return params.socketRemoteAddress;
  }

  // Select the hop immediately preceding our trusted proxies
  const targetIndex = Math.max(0, chain.length - params.trustedProxyHopCount);
  return chain[targetIndex];
}
```

### Additional Mandatory Penetration Defenses
- **Host Header & Password Reset Poisoning Defense**: Never construct password-reset, magic-link, or OAuth redirect URLs using `req.headers.host` or `X-Forwarded-Host`. Always read the canonical origin from an immutable server environment variable (`process.env.APP_URL`).
- **HTTP Request Smuggling (`CL.TE` / `TE.CL`) Defense**: Configure the edge load balancer and HTTP server to reject any request containing both `Content-Length` and `Transfer-Encoding`, normalize HTTP/2 -> HTTP/1.1 downgrade headers, and reject malformed whitespace in header names.
- **GraphQL Batching & Alias Amplification Defense**: Enforce max query depth ($\le 8$), max aliases per query ($\le 15$ to block `login1: login(...) ... login500: login(...)` brute-force amplification), max batch array size ($\le 1$ for mutations), and disable introspection in production.
- **CSRF**: For cookie-authenticated endpoints, enforce `SameSite=Strict` (or `Lax`), verify `Origin` / `Sec-Fetch-Site` headers on all `POST`/`PUT`/`PATCH`/`DELETE` requests, and require a cryptographic anti-CSRF header (`X-CSRF-Token`).
- **CORS**: Never reflect arbitrary `Origin` headers with `Access-Control-Allow-Credentials: true`. Match `Origin` against an explicit exact-match allowlist.
- **BOLA & BOPLA (Broken Object / Property-Level Authorization)**:
  - **BOLA**: Always filter by `tenant_id` and `owner_id` in the `WHERE` clause.
  - **BOPLA / Mass Assignment**: Never pass `req.body` directly into ORM `.create()` or `.update()`. Explicitly pick allowed DTO fields via Zod `.strict()` so attackers cannot inject `role: "admin"` or `is_verified: true`.

---

## 2. Secrets Management (KMS, HashiCorp Vault, Envelope Encryption & Rotation)

1. **Envelope Encryption Architecture**:
   - **KEK (Key Encryption Key)**: Master key stored inside hardware-backed **AWS KMS / Google Cloud KMS / HashiCorp Vault Transit Engine** (never leaves KMS).
   - **DEK (Data Encryption Key)**: Generated per tenant or per batch, used locally for fast `AES-256-GCM` encryption, and stored encrypted (`encrypted_dek`) alongside the record.
2. **Zero-Downtime Dual-Key Rotation**:
   - Support an active key ring (`activeKeyVersion: 'v3'`, `decryptableVersions: ['v3', 'v2', 'v1']`).
   - All new writes encrypt with `v3`; reads inspect the version prefix (`v2:...`) to decrypt seamlessly while a background job re-encrypts legacy `v1`/`v2` ciphertexts to `v3`.
   - For API keys and webhook secrets: allow a configurable overlap window (e.g., 24 hours) where both the primary and secondary secret are accepted during rotation.

---

## 3. Backup, Recovery & Disaster Recovery (PITR, RPO, RTO)

| Tier | Workload | Target RPO (Max Data Loss) | Target RTO (Max Recovery Time) | Architecture |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1 (Mission Critical)** | Financial ledgers, payments, auth | `RPO = 0s` | `RTO < 60s` | Multi-AZ synchronous standby replica + continuous WAL archiving to immutable object storage (`pgBackRest` / `WAL-G`). |
| **Tier 2 (Core Business)** | SaaS CRUD, orders, user profiles | `RPO < 5m` | `RTO < 15m` | Asynchronous streaming replica + continuous Point-In-Time Recovery (PITR) WAL shipping + daily base backups. |
| **Tier 3 (Analytical / Derived)** | Search indexes, caches, rollups | Rebuildable from primary | `RTO < 1h` | Snapshot backups + automated rebuild from primary RDBMS. |

- **Mandatory Backup Verification**: An untested backup is not a backup. Run an automated weekly CI/cron job that restores the latest base backup + WAL stream into an ephemeral container, runs `pg_amcheck` and invariant queries, and alerts if restoration fails or exceeds the RTO budget.

---

## 4. Infrastructure Networking (DNS, Reverse Proxies, Load Balancers & Service Discovery)

- **DNS & Traffic Routing**: Keep DNS TTLs low (`60s–300s`) on ingress records to allow rapid failover; configure `CAA` records to restrict certificate issuance and `SPF`/`DKIM`/`DMARC` on email domains.
- **L4 vs. L7 Load Balancing**:
  - **L4 (TCP/UDP / NLB)**: Ultra-low latency passthrough for high-throughput TCP/WebSocket/gRPC ingress.
  - **L7 (HTTP/HTTPS / ALB / Envoy / Nginx)**: TLS termination, HTTP/2 & HTTP/3 multiplexing, WAF filtering, path/header routing, and connection draining on pod termination.
- **Service Discovery & Zero-Trust Internal Networking**: Use Kubernetes DNS / Envoy Service Mesh with **mTLS (Mutual TLS)** and SPIFFE/SPIRE workload identities so internal service-to-service traffic is encrypted and authenticated inside the VPC.

---

## 5. Microservices Architecture (Bounded Contexts, Communication & Data Ownership)

1. **Database-per-Service Rule**: Never allow Service B to query or mutate Service A's database tables directly (shared-database coupling breaks independent deployment and schema evolution). Service A exposes versioned APIs or publishes domain events via its Transactional Outbox.
2. **Synchronous vs. Asynchronous Communication**:
   - **Synchronous (gRPC / Protobuf or REST)**: Use only when the caller requires an immediate read response; enforce strict deadlines/timeouts, circuit breakers, and hedging.
   - **Asynchronous (Events / Queues)**: Prefer for cross-service state propagation and long-running workflows to prevent temporal coupling (if Service B is down for 2 minutes, Service A still succeeds).

---

## 6. AI Backend Infrastructure (Model Gateways, Inference Queues & Streaming)

When a backend powers AI features (LLM generation, embeddings, document analysis, agents):
1. **Server-Side Model Gateway**:
   - Centralize all LLM/model provider calls behind an internal server-side Gateway service (never expose `GEMINI_API_KEY` or provider credentials to the client).
   - Implement provider fallback chains, prompt-version registries, and structured output validation (JSON Schema / Zod).
2. **Token-Aware Rate Limiting & Cost Ledgers**:
   - Rate-limit tenants by **Tokens Per Minute (TPM)** and **Daily Cost Budget (Minor Units)** in addition to Requests Per Minute (RPM).
   - Record `input_tokens`, `output_tokens`, `cached_tokens`, `model_id`, and `latency_ms` in an append-only `ai_usage_ledger` table.
3. **SSE Streaming & Async Inference Queues**:
   - For interactive chat/completion: stream tokens via **SSE** with client disconnect propagation (`req.signal` aborts upstream model generation immediately if the user closes the tab).
   - For heavy batch pipelines (document indexing, video generation, deep research): enqueue into a **BullMQ / Kafka Inference Queue** with concurrency caps matching provider quota limits.

---

## 7. Data Governance (PII Taxonomy, Retention, Crypto-Shredding & Immutable Audit Trails)

### PII Classification & GDPR Right-to-Erasure (Crypto-Shredding)
- Classify every schema column (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL_PII`, `RESTRICTED_FINANCIAL_HEALTH`).
- **Crypto-Shredding for Immutable Logs/Backups**: Encrypt a user's PII fields with a per-user DEK stored in `user_encryption_keys`. When a user exercises GDPR Right to Erasure, anonymize mutable profile rows AND permanently destroy the user's DEK—rendering any historical PII in immutable backups or event logs permanently undecryptable without corrupting financial ledger integrity.

### Tamper-Evident Keyed HMAC Hash-Chained Audit Trail
For security, compliance, and admin actions, maintain an append-only hash-chained `audit_logs` table where each row signs the previous row's hash (`prev_hash`) using **length-prefixed canonical encoding** (preventing delimiter-collision forgery) and a **KMS-backed HMAC secret** (preventing rogue DBAs from rewriting the hash chain):

```typescript
import crypto from 'node:crypto';

export function computeAuditChainHash(params: {
  auditHmacSecret: string;
  prevHashHex: string;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  payloadJson: string;
  createdAtIsoUtc: string;
}): string {
  if (params.auditHmacSecret.length < 32) {
    throw new Error('AUDIT_CHAIN_ERROR: auditHmacSecret must be at least 32 characters');
  }
  const fields = [
    params.prevHashHex,
    params.tenantId,
    params.actorId,
    params.action,
    params.resourceType,
    params.resourceId,
    params.payloadJson,
    params.createdAtIsoUtc,
  ];
  // Length-prefixed encoding ("len:value;") eliminates delimiter collision attacks
  const canonical = fields
    .map((f) => `${Buffer.byteLength(f, 'utf8')}:${f};`)
    .join('');

  return crypto
    .createHmac('sha256', params.auditHmacSecret)
    .update(canonical, 'utf8')
    .digest('hex');
}
```
