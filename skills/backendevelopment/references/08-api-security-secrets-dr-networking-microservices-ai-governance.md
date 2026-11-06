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
import net from 'node:net';

/**
 * Checks whether an IPv4 or IPv6 address belongs to loopback, link-local,
 * cloud metadata (169.254.169.254), RFC 1918 private, CGNAT, or ULA ranges.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;                     // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
    if (a === 169 && b === 254) return true;                               // 169.254.0.0/16 (AWS/GCP/Azure IMDS!)
    if (a === 172 && b >= 16 && b <= 31) return true;                      // 172.16.0.0/12
    if (a === 192 && b === 168) return true;                               // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true;                     // 100.64.0.0/10 (CGNAT)
    if (a >= 224) return true;                                             // Multicast & reserved
    return false;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;                    // Loopback & unspecified
    if (lower.startsWith('fe80:')) return true;                            // Link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;     // Unique Local (fc00::/7)
    if (lower.startsWith('::ffff:')) {
      const v4 = lower.slice(7);
      if (net.isIP(v4) === 4) return isPrivateOrReservedIp(v4);
    }
    return false;
  }
  return true;
}

export async function assertSafeOutboundUrl(rawUrl: string): Promise<URL> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:') {
    throw new Error('SSRF_BLOCKED: Only https:// URLs are permitted');
  }
  if (parsed.username || parsed.password) {
    throw new Error('SSRF_BLOCKED: URL credentials are forbidden');
  }
  const records = await dns.lookup(parsed.hostname, { all: true });
  if (records.length === 0) {
    throw new Error('SSRF_BLOCKED: Hostname did not resolve');
  }
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error(`SSRF_BLOCKED: Hostname resolved to restricted IP ${rec.address}`);
    }
  }
  return parsed;
}
```

### CSRF, CORS, XSS, SQLi & BOPLA Defense Matrix
- **CSRF**: For cookie-authenticated endpoints, enforce `SameSite=Strict` (or `Lax`), verify `Origin` / `Sec-Fetch-Site` headers on all `POST`/`PUT`/`PATCH`/`DELETE` requests, and require a cryptographic anti-CSRF header (`X-CSRF-Token` via the Double-Submit Cookie or Synchronizer Token pattern).
- **CORS**: Never reflect arbitrary `Origin` headers with `Access-Control-Allow-Credentials: true`. Match `Origin` against an explicit exact-match allowlist.
- **SQL Injection (SQLi)**: Use 100% parameterized queries (`$1, $2`). For dynamic `ORDER BY` or column names (which cannot use bind parameters), map user input against a frozen compile-time dictionary (`const SORT_COLUMN_MAP = { createdAt: 'created_at', amount: 'amount_minor' } as const`).
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

### Tamper-Evident Hash-Chained Audit Trail
For security, compliance, and admin actions, maintain an append-only hash-chained `audit_logs` table where each row signs the previous row's hash (`prev_hash`), making unauthorized database row deletion or tampering mathematically detectable:

```typescript
import crypto from 'node:crypto';

export function computeAuditChainHash(params: {
  prevHashHex: string;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  payloadJson: string;
  createdAtIsoUtc: string;
}): string {
  const canonical = [
    params.prevHashHex,
    params.tenantId,
    params.actorId,
    params.action,
    params.resourceType,
    params.resourceId,
    params.payloadJson,
    params.createdAtIsoUtc,
  ].join('|');

  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}
```
