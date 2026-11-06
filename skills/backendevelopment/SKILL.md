---
name: "advanced-backend-development"
description: >
  Complete, zero-loss backend engineering skill and architecture-selection engine
  that designs and implements the backend FOR any frontend or system requirement.
  Covers execution intelligence, field-type logic, currency-aware financial engines
  (exact prorated discount reconciliation, GST/VAT inclusive/exclusive, refunds & credit
  notes), cryptographic IDs/tokens/OTPs, strict UTC & DST-safe temporal architecture,
  Identity Verification vs. Authentication vs. Session Management vs. Authorization
  (RBAC/ABAC/ReBAC), probabilistic risk-based fingerprinting & hardware-backed auth,
  polyglot databases (PostgreSQL, MySQL, MongoDB, Redis), isolation-level selection,
  committed Transactional Outbox & Sagas, REST/GraphQL/WebSockets/SSE, payments,
  rate limiting, circuit breakers, streaming zero-buffer file upload security &
  malware scanning, lease-based background job workers, observability, testing,
  zero-downtime migrations, advanced SQL, multi-tenancy, search, SSRF/CSRF/BOLA API
  security, KMS/Vault secrets, PITR/DR, networking, microservices, AI gateways,
  and data governance.
---

# Advanced Backend Development Skill (Zero-Loss Architecture & Execution Constitution)

Use this skill whenever designing, architecting, or implementing the backend **for** any frontend or product requirement (Web, Mobile, Desktop, IoT, B2B SaaS, FinTech, E-Commerce, Healthcare, Real-Time Collaboration, AI Platforms, or Enterprise Distributed Systems).

## Skill Reference Modules

Load the modular reference specifications in `references/` according to the architectural domains required:

- `references/00-execution-intelligence-architecture-engine.md` — **Execution Intelligence & Architecture-Selection Engine**: Requirement analysis, SLO formulation, and deterministic decision matrices that decide *what* to implement and *why*.
- `references/01-domain-modeling-fields-timestamps-ids.md` — **Domain Modeling, Financial Engine, Timestamps & Generators**: Strict field types, exact penny-reconciled calculations, currency exponents, GST/VAT inclusive/exclusive math, refunds/credit notes, strict UTC vs. offset timestamps, and CSPRNG ID/Token/OTP/Reference generators.
- `references/02-auth-authorization-fingerprinting-security.md` — **Identity, AuthN, Session Management, AuthZ & Risk Signals**: Separation of Identity Verification, Authentication, Session Binding, Device Registration, Hardware-Backed Auth (Passkeys/WebAuthn/mTLS), Probabilistic Risk-Based Authentication, Behavioral Anomaly Detection, RBAC/ABAC/ReBAC, RFC-compliant IPv4/IPv6 prefix extraction, and AES-256-GCM envelope encryption.
- `references/03-databases-polyglot-storage-transactions.md` — **Polyglot Databases, Isolation Invariants, Committed Outbox & Caching**: PostgreSQL/MySQL/MongoDB/Redis selection, isolation level mapping by concurrency invariant, committed Transactional Outbox + Consumer Inbox deduplication, deadlock-free lock ordering, Read-Your-Own-Writes routing, and stampede-safe Redis caching.
- `references/04-apis-payments-webhooks-resilience.md` — **APIs, Versioning, OpenAPI, Payments, Rate Limiting & Circuit Breakers**: REST & GraphQL design, RFC 9457 Problem Details, API versioning, payment idempotency state machines, constant-time webhook verification, atomic Redis token-bucket rate limiting, and circuit breakers.
- `references/05-file-uploads-multi-storage-malware-scanning.md` — **Streaming File Upload Defense, Multi-Storage & Malware Scanning**: Bounded-memory streaming uploads, on-the-fly header magic-byte checks, streaming SHA-256 checksums, hard byte-stream cutoffs, content disarm/reconstruction (image re-encoding, PDF sanitization), UUID keys outside web root, `noexec` mounts, multi-cloud routing, and streaming ClamAV quarantine scanning.
- `references/06-async-queues-observability-testing-devops.md` — **Lease-Safe Job Queues, Observability, Testing & DevOps**: Atomic job acquisition, lease ownership (`workerInstanceId`), heartbeat lease renewal, `IN_PROGRESS` duplicate prevention, stalled-job crash recovery, DLQ replay procedures, structured JSON logging, Prometheus metrics, OpenTelemetry tracing, Unit/Integration/E2E testing, and Docker/Kubernetes/CI-CD.
- `references/07-events-realtime-sagas-migrations-sql-multitenancy-search.md` — **Events, WebSockets, SSE, Sagas, Zero-Downtime Migrations, Advanced SQL, Multi-Tenancy & Search**: Kafka/RabbitMQ/NATS, WebSocket rooms/heartbeats, SSE `Last-Event-ID`, Saga orchestration/compensation, Expand-and-Contract migrations, partitioning/window functions/EXPLAIN, RLS/schema/database multi-tenancy, and Elasticsearch/OpenSearch/Meilisearch/pgvector.
- `references/08-api-security-secrets-dr-networking-microservices-ai-governance.md` — **API Security, KMS/Vault, Disaster Recovery, Networking, Microservices, AI Infrastructure & Data Governance**: SSRF/CSRF/XSS/CORS/SQLi/BOLA defense, KMS/Vault key rotation, PITR/RPO/RTO disaster recovery, DNS/L4-L7 proxies/service discovery, DDD microservices, AI model gateways & streaming inference queues, and PII retention/crypto-shredding/audit trails.
- `references/09-adversarial-security-audit-and-verification-harness.md` — **Adversarial Security Audit & Defensive Verification Harness**: Complete penetration/vulnerability audit report of all skill primitives (SSRF DNS-rebinding TOCTOU pinning, IPv6 NAT64/6to4/hex-mapped filters, PDF `#XX` hex-escape polyglot stream blocking, fail-closed `NULLIF` RLS, Saga compensation retries, multi-signature webhook rotation, and executable CI security verification suite).

---

## 1. Execution Intelligence: Designing the Backend FOR Any Frontend

When given a frontend design, product specification, or user story, execute this 6-step **Architecture-Selection Protocol** (detailed in `references/00-execution-intelligence-architecture-engine.md`):

1. **Capability & Invariant Discovery**: Identify the business capabilities required by the frontend, data invariants (e.g., "account balance must never be negative", "seat cannot be double-booked"), compliance regimes (PCI-DSS, HIPAA, GDPR, SOC2), and tenancy boundaries.
2. **Workload & Latency SLO Classification**:
   - Latency targets are **configurable Service-Level Objectives (SLOs)** tailored per endpoint class, never a single rigid number:
     - **Tier 0 (Edge / Cached Reads / Autocomplete)**: Target `p95 < 50ms`, `p99 < 100ms`.
     - **Tier 1 (Interactive CRUD / Auth / Cart Mutations)**: Target `p95 < 150ms–250ms`, `p99 < 400ms`.
     - **Tier 2 (Complex Aggregations / Multi-Filter Search / Synchronous Payment Intent)**: Target `p95 < 500ms–1,000ms`.
     - **Tier 3 (Heavy Compute / External Bulk I/O / Media / Reports)**: Offload to **Asynchronous Job Queues** (`202 Accepted` + SSE/WebSocket/Polling status) whenever expected duration exceeds the endpoint's synchronous SLO budget or relies on fragile third-party availability.
3. **Storage & Isolation Selection**: Select relational, document, key-value, search, and blob engines based on query access patterns and select the minimum sufficient transaction isolation level that preserves the domain invariant.
4. **Communication Protocol Selection**: Choose REST (resource CRUD), GraphQL (complex client-driven view composition), WebSockets (bidirectional low-latency rooms/presence), SSE (unidirectional live feeds/AI token streaming), or gRPC/Events (internal service-to-service).
5. **Security & Trust Boundary Enforcement**: Never trust client-supplied prices, discounts, tax rates, roles, tenant IDs, or timestamps. Enforce Identity Verification, Authentication, Session Management, and Resource-Level Authorization independently.
6. **Operational & Failure Engineering**: Define idempotency keys, circuit breakers, rate limits, observability telemetry, backup RPO/RTO, and zero-downtime migration steps before shipping code.

---

## 2. Field Type Logic Design & Financial Calculation Engine

1. **Explicit Field Schemas**:
   - **Percentage Basis Points**: Explicitly constrain standard percentages to `0..10_000` (`10_000 bps = 100.00%`). If a domain allows multipliers above 100% (e.g., penalty rates), define a separate named type with its explicit business cap.
   - **Currency Minor Units & Exponents**: Store monetary values in integer minor units (`BIGINT`) together with ISO-4217 `currency_code` (`CHAR(3)`), respecting currency exponent rules (`0` decimals for `JPY`/`KRW`, `2` decimals for `USD`/`EUR`/`GBP`/`INR`, `3` decimals for `KWD`/`BHD`/`OMR`).
   - **Timestamps**: Distinguish `strictUtcTimestamp` (must end in `Z`) from `offsetTimestampNormalizedToUtc` (accepts ISO-8601 offset and normalizes to UTC on ingest).
2. **Financial Calculation Safeguards**:
   - **Input Validation**: Reject negative quantities, negative unit prices, out-of-range discount basis points (`< 0` or `> 10_000`), negative tax rates, or negative shipping amounts.
   - **Exact Prorated Discount Reconciliation**: Never round line-item prorated discounts independently without reconciliation (which causes a 1–N cent discrepancy between $\sum \text{lineDiscount}_i$ and $\text{orderDiscount}$). Allocate integer shares using floor division and distribute the exact remainder (`totalDiscount - sum(floorShares)`) one minor unit at a time via the **Largest Remainder Method** so $\sum \text{lineDiscount}_i \equiv \text{totalDiscount}$.
   - **Tax / GST Inclusive vs. Exclusive Policies**: Support both tax-exclusive pricing ($\text{Tax} = \text{round}(\text{Net} \times \text{rate})$) and tax-inclusive pricing ($\text{Net} = \text{round}(\frac{\text{Gross} \times 10000}{10000 + \text{rateBps}}), \text{Tax} = \text{Gross} - \text{Net}$).
   - **Refunds, Partial Refunds & Credit Notes**: Track cumulative refunded quantities, net amounts, and tax per line item; enforce $\sum \text{refundedMinor} \le \text{capturedMinor}$; generate immutable sequential Credit Notes and balanced reversing double-entry ledger rows.

---

## 3. Identity, Authentication, Session Management, Authorization & Risk Signals

Maintain strict architectural separation across the 4 security layers:

| Security Layer | Responsibility | Core Mechanisms |
| :--- | :--- | :--- |
| **1. Identity Verification** | Proving real-world or legal identity | Email/SMS OTP proofing, Document KYC, Business KYB, Bank micro-deposit verification. |
| **2. Authentication (AuthN)** | Verifying credential ownership at login/step-up | Argon2id passwords, WebAuthn / Passkeys (FIDO2 hardware-backed), OAuth2/OIDC, TOTP/HOTP MFA. |
| **3. Session Management** | Managing lifecycle of authenticated state | Bound session IDs, Refresh Token Rotation with family reuse detection, absolute & idle TTLs, explicit revocation lists. |
| **4. Authorization (AuthZ)** | Enforcing permissions on target resources | Multi-tenant BOLA/IDOR guards (`WHERE tenant_id = $1`), RBAC + ABAC + ReBAC policy evaluation. |

### Device Identity vs. Probabilistic Risk Fingerprinting
- **Never treat browser/network fingerprints as deterministic device identity**: IP addresses, ASNs, TLS/JA4 fingerprints, and User-Agent headers legitimately change across mobile carrier handoffs, VPNs, and browser updates, and can be shared behind carrier-grade NAT (CGNAT).
- **Separate 5 Distinct Controls**:
  1. **Session Binding**: Cryptographically bind the session/JWT (`cnf` claim) to an `HttpOnly; Secure; SameSite=Strict` cookie (`__Host-sid`) or DPoP / mTLS key.
  2. **Device Registration**: Explicit `user_devices` registry enrolled after strong authentication (MFA/Passkey), storing a long-lived cryptographic device keypair or attested token.
  3. **Hardware-Backed Authentication**: Prefer WebAuthn / Passkeys, Apple App Attest / DeviceCheck, Android Play Integrity, or client mTLS certificates where supported.
  4. **Risk-Based Authentication (RBA)**: Evaluate contextual signals (IP `/24` or RFC-compliant IPv6 `/48` prefix, ASN, Geo-velocity, JA4, device cookie) into a continuous risk score (`0..100`).
  5. **Behavioral Anomaly Detection**: Detect abnormal request cadences, enumeration patterns, or sudden privilege-escalation sequences.
- **Graduated Response Policy**: Fingerprint drift triggers **step-up MFA, CAPTCHA challenge, or session re-authentication**—never automatic account termination.

---

## 4. Polyglot Databases, Isolation Invariants & Committed Transactional Outbox

### Selecting Database Isolation Levels by Invariant
Do not mandate `SERIALIZABLE` everywhere (which degrades throughput with serialization aborts). Match isolation to the exact concurrency invariant:

| Concurrency Invariant | Required Isolation & Locking Pattern |
| :--- | :--- |
| **Single-row balance debit / inventory decrement** | `READ COMMITTED` + single atomic statement (`UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance`). |
| **Multi-account transfer / multi-item order checkout** | `READ COMMITTED` or `REPEATABLE READ` + pessimistic row locks acquired in deterministic sorted ID order (`SELECT ... WHERE id = ANY($1) ORDER BY id FOR UPDATE`). |
| **Point-in-time financial reconciliation / multi-query report** | `REPEATABLE READ` (`READ ONLY` transaction snapshot) so all queries see a consistent MVCC snapshot without blocking writers. |
| **Intersecting predicate invariants (e.g., on-call minimum staffing, complex cross-row rules)** | `SERIALIZABLE` (SSI) with automatic retry middleware for SQLSTATE `40001` (`serialization_failure`). |

### Committed Transactional Outbox & Consumer Inbox Sequence
An Outbox Relay / CDC worker **MUST ONLY read committed outbox records** (reading uncommitted rows would publish events for transactions that later roll back).
1. `BEGIN` PostgreSQL transaction.
2. Execute domain `INSERT` / `UPDATE` mutations.
3. `INSERT` event into `outbox_events` table.
4. `COMMIT` transaction.
5. Outbox Relay polls committed rows (`SELECT ... FROM outbox_events WHERE processed_at IS NULL ORDER BY created_at ASC LIMIT 100 FOR UPDATE SKIP LOCKED` under `READ COMMITTED`) or tails the committed PostgreSQL WAL via Debezium/logical replication.
6. Relay publishes the event to the message broker (Kafka / RabbitMQ / NATS / BullMQ) with **at-least-once delivery** and marks `processed_at = clock_timestamp()`.
7. Downstream consumer deduplicates inside its own transaction by inserting `event_id` into `inbox_processed_events (consumer_group, event_id PRIMARY KEY)` before applying side effects.

---

## 5. Lease-Safe Background Job Processing & Crash Recovery

Message queues provide **at-least-once delivery**, not universal exactly-once execution. Every worker implementation must enforce:
1. **Atomic Job Acquisition & Lease Ownership**: Acquire a job atomically (`SETNX` / Lua or `UPDATE jobs SET status = 'IN_PROGRESS', lease_owner = $workerId, lease_expires_at = clock_timestamp() + $leaseDuration WHERE id = $jobId AND (status = 'QUEUED' OR (status = 'IN_PROGRESS' AND lease_expires_at < clock_timestamp()))`).
2. **Explicit Handling of All Lock States**:
   - `ALREADY_COMPLETED`: Acknowledge message and exit immediately (`no-op`).
   - `IN_PROGRESS` (owned by another active worker whose lease has not expired): **Exit immediately without executing the handler** so two workers never run the same job concurrently.
   - `ACQUIRED`: Proceed with handler execution under a lease heartbeat.
3. **Lease Heartbeat & Fencing**: A background timer renews `lease_expires_at` every $\frac{\text{leaseDuration}}{3}$ while verifying `lease_owner = $workerId`. If renewal fails (lease lost), abort the in-flight handler via `AbortController`.
4. **Exactly-Once Business Effects via Idempotency**: Downstream DB writes or external API calls inside the worker must use deterministic idempotency keys (`jobId` + step name).
5. **Crash Recovery & DLQ Replay**: Stalled jobs whose `lease_expires_at` has passed are reclaimed up to `max_attempts` with exponential backoff + full jitter, then moved to the Dead-Letter Queue (`DLQ`) with an auditable replay endpoint.

---

## 6. Streaming File Upload Defense, Multi-Storage & Malware Scanning

1. **Zero Full-File Memory Buffering**: Never load entire uploaded files into RAM (`Buffer.concat` on multi-megabyte uploads causes OOM crashes under concurrency). Process uploads as **bounded-memory streams**:
   - Inspect the first 64 bytes on the first stream chunk to verify binary **magic numbers** against the strict extension allowlist.
   - Pipe chunks through a byte-counting `Transform` stream that immediately aborts the upload if `bytesRead > maxSizeBytes`.
   - Compute `SHA-256` incrementally as chunks flow through the stream.
2. **Deep Content Sanitization (Beyond Magic Bytes)**:
   - Magic bytes alone do not prove a file is safe (attackers craft valid-header polyglots or embed exploits in trailers/metadata).
   - **Images**: Decode and re-encode pixels into a fresh buffer/stream (`sharp` / `libvips`), stripping all EXIF/XMP metadata and destroying appended script payloads.
   - **PDFs**: Parse object tree to reject embedded `/JS`, `/JavaScript`, `/Launch`, `/AA`, `/OpenAction`, and `/EmbeddedFiles` streams.
3. **Storage Isolation & Streaming Quarantine Malware Scan**:
   - Generate a randomized UUIDv7 storage key (`{tenantId}/{yyyy}/{mm}/{uuidv7}.{ext}`), store outside the web root (`noexec,nosuid,nodev` on local mounts or private S3/GCS/R2 buckets), stream through **ClamAV `zINSTREAM`** in quarantine before promoting to production storage, and serve only with `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and sandbox CSP headers.

---

## 7. Complete Enterprise Engineering Domains (Modules 07 & 08)

Ensure every system design evaluates and incorporates:
- **Event-Driven Architecture**: Kafka, RabbitMQ, NATS JetStream, schema registries, partitioning keys for ordering guarantees.
- **Real-Time Communication**: WebSocket connection lifecycle, auth on upgrade, heartbeats, room backplanes, and Server-Sent Events (SSE) with `Last-Event-ID` replay.
- **Distributed Transactions**: Saga orchestration & choreography with idempotent compensating actions and bounded compensation retries.
- **Database Lifecycle & Advanced SQL**: Zero-downtime Expand-and-Contract migrations, `CREATE INDEX CONCURRENTLY`, declarative partitioning, CTEs, window functions, and `EXPLAIN (ANALYZE, BUFFERS)`.
- **Multi-Tenancy & Search**: Row-Level Security (RLS with `NOBYPASSRLS` runtime role + `NULLIF(current_setting(...), '')::uuid`) vs. Schema-per-tenant vs. DB-per-tenant; Elasticsearch / OpenSearch / Meilisearch + `pgvector` hybrid search.
- **Deep API Security & Secrets**: SSRF DNS-pinned socket agents + IPv6 tunnel blocklists, CSRF, XSS, CORS, SQLi, NoSQLi, BOLA/BOPLA, KMS/Vault envelope encryption & automated secret rotation.
- **Resilience, Networking, Microservices, AI & Governance**: PITR backups with tested RPO/RTO, DNS/L4-L7 load balancing/service discovery, DDD microservices, AI model gateways & streaming inference queues, and GDPR/PII retention & immutable hash-chained audit logs.

---

## 8. Penetration-Hardened Zero-Trust Defense Matrix (Mandatory on Every Backend)

Every backend created using this skill MUST enforce these 12 penetration-testing countermeasures by default:

| Penetration Attack Vector | Mandatory Code-Level Countermeasure |
| :--- | :--- |
| **1. JWT `alg: "none"`, Algorithm Confusion (`RS256` -> `HS256`) & `kid`/`jku` Injection** | Explicitly pin `allowedAlgorithm: 'EdDSA' \| 'RS256'`, reject tokens containing `jku`, `x5u`, `jwk`, or `x5c` headers, validate `kid` against `/^[a-zA-Z0-9_-]{1,64}$/` before looking up in an in-memory/KMS `KeyObject` dictionary, and verify `iss`, `aud`, `exp`, `nbf`, `sub`, `jti`. |
| **2. Login / Reset Timing Side-Channel & Account Enumeration** | Execute a dummy KDF verification (`verifyPasswordTimingSafe` against a boot-time `DUMMY_PASSWORD_HASH`) whenever `user === null`, and return identical HTTP status codes and generic messages on login, registration, and password reset. |
| **3. SSRF DNS Rebinding (`TTL=0` TOCTOU) & IPv6 Embedded Tunnels** | Resolve DNS **once** via `createPinnedSafeHttpsAgent`, block all RFC 1918, loopback, link-local/IMDS (`169.254.169.254`), CGNAT (`100.64.0.0/10`), hex-normalized IPv4-mapped IPv6 (`::ffff:a9fe:a9fe`), NAT64 (`64:ff9b::/96`), and 6to4 (`2002::/16`) addresses, and pin the socket `lookup` callback to the verified IP. |
| **4. Prototype Pollution (`__proto__`), JSON Depth Bombs & NoSQL `$` Operator Injection** | Sanitize all untrusted JSON inputs through `sanitizeUntrustedJsonInput` to strip `__proto__`, `constructor`, `prototype`, reject keys starting with `$` or containing `.`, cap object nesting depth ($\le 12$), and normalize strings to Unicode `NFKC` **before** validation. |
| **5. SQL Injection & `LIKE` Wildcard DoS** | Use 100% parameterized queries (`$1, $2`), map dynamic sort/filter column names against a frozen compile-time allowlist dictionary, and escape `%` and `_` wildcards via `escapeSqlLikePattern`. |
| **6. File Upload Polyglots, PDF `#XX` Hex Obfuscation & Memory Exhaustion** | Stream uploads through `SecurityGateTransformStream` (64KB bounded buffer, hard mid-stream byte cutoff, first-64-byte magic signature check, PDF `#XX` hex-escape decoding to block `/J#61vaScript`, image pixel re-encoding, and streaming ClamAV `zINSTREAM` scan in quarantine). |
| **7. BOLA / IDOR, BOPLA (Mass Assignment) & Multi-Tenant RLS Bypass** | Scope every query by `tenant_id`, strip unpermitted fields via Zod `.strict()`, run DB connections under a `NOSUPERUSER NOBYPASSRLS` role, and write RLS policies with `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`. |
| **8. HTTP/2 Single-Packet Race Conditions & Double-Spend Attacks** | Never use application-level `SELECT`-then-`UPDATE` check-then-act flows. Enforce atomic single-statement conditional updates (`UPDATE ... WHERE balance >= $1 RETURNING *`), deterministic sorted `FOR UPDATE` row locks, and `Idempotency-Key` state locks. |
| **9. `X-Forwarded-For` IP Spoofing & Host Header Password-Reset Poisoning** | Extract client IP strictly by counting backward `trustedProxyHopCount` hops from the right of `X-Forwarded-For` (`extractTrustedClientIp`). Never use `req.headers.host` or `X-Forwarded-Host` to build sensitive links—always use `process.env.APP_URL`. |
| **10. Webhook Replay & Secret-Rotation Signature Bypass** | Verify raw request bytes against all active/retiring secrets and all `v1=` signatures in constant time (`crypto.timingSafeEqual`), enforce a $\pm 300\text{s}$ timestamp window, and deduplicate `event_id` in `inbox_processed_events`. |
| **11. Duplicate Background Worker Execution & Zombie Leases** | Handle `ALREADY_COMPLETED` and `IN_PROGRESS` explicitly in workers, increment a monotonic `fencing_token` on every lease acquisition, renew leases via heartbeat, and reject stale worker writes whose `fencing_token` no longer matches. |
| **12. GraphQL Batching / Alias Brute-Force Amplification** | Enforce max query depth ($\le 8$), max aliases per document ($\le 15$), max mutation batch size ($\le 1$), query cost limits, and per-resolver rate limiting. |

