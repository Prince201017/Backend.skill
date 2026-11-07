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
  data governance, omnichannel notifications/email/SMS/OTP/push/chat delivery,
  complete BaaS provider architectures (Supabase, Firebase, Convex, Appwrite, Amplify,
  PocketBase), and incoming/outgoing request I/O tracing with correlated log telemetry.
---

# Advanced Backend Development Skill (Zero-Loss Architecture & Execution Constitution)

Use this skill whenever designing, architecting, or implementing the backend **for** any frontend or product requirement (Web, Mobile, Desktop, IoT, B2B SaaS, FinTech, E-Commerce, Healthcare, Real-Time Collaboration, AI Platforms, or Enterprise Distributed Systems).

## Skill Modules (`/skills/*.md`)

Load the modular specifications directly from `/skills/` according to the architectural domains required:

- `00-execution-intelligence-architecture-engine.md` — **Execution Intelligence & Architecture-Selection Engine**: Requirement analysis, SLO formulation, and deterministic decision matrices that decide *what* to implement and *why*.
- `01-domain-modeling-fields-timestamps-ids.md` — **Domain Modeling, Financial Engine, Timestamps & Generators**: Strict field types, exact penny-reconciled calculations (`allocateProratedAmountExact` with weight-sum invariants), currency exponents, GST/VAT inclusive/exclusive math, refunds/credit notes, strict UTC vs. offset timestamps, and CSPRNG ID/Token/OTP (`verifyOtpCodeConstantTime` with expiration & entropy checks) generators.
- `02-auth-authorization-fingerprinting-security.md` — **Identity, AuthN, Session Management, AuthZ & Risk Signals**: Separation of Identity Verification, Authentication, Session Binding (`__Host-sid` SHA-256 `cnf` binding), Refresh Token Reuse Detection (`rotateRefreshTokenWithReuseDetection`), Hardware-Backed Auth (Passkeys/WebAuthn/mTLS), Probabilistic Risk-Based Authentication, Intra-Tenant Horizontal BOLA + ReBAC ownership checks (`authorizeAction`), and RFC-compliant IPv4/IPv6 prefix extraction.
- `03-databases-polyglot-storage-transactions.md` — **Polyglot Databases, Isolation Invariants, 3-Phase Committed Outbox & Tenant-Scoped Caching**: PostgreSQL/MySQL/MongoDB/Redis selection, isolation level mapping by concurrency invariant, 3-Phase Lease-Claim Outbox Relay (`runCommittedOutboxRelayBatch` holding zero DB locks across network I/O) + Consumer Inbox deduplication, deadlock-free lock ordering, Read-Your-Own-Writes routing, and mandatory tenant-namespaced single-flight Redis caching (`getOrComputeCachedSingleFlight`).
- `04-apis-payments-webhooks-resilience.md` — **APIs, Versioning, OpenAPI, Payments, Rate Limiting, Circuit Breakers & Safe Error Boundary**: REST & GraphQL design, RFC 9457 Problem Details (`OperationalAppError` & `toSafeProblemDetailsResponse` with zero stack/SQL leakage), payment idempotency state machine (`executeWithIdempotencyLock`), constant-time multi-signature webhook verification, atomic Redis Lua token-bucket rate limiting (with `refill_rate > 0` guard), and circuit breakers.
- `05-file-uploads-multi-storage-malware-scanning.md` — **Streaming File Upload Defense, Multi-Storage & Malware Scanning**: Bounded-memory 64KB streaming uploads, strict `tenantId` path-traversal guard, on-the-fly header magic-byte checks, PDF `#XX` hex-escape active-content deobfuscation, streaming SHA-256 checksums, hard byte-stream cutoffs, image pixel re-encoding, and streaming ClamAV `zINSTREAM` quarantine scanning.
- `06-async-queues-observability-testing-devops.md` — **Lease-Safe Job Queues, Observability, Testing & DevOps**: Atomic job acquisition with typed interval arithmetic, lease ownership (`workerInstanceId`), heartbeat lease renewal, `IN_PROGRESS` duplicate prevention, monotonic `fencing_token`, stalled-job crash recovery, DLQ replay procedures, prototype-safe & circular-reference-safe `redactSensitiveFields` JSON logging, Prometheus metrics, OpenTelemetry tracing, and CI/CD.
- `07-events-realtime-sagas-migrations-sql-multitenancy-search.md` — **Events, WebSockets, SSE, Sagas, Zero-Downtime Migrations, Advanced SQL, Multi-Tenancy & Search**: Kafka/RabbitMQ/NATS, WebSocket rooms/heartbeats, CRLF/CR injection-safe `formatSseFrame` SSE streaming with `Last-Event-ID`, Saga orchestration with bounded compensation retries, Expand-and-Contract migrations, partitioning/window functions, `NOBYPASSRLS` + `NULLIF` multi-tenancy, and hybrid search.
- `08-api-security-secrets-dr-networking-microservices-ai-governance.md` — **API Security, KMS/Vault, Disaster Recovery, Networking, Microservices, AI Infrastructure & Data Governance**: SSRF DNS-pinned `createPinnedSafeHttpsAgent` + 128-bit IPv6 tunnel blocklist, `sanitizeUntrustedJsonInput`, right-to-left `extractTrustedClientIp`, KMS/Vault envelope encryption, PITR/RPO/RTO disaster recovery, AI model gateways, and length-prefixed keyed HMAC hash-chained audit trails (`computeAuditChainHash`).
- `09-adversarial-security-audit-and-verification-harness.md` — **Adversarial Security Audit & Defensive Verification Harness**: Complete penetration/vulnerability audit report of all skill primitives and executable CI security verification suite (`PEN-01` through `PEN-11`).
- `10-omnichannel-notifications-email-messaging-security.md` — **Omnichannel Notifications, Email, SMS/WhatsApp/OTP, Push & Chat Delivery Architecture**: Priority queue isolation (`P0_CRITICAL`..`P3_BULK`), Definitive-vs-Ambiguous multi-provider failover (`dispatchWithSafeMultiProviderFailover`), SMTP CRLF & SSTI sanitization, WHATWG control-char-safe `validateSafeNotificationActionUrl`, DKIM/SPF/DMARC/ARC + RFC 8058 one-click unsubscribe, and positive-cost-validated SMS toll-fraud & country-prefix budget caps.
- `11-baas-providers-supabase-firebase-amplified-security.md` — **Complete BaaS Provider Architecture & Security Hardening (Supabase, Firebase, Convex, Appwrite, AWS Amplify, PocketBase)**: Supabase PostgreSQL RLS (`auth.jwt() -> 'app_metadata'` with `SELECT`/`INSERT`/`UPDATE`/`DELETE` policies and `SET search_path = public, pg_temp`), Firebase 8-Pillar `firestore.rules` fortress, App Check, and Hexagonal Anti-Lock-In Repository Adapters.
- `12-request-io-tracing-service-visualization-and-log-correlation.md` — **Incoming/Outgoing Request I/O Tracing, Service Dependency Visualization & Correlated Log Telemetry**: W3C `traceparent` propagation, circular-safe PII-scrubbed I/O envelope snapshots (`scrubIoPayload`), 5-stage service hop DAG capture (`traceServiceHop` with uncaught error span recording), and correlated structured JSON log telemetry.
- `13-critical-risk-audit-reliability-and-production-readiness.md` — **12-Domain Critical Risk Audit, Database Constraints, API Boundary Guards & Production Reliability**: Pre-deployment audit matrix across all 12 critical risk domains, composite multi-tenant foreign keys (`FOREIGN KEY (tenant_id, customer_user_id)`), `withTenantTransaction` (`SET LOCAL`), `assertNoSecretsExposedToFrontendEnv`, AAD-bound `AES-256-GCM` encryption, strict CORS/CSRF guards, `/healthz` + `/readyz` probes, and `SIGTERM` graceful shutdown draining.

---

## 1. Execution Intelligence: Designing the Backend FOR Any Frontend

When given a frontend design, product specification, or user story, execute this 6-step **Architecture-Selection Protocol** (detailed in `00-execution-intelligence-architecture-engine.md`):

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
| **3. Session Management** | Managing lifecycle of authenticated state | Bound session IDs (`__Host-sid`), Refresh Token Rotation with family reuse detection, absolute & idle TTLs, explicit revocation lists. |
| **4. Authorization (AuthZ)** | Enforcing permissions on target resources | Multi-tenant & Intra-tenant BOLA/IDOR guards (`WHERE tenant_id = $1`, `ownerId` / ReBAC checks), RBAC + ABAC + ReBAC policy evaluation. |

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

## 4. Polyglot Databases, Isolation Invariants & 3-Phase Committed Transactional Outbox

### Selecting Database Isolation Levels by Invariant
Do not mandate `SERIALIZABLE` everywhere (which degrades throughput with serialization aborts). Match isolation to the exact concurrency invariant:

| Concurrency Invariant | Required Isolation & Locking Pattern |
| :--- | :--- |
| **Single-row balance debit / inventory decrement** | `READ COMMITTED` + single atomic statement (`UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance`). |
| **Multi-account transfer / multi-item order checkout** | `READ COMMITTED` or `REPEATABLE READ` + pessimistic row locks acquired in deterministic sorted ID order (`SELECT ... WHERE id = ANY($1) ORDER BY id FOR UPDATE`). |
| **Point-in-time financial reconciliation / multi-query report** | `REPEATABLE READ` (`READ ONLY` transaction snapshot) so all queries see a consistent MVCC snapshot without blocking writers. |
| **Intersecting predicate invariants (e.g., on-call minimum staffing, complex cross-row rules)** | `SERIALIZABLE` (SSI) with automatic retry middleware for SQLSTATE `40001` (`serialization_failure`). |

### 3-Phase Committed Transactional Outbox & Consumer Inbox Sequence
An Outbox Relay / CDC worker **MUST ONLY read committed outbox records** and **MUST NOT hold database locks open across external network I/O**:
1. `BEGIN` PostgreSQL transaction (`withTenantTransaction` setting `SET LOCAL app.current_tenant_id`).
2. Execute domain `INSERT` / `UPDATE` mutations.
3. `INSERT` event into `outbox_events` table.
4. `COMMIT` transaction.
5. **Phase 1 (Short Lease Claim)**: Outbox Relay claims a batch of committed rows (`UPDATE outbox_events SET leased_until = clock_timestamp() + interval '30 seconds' WHERE event_id IN (SELECT event_id FROM outbox_events WHERE processed_at IS NULL AND (leased_until IS NULL OR leased_until < clock_timestamp()) ORDER BY created_at ASC LIMIT 100 FOR UPDATE SKIP LOCKED) RETURNING *`) and commits immediately so zero DB locks are held during network publish.
6. **Phase 2 (Out-of-Transaction Network Publish)**: Relay publishes claimed events to the message broker (Kafka / RabbitMQ / NATS / BullMQ).
7. **Phase 3 (Mark Processed)**: Relay marks succeeded event IDs with `processed_at = clock_timestamp()`.
8. **Idempotent Consumer Inbox**: Downstream consumer deduplicates inside its own transaction by inserting `event_id` into `inbox_processed_events (consumer_group, event_id PRIMARY KEY)` before applying side effects.

---

## 5. Lease-Safe Background Job Processing & Crash Recovery

Message queues provide **at-least-once delivery**, not universal exactly-once execution. Every worker implementation must enforce:
1. **Atomic Job Acquisition & Lease Ownership**: Acquire a job atomically (`SETNX` / Lua or `UPDATE jobs SET status = 'IN_PROGRESS', lease_owner = $workerId, lease_expires_at = clock_timestamp() + ($3::bigint * interval '1 millisecond') WHERE id = $jobId AND (status = 'QUEUED' OR (status = 'IN_PROGRESS' AND lease_expires_at < clock_timestamp()))`).
2. **Explicit Handling of All Lock States**:
   - `ALREADY_COMPLETED`: Acknowledge message and exit immediately (`no-op`).
   - `IN_PROGRESS` (owned by another active worker whose lease has not expired): **Exit immediately without executing the handler** so two workers never run the same job concurrently.
   - `ACQUIRED`: Proceed with handler execution under a lease heartbeat.
3. **Lease Heartbeat & Fencing**: A background timer renews `lease_expires_at` every $\frac{\text{leaseDuration}}{3}$ while verifying `lease_owner = $workerId` and `fencing_token`. If renewal fails (lease lost), abort the in-flight handler via `AbortController`.
4. **Exactly-Once Business Effects via Idempotency**: Downstream DB writes or external API calls inside the worker must use deterministic idempotency keys (`jobId` + step name).
5. **Crash Recovery & DLQ Replay**: Stalled jobs whose `lease_expires_at` has passed are reclaimed up to `max_attempts` with exponential backoff + full jitter, then moved to the Dead-Letter Queue (`DLQ`) with an auditable replay endpoint.

---

## 6. Streaming File Upload Defense, Multi-Storage & Malware Scanning

1. **Zero Full-File Memory Buffering**: Never load entire uploaded files into RAM (`Buffer.concat` on multi-megabyte uploads causes OOM crashes under concurrency). Process uploads as **bounded-memory streams**:
   - Validate `tenantId` against `/^[a-zA-Z0-9_-]{1,64}$/` to prevent path traversal in object storage keys.
   - Inspect the first 64 bytes on the stream to verify binary **magic numbers** against the strict extension allowlist.
   - Pipe chunks through a byte-counting `Transform` stream that immediately aborts the upload if `bytesRead > maxSizeBytes`.
   - Compute `SHA-256` incrementally as chunks flow through the stream.
2. **Deep Content Sanitization (Beyond Magic Bytes)**:
   - **Images**: Decode and re-encode pixels into a fresh buffer/stream (`sharp` / `libvips`), stripping all EXIF/XMP metadata and destroying appended script payloads.
   - **PDFs**: Deobfuscate `#XX` hex escapes and reject embedded `/JS`, `/JavaScript`, `/Launch`, `/AA`, `/OpenAction`, and `/EmbeddedFiles` streams.
3. **Storage Isolation & Streaming Quarantine Malware Scan**:
   - Generate a randomized UUIDv7 storage key (`{tenantId}/{yyyy}/{mm}/{uuidv7}.{ext}`), store outside the web root (`noexec,nosuid,nodev` on local mounts or private S3/GCS/R2 buckets), stream through **ClamAV `zINSTREAM`** in quarantine before promoting to production storage, and serve only with `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and sandbox CSP headers.

---

## 7. Complete Enterprise Engineering Domains (Modules 07 & 08)

Ensure every system design evaluates and incorporates:
- **Event-Driven Architecture**: Kafka, RabbitMQ, NATS JetStream, schema registries, partitioning keys for ordering guarantees.
- **Real-Time Communication**: WebSocket connection lifecycle, auth on upgrade, heartbeats, room backplanes, and CRLF-safe Server-Sent Events (SSE) with `Last-Event-ID` replay.
- **Distributed Transactions**: Saga orchestration & choreography with idempotent compensating actions and bounded compensation retries.
- **Database Lifecycle & Advanced SQL**: Zero-downtime Expand-and-Contract migrations (`SET lock_timeout = '2s'`), `CREATE INDEX CONCURRENTLY`, declarative partitioning, CTEs, window functions, and `EXPLAIN (ANALYZE, BUFFERS)`.
- **Multi-Tenancy & Search**: Row-Level Security (RLS with `NOBYPASSRLS` runtime role + `NULLIF(current_setting(...), '')::uuid` + composite foreign keys) vs. Schema-per-tenant vs. DB-per-tenant; Elasticsearch / OpenSearch / Meilisearch + `pgvector` hybrid search.
- **Deep API Security & Secrets**: SSRF DNS-pinned socket agents + IPv6 tunnel blocklists, 3-layer CSRF, XSS, strict CORS allowlists, SQLi, NoSQLi, BOLA/BOPLA, KMS/Vault AAD-bound `AES-256-GCM` envelope encryption & automated secret rotation.
- **Resilience, Networking, Microservices, AI & Governance**: PITR backups with tested RPO/RTO, DNS/L4-L7 load balancing/service discovery, DDD microservices, AI model gateways & streaming inference queues, and GDPR/PII retention & length-prefixed HMAC hash-chained audit logs.

---

## 8. Penetration-Hardened Zero-Trust Defense Matrix (Mandatory on Every Backend)

Every backend created using this skill MUST enforce these 12 penetration-testing countermeasures by default:

| Penetration Attack Vector | Mandatory Code-Level Countermeasure |
| :--- | :--- |
| **1. JWT `alg: "none"`, Algorithm Confusion (`RS256` -> `HS256`), `kid`/`jku` Injection & Token Theft** | Explicitly pin `allowedAlgorithm: 'EdDSA' \| 'RS256'`, cap token size ($\le 8\text{KB}$), reject `jku`/`x5u`/`jwk`/`x5c`, validate `kid` against `/^[a-zA-Z0-9_-]{1,64}$/`, verify `__Host-sid` session binding (`cnf.sidHash`), and revoke the entire `familyId` on refresh token replay. |
| **2. Login / Reset Timing Side-Channel & Account Enumeration** | Execute a dummy KDF verification (`verifyPasswordTimingSafe` against a boot-time `DUMMY_PASSWORD_HASH`) whenever `user === null`, and return identical HTTP status codes and generic messages on login, registration, and password reset. |
| **3. SSRF DNS Rebinding (`TTL=0` TOCTOU) & IPv6 Embedded Tunnels** | Resolve DNS **once** via `createPinnedSafeHttpsAgent`, block all RFC 1918, loopback, link-local/IMDS (`169.254.169.254`), CGNAT (`100.64.0.0/10`), hex-normalized IPv4-mapped IPv6 (`::ffff:a9fe:a9fe`), NAT64 (`64:ff9b::/96`), and 6to4 (`2002::/16`) addresses, and pin the socket `lookup` callback to the verified IP. |
| **4. Prototype Pollution (`__proto__`), JSON Depth Bombs & NoSQL `$` Operator Injection** | Sanitize all untrusted JSON inputs through `sanitizeUntrustedJsonInput` and `parseAndValidateJsonBodyStrict` to strip `__proto__`, `constructor`, `prototype`, reject keys starting with `$` or containing `.`, cap object nesting depth ($\le 12$), and normalize strings to Unicode `NFKC` **before** validation. |
| **5. SQL Injection & `LIKE` Wildcard DoS** | Use 100% parameterized queries (`$1, $2`), map dynamic sort/filter column names against a frozen compile-time allowlist dictionary (`resolveSafeOrderByClause`), and escape `%` and `_` wildcards via `escapeSqlLikePattern`. |
| **6. File Upload Polyglots, PDF `#XX` Hex Obfuscation, Path Traversal & OOM** | Validate `tenantId` against `/^[a-zA-Z0-9_-]{1,64}$/`, stream uploads through `SecurityGateTransformStream` (64KB bounded buffer, hard mid-stream byte cutoff, first-64-byte magic signature check, PDF `#XX` hex-escape decoding, image pixel re-encoding, and streaming ClamAV `zINSTREAM` scan in quarantine). |
| **7. Vertical & Intra-Tenant Horizontal BOLA / IDOR, BOPLA & Multi-Tenant RLS Bypass** | Scope every query by `tenant_id`, enforce `ownerId` / ReBAC relation checks for non-privileged roles (`authorizeAction`), use composite foreign keys (`FOREIGN KEY (tenant_id, user_id)`), run DB connections under a `NOSUPERUSER NOBYPASSRLS` role with `withTenantTransaction` (`SET LOCAL`), and namespace all Redis cache keys (`tenant:${tenantId}:${resourceKey}`). |
| **8. HTTP/2 Single-Packet Race Conditions & Double-Spend Attacks** | Never use application-level `SELECT`-then-`UPDATE` check-then-act flows. Enforce atomic single-statement conditional updates (`UPDATE ... WHERE balance >= $1 RETURNING *`), deterministic sorted `FOR UPDATE` row locks, and `executeWithIdempotencyLock` state machines. |
| **9. `X-Forwarded-For` IP Spoofing & Host Header Password-Reset Poisoning** | Extract client IP strictly by counting backward `trustedProxyHopCount` hops from the right of `X-Forwarded-For` (`extractTrustedClientIp`). Never use `req.headers.host` or `X-Forwarded-Host` to build sensitive links—always use `process.env.APP_URL`. |
| **10. Webhook Replay & Secret-Rotation Signature Bypass** | Verify raw request bytes against all active/retiring secrets and all `v1=` signatures in constant time (`crypto.timingSafeEqual`), enforce a $\pm 300\text{s}$ timestamp window, and deduplicate `event_id` in `inbox_processed_events`. |
| **11. Duplicate Background Worker Execution & Zombie Leases** | Handle `ALREADY_COMPLETED` and `IN_PROGRESS` explicitly in workers, increment a monotonic `fencing_token` on every lease acquisition, renew leases via heartbeat, and reject stale worker writes whose `fencing_token` no longer matches. |
| **12. Stack Trace / SQL Leakage, Supply-Chain Scripts & Uncoordinated Shutdown** | Mask all non-operational errors behind `toSafeProblemDetailsResponse`, enforce `assertNoSecretsExposedToFrontendEnv` at boot, run `npm ci --ignore-scripts` in CI, and drain active requests on `SIGTERM` via `ProductionLifecycleCoordinator`. |

---

## 9. Omnichannel Notification, Email, SMS/OTP, Push & Chat Delivery (`10-omnichannel-notifications-email-messaging-security.md`)

1. **4-Lane Priority Queue Isolation**: Separate `P0_CRITICAL` (OTP / security alerts), `P1_TRANSACTIONAL` (receipts / password resets), `P2_COLLABORATIVE` (mentions / assignments), and `P3_BULK` (marketing campaigns) so bulk jobs never delay critical OTPs.
2. **Definitive vs. Ambiguous Multi-Provider Failover**: Only trigger automatic secondary provider failover (e.g., AWS SES -> Postmark, Twilio -> Vonage) on `DEFINITIVE_PRE_ACCEPTANCE` errors (`CONNECT_TIMEOUT`, `HTTP_502/503/504`, `HTTP_429`). Hold `AMBIGUOUS_POST_WRITE` timeouts in `PENDING_RECONCILIATION` to prevent duplicate delivery.
3. **Anti-Abuse, SMTP CRLF Guard & SMS Toll-Fraud Prevention**: Reject `\r`/`\n` in all email headers, block control characters in `validateSafeNotificationActionUrl`, enforce positive-cost-validated country-prefix SMS budgets, and never bypass transport-level `HARD_BOUNCE` or `SPAM_COMPLAINT` suppressions (use Cross-Channel Fallback instead).

---

## 10. Complete BaaS Provider Architecture & Hardening (`11-baas-providers-supabase-firebase-amplified-security.md`)

1. **Supabase**: Enforce RLS on every `public` table using `auth.jwt() -> 'app_metadata'` (never client-writable `user_metadata`), isolate `service_role` strictly on the server, lock down `SET search_path = public, pg_temp` on SQL functions, and define explicit `SELECT`, `INSERT`, `UPDATE`, and `DELETE` RLS policies.
2. **Firebase**: Enforce the 8-Pillar `firestore.rules` Fortress (`rules_version = '2'`, default deny, `isValid[Entity]` schema/size bounds, `affectedKeys().hasOnly()`, immutable ownership, Query Enforcer `allow list`, explicit `allow delete`), keep `firebase-blueprint.json` in sync, and wrap client SDK calls with `handleFirestoreError`.
3. **Hexagonal Anti-Lock-In Adapters**: Wrap BaaS SDKs (Supabase, Firebase, Convex, Appwrite, Amplify, PocketBase) behind domain repository and auth verifier interfaces (`OrderRepositoryPort`) so business logic remains portable.

---

## 11. Request I/O Tracing, Service Topology & Correlated Logs (`12-request-io-tracing-service-visualization-and-log-correlation.md`)

1. **End-to-End W3C `traceparent` Correlation**: Mint or propagate `trace_id` and `span_id` across every hop (`INGRESS_GATEWAY` -> `AUTH_RBA_ENGINE` -> `BAAS_DATA_PLANE` -> `ASYNC_OUTBOX_RELAY` -> `EGRESS_EXTERNAL_PROVIDER`).
2. **Circular-Safe PII-Scrubbed I/O Envelopes**: Redact secrets, tokens, PANs, and OTPs (`scrubIoPayload` with `WeakSet` cycle detection and prototype-pollution guards), enforce byte-size caps, and record failed spans on uncaught exceptions in `traceServiceHop`.

---

## 12. Pre-Deployment 12-Domain Critical Risk Audit & Production Reliability (`13-critical-risk-audit-reliability-and-production-readiness.md`)

Before shipping or certifying any backend implementation, verify all 12 critical risk gates in `13-critical-risk-audit-reliability-and-production-readiness.md`:
1. **Database Constraints & Pooled RLS**: Composite multi-tenant foreign keys (`FOREIGN KEY (tenant_id, user_id)`), `CHECK` constraints, and `withTenantTransaction()` using transaction-scoped `SET LOCAL app.current_tenant_id`.
2. **Secrets & AAD Envelope Encryption**: Boot-time `assertNoSecretsExposedToFrontendEnv()` blocking `service_role` / `sk_live_` keys in `NEXT_PUBLIC_*`/`VITE_*` variables, plus `encryptWithTenantAad()` / `decryptWithKeyRing()`.
3. **API Boundary & Production Reliability**: Strict `evaluateCorsHeaders()` allowlists, 3-layer `verifyCsrfProtection()`, `/healthz` vs. `/readyz` separation, and `SIGTERM` connection draining via `ProductionLifecycleCoordinator`.

