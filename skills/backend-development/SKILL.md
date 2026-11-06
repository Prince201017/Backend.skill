---
name: "advanced-backend-development"
description: >
  Complete, zero-loss backend engineering skill capable of designing and implementing
  the backend for any frontend or system. Covers field-type logic design, deterministic
  calculations, cryptographic IDs/tokens/OTPs/complex generators, UTC/timestamp architecture,
  Authentication, RBAC/ABAC/ReBAC Authorization, request/device fingerprinting, polyglot
  multi-database management (PostgreSQL, MySQL, MongoDB, Redis), RESTful & GraphQL APIs,
  payment gateways & double-entry ledgers, API versioning & OpenAPI/Swagger governance,
  horizontal scaling & caching, HTTPS/TLS & encryption, rate limiting & throttling,
  circuit breakers, structured logging, metrics, distributed tracing, unit/integration/E2E
  testing, asynchronous job queues & workers, multi-cloud secure file uploads (whitelist,
  magic bytes, size limits, UUID naming, outside web root, noexec, malware scanning),
  and Docker/Kubernetes/CI-CD DevOps pipelines.
---

# Advanced Backend Development Skill (Zero-Loss Architecture Constitution)

Use this skill whenever designing, architecting, or implementing a backend for **any** frontend (Web, Mobile, Desktop, IoT, B2B SaaS, FinTech, E-Commerce, Healthcare, Real-Time, or Enterprise platforms). **Never omit any layer of this specification.**

## Skill Reference Modules

In addition to the core rules in this `SKILL.md`, load the deep-dive reference files as needed:

1. `references/01-domain-modeling-fields-timestamps-ids.md` — Frontend-to-Backend reverse engineering, strict field types, financial calculations, UTC timestamps, and ID/Token/OTP/Complex generators.
2. `references/02-auth-authorization-fingerprinting-security.md` — Authentication (Session, JWT, OAuth2/OIDC, Passkeys), Authenticated Authorization (RBAC, ABAC, ReBAC), Device/Request Fingerprinting, TLS, Input Validation, and Encryption.
3. `references/03-databases-polyglot-storage-transactions.md` — Multi-Database Management: Relational ACID (PostgreSQL, MySQL), NoSQL & In-Memory (MongoDB, Redis), Connection Pooling, Isolation Levels, Read Replicas, and Caching patterns.
4. `references/04-apis-payments-webhooks-resilience.md` — RESTful & GraphQL APIs, API Versioning, OpenAPI/Swagger Governance, Third-Party Integrations, Payment Endpoints, Idempotency, Rate Limiting & Throttling, and Circuit Breakers.
5. `references/05-file-uploads-multi-storage-malware-scanning.md` — Defending the Server: Extension Whitelisting, MIME & Magic Number Binary Verification, Size Restrictions, UUID Randomization, Outside-Web-Root Storage, `noexec` Permissions, Multi-Storage Routing (S3, GCS, R2, Local), and Malware Scanning (ClamAV/Quarantine).
6. `references/06-async-queues-observability-testing-devops.md` — Asynchronous Job Queues & Workers (BullMQ, Celery, Sidekiq), Observability (Structured JSON Logging, Metrics, Distributed Tracing), Automated Testing (Unit, Integration, E2E), and DevOps (Docker, Kubernetes, Git, CI/CD).

---

## 1. Designing the Backend for Any Frontend (Reverse-Engineering Protocol)

To design a complete backend from any frontend UI, wireframe, or product requirement, execute this 5-step deterministic protocol:

1. **Entity & State Extraction**: Inspect every view, form, table, and state transition. Map UI nouns to normalized domain entities (`User`, `Organization`, `Order`, `LedgerEntry`, `AuditLog`) and UI verbs to command/query endpoints.
2. **Boundary & Trust Separation**: Never trust client-side calculations, prices, discounts, permissions, timestamps, or IDs. Every derived value (cart totals, taxes, balances, role checks, state transitions) MUST be computed and enforced server-side.
3. **Field-Level Contract Specification**: Every input and output field must have an explicit schema definition (type, min/max bounds, regex/format, nullability, default, mutability, PII classification, and indexing strategy).
4. **Synchronous vs. Asynchronous Split**:
   - **Synchronous (< 200ms p95)**: CRUD mutations, auth checks, cached reads, lightweight state transitions.
   - **Asynchronous (Job Queue + Worker)**: PDF generation, video/image transcoding, bulk emails/SMS, malware scanning, webhook fan-out, AI inference, reconciliation reports.
5. **Failure & Idempotency Mapping**: Every mutating endpoint (`POST`, `PUT`, `PATCH`, `DELETE`) must define its transaction boundary, rollback behavior, idempotency key strategy, and error codes.

---

## 2. Field Type Logic Design, Processing & Deterministic Calculations

Never use loose types (`any`, untyped JSON strings, or floating-point numbers for money).

| Domain Concept | Forbidden Type | Required Backend & DB Type | Processing & Validation Rule |
| :--- | :--- | :--- | :--- |
| **Monetary / Currency** | `float`, `double`, JS `number` | Minor units (`BIGINT` cents/paise) or `NUMERIC(19, 4)` + ISO-4217 `currency_code` (`CHAR(3)`) | Use `BigInt` or arbitrary-precision decimal libraries (`decimal.js`). Apply Banker's Rounding (`ROUND_HALF_EVEN`). |
| **Identifiers (PK/FK)** | Sequential `INT` exposed in URLs | Internal `BIGINT` + External `UUIDv7` or `ULID` (`CHAR(26)` / `UUID`) | Time-ordered UUIDv7/ULID prevents B-Tree index fragmentation and stops ID enumeration attacks. |
| **Email / Handle** | Case-sensitive `VARCHAR` | PostgreSQL `CITEXT` or normalized lowercase `VARCHAR(254)` | Trim, normalize Unicode (`NFKC`), lowercase before hashing or indexing. |
| **Phone Numbers** | Unformatted strings | E.164 format `VARCHAR(16)` (e.g., `+14155552671`) | Parse and validate country code + subscriber number before storage. |
| **Status / State Machine** | Free-text string or boolean flags (`is_paid`, `is_shipped`) | Strict Enum + transition matrix (`status` + `status_updated_at`) | Enforce allowed transitions (`PENDING -> PAID -> FULFILLED`). Reject illegal state jumps. |
| **Percentages / Rates** | `float` | Basis points (`INT`, where `10000 = 100.00%`) or `NUMERIC(7, 4)` | Store tax/commission rates in basis points (`250 bps = 2.50%`) for exact integer math. |
| **Geospatial** | Separate unindexed strings | PostGIS `GEOGRAPHY(POINT, 4326)` or validated `NUMERIC(9,6)` lat/lng | Validate latitude `[-90, 90]` and longitude `[-180, 180]`. Index with GiST. |
| **Structured Metadata** | Unvalidated `TEXT` | `JSONB` validated at application boundary via Zod/JSON Schema | Index hot paths with GIN indexes; never store relational foreign keys solely inside JSON. |

### Server-Side Calculation Rules
- **Order & Invoice Totals**:
  $$\text{LineTotal} = \text{Quantity} \times \text{UnitPriceMinorUnits}$$
  $$\text{NetPayable} = \sum \text{LineTotal} - \text{VerifiedDiscountMinorUnits} + \text{CalculatedTaxMinorUnits} + \text{ShippingMinorUnits}$$
- **Inventory & Balance Updates**: Always use atomic database increments with guard clauses (`UPDATE accounts SET balance_minor = balance_minor - $1 WHERE id = $2 AND balance_minor >= $1 RETURNING balance_minor`) or `SELECT ... FOR UPDATE` inside an ACID transaction to eliminate race conditions (TOCTOU).

---

## 3. ID, Token, OTP & Complex Generation Engines

Never use `Math.random()` for any backend identifier, token, or code. Always use OS-backed CSPRNG (`crypto.randomBytes`, `crypto.randomInt`, `crypto.subtle`).

| Generator Type | Use Case | Specification & Implementation Standard |
| :--- | :--- | :--- |
| **UUIDv7 / ULID** | Primary keys, database records | 48-bit Unix ms timestamp + 74–80 bits cryptographic randomness. Monotonically increasing for high-speed B-Tree inserts. |
| **Snowflake ID (64-bit)** | High-throughput distributed events/messages | `1 bit unused + 41 bits timestamp + 10 bits machine/worker ID + 12 bits sequence` (4,096 IDs/ms/node). |
| **Prefix-Scoped API Keys** | Developer API keys, secret tokens | Format: `<env_prefix>_<random_base62>_<checksum>` (e.g., `sk_live_4f9a8b...`). Store **only** the SHA-256 / HMAC-SHA256 hash in the DB alongside a 4-char display prefix (`sk_live_...9x2a`). |
| **Numeric OTP** | SMS / Email verification | `crypto.randomInt(100000, 1000000)` (6 digits). Store HMAC-SHA256 hash in Redis/DB with strict TTL (3–5 mins), max 3–5 verification attempts, and constant-time comparison (`crypto.timingSafeEqual`). |
| **TOTP / HOTP (RFC 6238)** | Authenticator Apps (2FA/MFA) | 160-bit Base32-encoded secret encrypted at rest; 30-second step window with $\pm 1$ window drift tolerance and replay cache for used codes. |
| **Human-Readable Reference Codes** | Order numbers, booking refs, invite codes | Custom Crockford Base32 alphabet (`23456789ABCDEFGHJKLMNPQRSTUVWXYZ` — excludes `0, O, 1, I, L` to prevent visual ambiguity) + Luhn mod N check character (e.g., `ORD-2026-8K4M9P-7`). |
| **Opaque Session / Refresh Tokens** | Auth sessions, password resets | 32 bytes (256 bits) from `crypto.randomBytes(32).toString('base64url')`. Hash with SHA-256 before database storage. |

---

## 4. Timestamp, Date & Temporal Architecture

1. **Universal Storage Rule**: Store all points in time in **UTC** (`TIMESTAMPTZ` in PostgreSQL, Unix epoch milliseconds/nanoseconds in Redis/events). Never store local server time.
2. **Wire Format**: Always serialize timestamps in **ISO-8601 UTC** (`2026-11-05T16:26:45.123Z`).
3. **Wall-Clock & Recurring Events**: For future calendar events, bookings, or billing cycles affected by Daylight Saving Time (DST), store **both** the UTC timestamp AND the IANA timezone identifier (`America/New_York`, `Asia/Kolkata`) + local wall time.
4. **Monotonic Clocks for Duration**: Never use `Date.now()` to measure elapsed time or timeouts (vulnerable to NTP clock skew/leap seconds). Use monotonic clocks (`process.hrtime.bigint()` or `performance.now()`).
5. **Standard Temporal Columns**:
   - `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
   - `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
   - `deleted_at TIMESTAMPTZ NULL` (for soft deletes with partial unique indexes: `CREATE UNIQUE INDEX ... WHERE deleted_at IS NULL`)
   - `version INT NOT NULL DEFAULT 1` (for optimistic concurrency control)

---

## 5. Authentication, Authenticated Authorization & Fingerprinting

### Authentication
- **Password Hashing**: Argon2id (`memoryCost >= 64MB`, `timeCost >= 3`, `parallelism >= 4`) or bcrypt (`cost >= 12`). Never use plain SHA/MD5.
- **Token Architecture**:
  - **Short-Lived Access Token**: 5–15 minute TTL (stateless JWT signed with asymmetric `EdDSA`/`RS256` or PASETO v4, with strict `iss`, `aud`, `exp`, `nbf`, `sub`, `jti` validation).
  - **Rotating Refresh Token**: 7–30 day TTL stored in `HttpOnly; Secure; SameSite=Strict` cookie. Implement **Refresh Token Rotation with Reuse Detection**: every refresh issues a new token in the same `token_family_id`. If an already-rotated token is presented again, immediately revoke the entire token family.
- **MFA / Step-Up Auth**: Require fresh authentication (`amr` claim + timestamp < 5 mins) for sensitive mutations (changing password, adding payout bank account, deleting organization, exporting PII).

### Authenticated Authorization (Never Trust Authentication Alone)
Authentication proves *who* the caller is; Authorization proves *what* they are allowed to touch on *this specific resource*.
- **BOLA / IDOR Defense**: Every database query MUST scope by tenant/owner (`WHERE id = $1 AND organization_id = $2`). Never fetch by `id` alone.
- **Multi-Layer Access Control**:
  1. **RBAC (Role-Based)**: Coarse-grained roles (`owner`, `admin`, `billing_manager`, `member`, `viewer`) mapped to atomic permissions (`invoice:create`, `invoice:refund`, `user:remove`).
  2. **ABAC (Attribute-Based)**: Policy evaluation over subject, resource, action, and environment attributes (e.g., `user.clearance >= resource.classification && request.country === 'US' && !resource.isLocked`).
  3. **ReBAC (Relationship-Based / Zanzibar model)**: Graph-based ownership and inheritance (`user:alice` is `editor` of `folder:eng` which is `parent` of `doc:spec`).

### Request & Device Fingerprinting
Bind sessions and tokens to contextual fingerprints to detect session hijacking, credential stuffing, and bot scraping:
- **Device & Transport Signals**: Combine normalized `User-Agent`, Client Hints (`Sec-CH-UA`, `Sec-CH-UA-Platform`), TLS/JA3/JA4 fingerprint (from reverse proxy headers), Autonomous System Number (ASN), IP `/24` prefix (IPv4) or `/48` prefix (IPv6), Accept-Language, and client hardware/canvas hash into a risk score.
- **Token Binding**: Store a SHA-256 hash of a random device-binding cookie (`__Host-fp`) inside the JWT `cnf` claim. If the JWT is stolen via XSS/logs, an attacker cannot use it without the `HttpOnly` `__Host-fp` cookie.
- **Velocity & Anomaly Detection**: Trigger step-up MFA or session revocation on impossible travel (e.g., login from Tokyo 5 minutes after New York) or sudden ASN/device-fingerprint switches.

---

## 6. Databases & Polyglot Storage Management

Choose and orchestrate multiple databases according to data access patterns, ACID guarantees, and latency budgets:

| Engine Type | Technologies | When to Choose | Mandatory Engineering Practices |
| :--- | :--- | :--- | :--- |
| **Relational (RDBMS)** | **PostgreSQL**, **MySQL** | Structured schemas, financial ledgers, orders, inventory, user accounts, multi-row ACID transactions. | Enforce foreign keys, `CHECK` constraints, `SERIALIZABLE` or `REPEATABLE READ` isolation for financial flows, connection pooling (PgBouncer/Supavisor), and B-Tree/GIN/partial indexes. |
| **Document / Wide-Column NoSQL** | **MongoDB**, DynamoDB, Firestore | Polymorphic product catalogs, dynamic form schemas, high-ingest telemetry, CMS content trees. | Validate documents with strict schema validation, design indexes around exact query shapes, embed bounded 1:N subdocuments, reference unbounded 1:N collections. |
| **In-Memory Data Store** | **Redis**, Valkey | Sub-millisecond caching, distributed locks (Redlock), rate-limiting counters, session stores, pub/sub, BullMQ job queues. | Always set explicit TTLs, configure `maxmemory-policy` (`allkeys-lru` for cache, `noeviction` for queues), use Lua scripts for multi-step atomic operations. |
| **Object / Blob Storage** | **AWS S3**, **Google Cloud Storage**, Cloudflare R2 | User uploads, invoices, backups, static media, ML datasets. | Private buckets by default, short-lived Presigned URLs (5–15 min TTL), lifecycle policies, server-side encryption (SSE-KMS). |

### Multi-Database Consistency (Transactional Outbox Pattern)
Never dual-write directly to PostgreSQL and Redis/MongoDB/Kafka in the same request without coordination (if the second write fails, state diverges).
1. Write the domain mutation AND an `outbox_events` row inside the **same single PostgreSQL ACID transaction**.
2. An asynchronous Outbox Relay / CDC worker reads uncommitted outbox rows, publishes them to Redis/MongoDB/Message Queue, and marks them processed idempotently.

---

## 7. APIs, Third-Party Services, Payment Endpoints & Governance

### RESTful & GraphQL API Design
- **REST Conventions**: Resource-oriented plural nouns (`/api/v1/orders`, `/api/v1/orders/{orderId}/refunds`), semantic HTTP verbs (`GET` idempotent read, `POST` create/action, `PUT` full replace, `PATCH` partial update, `DELETE` remove), and RFC 9457 Problem Details for standardized error payloads (`type`, `title`, `status`, `detail`, `instance`, `requestId`, `errors[]`).
- **GraphQL Security**: Enforce query depth limiting (max depth 7–10), query complexity/cost analysis, persisted queries in production, DataLoader batching to eliminate $N+1$ database queries, and field-level authorization directives.
- **Cursor-Based Pagination**: Prefer keyset/cursor pagination (`?cursor=eyJpZCI6...&limit=25`) over `OFFSET` pagination (`OFFSET 100000` forces the DB to scan and discard 100,000 rows).

### API Versioning & OpenAPI / Swagger Governance
- **API Versioning**: Route all endpoints under explicit version namespaces (`/api/v1/...`, `/api/v2/...`) or date-based revision headers (`API-Version: 2026-11-01`). Never introduce breaking changes (removing fields, changing field types, tightening required inputs) to an active version; use the Expand-and-Contract pattern and emit `Deprecation` + `Sunset` HTTP headers for legacy mobile/web clients.
- **OpenAPI 3.1 / Swagger Generation**: Generate OpenAPI specs directly from code-first Zod/TypeBox schemas so runtime validation and interactive Swagger documentation can never drift out of sync.

### Payment Endpoints & Financial Implementations
1. **Idempotency Keys**: Require an `Idempotency-Key` header (UUIDv4/v7) on every payment, refund, payout, or transfer endpoint. Lock the key in Redis/DB (`SET idemp:{tenant}:{key} IN_PROGRESS NX EX 86400`), store the canonical request hash + response payload, and replay the exact response on network retries.
2. **Zero Raw PAN Handling (PCI-DSS)**: Never touch raw credit card numbers on your server. Use client-side tokenization (Stripe Elements / Checkout / PaymentIntents) and only process payment tokens/intents server-side.
3. **Signed Webhook Verification**: Never unlock goods or credit balances from a client-side redirect. Always wait for the payment gateway webhook (`payment_intent.succeeded`), verify the raw body cryptographic HMAC signature (`Stripe-Signature`) + timestamp tolerance (< 300s to block replay attacks), and deduplicate by `event.id` in a `processed_webhooks` table inside an ACID transaction.
4. **Double-Entry Ledger**: Record every financial movement as balanced debit and credit entries (`SUM(debits) == SUM(credits)`) in an append-only `ledger_entries` table. Never overwrite or `DELETE` historical financial rows—issue compensating reversal entries instead.

---

## 8. Scalability, Performance, Rate Limiting & Circuit Breakers

### Scalability & Caching
- **Stateless Horizontal Scaling**: Store zero local session or file state in application container memory so Load Balancers (ALB, Nginx, Envoy, Cloud Load Balancing) can route requests across $N$ auto-scaled replicas.
- **Multi-Tier Caching (Redis)**:
  - **Cache-Aside with Stampede Protection**: Use single-flight request coalescing or probabilistic early expiration (XFetch) so 10,000 concurrent requests on a cache miss don't hammer PostgreSQL simultaneously.
  - **Negative Caching**: Cache `NOT_FOUND` results briefly (30–60s TTL) to stop cache-penetration attacks against non-existent IDs.

### Rate Limiting & Throttling
Enforce multi-dimensional rate limits at both the Edge/Reverse Proxy and Application layers using atomic Redis Lua scripts:
- **Algorithms**:
  - **Token Bucket**: Allows controlled bursts up to bucket capacity while enforcing average refill rate.
  - **Sliding Window Log / Counter**: Prevents boundary-spike abuse at fixed minute edges.
- **Granular Tiers**:
  - Auth / OTP / Password Reset endpoints: **3–5 requests / 15 min** per IP + target account + device fingerprint.
  - Write / Mutation APIs: **60 requests / min** per authenticated user/tenant.
  - Read APIs: **300–1,000 requests / min** per API key/tenant.
- **Standard Response Headers**: Always return `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After` on HTTP `429 Too Many Requests`.

### Circuit Breakers & Bulkheads
Protect your backend from cascading failures when third-party services (payment gateways, SMS providers, external APIs) degrade:
- **State Machine**:
  - **CLOSED**: Requests flow normally with strict connection/read timeouts (e.g., 3,000ms). Track failure rate in a rolling window.
  - **OPEN**: When failure rate exceeds threshold (e.g., $> 50\%$ over 20 requests or 5 consecutive timeouts), trip the circuit **OPEN** for a cooldown window (e.g., 30s). Fail fast (< 1ms) or enqueue to a fallback queue without calling the dead dependency.
  - **HALF-OPEN**: After cooldown, allow a small number of probe requests (e.g., 3). If they succeed, transition to **CLOSED**; if any fails, immediately re-open.
- **Exponential Backoff with Full Jitter**: On transient network errors (`502`, `503`, `504`, `ECONNRESET`), retry with full jitter: $\text{sleep} = \text{random}(0, \min(\text{cap}, \text{base} \times 2^{\text{attempt}}))$.

---

## 9. Securing File Uploads, Multi-Storage & Malware Scanning

Allowing file uploads introduces Remote Code Execution (RCE), Path Traversal, XSS, SSRF, and Denial-of-Service risks. Enforce this mandatory 7-stage defense pipeline:

### Stage 1: Gatekeeper Validation
1. **Strict Extension Whitelisting**: Only permit an explicit allowlist per upload context (e.g., `['.jpg', '.jpeg', '.png', '.webp', '.pdf']`). **Never** use a blacklist—attackers bypass blacklists via `.phtml`, `.php5`, `.phar`, `.svg` (embedded JS), `.htaccess`, or double extensions (`shell.php.jpg`).
2. **MIME-Type & Magic Number Binary Verification**: Never trust the `Content-Type` header or filename extension. Inspect the **magic numbers** (first 16–64 bytes of the actual file buffer):
   - JPEG: `FF D8 FF`
   - PNG: `89 50 4E 47 0D 0A 1A 0A`
   - WebP: `52 49 46 46 ... 57 45 42 50`
   - PDF: `25 50 44 46 2D` (`%PDF-`)
   Reject immediately if magic bytes, MIME type, and whitelisted extension do not all match.
3. **Strict File Size Restrictions**: Enforce hard maximum byte limits at **both** the reverse proxy (`client_max_body_size 5M;` in Nginx / Cloud Armor) and stream parser (abort stream immediately if byte counter exceeds limit) to block 50GB disk-exhaustion DoS attacks. Also guard against **Zip Bombs / Image Decompression Bombs** (limit max pixel dimensions, e.g., $8192 \times 8192$).

### Stage 2: Storage & Execution Prevention
4. **Randomize File Names (UUIDv7)**: Discard the user's original filename for storage paths to defeat path traversal (`../../etc/passwd`), null-byte injection, and overwrite attacks. Generate a fresh UUIDv7 key: `uploads/{tenant_id}/{yyyy}/{mm}/{uuidv7}.{safe_ext}`. Store the sanitized display name only as database metadata.
5. **Store Outside the Web Root**: Never store uploaded files inside the application source tree or public static web root (`/public`, `/var/www/html`). Offload directly to isolated cloud object storage (**AWS S3, Google Cloud Storage, Cloudflare R2, Azure Blob**) or an isolated volume outside the web root.
6. **Disable Execution Permissions (`noexec`)**:
   - On local/attached disks: Mount the upload partition with `noexec,nosuid,nodev` OS flags and set file permissions to `0600` or `0640` (never `0755` or `+x`).
   - On HTTP delivery: Serve user files from a separate sandbox domain (`*.usercontent.example.com`) with headers:
     - `Content-Disposition: attachment; filename="safe.pdf"`
     - `X-Content-Type-Options: nosniff`
     - `Content-Security-Policy: default-src 'none'; sandbox`
   - Re-encode images (`sharp` / `libvips`) to strip EXIF GPS metadata and destroy polyglot payloads hidden in image comments/chunks.

### Stage 3: Multi-Storage Orchestration & Malware Scanning
7. **Quarantine-First Malware Scanning & Multi-Storage Router**:
   - **Quarantine Bucket**: Uploads land first in an unpublicized `quarantine-bucket` with status `PENDING_SCAN`.
   - **Malware Scanning Worker**: An async worker streams the quarantined object through **ClamAV (`clamd` instream scan)** + YARA signature rules + SHA-256 hash lookup against threat feeds.
   - **Promotion or Purge**:
     - If `CLEAN`: Move/copy to the primary production storage provider (and optionally replicate across multi-cloud targets: S3 primary + GCS/R2 replica) and mark database record `AVAILABLE`.
     - If `INFECTED`: Immediately delete from quarantine, write a high-severity security audit event, alert SOC, and block the uploader's fingerprint/account.

---

## 10. Asynchronous Job Queues & Background Workers

Never run heavy or external-IO-bound tasks inside the HTTP request-response cycle:
- **Architecture (BullMQ / Celery / Sidekiq / Cloud Tasks)**:
  1. HTTP API validates input, persists a `jobs` state record (`QUEUED`), pushes a minimal payload (`{ jobId, tenantId, traceId }`) to the queue, and immediately returns `202 Accepted` with a status polling URL or WebSocket channel.
  2. Dedicated **Worker Processes** pull jobs with bounded concurrency, update progress (`PROCESSING`), and write results (`COMPLETED` / `FAILED`).
- **Mandatory Queue Engineering Rules**:
  - **Idempotent Workers**: Workers will receive duplicate deliveries (`at-least-once` semantics). Guard every job with an idempotency state check.
  - **Dead-Letter Queues (DLQ)**: Configure max attempts (e.g., 5 attempts with exponential backoff). Failed jobs move to a DLQ for inspection and replay instead of blocking the queue or disappearing silently.
  - **Graceful Shutdown**: On `SIGTERM`, workers must stop accepting new jobs, finish in-flight jobs within the drain timeout, and close DB/Redis connections cleanly.

---

## 11. Observability & Monitoring (Logging, Metrics, Tracing)

Never rely on unstructured `console.log()` in production.

1. **Structured JSON Logging (Pino / Winston / Zap -> ELK / Datadog / Loki)**:
   - Every log entry must be valid single-line JSON containing: `timestamp` (ISO-8601 UTC), `level`, `service`, `env`, `version`, `trace_id`, `span_id`, `request_id`, `tenant_id`, `user_id`, `http.method`, `http.route`, `http.status_code`, `duration_ms`, and `message`.
   - **Automatic PII Redaction**: Configure logger redaction paths (`req.headers.authorization`, `req.headers.cookie`, `*.password`, `*.token`, `*.otp`, `*.creditCard`, `*.ssn`) so secrets never touch disk or log aggregators.
2. **Metrics (OpenTelemetry / Prometheus / Grafana)**:
   - **System Vitals**: CPU utilization, memory RSS/heap, event-loop lag, DB connection pool utilization, Redis memory.
   - **RED Method for APIs**: **R**ate (requests/sec), **E**rrors (4xx/5xx rate), **D**uration (histogram buckets for `p50`, `p95`, `p99` latency).
   - **Queue Metrics**: Queue depth, oldest job age, worker processing time, DLQ count.
3. **Distributed Tracing (OpenTelemetry / W3C Trace Context)**:
   - Propagate `traceparent` and `tracestate` headers across every HTTP call, database query, Redis command, and background queue job so a single request can be traced end-to-end across all services.

---

## 12. Automated Testing & DevOps / Deployment Pipelines

### Automated Testing Pyramid
1. **Unit Tests (Fast, Isolated)**: Test pure domain logic, pricing/tax calculations, state machines, ID/OTP generators, and validators in isolation with zero network/DB calls. Target 100% coverage on financial and security logic.
2. **Integration Tests (Real Infrastructure via Testcontainers)**: Spin up ephemeral PostgreSQL, Redis, and S3 (MinIO/LocalStack) containers. Verify API routes, SQL transactions, race-condition concurrency (`Promise.all` parallel debits), auth middleware, rate limiters, and file upload magic-byte gates against a real database.
3. **End-to-End (E2E) & Contract Tests**: Simulate complete multi-step user journeys (`Register -> Verify OTP -> Login -> Upload Document -> Create Order -> Process Payment Webhook -> Verify Ledger & Audit Log`) and validate OpenAPI contract compliance.

### DevOps, Containerization & Orchestration
- **Docker**: Multi-stage builds (`builder` -> minimal distroless/alpine runtime image), pinned image digests, non-root user (`USER node` / UID `10001`), read-only root filesystem where possible, and zero secrets baked into layers.
- **Kubernetes**: Define `/health/live` (liveness probe — process is up) and `/health/ready` (readiness probe — DB & Redis connections healthy), CPU/Memory `requests` and `limits`, `HorizontalPodAutoscaler` (HPA), `PodDisruptionBudget` (PDB), and `NetworkPolicy` zero-trust pod-to-pod rules.
- **Git & CI/CD Pipeline**: Automated pipeline on every PR: `Lint & Typecheck -> Secret & SAST Scan -> Unit Tests -> Integration Tests -> OpenAPI Breaking-Change Check -> Build & Sign Container Image -> Trivy CVE Scan -> Zero-Downtime Rolling/Canary Deploy + Expand/Contract DB Migration`.
