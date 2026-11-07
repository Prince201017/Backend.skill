---
name: advanced-backend-engineering-and-security-v2
description: Production-grade, security-first TypeScript backend engineering standard covering evidence-based architecture selection, tenant transaction isolation, ReBAC/RBAC authorization, fenced idempotency, persistent webhook deduplication, pinned DNS SSRF defense, quarantine-first file uploads, durable queues/sagas, Maker-Checker financial controls, BaaS security rules, and 33-category adversarial verification.
---

# Advanced Backend Engineering & Security Skill (V2 Remediated Standard)

## 1. Purpose & Non-Negotiable Engineering Rules

This master specification and its 16 modular reference files (`00`–`15`) define a security-first, technically verifiable TypeScript backend engineering standard. Every pattern, code implementation, and verification test across this library obeys these non-negotiable rules:

1. **Zero Trust for Client-Supplied Claims**: Never treat client-provided tenant IDs, user IDs, roles, boolean flags (`isAdmin`, `dualApprovalConfirmed`, `gatewayOidcVerified`), headers, or resource ownership claims as proof of authorization.
2. **Explicit Trust Boundaries & Failure Modes**: Every security control identifies its trust boundary, threat model, enforcement location, and deterministic failure behavior.
3. **Authenticate & Authorize Before Establishing Database Context**: In multi-tenant PostgreSQL architectures (`withTenantTransaction`), never populate `app.current_tenant_id` or `app.current_user_id` before verifying the caller's cryptographic identity, active tenant status, active membership status (`status = 'ACTIVE'`), and required action permission inside the transaction.
4. **ReBAC Ownership != Administrative Authority**: Resource ownership (`owner` of an order, file, or project) grants only explicitly mapped owner actions (e.g., viewing or cancelling one's own draft) and NEVER bypasses administrative or financial permission checks (`order:refund`, `ledger:export`, `member:invite`, or marking a BaaS project `'COMPLETED'`).
5. **Fenced Idempotency & Reconciliation over Blind Retry**: Mutating operations and payments enforce leased idempotency keys with `lockOwnerToken`, monotonic `fencingToken`, periodic lease renewal, conditional completion, and transition to `UNKNOWN_RECONCILIATION_REQUIRED` when a provider fails ambiguously after request transmission.
6. **Evidence-Based Architecture Selection**: Default to a **PostgreSQL-First Modular Monolith**. Introduce Redis, Meilisearch/OpenSearch, Kafka, Dedicated Vector DBs, or Kubernetes only when quantitative workload triggers are met.
7. **Honest Verification Reporting**: Never claim a system is production-ready or that tests passed unless verified; distinguish executed in-process Node.js tests (`node:test`) from external-daemon integration tests (live PostgreSQL, ClamAV, Firebase Emulator).

---

## 2. Master Module Index & Security Mapping (`00`–`15`)

| Module File | Core Architectural & Security Scope | Key Remediated Implementations |
| :--- | :--- | :--- |
| **`00-execution-intelligence-architecture-engine.md`** | Evidence-driven architecture selection, PostgreSQL-first defaults, failure modes, and DR targets vs. verified capabilities. | `selectBackendArchitecture()`, `evaluateDisasterRecoveryReadiness()` |
| **`01-domain-modeling-fields-timestamps-ids.md`** | `ReadonlyMap` ISO-4217 currency math, PG `BIGINT` bounds, configurable tax rounding, mandatory-expiry atomic OTP consumption, and double-entry ledger locking. | `CURRENCY_EXPONENTS_MAP`, `allocateMinorUnitsDeterministic()`, `verifyAndConsumeOtpAtomically()`, `persistBalancedJournalAtomically()` |
| **`02-auth-authorization-fingerprinting-security.md`** | Trusted-store RBAC + ReBAC authorization (`CRITICAL 2.B`), refresh token reuse detection with absolute session expiry + device binding, and cryptographic API Gateway OIDC verification. | `authorizeActionFromTrustedStore()`, `rotateRefreshTokenWithReuseDetection()`, `extractVerifiedApiGatewayUserInfo()` |
| **`03-databases-polyglot-storage-transactions.md`** | Single-transaction transactional outbox/inbox consumer (`TransactionalDbClient`) and post-hit authorized single-flight Redis cache (`USER_PRIVATE` vs `TENANT_SHARED`). | `consumeEventIdempotently()`, `getOrComputeAuthorizedCachedSingleFlight()` |
| **`04-apis-payments-webhooks-resilience.md`** | Fenced idempotency locks with lease renewal & reconciliation (`CRITICAL 2.C`) and persistent, monotonic webhook deduplication (`CRITICAL 2.D`). | `executeWithIdempotencyLock()`, `reconcileAmbiguousPayment()`, `verifyAndProcessWebhookIdempotently()` |
| **`05-file-uploads-multi-storage-malware-scanning.md`** | Quarantine-first streaming uploads (`CRITICAL 2.F`), magic-byte/dimension validation, mandatory CDR re-encoding, SHA-256 + version-pinned promotion, and download gate. | `StreamingMultiStorageOrchestrator`, `validateMagicBytesAndDimensions()`, `authorizeApprovedFileDownload()` |
| **`06-async-queues-observability-testing-devops.md`** | Queue worker `next_run_at <= clock_timestamp()` + `attempt < max_attempts` lease acquisition, expired-lease completion fencing, and comprehensive log secret redaction. | `PG_ACQUIRE_JOB_LEASE_SQL`, `executeQueueWorkerJob()`, `redactSensitiveFields()` |
| **`07-events-realtime-sagas-migrations-sql-multitenancy-search.md`** | Durable persistent saga state machine (`DurableSagaStateStore`) with crash recovery, reverse compensation, `RECONCILIATION_REQUIRED` state, and Expand-and-Contract SQL migrations. | `runOrResumeDurableSaga()` |
| **`08-api-security-secrets-dr-networking-microservices-ai-governance.md`** | Pinned DNS + `https.request` SSRF defense (`CRITICAL 2.E`, replacing broken `fetch` `agent` pattern), hop-by-hop redirect validation, and CIDR-verified `X-Forwarded-For` IP extraction. | `resolveAndPinSafeTarget()`, `executePinnedSafeHttpsRequest()`, `extractTrustedClientIpByCidr()` |
| **`09-adversarial-security-audit-and-verification-harness.md`** | Complete V2 Repository Audit, Risk Register (`CRIT-01`..`CRIT-07`, `HIGH-01`..`HIGH-12`), 33-Category Security Test Matrix (`TEST-01`..`TEST-33`), and verification reports. | 33-Category Adversarial Test Matrix & Live PostgreSQL RLS DDL |
| **`10-omnichannel-notifications-email-messaging-security.md`** | Atomic 3-phase SMS budget reservation (`Reserve -> Commit / Release`), recipient consent/verification enforcement, `ACCEPTED_BY_PROVIDER` vs `DELIVERED`, and `502`/`503`/`504` ambiguity handling. | `dispatchSmsWithBudgetAndFailover()`, `classifyNotificationProviderFailure()` |
| **`11-baas-providers-supabase-firebase-amplified-security.md`** | Multi-tenant Firestore & Supabase RLS security rules verifying active tenant membership (`status == 'ACTIVE'`) and blocking client-driven `'COMPLETED'` state transitions. | `firestore.rules`, `evaluateFirestoreProjectRule()`, Supabase RLS Policies |
| **`12-request-io-tracing-service-visualization-and-log-correlation.md`** | Immutable `AsyncLocalStorage` child span propagation, expanded secret redaction, and hard 32 KB (`32_768` bytes) full trace envelope enforcement. | `runInRootTraceContext()`, `executeTracedHop()`, `exportCorrelatedTraceEnvelope()` |
| **`13-critical-risk-audit-reliability-and-production-readiness.md`** | Post-authorization `withTenantTransaction()` (`CRITICAL 2.A`), unanchored frontend bundle/source-map/env secret scanner, and 9-step coordinated graceful shutdown. | `withTenantTransaction()`, `scanReleaseArtifactsAndEnvForSecrets()`, `executeCoordinatedGracefulShutdown()` |
| **`14-api-gateway-mcp-quotas-and-business-logic-engine.md`** | Server-verified Maker-Checker approval with canonical SHA-256 payload binding & atomic balance deduction (`CRITICAL 2.G`), OpenAPI all-alternatives auditor, and runtime MCP tool guard. | `approvePendingFinancialOperation()`, `executeVerifiedBusinessApprovalAndReservation()`, `auditOpenApiSecurityAlternatives()`, `executeMcpToolWithRuntimeAuthz()` |
| **`15-security-hardening-checklist-and-markdown-parser.md`** | Deterministic Markdown specification parser extracting security checklist controls and scanning for forbidden documentation anti-patterns. | `parseMarkdownSecurityChecklist()` |

---

## 3. Canonical Quick-Reference Architecture & Security Rules

### 3.1 Multi-Tenant Database Isolation (`Module 13`)
- **Never** execute `SET app.current_tenant_id` (session-scoped) on a pooled connection.
- **Never** execute `SELECT set_config('app.current_tenant_id', $1, true)` before verifying the caller's server-side identity, active tenant status (`ACTIVE`), active membership status (`ACTIVE`), and role permission inside `withTenantTransaction()`.
- Always write PostgreSQL RLS policies using `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid` so missing context fails closed (`NULL`).

### 3.2 Authorization & ReBAC (`Module 02`)
- Resolve all subject roles, membership states, resource attributes, and ReBAC relationships from `AuthorizationFactStore` on the server.
- Evaluate RBAC (`ROLE_PERMISSIONS`) and ReBAC (`REBAC_ACTION_POLICY`) through explicit, separate policy tables so an `owner` of an order or document can never authorize `order:refund`, `ledger:export`, or `member:invite`.

### 3.3 Idempotency, Payments & Webhooks (`Module 04` & `Module 14`)
- Every mutating payment/financial endpoint requires a leased idempotency lock with `lockOwnerToken` and monotonic `fencingToken`.
- If a downstream payment or SMS provider fails after request bytes were written (`502`, `504`, post-write `503`, `ETIMEDOUT`), transition the record to `UNKNOWN_RECONCILIATION_REQUIRED` (`AMBIGUOUS_POST_WRITE`) and reconcile before retrying.
- Every high-value financial operation requires Maker-Checker approval bound to `computeCanonicalOperationHash(operation)` with `makerUserId !== checkerUserId` and atomic database balance reservation.

### 3.4 Outbound Network & File Upload Defense (`Module 05` & `Module 08`)
- Never pass `https.Agent` to Node's built-in `fetch()` (Undici ignores it). Use `executePinnedSafeHttpsRequest()` (`node:https` `https.request` with custom `lookup` pinning validated public DNS A/AAAA records and re-validating every redirect hop).
- Stream all uploads to an isolated quarantine bucket first, validate extension + MIME + magic bytes + image dimensions independently, pass through mandatory CDR (`createMandatorySanitizerTransform`), scan for malware, and verify `quarantineVersionId` + `sha256Checksum` while promoting to the approved bucket.
