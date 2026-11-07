# High-Security Backend Skill Expansion: Omnichannel Messaging, BaaS Providers & Interactive I/O Flow Visualizer

This plan expands the **Advanced Backend Development Skill** with three major capabilities:
1. **Penetration-Hardened Omnichannel Notification, Email & Messaging (`Module 10`)** (incorporating all 7 security and failover vulnerability fixes).
2. **Complete BaaS (Backend-as-a-Service) Provider Architecture & Security Hardening (`Module 11`)** covering **Supabase, Firebase, Appwrite, Convex, AWS Amplify, and PocketBase** with zero-trust rules, key isolation, and hexagonal anti-lock-in adapters.
3. **Incoming/Outgoing Request I/O, Service Topology & Correlated Log Telemetry (`Module 12` + Interactive Visualizer)** providing both the backend observability specification and an interactive **Backend I/O & Service Flow Visualizer with Live Structured Logs** alongside the Skill Specification Reader.

### User Review & Critical Decisions

> [!IMPORTANT]
> This revised plan incorporates your request for complete BaaS provider implementations (Supabase, Firebase, and more) and an interactive Incoming/Outgoing Request Data & Service Log Visualizer, while preserving all 7 security vulnerability fixes from the previous revision.

- **Confirmed Decision 1 — Omnichannel Notification, Email & Messaging (`Module 10`)**: Covers Email (SES, Postmark, SendGrid), SMS/WhatsApp/OTP (Twilio, Vonage), Push (FCM v1, APNs `.p8`, WebPush VAPID), In-App (SSE/WebSocket), and Chat Webhooks, hardened with Definitive-vs-Ambiguous failover classification, Transport-Suppression vs. Preference separation with Cross-Channel Fallback, Keyed `HMAC-SHA256` suppression hashes, SMS Toll-Fraud & Country-Prefix Cost-Cap guards, and scanner-safe OTP/magic-link delivery.
- **Confirmed Decision 2 — Complete BaaS Provider Architecture (`Module 11`)**:
  - **Supabase**: Strict separation of `anon` vs. `service_role` keys, PostgreSQL Row-Level Security (`auth.uid()`, `auth.jwt() -> 'app_metadata'`, never trusting user-mutable `user_metadata` for roles!), PostgREST schema lockdown, `SECURITY DEFINER` `search_path` hardening, Edge Functions, and Storage bucket RLS.
  - **Firebase**: The Eight Pillars of Hardened Firestore Rules (`rules_version = '2'`, default-deny catch-all, Master Gate parent `get()`, `isValid[Entity]` blueprints with `hasAll`/`hasOnly` and `affectedKeys().hasOnly()`, `isValidId` path variable guards, Split Collection PII isolation, `existsAfter` atomicity, and Query Enforcer `allow list`), Firebase App Check, Admin SDK server routes, and structured `FirestoreErrorInfo` diagnostics.
  - **Multi-BaaS & Hexagonal Portability**: Covers Appwrite, Convex, AWS Amplify, and PocketBase behind clean Repository/Adapter interfaces so BaaS providers can be combined with custom backend workers or swapped without rewriting business logic.
- **Confirmed Decision 3 — Incoming/Outgoing I/O & Log Flow Visualization (`Module 12` + Interactive Console)**: Adds a dual-mode workspace where engineers can switch between the **Skill Specification Reader** (all markdown modules) and the **Interactive I/O & Service Flow Visualizer** to inspect incoming request payloads, middleware security gates, BaaS/DB/Queue/Outbound service calls, outgoing response data, and correlated structured JSON logs (`trace_id`, `span_id`, PII redaction, per-hop latency).

---

### 1. Overview & Core Concept

- **What It Does**: Delivers a complete, zero-loss backend engineering skill covering custom backends, BaaS platforms (Supabase, Firebase, Convex, Appwrite, Amplify), and omnichannel messaging, paired with an interactive I/O trace and log visualizer that demonstrates how incoming requests, internal security gates, outgoing service calls, and structured JSON logs flow through a hardened backend.
- **Target Audience / Persona**: Backend engineers, security architects, and AI coding agents designing custom, BaaS-backed, or hybrid backend systems who need both copy-ready architectural specifications and real-time visibility into request/response data and log telemetry.
- **Key Value**: Bridges the gap between BaaS speed and enterprise backend security while providing transparent visual inspection of every incoming byte, internal service hop, outgoing third-party payload, and structured log entry.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Mode 1 — Skill Specification Reader & Exporter**: Browse, search, and copy the master `SKILL.md` constitution and all reference modules (`00` through `12`), including the new Omnichannel Messaging, BaaS Provider Engineering, and I/O Telemetry specifications.
  2. **Mode 2 — Interactive Backend I/O, Service Flow & Log Visualizer**:
     - **Scenario & Payload Selector**: Select from realistic backend scenarios (*1. Omnichannel OTP & Email Failover*, *2. Supabase RLS + Edge Function Checkout*, *3. Firebase 8-Pillar Firestore Write & Admin Webhook*, *4. Streaming File Upload & ClamAV Quarantine Scan*, *5. Adversarial Penetration Attack Blocked: SSRF / JWT Forgery / SMS Pumping*) or edit the live incoming request JSON/headers.
     - **Pipeline & Service Node Graph**: Step through or run the request across each backend hop (`Client Ingress -> Security & RBA Gate -> BaaS / Primary DB -> Committed Outbox & Queue -> Outgoing External Service -> Client Response`). Clicking any service node reveals its exact **Incoming Input Payload**, **Applied Security Rules/Queries**, and **Outgoing Output Payload**.
     - **Correlated Structured Log Stream**: Inspect the synchronized JSON log stream (`timestamp`, `level`, `service`, `trace_id`, `span_id`, `duration_ms`, automatic `[REDACTED]` secrets/PII, and status codes) with live filtering by log level (`INFO`, `WARN`, `ERROR`, `SECURITY_AUDIT`) and service hop.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: High-precision developer console and architectural specification workspace following the SaaS & Developer Console design guidelines (`single-elevation depth`, `1px solid` hairline borders, zero nested card clutter, zero decorative pulsing dots).
  - *Color Palette & Mood*: Deep slate/obsidian canvas (`#0A0D14` / `bg-slate-950`), elevated structural panels (`bg-slate-900`), crisp hairline dividers (`border-slate-800`), alabaster primary typography (`text-slate-100`), and semantic status indicators paired with explicit text labels (`NOMINAL / 200 OK` in emerald `#16A34A`, `FAILOVER / WARN` in amber `#D97706`, `BLOCKED / 403` in crimson `#DC2626`).
  - *Typography & Hierarchy*: `Plus Jakarta Sans` for structural headers and navigation, paired with `JetBrains Mono` (`font-mono tabular-nums`) for all I/O payloads, latency breakdowns, SQL/Firestore rules, and structured JSON logs.
  - *Layout Structure*: Clean 3-zone Top Bar Contract (Brand wordmark on the left, single-line view navigation links in the center, and a primary action button on the right) above a full-width 1440px split workspace canvas.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1 — BaaS Security: Never Trust Client-Mutable Metadata or Unbounded Client Queries**
  - *Chosen Approach*:
    - In **Supabase**, RLS policies must never check `auth.jwt() -> 'user_metadata'` (which any authenticated user can overwrite via `supabase.auth.updateUser()`); roles and tenant IDs must live in `app_metadata` (server-only) or a protected database table, and `service_role` keys are restricted strictly to backend environments.
    - In **Firebase**, enforce the Eight Pillars of Firestore Rules (`rules_version = '2'`, `isValid[Entity]` schema/size guards, `affectedKeys().hasOnly()` action branches, `allow list` resource filters, and server-timestamp enforcement `request.time`).
  - *Why*: The #1 cause of BaaS data breaches in penetration tests is misconfigured client-accessible tables/collections where developers confuse client-editable user metadata with server-controlled roles or allow blanket `isSignedIn()` list reads.
- **Decision 2 — Hybrid BaaS + Custom Backend Escape Hatch (Hexagonal Port/Adapter)**
  - *Chosen Approach*: Use BaaS directly for low-risk CRUD and real-time subscriptions guarded by RLS/Firestore Rules, but route multi-step financial mutations, third-party secret API calls, and omnichannel messaging through server-side API routes / Edge Functions using a provider-agnostic Repository interface.
  - *Why*: Prevents vendor lock-in and ensures complex invariants (double-entry ledgers, SMS cost caps, multi-provider failover) execute in a trusted server environment.
- **Decision 3 — Unified W3C Trace-Correlated I/O & Log Envelope**
  - *Chosen Approach*: Every incoming request generates or propagates a W3C `traceparent` (`trace_id` + parent `span_id`), and every internal hop (Auth, DB/BaaS, Outbox, Queue Worker, External Provider) records a structured span with sanitized `input_summary`, `output_summary`, `duration_ms`, and correlated JSON log lines.
  - *Why*: Allows engineers to trace a single user request from the initial HTTP ingress all the way through BaaS mutations, background queue workers, and outgoing email/SMS gateway webhooks in one unified timeline.

---

### 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                       TOP BAR CONTRACT (Brand · Nav Links · Action)                     │
└────────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │
         ┌───────────────────────────────────┴───────────────────────────────────┐
         ▼ (View 1: Interactive I/O & Log Visualizer)                            ▼ (View 2: Skill Spec Reader)
┌─────────────────────────────────────────────────────────┐     ┌─────────────────────────────────────────┐
│      SCENARIO & INCOMING REQUEST PAYLOAD INSPECTOR      │     │     SKILL.md + MODULES 00..12 VIEWER    │
│  • Select Flow: Messaging / Supabase / Firebase / PenTest│     │  • 00..09 Core & Security Modules       │
│  • Edit Request Headers, Auth Claims & JSON Body        │     │  • 10 Omnichannel Notification/Email/SMS│
└────────────────────────────┬────────────────────────────┘     │  • 11 BaaS Providers (Supabase/Firebase)│
                             │                                  │  • 12 I/O & Service Log Telemetry       │
                             ▼                                  └─────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│        SERVICE-TO-SERVICE PIPELINE TOPOLOGY GRAPH       │
│  [1. API Ingress & Sanitizer] ──► [2. AuthN/AuthZ/RBA]  │
│               │                            │            │
│               ▼                            ▼            │
│  [3. BaaS (Supabase RLS / Firestore) or Primary Postgres]│
│               │                                         │
│               ▼                                         │
│  [4. Committed Outbox & Priority Queue (P0/P1/P2)]      │
│               │                                         │
│               ▼                                         │
│  [5. Outgoing Service Router (SES/Twilio/FCM/Stripe)]   │
└───────────────┬────────────────────────────┬────────────┘
                │                            │
                ▼                            ▼
┌──────────────────────────────┐ ┌────────────────────────────────────────────────────────┐
│ NODE INPUT / OUTPUT PAYLOADS │ │ CORRELATED STRUCTURED JSON LOG STREAM (`trace_id`)     │
│ • Hop Input Data (Redacted)  │ │ • Filter by Level (INFO / WARN / ERROR / SECURITY)     │
│ • Security Policy Evaluated  │ │ • Filter by Service Hop (Ingress / BaaS / Worker / Out)│
│ • Hop Output & Status Code   │ │ • Inspect JSON Log Fields, Spans & Latency Breakdown   │
└──────────────────────────────┘ └────────────────────────────────────────────────────────┘
```

- **Data Model & State**:
  - **Module 10 (`10-omnichannel-notifications-email-messaging-security.md`)**: Complete schemas and TypeScript engines for Email, SMS/WhatsApp/OTP, Push, In-App, and Chat delivery with Definitive-vs-Ambiguous failover, HMAC suppression lists, and SMS toll-fraud cost caps.
  - **Module 11 (`11-baas-providers-supabase-firebase-amplified-security.md`)**: Complete architecture and security patterns for **Supabase** (SQL RLS policies using `auth.jwt() -> 'app_metadata'`, PostgREST schema lockdown, `SECURITY DEFINER` hardening, Storage RLS, Edge Functions), **Firebase** (8-Pillar `firestore.rules` template, `firebase-blueprint.json` IR synchronization, `handleFirestoreError` structured diagnostics, App Check, Admin SDK verification), **Appwrite, Convex, AWS Amplify, PocketBase**, and Hexagonal Repository adapters.
  - **Module 12 (`12-request-io-tracing-service-visualization-and-log-correlation.md`)**: Specification for capturing, redacting, correlating, and visualizing incoming request payloads, service-to-service hop envelopes, outgoing third-party requests/responses, and W3C `traceparent` structured JSON logs.
  - **Interactive I/O & Log Visualizer State**: Client-side interactive state machine driving scenario selection, live request payload editing, step-by-step hop selection, input/output diff inspection, and multi-criteria log filtering.
