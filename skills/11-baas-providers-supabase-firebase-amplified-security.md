# Module 11: BaaS (Backend-as-a-Service) Providers — Supabase, Firebase, Convex, Appwrite, Amplify & Anti-Lock-In Architecture

This reference provides the complete, penetration-hardened implementation guide for building with or integrating **Backend-as-a-Service (BaaS)** providers (**Supabase, Firebase, Convex, Appwrite, AWS Amplify, PocketBase**) while maintaining enterprise zero-trust security, preventing client-side privilege escalation, and preserving architectural portability.

---

## 1. BaaS Selection & Trust-Boundary Matrix

| BaaS Platform | Core Storage Engine | Auth & Security Enforcement | When to Choose | Critical Penetration Pitfall to Prevent |
| :--- | :--- | :--- | :--- | :--- |
| **Supabase** | PostgreSQL + PostgREST + GoTrue + Realtime + Storage | PostgreSQL Row-Level Security (`RLS`) + JWT claims | Relational schemas, SQL joins, `pgvector`, full ACID transactions, instant REST/GraphQL APIs. | Checking `auth.jwt() -> 'user_metadata'` in RLS (clients can self-edit `user_metadata`!), exposing `service_role` key to browser, or leaving tables in `public` without `ENABLE ROW LEVEL SECURITY`. |
| **Firebase** | Cloud Firestore (Document NoSQL) + Firebase Auth + Cloud Storage | `firestore.rules` (`rules_version = '2'`) + App Check + Admin SDK | Real-time mobile/web sync, offline-first client caches, rapid document prototyping. | Writing `allow read: if request.auth != null;` on PII collections, omitting `affectedKeys().hasOnly()` on updates, or trusting `request.auth.token.email` without `email_verified == true`. |
| **Convex** | Reactive Relational-Document Transactional Store | Server-only TypeScript `query`, `mutation`, `action` functions + Zod | End-to-end TypeScript reactivity where clients never write raw DB queries directly. | Exposing internal admin mutations as public `mutation` instead of `internalMutation`. |
| **Appwrite / PocketBase** | MariaDB / SQLite + Collection Permissions + Storage | Document/Collection permission strings + Server API keys | Self-hosted or single-binary BaaS deployments. | Granting collection-level `read("any")` or `update("users")` instead of document-specific owner permissions. |
| **AWS Amplify** | DynamoDB + AppSync GraphQL + Cognito + S3 | `@auth` GraphQL directives + IAM roles + Cognito Groups | Deep AWS ecosystem integration with managed GraphQL subscriptions. | Overly permissive `@auth(rules: [{ allow: private }])` allowing any signed-in Cognito user to mutate another tenant's records. |

---

## 2. Supabase Security Hardening (PostgreSQL RLS, `app_metadata`, PostgREST & Edge Functions)

### The 5 Non-Negotiable Supabase Security Laws
1. **`anon` Key vs. `service_role` Key**:
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY` is safe for browsers **ONLY** if every single table in exposed schemas has `ENABLE ROW LEVEL SECURITY` enabled.
   - `SUPABASE_SERVICE_ROLE_KEY` bypasses all RLS completely and MUST only exist in backend server environments (never prefixed with `NEXT_PUBLIC_` or `VITE_`).
2. **Never Trust `user_metadata` in RLS Policies (Privilege Escalation Vector)**:
   - Any authenticated user can call `supabase.auth.updateUser({ data: { role: 'admin', tenant_id: 'victim-tenant' } })` from the browser devtools, which mutates `raw_user_meta_data` (`auth.jwt() -> 'user_metadata'`).
   - **Mandatory Rule**: Store authorization roles and `tenant_id` in **`raw_app_meta_data` (`auth.jwt() -> 'app_metadata'`)** (which can only be modified by `service_role` on the backend) or look them up in a protected `organization_members` table!
3. **`SECURITY DEFINER` Function Hardening**:
   - Any PostgreSQL function marked `SECURITY DEFINER` executes with the privileges of the function creator. Always explicitly pin `SET search_path = public, pg_temp;` to prevent schema-shadowing privilege escalation, and revoke `EXECUTE` from `PUBLIC` / `anon` if the function is internal.
4. **Performance Optimization in Supabase RLS**:
   - Wrap `auth.uid()` and `auth.jwt()` in an `(SELECT auth.uid())` scalar subquery (`user_id = (SELECT auth.uid())`) so PostgreSQL caches the result as an `InitPlan` once per query rather than re-evaluating the function on every single row scan!

```sql
-- Hardened Supabase Multi-Tenant Schema & RLS Policy Blueprint
CREATE TABLE public.projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL CHECK (char_length(trim(name)) >= 2),
    budget_minor BIGINT NOT NULL DEFAULT 0 CHECK (budget_minor >= 0),
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Enable and force Row-Level Security
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects FORCE ROW LEVEL SECURITY;

-- Helper function reading ONLY server-controlled app_metadata (NEVER user_metadata!)
CREATE OR REPLACE FUNCTION public.current_jwt_tenant_id()
RETURNS UUID
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
  SELECT NULLIF(
    ((SELECT auth.jwt()) -> 'app_metadata' ->> 'tenant_id'),
    ''
  )::uuid;
$$;

-- SELECT Policy: Cached InitPlan evaluation of auth.uid() and app_metadata.tenant_id
CREATE POLICY projects_select_policy ON public.projects
    FOR SELECT
    TO authenticated
    USING (
        tenant_id = (SELECT public.current_jwt_tenant_id())
    );

-- INSERT Policy: Prevent cross-tenant or cross-owner spoofing on creation
CREATE POLICY projects_insert_policy ON public.projects
    FOR INSERT
    TO authenticated
    WITH CHECK (
        tenant_id = (SELECT public.current_jwt_tenant_id())
        AND owner_id = (SELECT auth.uid())
        AND is_locked = FALSE
    );

-- UPDATE Policy: Prevent changing immutable owner_id or tenant_id, and block updates when locked
CREATE POLICY projects_update_policy ON public.projects
    FOR UPDATE
    TO authenticated
    USING (
        tenant_id = (SELECT public.current_jwt_tenant_id())
        AND owner_id = (SELECT auth.uid())
        AND is_locked = FALSE
    )
    WITH CHECK (
        tenant_id = (SELECT public.current_jwt_tenant_id())
        AND owner_id = (SELECT auth.uid())
    );

-- DELETE Policy: Explicitly restrict deletion to unlocked rows owned by the caller in the active tenant
CREATE POLICY projects_delete_policy ON public.projects
    FOR DELETE
    TO authenticated
    USING (
        tenant_id = (SELECT public.current_jwt_tenant_id())
        AND owner_id = (SELECT auth.uid())
        AND is_locked = FALSE
    );
```

---

## 3. Firebase Security Hardening (The 8-Pillar `firestore.rules` Fortress & Admin SDK)

When using Firebase (Firestore + Firebase Auth), client SDKs talk directly to Firestore. Your `firestore.rules` file **is** your backend authorization and schema validation layer for client-direct operations.

### Hardened `firestore.rules` Reference Implementation
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Pillar 0: Default-Deny Global Catch-All
    match /{document=**} {
      allow read, write: if false;
    }

    // Core Reusable Primitives
    function isSignedIn() {
      return request.auth != null && request.auth.token.email_verified == true;
    }
    function isValidId(id) {
      return id is string && id.size() >= 1 && id.size() <= 128 && id.matches('^[a-zA-Z0-9_\\-]+$');
    }
    function incoming() {
      return request.resource.data;
    }
    function existing() {
      return resource.data;
    }
    function isAdmin() {
      return isSignedIn() && exists(/databases/$(database)/documents/admins/$(request.auth.uid));
    }

    // Pillar 6: Split-Collection PII Isolation (Public profile vs. Private PII vault)
    match /users/{userId} {
      function isValidPublicProfile(data) {
        return data.keys().hasAll(['displayName', 'createdAt', 'updatedAt'])
          && data.keys().hasOnly(['displayName', 'avatarUrl', 'createdAt', 'updatedAt'])
          && data.displayName is string && data.displayName.size() >= 2 && data.displayName.size() <= 80
          && (!('avatarUrl' in data) || (data.avatarUrl is string && data.avatarUrl.size() <= 500));
      }

      allow get: if isSignedIn() && isValidId(userId);
      allow list: if isSignedIn() && (request.auth.uid == userId || isAdmin());

      allow create: if isSignedIn()
        && isValidId(userId)
        && request.auth.uid == userId
        && isValidPublicProfile(incoming())
        && incoming().createdAt == request.time
        && incoming().updatedAt == request.time;

      allow update: if isSignedIn()
        && isValidId(userId)
        && request.auth.uid == userId
        && isValidPublicProfile(incoming())
        && incoming().createdAt == existing().createdAt
        && incoming().updatedAt == request.time
        && incoming().diff(existing()).affectedKeys().hasOnly(['displayName', 'avatarUrl', 'updatedAt']);

      allow delete: if false;

      // Strict Private PII Subcollection: Owner or Admin ONLY
      match /private/{docId} {
        allow get: if isSignedIn() && isValidId(userId) && isValidId(docId) && (request.auth.uid == userId || isAdmin());
        allow list, write: if false; // Mutated only via server-side Admin SDK after KYC/validation
      }
    }

    // Pillar 1, 2, 5, 6 & 8: Projects & Relational Subcollections
    match /projects/{projectId} {
      function isValidProject(data) {
        return data.keys().hasAll(['ownerId', 'name', 'status', 'createdAt', 'updatedAt'])
          && data.keys().hasOnly(['ownerId', 'name', 'status', 'createdAt', 'updatedAt'])
          && data.ownerId is string && isValidId(data.ownerId)
          && data.name is string && data.name.size() >= 2 && data.name.size() <= 120
          && data.status in ['DRAFT', 'ACTIVE', 'COMPLETED'];
      }

      allow get: if isSignedIn() && isValidId(projectId) && (existing().ownerId == request.auth.uid || isAdmin());
      // Pillar 8: Query Enforcer — never allow blanket list!
      allow list: if isSignedIn() && resource.data.ownerId == request.auth.uid;

      allow create: if isSignedIn()
        && isValidId(projectId)
        && isValidProject(incoming())
        && incoming().ownerId == request.auth.uid
        && incoming().status == 'DRAFT'
        && incoming().createdAt == request.time
        && incoming().updatedAt == request.time;

      // Pillar 5 & 6: Action-Based Updates + Terminal State Locking ('COMPLETED' cannot be mutated)
      allow update: if isSignedIn()
        && isValidId(projectId)
        && isValidProject(incoming())
        && existing().status != 'COMPLETED'
        && incoming().ownerId == existing().ownerId
        && incoming().createdAt == existing().createdAt
        && incoming().updatedAt == request.time
        && (
          isAdmin() ||
          (existing().ownerId == request.auth.uid
            && incoming().diff(existing()).affectedKeys().hasOnly(['name', 'status', 'updatedAt']))
        );

      allow delete: if isSignedIn() && isValidId(projectId) && existing().ownerId == request.auth.uid && existing().status == 'DRAFT';
    }
  }
}
```

---

## 4. Hexagonal Anti-Lock-In Adapter Pattern (Combining BaaS with Custom Backends)

Never scatter raw `supabase.from(...)` or `getDocs(collection(db, ...))` calls across domain services or payment/notification workers. Wrap BaaS providers behind a **Domain Repository Port** so you can switch between Supabase, Firebase, Convex, or self-hosted PostgreSQL without changing a single line of business logic:

```typescript
export interface OrderRecord {
  id: string;
  tenantId: string;
  userId: string;
  grandTotalMinor: bigint;
  currencyCode: string;
  status: 'PENDING' | 'PAID' | 'REFUNDED';
  version: number;
  createdAtUtc: string;
}

/**
 * Provider-Agnostic Domain Repository Port
 */
export interface OrderRepositoryPort {
  readonly providerName: 'supabase-postgres' | 'firebase-firestore' | 'convex' | 'native-pg';
  findByIdScoped(tenantId: string, orderId: string): Promise<OrderRecord | null>;
  createOrderWithOutboxAtomically(
    order: OrderRecord,
    outboxEvent: { eventId: string; eventType: string; payload: Record<string, unknown> }
  ): Promise<void>;
  transitionStatusCas(
    tenantId: string,
    orderId: string,
    expectedVersion: number,
    nextStatus: OrderRecord['status']
  ): Promise<boolean>;
}
```
