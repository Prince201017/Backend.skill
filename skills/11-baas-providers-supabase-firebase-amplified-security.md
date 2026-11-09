# Module 11: BaaS Providers (Supabase, Firebase, Appwrite, Convex, Amplify) & Amplified Security

## 1. Scope & Threat Model

Backend-as-a-Service (BaaS) platforms expose database query engines (PostgREST, Firestore client SDKs), storage buckets, and Realtime WebSocket channels directly to browser and mobile clients. Any missing Row-Level Security (RLS) policy, unverified JWT claim, `service_role` confused-deputy usage, or overly permissive document rule allows immediate cross-tenant data exfiltration or unauthorized business state manipulation.

### Trust Boundaries & Failure Modes
1. **Firebase Firestore Rules Cross-Tenant & State-Machine Bypass**:
   - *Vulnerability*: A rule on `/projects/{projectId}` that checks `resource.data.ownerId == request.auth.uid` without verifying active tenant membership (`/tenants/$(tenantId)/members/$(request.auth.uid)`) allows a user removed from a tenant (or operating across tenants) to read/mutate tenant resources. Furthermore, allowing `request.resource.data.status in ['DRAFT', 'ACTIVE', 'COMPLETED']` on client updates lets a browser client directly mark a billing/compliance project as `'COMPLETED'`, bypassing server-side verification and invoicing.
   - *Enforcement*:
     - Every multi-tenant Firestore document MUST carry an immutable `tenantId`.
     - Rules MUST verify `isActiveTenantMember(tenantId)` by reading `/databases/$(database)/documents/tenants/$(tenantId)/members/$(request.auth.uid)` and checking `data.status == 'ACTIVE'`.
     - Restricted terminal/privileged states (`'COMPLETED'`, `'APPROVED'`, `'SETTLED'`) MUST only be written by the backend Firebase Admin SDK (which bypasses client rules inside server-side transactions) — client writes are strictly constrained to initial `'DRAFT'` creation and `'DRAFT' -> 'ACTIVE'` transitions.
2. **Supabase PostgREST, Storage, Realtime & Edge Function Hardening (`DEVIL-12`)**:
   - Revoke all default privileges from the `anon` role on private tables (`REVOKE ALL ON TABLE ... FROM anon`).
   - Never use `user_metadata` inside RLS policies (`auth.jwt() -> 'user_metadata'`), because authenticated users can mutate their own `user_metadata` via `supabase.auth.updateUser()`. Always join against an authoritative `public.tenant_members` table with `status = 'ACTIVE'`.
   - **Edge Function `SUPABASE_SERVICE_ROLE_KEY` Confused-Deputy Trap**: Never use a `SUPABASE_SERVICE_ROLE_KEY` client to execute user-parameterized queries in an Edge Function without explicit tenant/role checks; prefer forwarding the caller's `Authorization` header to an `ANON_KEY` client so PostgreSQL RLS policies remain enforced.
   - **Realtime & Storage RLS**: Enforce explicit RLS on `realtime.messages` and `storage.objects` so clients cannot snoop on another tenant's Realtime Broadcast/Presence channel or bypass Module 05's quarantine malware pipeline.

---

## 2. Production Firebase Firestore Security Rules (Tenant Membership + State Machine Lockdown)

```javascript
// firestore.rules — 8-Pillar Multi-Tenant & State-Machine Hardened Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // 1. Default Deny All
    match /{document=**} {
      allow read, write: if false;
    }

    // 2. Core Identity & Active Tenant Membership Helpers
    function isSignedIn() {
      return request.auth != null
        && request.auth.uid is string
        && request.auth.uid.size() > 0
        && request.auth.token.email_verified == true;
    }

    function memberDocPath(tenantId) {
      return /databases/$(database)/documents/tenants/$(tenantId)/members/$(request.auth.uid);
    }

    function isActiveTenantMember(tenantId) {
      return isSignedIn()
        && tenantId is string
        && tenantId.size() > 0
        && exists(memberDocPath(tenantId))
        && get(memberDocPath(tenantId)).data.status == 'ACTIVE';
    }

    function hasActiveTenantRole(tenantId, allowedRoles) {
      return isActiveTenantMember(tenantId)
        && get(memberDocPath(tenantId)).data.role in allowedRoles;
    }

    function hasExactKeys(data, requiredKeys, optionalKeys) {
      let allowedKeys = requiredKeys.concat(optionalKeys);
      return data.keys().hasAll(requiredKeys)
        && data.keys().hasOnly(allowedKeys);
    }

    // 3. Tenant Membership Roster (Read-only to active tenant members; mutated only via Admin SDK)
    match /tenants/{tenantId}/members/{memberUid} {
      allow get: if isSignedIn() && (request.auth.uid == memberUid || isActiveTenantMember(tenantId));
      allow list: if isActiveTenantMember(tenantId);
      allow create, update, delete: if false; // Managed exclusively by backend Admin SDK
    }

    // 4. Tenant Projects Collection — Enforces Active Tenant Membership & Blocks Client 'COMPLETED' Transition
    match /projects/{projectId} {
      function isValidProjectShape(data) {
        return hasExactKeys(
            data,
            ['tenantId', 'ownerId', 'name', 'status', 'budgetCents', 'createdAt', 'updatedAt'],
            ['description']
          )
          && data.tenantId is string && data.tenantId.size() >= 3 && data.tenantId.size() <= 64
          && data.ownerId is string && data.ownerId.size() > 0
          && data.name is string && data.name.size() >= 1 && data.name.size() <= 120
          && data.budgetCents is int && data.budgetCents >= 0 && data.budgetCents <= 1000000000
          && data.createdAt is timestamp
          && data.updatedAt is timestamp
          && (!('description' in data) || (data.description is string && data.description.size() <= 2000));
      }

      // Read: Caller must be an ACTIVE member of the project's tenant
      allow get, list: if isActiveTenantMember(resource.data.tenantId);

      // Create: Caller must be an ACTIVE member (ADMIN or EDITOR), ownerId must be caller,
      // and initial status MUST be 'DRAFT' (clients can never create directly in 'ACTIVE' or 'COMPLETED')
      allow create: if isValidProjectShape(request.resource.data)
        && hasActiveTenantRole(request.resource.data.tenantId, ['ADMIN', 'EDITOR'])
        && request.resource.data.ownerId == request.auth.uid
        && request.resource.data.status == 'DRAFT'
        && request.resource.data.createdAt == request.time
        && request.resource.data.updatedAt == request.time;

      // Update: Caller must be an ACTIVE member of the existing project's tenant,
      // immutable fields (tenantId, ownerId, createdAt) must not change,
      // and client-driven status transitions are strictly limited to 'DRAFT' -> 'DRAFT' or 'DRAFT' -> 'ACTIVE'.
      // Transitioning to 'COMPLETED' is FORBIDDEN from client SDKs and must be executed by the backend Admin SDK.
      allow update: if isValidProjectShape(request.resource.data)
        && isActiveTenantMember(resource.data.tenantId)
        && (resource.data.ownerId == request.auth.uid || hasActiveTenantRole(resource.data.tenantId, ['ADMIN']))
        && request.resource.data.tenantId == resource.data.tenantId
        && request.resource.data.ownerId == resource.data.ownerId
        && request.resource.data.createdAt == resource.data.createdAt
        && request.resource.data.updatedAt == request.time
        && resource.data.status in ['DRAFT', 'ACTIVE']
        && request.resource.data.status in ['DRAFT', 'ACTIVE']
        && !(resource.data.status == 'ACTIVE' && request.resource.data.status == 'DRAFT');

      // Delete: Never allowed from client SDK
      allow delete: if false;
    }
  }
}
```

---

## 3. Executable Firestore Rule Policy Evaluator & Negative Test Harness

```typescript
// Executable TypeScript — Deterministic Evaluator for /projects/{projectId} Security Policy
export interface FirestoreAuthContext {
  uid: string;
  emailVerified: boolean;
}

export interface TenantMemberDoc {
  tenantId: string;
  uid: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  role: 'ADMIN' | 'EDITOR' | 'VIEWER';
}

export interface ProjectDoc {
  tenantId: string;
  ownerId: string;
  name: string;
  status: 'DRAFT' | 'ACTIVE' | 'COMPLETED';
  budgetCents: number;
  createdAtMs: number;
  updatedAtMs: number;
  description?: string;
}

export function evaluateFirestoreProjectRule(params: {
  operation: 'read' | 'create' | 'update' | 'delete';
  auth: FirestoreAuthContext | null;
  membership: TenantMemberDoc | null;
  existingDoc: ProjectDoc | null;
  incomingDoc: ProjectDoc | null;
  requestTimeMs: number;
}): { allowed: boolean; denialReason?: string } {
  const { operation, auth, membership, existingDoc, incomingDoc, requestTimeMs } = params;

  if (!auth || !auth.uid || !auth.emailVerified) {
    return { allowed: false, denialReason: 'UNAUTHENTICATED_OR_UNVERIFIED_EMAIL' };
  }

  const isActiveMemberOf = (tenantId: string): boolean =>
    Boolean(
      membership &&
        membership.uid === auth.uid &&
        membership.tenantId === tenantId &&
        membership.status === 'ACTIVE'
    );

  if (operation === 'read') {
    if (!existingDoc || !isActiveMemberOf(existingDoc.tenantId)) {
      return { allowed: false, denialReason: 'CROSS_TENANT_OR_INACTIVE_MEMBER_READ_DENIED' };
    }
    return { allowed: true };
  }

  if (operation === 'delete') {
    return { allowed: false, denialReason: 'CLIENT_DELETE_FORBIDDEN' };
  }

  const isValidShape = (doc: ProjectDoc | null): doc is ProjectDoc => {
    if (!doc) return false;
    if (typeof doc.tenantId !== 'string' || doc.tenantId.length < 3 || doc.tenantId.length > 64) return false;
    if (typeof doc.ownerId !== 'string' || doc.ownerId.length === 0) return false;
    if (typeof doc.name !== 'string' || doc.name.length < 1 || doc.name.length > 120) return false;
    if (!Number.isInteger(doc.budgetCents) || doc.budgetCents < 0 || doc.budgetCents > 1_000_000_000) return false;
    return true;
  };

  if (operation === 'create') {
    if (!isValidShape(incomingDoc)) {
      return { allowed: false, denialReason: 'INVALID_PROJECT_SCHEMA' };
    }
    if (!isActiveMemberOf(incomingDoc.tenantId)) {
      return { allowed: false, denialReason: 'CROSS_TENANT_OR_INACTIVE_MEMBER_CREATE_DENIED' };
    }
    if (!membership || !['ADMIN', 'EDITOR'].includes(membership.role)) {
      return { allowed: false, denialReason: 'INSUFFICIENT_TENANT_ROLE_FOR_CREATE' };
    }
    if (incomingDoc.ownerId !== auth.uid) {
      return { allowed: false, denialReason: 'OWNER_ID_SPOOFING_DENIED' };
    }
    if (incomingDoc.status !== 'DRAFT') {
      return { allowed: false, denialReason: 'INITIAL_STATUS_MUST_BE_DRAFT' };
    }
    if (incomingDoc.createdAtMs !== requestTimeMs || incomingDoc.updatedAtMs !== requestTimeMs) {
      return { allowed: false, denialReason: 'TIMESTAMP_SPOOFING_DENIED' };
    }
    return { allowed: true };
  }

  // operation === 'update'
  if (!existingDoc || !isValidShape(incomingDoc)) {
    return { allowed: false, denialReason: 'INVALID_UPDATE_TARGET_OR_SCHEMA' };
  }
  if (!isActiveMemberOf(existingDoc.tenantId)) {
    return { allowed: false, denialReason: 'CROSS_TENANT_OR_INACTIVE_MEMBER_UPDATE_DENIED' };
  }
  const isOwnerOrAdmin =
    existingDoc.ownerId === auth.uid || (membership !== null && membership.role === 'ADMIN');
  if (!isOwnerOrAdmin) {
    return { allowed: false, denialReason: 'NOT_OWNER_OR_TENANT_ADMIN' };
  }
  if (
    incomingDoc.tenantId !== existingDoc.tenantId ||
    incomingDoc.ownerId !== existingDoc.ownerId ||
    incomingDoc.createdAtMs !== existingDoc.createdAtMs
  ) {
    return { allowed: false, denialReason: 'IMMUTABLE_FIELD_MUTATION_DENIED' };
  }
  if (incomingDoc.updatedAtMs !== requestTimeMs) {
    return { allowed: false, denialReason: 'UPDATED_AT_MUST_EQUAL_REQUEST_TIME' };
  }
  if (
    !['DRAFT', 'ACTIVE'].includes(existingDoc.status) ||
    !['DRAFT', 'ACTIVE'].includes(incomingDoc.status) ||
    (existingDoc.status === 'ACTIVE' && incomingDoc.status === 'DRAFT')
  ) {
    return { allowed: false, denialReason: 'UNAUTHORIZED_CLIENT_STATUS_TRANSITION' };
  }

  return { allowed: true };
}
```

---

## 4. Supabase RLS Policy Standard: Tables, Immutability Triggers, Realtime Channels & Storage (`DEVIL-15` Remediated)

```sql
SET lock_timeout = '3s';
SET statement_timeout = '10s';

-- 0. Idempotent Prerequisite Roles, Schemas & Base Tables for Clean Database Installation
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid;
$$;

CREATE SCHEMA IF NOT EXISTS realtime;
CREATE OR REPLACE FUNCTION realtime.topic() RETURNS TEXT LANGUAGE sql STABLE AS $$
  SELECT COALESCE(current_setting('realtime.topic', true), '');
$$;
CREATE TABLE IF NOT EXISTS realtime.messages (
  id UUID PRIMARY KEY,
  topic TEXT NOT NULL,
  extension TEXT NOT NULL,
  payload JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE IF NOT EXISTS storage.objects (
  id UUID PRIMARY KEY,
  bucket_id TEXT NOT NULL,
  name TEXT NOT NULL,
  owner UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS public.tenant_members (
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL,
  role VARCHAR(32) NOT NULL CHECK (role IN ('ADMIN', 'EDITOR', 'VIEWER')),
  status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.projects (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  owner_id UUID NOT NULL,
  name VARCHAR(120) NOT NULL,
  status VARCHAR(16) NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'COMPLETED')),
  budget_cents BIGINT NOT NULL CHECK (budget_cents >= 0 AND budget_cents <= 1000000000),
  description VARCHAR(2000) NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS public.uploads (
  upload_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  owner_user_id UUID NOT NULL,
  safe_storage_key TEXT NOT NULL UNIQUE,
  status VARCHAR(32) NOT NULL CHECK (status IN ('QUARANTINED', 'SCANNING', 'APPROVED', 'REJECTED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 1. Authoritative Supabase RLS Policies & Immutability Trigger on public.projects (DEVIL-15 Remediation)
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.projects FROM anon;
REVOKE DELETE ON TABLE public.projects FROM authenticated;

CREATE POLICY tenant_active_member_select_projects
  ON public.projects
  FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1
      FROM public.tenant_members tm
      WHERE tm.tenant_id = projects.tenant_id
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
    )
  );

CREATE POLICY tenant_active_editor_insert_projects
  ON public.projects
  FOR INSERT
  TO authenticated
  WITH CHECK (
    projects.owner_id = auth.uid()
    AND projects.status = 'DRAFT'
    AND projects.budget_cents >= 0
    AND projects.budget_cents <= 1000000000
    AND EXISTS (
      SELECT 1
      FROM public.tenant_members tm
      WHERE tm.tenant_id = projects.tenant_id
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
        AND tm.role IN ('ADMIN', 'EDITOR')
    )
  );

CREATE POLICY tenant_active_editor_update_projects
  ON public.projects
  FOR UPDATE
  TO authenticated
  USING (
    projects.status IN ('DRAFT', 'ACTIVE')
    AND EXISTS (
      SELECT 1
      FROM public.tenant_members tm
      WHERE tm.tenant_id = projects.tenant_id
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
        AND (projects.owner_id = auth.uid() OR tm.role = 'ADMIN')
    )
  )
  WITH CHECK (
    -- Clients can never transition a project directly to 'COMPLETED' via PostgREST
    projects.status IN ('DRAFT', 'ACTIVE')
    AND EXISTS (
      SELECT 1
      FROM public.tenant_members tm
      WHERE tm.tenant_id = projects.tenant_id
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
        AND (projects.owner_id = auth.uid() OR tm.role = 'ADMIN')
    )
  );

-- Explicit deny policy for client DELETE on public.projects
CREATE POLICY tenant_projects_deny_client_delete
  ON public.projects
  FOR DELETE
  TO authenticated
  USING (false);

-- PostgreSQL RLS WITH CHECK only sees the NEW row and cannot compare NEW vs. OLD columns by itself!
-- Enforce column immutability (tenant_id, owner_id, created_at) and forbid ACTIVE -> DRAFT downgrade via trigger:
CREATE OR REPLACE FUNCTION public.enforce_project_immutable_columns_and_state()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id THEN
    RAISE EXCEPTION 'IMMUTABLE_COLUMN_VIOLATION: project.tenant_id cannot be reassigned across tenants';
  END IF;
  IF NEW.owner_id <> OLD.owner_id THEN
    RAISE EXCEPTION 'IMMUTABLE_COLUMN_VIOLATION: project.owner_id cannot be mutated by client update';
  END IF;
  IF NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'IMMUTABLE_COLUMN_VIOLATION: project.created_at is immutable';
  END IF;
  IF OLD.status = 'ACTIVE' AND NEW.status = 'DRAFT' THEN
    RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Cannot downgrade project from ACTIVE to DRAFT';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_project_immutable_columns
  BEFORE UPDATE ON public.projects
  FOR EACH ROW
  EXECUTE FUNCTION public.enforce_project_immutable_columns_and_state();

-- 2. Supabase Realtime Channel Authorization (realtime.messages) — Both Subscribe (SELECT) & Publish (INSERT)
-- Blocks cross-tenant WebSocket channel snooping AND unauthorized message injection on Broadcast/Presence topics ("tenant:<uuid>:events")
ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE realtime.messages FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_realtime_channel_subscribe_isolation
  ON realtime.messages
  FOR SELECT
  TO authenticated
  USING (
    realtime.topic() LIKE 'tenant:%'
    AND EXISTS (
      SELECT 1
      FROM public.tenant_members tm
      WHERE tm.tenant_id = NULLIF(split_part(realtime.topic(), ':', 2), '')::uuid
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
    )
  );

CREATE POLICY tenant_realtime_channel_publish_isolation
  ON realtime.messages
  FOR INSERT
  TO authenticated
  WITH CHECK (
    realtime.topic() LIKE 'tenant:%'
    AND EXISTS (
      SELECT 1
      FROM public.tenant_members tm
      WHERE tm.tenant_id = NULLIF(split_part(realtime.topic(), ':', 2), '')::uuid
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
        AND tm.role IN ('ADMIN', 'EDITOR')
    )
  );

-- 3. Supabase Storage RLS (storage.objects)
-- Never allow direct client downloads from the 'quarantine' bucket; only allow reading 'production' bucket objects
-- when the corresponding public.uploads record is in 'APPROVED' state, caller is an ACTIVE tenant member,
-- AND caller is either the file owner or a tenant ADMIN (preventing Intra-Tenant Storage BOLA!).
CREATE POLICY storage_approved_objects_only
  ON storage.objects
  FOR SELECT
  TO authenticated
  USING (
    bucket_id = 'production'
    AND EXISTS (
      SELECT 1
      FROM public.uploads u
      INNER JOIN public.tenant_members tm
        ON tm.tenant_id = u.tenant_id
      WHERE u.safe_storage_key = storage.objects.name
        AND u.status = 'APPROVED'
        AND tm.user_id = auth.uid()
        AND tm.status = 'ACTIVE'
        AND (u.owner_user_id = auth.uid() OR tm.role = 'ADMIN')
    )
  );
```
