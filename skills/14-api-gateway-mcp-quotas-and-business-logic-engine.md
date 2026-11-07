# Module 14: API Gateway Security, Header Forwarding, Client Auth, MCP Traffic Security, Quotas & Business Logic Engine

This reference provides the complete, zero-loss architecture and penetration-hardened code implementations for:
1. **API Gateway Backend Security, Service Account Zero-Downtime Lockdown & `X-Apigateway-Api-Userinfo` Header Forwarding**
2. **Usage Attribution Protocol for `gcloud`, REST API & MCP Terminal Invocations**
3. **Client Authentication (API Keys, Managed Services, OpenAPI 2.0 vs. 3.x JWTs, Identity Provider Matrix & Security Composition Rules)**
4. **Model Context Protocol (MCP) Traffic Security, `tools/list` Lockdown, OpenAPI Header-Injection Defense & Shared Quotas**
5. **API Gateway Quotas, Rate Limiting & Zero-Outage Metric Transitions (Preventing Service Control `HTTP 500` Outages)**
6. **Enterprise Business Logic Building Engine (Composable Policy Rules, Tiered Pricing/Quotas, Approval Workflows & Invariant Guards)**

---

## 1. Backend Security and Header Forwarding Reference

### A. Gateway Service Account and Zero-Downtime Lockdown
API Gateway signs outbound backend requests with an OpenID Connect (OIDC) ID token generated for the gateway service account configured on the API config. Execute the steps below **in exact sequential order** so existing gateways do not receive `403 Forbidden` responses while transitioning to an OIDC-secured backend:

1. **Create a dedicated service account for the gateway**. NEVER use the Compute Engine default service account (`{project_number}-compute@developer.gserviceaccount.com`) in production. **Rationale:** The Compute Engine default service account often carries broad project permissions (`roles/editor`), which violates least privilege.
   ```bash
   gcloud iam service-accounts create {gateway_sa_name} \
     --display-name="API Gateway backend invoker" \
     --project={project_id}
   ```
2. **Grant the gateway service account ONLY the invoker role on the target backend resource** (request human approval before applying IAM bindings):
   - **Cloud Run service or Cloud Run functions (2nd gen):** `roles/run.invoker`
     ```bash
     gcloud run services add-iam-policy-binding {backend_service} \
       --member="serviceAccount:{gateway_sa_name}@{project_id}.iam.gserviceaccount.com" \
       --role="roles/run.invoker" \
       --region={region} \
       --project={project_id}
     ```
   - **Cloud Run functions (1st gen):** `roles/cloudfunctions.invoker` (as used in legacy Cloud Functions setups).
3. **Grant the deployment identity `roles/iam.serviceAccountUser`** on `{gateway_sa_name}@{project_id}.iam.gserviceaccount.com` so it can attach the service account to an API config.
4. **Create the API config with `--backend-auth-service-account` and roll it out to the gateway** (note that only one API config can be created for a given API at a time, and config creation can take several minutes):
   ```bash
   gcloud api-gateway api-configs create {config_id} \
     --api={api_id} \
     --openapi-spec={candidate_openapi_spec} \
     --backend-auth-service-account={gateway_sa_name}@{project_id}.iam.gserviceaccount.com \
     --project={project_id}

   gcloud api-gateway gateways update {gateway_id} \
     --api={api_id} \
     --api-config={config_id} \
     --location={region} \
     --project={project_id}
   ```
5. **After the gateway is actively serving `{config_id}`**, request human approval and restrict the backend service so that it rejects unauthenticated direct traffic (`--no-allow-unauthenticated`). **Rationale:** Locking down the backend before the gateway switches to `{config_id}` breaks live gateway traffic with `403` errors, whereas leaving `--allow-unauthenticated` enabled permanently lets callers invoke `*.run.app` directly and bypass API Gateway.
   ```bash
   gcloud run services update {backend_service} \
     --no-allow-unauthenticated \
     --region={region} \
     --project={project_id}
   ```

### B. Backend Authentication Extensions (OpenAPI 2.0 vs. 3.x)
In OpenAPI 2.0, `x-google-backend` is an inline object with `snake_case` fields. In OpenAPI 3.x, you **MUST** define named backends inside the root `x-google-api-management.backends` map, and set `x-google-backend` to the string name of that backend using the documented `camelCase` field names (`jwtAudience`, `disableAuth`, `pathTranslation`). **Rationale:** OpenAPI 3.x configs reject inline `x-google-backend` objects.

| Setting | OpenAPI 2.0 (`x-google-backend`) | OpenAPI 3.x (`x-google-api-management.backends.{name}`) | Behavior |
| :--- | :--- | :--- | :--- |
| **Backend URL** | `address` | `address` | Required target backend URL. |
| **OIDC JWT Audience** | `jwt_audience` | `jwtAudience` | Defaults to `address`. Set this field to the OAuth 2.0 client ID when the backend is protected by Identity-Aware Proxy (IAP) or runs on App Engine. |
| **Disable Backend Auth** | `disable_auth` | `disableAuth` | Defaults to `false`. Set to `true` to prevent the gateway proxy from obtaining and attaching an instance OIDC ID token (leaving any client `Authorization` header unreplaced by a gateway ID token). |
| **Path Translation** | `path_translation` | `pathTranslation` | Defaults to `APPEND_PATH_TO_ADDRESS` when `x-google-backend` is at the root level, and `CONSTANT_ADDRESS` when set at the operation level. |
| **Deadline** | `deadline` | `deadline` | Defaults to `15.0` seconds. Configurable up to `3600` seconds on streaming endpoints or `600` seconds on non-streaming gateways (values above `600` on non-streaming gateways are rejected at `gateways create` or `update` time). |
| **Protocol** | `protocol` | `protocol` | Defaults to `http/1.1`. Set to `h2` for gRPC backends or `http/1.1` for WebSocket backends. |

```yaml
openapi: 3.0.4
info:
  title: Orders API
  version: 1.0.0
x-google-api-management:
  backends:
    orders-backend:
      address: https://{backend_service}-{hash}.a.run.app
      jwtAudience: https://{backend_service}-{hash}.a.run.app
      pathTranslation: APPEND_PATH_TO_ADDRESS
      deadline: 30.0
      protocol: http/1.1
x-google-backend: orders-backend
```

### C. Header Override and `X-Apigateway-Api-Userinfo`
When `x-google-backend` routes a request to a backend with backend authentication enabled, API Gateway **overrides the incoming `Authorization` header** with the gateway's own OIDC ID token so the backend (such as Cloud Run) can authenticate the gateway.
- Backends **MUST** read the end-user or client JWT claims from the `X-Apigateway-Api-Userinfo` header rather than the `Authorization` header. **Rationale:** The `Authorization` header received by the backend carries the gateway service account token, whereas `X-Apigateway-Api-Userinfo` contains the `base64url`-encoded JSON payload of the client JWT verified by API Gateway.
- Decode `X-Apigateway-Api-Userinfo` in the backend using standard `base64url` decoding (adding `=` padding if required by the language runtime) and parse the JSON claims (`sub`, `iss`, `aud`), **ONLY AFTER** confirming that the request arrived over the authenticated gateway channel (`extractVerifiedApiGatewayUserInfo` in `Module 02`).

### D. Default Gateway Hostname (`*.gateway.dev`) and Load Balancer Limitation
API Gateway assigns every gateway a default hostname in `defaultHostname`, typically `https://{gateway_id}-{hash}.{region_code}.gateway.dev`. Read it with `gcloud api-gateway gateways describe {gateway_id} --location={region} --format="value(defaultHostname)"` instead of building it from the gateway name.
- API Gateway does **not** support ingress restriction settings to disable direct access to the gateway's `defaultHostname`.
- If you place an External Application Load Balancer, Google Cloud Armor policy, or Identity-Aware Proxy (IAP) in front of API Gateway via a serverless Network Endpoint Group (NEG), **NEVER** rely on the load balancer alone to block unauthorized requests. **Rationale:** Clients that discover the gateway's `defaultHostname` (`*.gateway.dev`) can send requests directly to the gateway and bypass the load balancer and Google Cloud Armor. Always enforce JWT or API key security in the API Gateway OpenAPI specification and IAM on the backend.

---

## 2. Usage Attribution Protocol (Terminal Execution Only)

Before executing any `gcloud`, REST API, or MCP command directly in the terminal with this skill, follow these usage attribution instructions. The tag identifies only the skill and its version; it carries no user data:
- **`gcloud` CLI Commands**: Prefix every `gcloud` invocation inline with the metrics environment variable (never use `gcloud config set`, which would persist beyond the current task):
  ```bash
  CLOUDSDK_METRICS_REQUEST_ATTRIBUTION="agent-skills/1.0 (skill:api-gateway-backend-security-and-rate-limiting)" \
  gcloud <command> [flags]
  ```
- **Direct HTTP, REST, and MCP Requests**: Include `agent-skills/1.0 (skill:api-gateway-backend-security-and-rate-limiting)` in the `User-Agent` header (appending to any existing `User-Agent` rather than overwriting it):
  ```http
  User-Agent: <existing_user_agent> agent-skills/1.0 (skill:api-gateway-backend-security-and-rate-limiting)
  ```
- **Strict Constraint for Generated Code**: The tracking prefix is strictly for commands executed directly in the terminal. **Do NOT** include this tracking prefix in generated scripts, Terraform templates, or application code provided to the user for their own repositories.
- **User Opt-Out**: If the user asks to disable or remove tracking or attribution tags, omit the `CLOUDSDK_METRICS_REQUEST_ATTRIBUTION` variable and custom `User-Agent` suffix from all commands.

---

## 3. Client Authentication Reference (API Keys and JWT)

### A. API Key Configuration & Restrictions
Use an API key to identify the calling Google Cloud consumer project for quota enforcement, billing, and usage tracking. **Do not use an API key alone to authenticate end-user identity** (an API key identifies a project, not a user, and can be extracted from client apps).
- Pass the API key in the `x-api-key` HTTP header as the standard convention. Use the `key` query parameter only as an escape hatch when the client cannot set custom HTTP headers (query parameters leak into proxy logs, browser history, and access logs).
- Before a consumer project can call an API with an API key:
  1. Inspect `managedService`: `gcloud api-gateway apis describe {api_id} --project={project_id} --format="value(managedService)"`
  2. Enable the managed service in `{consumer_project_id}`: `gcloud services enable {managed_service_name} --project={consumer_project_id}`
  3. Add API target restrictions (`--api-target=service={managed_service_name}`) and application restrictions to every production API key. When restricting by HTTP referrer, **always include the URL scheme** (`https://{domain}/*` instead of `{domain}/*`).

### B. JWT Configuration in OpenAPI 2.0 and 3.x
- Specify `x-google-jwks_uri` (OpenAPI 2.0) or `x-google-auth.jwksUri` (OpenAPI 3.x) on every JWT security definition. API Gateway caches the JWKS for **5 minutes** (publish rotated signing keys at least 5 minutes before signing traffic).
- Give each JWT security scheme a **unique `issuer` value** (API Gateway routes token verification by matching the `iss` claim to a unique security definition).
- Required JWT claims are `iss`, `sub`, `aud`, `iat`, and `exp`. The `aud` claim cannot be an internal address or an IPv4/IPv6 address.
- API Gateway validates JWT claims and signatures, but **does not check IAM permissions** of a calling service account and **ignores OAuth `scopes`** declared in the OpenAPI document (enforce scopes/roles inside backend authorization middleware).

| Identity Provider | `issuer` (`x-google-issuer`) | `jwksUri` (`x-google-jwks_uri`) | `audiences` (`x-google-audiences`) |
| :--- | :--- | :--- | :--- |
| **Firebase Authentication** | `https://securetoken.google.com/{project_id}` | `https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com` | `{project_id}` |
| **Auth0** | `https://{your_auth0_domain}/` (trailing slash required) | `https://{your_auth0_domain}/.well-known/jwks.json` | Auth0 API Identifier or Client ID |
| **Okta** | `https://{your_okta_domain}/oauth2/default` | `https://{your_okta_domain}/oauth2/default/v1/keys` | Okta Client ID or Audience |
| **Google ID token (OAuth client)** | `https://accounts.google.com` | `https://www.googleapis.com/oauth2/v3/certs` | OAuth 2.0 Client ID |
| **Google ID token (Service Account impersonation)** | `https://accounts.google.com` | `https://www.googleapis.com/oauth2/v3/certs` | `{jwt_audience}` — **CRITICAL**: Any Google identity can mint such a token, so verify the `email` claim in `X-Apigateway-Api-Userinfo` on the backend, or use self-signed JWTs! |
| **Service account self-signed JWT** | `{service_account_email}` | `https://www.googleapis.com/robot/v1/metadata/x509/{service_account_email}` | `https://{managed_service_name}` |

### C. Security Composition and Override Rules
**Critical Rule — Operation-level `security` replaces root-level `security`:** If an operation declares its own `security` block with only a JWT scheme (`- service_jwt: []`), it overrides the document-level `security` block and **removes any root `api_key` requirement** (breaking per-project quota enforcement!). To preserve per-project quota tracking on an operation that overrides `security`, you **MUST** include `api_key: []` and `service_jwt: []` in the **same** security requirement object:

```yaml
security:
  - api_key: []
    service_jwt: []
```

---

## 4. MCP Traffic Security and Quotas Reference (Public Preview)

Model Context Protocol (MCP) support on API Gateway exposes a stateless JSON-RPC 2.0 endpoint at `POST https://{default_hostname}/mcp` (OpenAPI 3.x only, up to 1,000 tools per gateway, mutually exclusive with `x-google-model-router`).

### A. Authentication Model per MCP Method & Response Inspection
| MCP Method | Default Authentication | Supported Security Schemes | Behavior & Failure Status Trap |
| :--- | :--- | :--- | :--- |
| `initialize` | Unauthenticated | None | Handled directly by gateway handshake layer; never reaches backend. |
| `notifications/initialized` | Unauthenticated | None | Returns `HTTP 202 Accepted`; never reaches backend. |
| `tools/list` | **Unauthenticated by default!** | Exactly **one** JWT scheme (`oauth2` with `x-google-auth`) OR **one** API key scheme (`apiKey` with `in: header`, `name: x-api-key`) | Configured via `x-google-api-management.mcp.tools-list.security`. **Trap:** `tools/list` with an **invalid API key returns HTTP `200`** with a JSON-RPC error (`-32000`) in the body! Always inspect both HTTP status, `WWW-Authenticate`, and JSON-RPC `error`. |
| `tools/call` | Inherits operation `security` | JWT (`oauth2`) and API keys (`apiKey`) | Transcoded into the underlying REST request and subject to the operation's exact `security` and `x-google-quota` rules. |

### B. Tool Discovery Security (`tools/list`) & Sensitive Operation Rules
1. **Always Lock Down `tools/list` in Production**: Configure `x-google-api-management.mcp.tools-list.security` with **exactly one** security scheme. An empty block (`security: {}`) passes config creation with no error and leaves `tools/list` unauthenticated! If you use a JWT scheme on `tools-list.security`, you **MUST** also list that same JWT scheme in the root `security` list.
2. **Explicitly Exclude Sensitive Operations (`x-google-mcp-tool: false`)**: Setting `x-google-api-management.mcp` to an object automatically enables MCP globally for all eligible `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` operations. Set `x-google-mcp-tool: false` on administrative, bulk-delete, or health-check operations, and **NEVER treat `x-google-mcp-tool: false` as an access control boundary** (the underlying REST endpoint remains live and callable!).
3. **NEVER Declare Trust-Bearing Identity Headers as OpenAPI `in: header` Parameters**: API Gateway exposes OpenAPI `in: header` parameters as top-level properties in the MCP tool `arguments` schema and **injects agent-supplied values directly into the backend HTTP request headers**!
4. **Assign Higher Quota Costs to Mutating MCP Tools**: Because AI agent loops can issue rapid retries, assign higher `x-google-quota` costs (`write-requests: 5`) to mutating `POST`, `PUT`, `PATCH`, and `DELETE` operations.

### C. Automated OpenAPI 3.x Gateway, MCP & Quota Specification Security Auditor
Run this deterministic verifier in CI/CD before `gcloud api-gateway api-configs create` to block MCP header injection, unauthenticated `tools/list`, root-level `x-google-quota` no-ops, and metric-removal `HTTP 500` outages:

```typescript
export interface OpenApi3OperationSpec {
  operationId?: string;
  description?: string;
  'x-google-mcp-tool'?: boolean | { name?: string; description?: string };
  'x-google-quota'?: Record<string, number>;
  security?: Array<Record<string, string[]>>;
  parameters?: Array<{ name: string; in: 'header' | 'query' | 'path' | 'cookie' }>;
  responses?: Record<string, unknown>;
}

export interface OpenApi3GatewaySpec {
  openapi: string;
  security?: Array<Record<string, string[]>>;
  'x-google-quota'?: Record<string, number>;
  'x-google-api-management'?: {
    backends?: Record<
      string,
      {
        address: string;
        jwtAudience?: string;
        disableAuth?: boolean;
        pathTranslation?: 'APPEND_PATH_TO_ADDRESS' | 'CONSTANT_ADDRESS';
        deadline?: number;
        protocol?: 'http/1.1' | 'h2';
      }
    >;
    metrics?: Record<string, { displayName?: string }>;
    quota?: {
      limits?: Record<string, { metric: string; values: number }>;
    };
    mcp?: {
      'tools-list'?: {
        security?: Record<string, unknown[]>;
      };
    };
  };
  components?: {
    securitySchemes?: Record<
      string,
      {
        type: 'apiKey' | 'oauth2';
        name?: string;
        in?: 'header' | 'query';
        'x-google-auth'?: {
          issuer: string;
          jwksUri: string;
          audiences?: string[];
        };
      }
    >;
  };
  paths: Record<string, Record<string, OpenApi3OperationSpec>>;
}

const FORBIDDEN_MCP_TRUST_HEADERS = new Set([
  'x-user-id',
  'x-tenant-id',
  'x-user-role',
  'x-roles',
  'x-apigateway-api-userinfo',
  'x-forwarded-for',
  'x-real-ip',
  'authorization',
]);

export function auditOpenApiGatewayAndMcpSecurity(params: {
  candidateSpec: OpenApi3GatewaySpec;
  activeGatewayReferencedMetrics?: ReadonlySet<string>;
  isStreamingGateway?: boolean;
}): { passed: boolean; violations: string[] } {
  const violations: string[] = [];
  const { candidateSpec } = params;
  const mgmt = candidateSpec['x-google-api-management'];
  const schemes = candidateSpec.components?.securitySchemes ?? {};

  // 1. Root-level x-google-quota is silently ignored in OpenAPI 3.x!
  if (candidateSpec['x-google-quota']) {
    violations.push(
      'QUOTA_SILENT_NOOP: Root-level x-google-quota is ignored in OpenAPI 3.x; declare x-google-quota on each operation.'
    );
  }

  // 2. Check backend deadline bounds (max 600s on non-streaming gateways, 3600s on streaming)
  const maxDeadline = params.isStreamingGateway ? 3600 : 600;
  for (const [backendName, backend] of Object.entries(mgmt?.backends ?? {})) {
    if (backend.deadline !== undefined && backend.deadline > maxDeadline) {
      violations.push(
        `BACKEND_DEADLINE_REJECTED: Backend "${backendName}" deadline (${backend.deadline}s) exceeds max ${maxDeadline}s.`
      );
    }
  }

  // 3. Check whole-API quota metric removal hazard (causes HTTP 500 on existing gateways!)
  const definedMetrics = new Set(Object.keys(mgmt?.metrics ?? {}));
  if (params.activeGatewayReferencedMetrics) {
    for (const activeMetric of params.activeGatewayReferencedMetrics) {
      if (!definedMetrics.has(activeMetric)) {
        violations.push(
          `QUOTA_OUTAGE_RISK_HTTP_500: Active gateway metric "${activeMetric}" was removed or renamed. Keep both old and new metrics defined until all gateways upgrade (Path A).`
        );
      }
    }
  }

  // 4. Verify unique issuer per oauth2 JWT scheme
  const seenIssuers = new Set<string>();
  for (const [schemeName, scheme] of Object.entries(schemes)) {
    if (scheme.type === 'oauth2') {
      const issuer = scheme['x-google-auth']?.issuer;
      const jwksUri = scheme['x-google-auth']?.jwksUri;
      if (!issuer || !jwksUri) {
        violations.push(`JWT_SCHEME_INVALID: Scheme "${schemeName}" is missing x-google-auth.issuer or jwksUri.`);
      } else if (seenIssuers.has(issuer)) {
        violations.push(`JWT_DUPLICATE_ISSUER: Scheme "${schemeName}" reuses issuer "${issuer}". Each JWT scheme must have a unique issuer.`);
      } else {
        seenIssuers.add(issuer);
      }
    }
  }

  // 5. MCP tools/list security audit
  const mcpEnabled = mgmt?.mcp !== undefined;
  if (mcpEnabled) {
    const toolsListSec = mgmt?.mcp?.['tools-list']?.security;
    const schemeKeys = toolsListSec ? Object.keys(toolsListSec) : [];
    if (schemeKeys.length === 0) {
      violations.push(
        'MCP_TOOLS_LIST_UNAUTHENTICATED: x-google-api-management.mcp.tools-list.security is missing or empty ({}), exposing all tool schemas to unauthenticated callers.'
      );
    } else if (schemeKeys.length > 1) {
      violations.push(
        'MCP_TOOLS_LIST_MULTI_SCHEME_INVALID: tools-list.security must name EXACTLY ONE security scheme.'
      );
    } else {
      const chosenSchemeName = schemeKeys[0];
      const chosenScheme = schemes[chosenSchemeName];
      if (!chosenScheme) {
        violations.push(`MCP_TOOLS_LIST_UNKNOWN_SCHEME: Scheme "${chosenSchemeName}" is not defined in components.securitySchemes.`);
      } else if (chosenScheme.type === 'apiKey') {
        if (chosenScheme.in !== 'header' || chosenScheme.name !== 'x-api-key') {
          violations.push(
            `MCP_TOOLS_LIST_API_KEY_HEADER_REQUIRED: API key scheme "${chosenSchemeName}" on tools/list MUST use in: header and name: x-api-key.`
          );
        }
      } else if (chosenScheme.type === 'oauth2') {
        const rootHasScheme = (candidateSpec.security ?? []).some((req) => chosenSchemeName in req);
        if (!rootHasScheme) {
          violations.push(
            `MCP_TOOLS_LIST_JWT_MISSING_FROM_ROOT: JWT scheme "${chosenSchemeName}" used in tools-list.security MUST also be listed in root security.`
          );
        }
      }
    }
  }

  // 6. Inspect every operation for MCP Header Injection, Quota API-Key requirement, and 204 MCP incompatibility
  for (const [pathKey, pathItem] of Object.entries(candidateSpec.paths)) {
    for (const [method, op] of Object.entries(pathItem)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method.toLowerCase())) continue;

      const isExposedAsMcpTool = mcpEnabled && op['x-google-mcp-tool'] !== false;
      if (isExposedAsMcpTool) {
        for (const param of op.parameters ?? []) {
          if (param.in === 'header' && FORBIDDEN_MCP_TRUST_HEADERS.has(param.name.toLowerCase())) {
            violations.push(
              `MCP_HEADER_INJECTION_VULNERABILITY: Operation "${method.toUpperCase()} ${pathKey}" exposes trust header "${param.name}" as an OpenAPI header parameter on an MCP tool, allowing AI agents to spoof identity headers!`
            );
          }
        }
        if (op.responses && '204' in op.responses) {
          violations.push(
            `MCP_204_UNSUPPORTED: Operation "${method.toUpperCase()} ${pathKey}" returns HTTP 204 (empty body), which is unsupported for MCP tools.`
          );
        }
      }

      // If operation uses x-google-quota, verify that an apiKey security scheme is required
      if (op['x-google-quota']) {
        const effectiveSec = op.security ?? candidateSpec.security ?? [];
        const hasApiKey = effectiveSec.some((reqObj) =>
          Object.keys(reqObj).some((secName) => schemes[secName]?.type === 'apiKey')
        );
        if (!hasApiKey) {
          violations.push(
            `QUOTA_MISSING_API_KEY_SECURITY: Operation "${method.toUpperCase()} ${pathKey}" declares x-google-quota but overrides or omits an apiKey security requirement.`
          );
        }
      }
    }
  }

  return {
    passed: violations.length === 0,
    violations,
  };
}
```

---

## 5. Quotas and Rate Limiting Reference (Whole-API Scope & Safe Metric Migration)

1. **Quotas Apply to the Whole API Immediately on Config Creation**:
   - You declare `metrics` and `quota.limits` inside an API config, but API Gateway applies those definitions to the parent **API resource** across all gateways immediately when `gcloud api-gateway api-configs create` executes (even before `gateways update` is called!).
   - **Critical Outage Rule**: **NEVER** rename or remove a quota metric in a new API config while any gateway of the API still serves an older API config that references the old metric name in `x-google-quota`. Overwriting the API's metric definitions in Service Control causes every call to a quota-enforced method on older gateways to fail with `HTTP 500: Failed to call Service Control Quota`.
   - **Safe Transition Path A (Zero-Downtime Additive Dual-Metric Transition)**: Keep both the old metric and the new metric defined in `metrics` and `quota.limits` in every newly created API config until all gateways of the API have been updated to configs that no longer reference the old metric.
   - **Safe Transition Path B (Immediate Uniform Upgrade)**: Update every gateway of the API to the newly created API config immediately.

2. **OpenAPI 2.0 to 3.x Quota Migration Checklist**:
   - Move `metrics` and `quota` from `x-google-management` into `x-google-api-management`.
   - Convert `metrics` and `quota.limits` from YAML arrays (`- name: ...`) into YAML maps keyed by metric and limit name, preserving exact metric keys.
   - Remove `valueType`, `metricKind`, `unit`, and `STANDARD:` wrapper keys (`values` in OpenAPI 3.x is a direct `int64` integer).
   - Replace `x-google-quota: { metricCosts: { "read-requests": 1 } }` with `x-google-quota: { read-requests: 1 }` on each operation.

---

## 6. Enterprise Business Logic Policy & Approval Workflow Engine

When building complex B2B SaaS, FinTech, E-Commerce, or AI agent backends, use a deterministic **Business Policy & Multi-Stage Approval Engine** that evaluates domain invariants, velocity limits, four-eyes approval thresholds (maker-checker separation of duties), and MCP agent guardrails in a single auditable pipeline:

```typescript
export type BusinessPolicyOutcome =
  | { status: 'APPROVED_IMMEDIATE'; appliedRules: string[] }
  | { status: 'REQUIRES_MAKER_CHECKER_APPROVAL'; requiredApproverRole: string; reason: string }
  | { status: 'REJECTED_INVARIANT'; ruleCode: string; reason: string };

export interface BusinessActionContext {
  tenantId: string;
  actorUserId: string;
  actorRoles: readonly string[];
  invokedViaMcpAgent: boolean;
  actionType: 'ORDER_REFUND' | 'PAYOUT_DISBURSEMENT' | 'CREDIT_LIMIT_OVERRIDE' | 'BULK_EXPORT';
  amountMinor: bigint;
  tenantAvailableBalanceMinor: bigint;
  makerCheckerApproverUserId?: string;
  makerCheckerApprovalFloorMinor: bigint;
  mcpAgentMaxAutonomousAmountMinor: bigint;
}

/**
 * Evaluates domain invariants, AI agent autonomous spending caps, and Maker-Checker
 * ("Four-Eyes" Separation of Duties) approval rules for sensitive business operations.
 */
export function evaluateEnterpriseBusinessLogicPolicy(
  ctx: BusinessActionContext
): BusinessPolicyOutcome {
  const appliedRules: string[] = [];

  // 1. Non-Negative & Available Balance Invariant
  if (ctx.amountMinor < 0n) {
    return {
      status: 'REJECTED_INVARIANT',
      ruleCode: 'BL_NEGATIVE_AMOUNT_FORBIDDEN',
      reason: 'Transaction amountMinor cannot be negative.',
    };
  }
  if (
    (ctx.actionType === 'ORDER_REFUND' || ctx.actionType === 'PAYOUT_DISBURSEMENT') &&
    ctx.amountMinor > ctx.tenantAvailableBalanceMinor
  ) {
    return {
      status: 'REJECTED_INVARIANT',
      ruleCode: 'BL_INSUFFICIENT_TENANT_RESERVE_BALANCE',
      reason: `Requested amount (${ctx.amountMinor}) exceeds available tenant reserve balance (${ctx.tenantAvailableBalanceMinor}).`,
    };
  }
  appliedRules.push('BALANCE_RESERVE_INVARIANT_PASSED');

  // 2. AI Agent / MCP Autonomous Execution Guardrail
  if (ctx.invokedViaMcpAgent && ctx.amountMinor > ctx.mcpAgentMaxAutonomousAmountMinor) {
    return {
      status: 'REQUIRES_MAKER_CHECKER_APPROVAL',
      requiredApproverRole: 'finance',
      reason: `MCP Agent autonomous limit (${ctx.mcpAgentMaxAutonomousAmountMinor}) exceeded; human finance approval required.`,
    };
  }
  appliedRules.push('MCP_AGENT_AUTONOMY_CAP_PASSED');

  // 3. Maker-Checker ("Four-Eyes" Separation of Duties) for High-Value Operations
  if (ctx.amountMinor >= ctx.makerCheckerApprovalFloorMinor) {
    if (!ctx.makerCheckerApproverUserId) {
      return {
        status: 'REQUIRES_MAKER_CHECKER_APPROVAL',
        requiredApproverRole: 'owner',
        reason: `Amount (${ctx.amountMinor}) meets or exceeds Maker-Checker floor (${ctx.makerCheckerApprovalFloorMinor}).`,
      };
    }
    // CRITICAL BUSINESS LOGIC INVARIANT: The Maker (initiator) CANNOT approve their own high-value request!
    if (ctx.makerCheckerApproverUserId === ctx.actorUserId) {
      return {
        status: 'REJECTED_INVARIANT',
        ruleCode: 'BL_SELF_APPROVAL_FORBIDDEN',
        reason: 'Separation-of-duties violation: initiator (Maker) cannot act as Reviewer (Checker) on their own transaction.',
      };
    }
    appliedRules.push('MAKER_CHECKER_DUAL_CONTROL_VERIFIED');
  }

  return {
    status: 'APPROVED_IMMEDIATE',
    appliedRules,
  };
}
```
