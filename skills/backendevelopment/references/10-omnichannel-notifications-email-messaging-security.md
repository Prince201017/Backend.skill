# Module 10: High-Security Omnichannel Notification, Email, SMS/WhatsApp/OTP, Push & Chat Delivery Architecture

This reference provides the complete, penetration-hardened specification and implementation engines for **Transactional & Bulk Email**, **SMS / WhatsApp / OTP Delivery**, **Mobile & Web Push (`FCM v1`, `APNs .p8`, `WebPush VAPID`)**, **In-App Real-Time Feeds (`SSE` / `WebSocket`)**, and **Chat / Collaboration Webhooks**.

---

## 1. Seven Critical Messaging & Failover Vulnerabilities Prevented by Design

| Vulnerability ID | Attack / Failure Vector | Mandatory Architectural Countermeasure |
| :--- | :--- | :--- |
| **MSG-VULN-01** | **Cross-Provider Duplicate Send on Ambiguous Timeout**: Provider A (SES/Twilio) and Provider B (Postmark/Vonage) do not share idempotency state. Blindly failing over to Provider B when Provider A times out after socket write sends duplicate OTPs/emails and double-charges the tenant. | Classify every provider error into `DEFINITIVE_PRE_ACCEPTANCE` (`ECONNREFUSED`, DNS failure, local Circuit Breaker `OPEN`, HTTP `429`/`503` rejected before ingest) vs. `AMBIGUOUS_POST_WRITE` (socket read timeout after write, `502`/`504`). Auto-failover to Provider B **only** on `DEFINITIVE_PRE_ACCEPTANCE`; transition ambiguous states to `AMBIGUOUS_PENDING_RECONCILIATION`. |
| **MSG-VULN-02** | **Domain Reputation Destruction vs. Security Alert Blackhole**: Letting `P0` security emails bypass `HARD_BOUNCE` or `SPAM_COMPLAINT` suppression lets attackers trigger password resets to bounce/spam-trap addresses until SES/SendGrid suspends the entire domain. | Separate **User Marketing Preferences** (bypassed by `P0`/`P1` security & transactional messages) from **Transport-Level Suppression (`HARD_BOUNCE`, `SPAM_COMPLAINT`)** (never bypassed on that transport channel; automatically triggers **Out-of-Band Cross-Channel Fallback** to Push + In-App + SMS). |
| **MSG-VULN-03** | **Unsalted `recipient_hash` Rainbow-Table Reversal**: E.164 phone numbers have only $\sim 10^{10}$ combinations; unsalted SHA-256 hashes in suppression tables are reversed in seconds via GPU rainbow tables. | Compute `recipient_hmac = HMAC-SHA256(KMS_SUPPRESSION_PEPPER, normalizeNFKC(recipient))` with explicit `key_version`. |
| **MSG-VULN-04** | **Quiet-Hours Filter Starving Expiring `P0` OTPs**: Holding all notifications during user quiet hours delays 5-minute 2FA OTPs and login alerts until morning. | Enforce Quiet Hours **exclusively** on `P2_BULK_MARKETING` and non-urgent digests; `P0_CRITICAL_OTP` and `P1_TRANSACTIONAL` always bypass Quiet Hours immediately. |
| **MSG-VULN-05** | **ESP Link-Wrapper Token Pre-Consumption & `action_url` XSS**: ESP click-tracking rewrites magic links and corporate email scanners (`GET` prefetchers) consume single-use tokens before the user clicks them. Unvalidated `action_url` allows `javascript:` XSS. | Force `trackLinks: false` and `trackOpens: false` on all `P0` OTP/magic-link/reset templates; require a two-step `GET` landing -> `POST` confirmation flow to consume tokens; and validate `action_url` against relative paths or allowlisted `https://` origins. |
| **MSG-VULN-06** | **Shared-Device Push Token Leakage & Lock-Screen PII Exposure**: When User A logs out and User B logs in on the same phone/browser, User A's stale FCM/APNs token leaks private alerts to User B, and raw lock-screen payloads expose PII. | Enforce **Exclusive Push-Token Ownership** (binding a token to User B atomically detaches it from User A; session logout deactivates the token) and **Zero-PII Lock-Screen Push** (send opaque `notification_id` wake-up payload; client fetches decrypted content over authenticated TLS). |
| **MSG-VULN-07** | **Mass-Unsubscribe / Fake-Bounce Denial of Service**: Forged unsubscribe requests or unverified bounce webhooks allow attackers to mute victim accounts. | Sign RFC 8058 `List-Unsubscribe` URLs with constant-time `HMAC-SHA256(secret, tenantId:userId:topic:expiresAt)` and verify cryptographic signatures + `event_id` deduplication on all provider webhooks. |

---

## 2. Database Schema: Templates, Suppression, Preferences, Push Tokens & Delivery Ledger

```sql
-- 1. Pre-Registered Versioned Templates (Prevents Runtime SSTI)
CREATE TABLE notification_templates (
    template_id VARCHAR(64) NOT NULL,
    version INT NOT NULL,
    channel VARCHAR(16) NOT NULL CHECK (channel IN ('EMAIL', 'SMS', 'WHATSAPP', 'PUSH', 'IN_APP', 'CHAT_WEBHOOK')),
    priority_lane VARCHAR(24) NOT NULL CHECK (priority_lane IN ('P0_CRITICAL_OTP', 'P1_TRANSACTIONAL', 'P2_BULK_MARKETING')),
    disable_tracking BOOLEAN NOT NULL DEFAULT FALSE,
    subject_template TEXT NULL,
    body_template TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (template_id, version)
);

-- 2. Transport-Level Suppression List (Keyed HMAC-SHA256 Recipient Hash)
CREATE TABLE notification_suppression_list (
    tenant_id UUID NOT NULL,
    channel VARCHAR(16) NOT NULL,
    recipient_hmac CHAR(64) NOT NULL, -- HMAC-SHA256(pepper, normalized_recipient)
    pepper_version VARCHAR(16) NOT NULL DEFAULT 'v1',
    reason VARCHAR(32) NOT NULL CHECK (reason IN ('HARD_BOUNCE', 'SPAM_COMPLAINT', 'INVALID_DESTINATION', 'CARRIER_BLOCK')),
    provider_event_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, channel, recipient_hmac)
);

-- 3. User Notification Consent & Quiet Hours (P2_BULK_MARKETING & Non-Critical Topics)
CREATE TABLE user_notification_preferences (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    topic VARCHAR(64) NOT NULL,
    email_opt_in BOOLEAN NOT NULL DEFAULT TRUE,
    sms_opt_in BOOLEAN NOT NULL DEFAULT FALSE,
    push_opt_in BOOLEAN NOT NULL DEFAULT TRUE,
    in_app_opt_in BOOLEAN NOT NULL DEFAULT TRUE,
    quiet_hours_start_minute INT NULL CHECK (quiet_hours_start_minute BETWEEN 0 AND 1439),
    quiet_hours_end_minute INT NULL CHECK (quiet_hours_end_minute BETWEEN 0 AND 1439),
    timezone_iana VARCHAR(64) NOT NULL DEFAULT 'UTC',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, user_id, topic)
);

-- 4. Exclusive Push Device Token Registry (Prevents Shared-Device Cross-User Leakage)
CREATE TABLE push_device_registrations (
    device_token_hmac CHAR(64) PRIMARY KEY, -- Unique across entire platform: 1 physical device token = 1 active user!
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL, -- Cascade-revoked when auth_sessions row is logged out/revoked
    platform VARCHAR(16) NOT NULL CHECK (platform IN ('IOS_APNS', 'ANDROID_FCM', 'WEB_VAPID')),
    encrypted_device_token TEXT NOT NULL, -- AES-256-GCM encrypted token
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 5. Unified Omnichannel Delivery Ledger
CREATE TABLE notification_deliveries (
    id UUID PRIMARY KEY,
    idempotency_key VARCHAR(128) NOT NULL,
    tenant_id UUID NOT NULL,
    user_id UUID NULL,
    channel VARCHAR(16) NOT NULL,
    priority_lane VARCHAR(24) NOT NULL,
    template_id VARCHAR(64) NOT NULL,
    recipient_masked VARCHAR(64) NOT NULL, -- e.g. "h***@gmail.com" or "+1415***2671" (Zero raw PII in logs)
    recipient_hmac CHAR(64) NOT NULL,
    provider_id VARCHAR(32) NULL,
    provider_message_id VARCHAR(128) NULL,
    status VARCHAR(40) NOT NULL CHECK (status IN (
        'QUEUED',
        'SENT',
        'DELIVERED',
        'AMBIGUOUS_PENDING_RECONCILIATION',
        'SUPPRESSED_CROSS_CHANNEL_FALLBACK',
        'BOUNCED',
        'FAILED_DLQ'
    )),
    cost_micros BIGINT NOT NULL DEFAULT 0,
    traceparent VARCHAR(128) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, idempotency_key, channel)
);
```

---

## 3. Anti-CRLF Header Sanitizer, Anti-SSTI Template Renderer & Safe Action-URL Validator

Never evaluate user-supplied templates dynamically (`eval`, `new Function`) and never interpolate raw user strings into email `Subject`, `From`, `Reply-To`, or HTML bodies without escaping.

```typescript
import crypto from 'node:crypto';

/**
 * 1. Strips CR (\r), LF (\n), and Null (\0) bytes to prevent SMTP Header Injection
 * (e.g., injecting "Subject: Hi\r\nBcc: victim@example.com").
 */
export function sanitizeHeaderFieldAntiCrlf(value: string, maxLength = 250): string {
  const normalized = value.normalize('NFKC');
  if (/[\r\n\0]/.test(normalized)) {
    throw new Error('HEADER_INJECTION_BLOCKED: CR/LF/Null characters are forbidden in headers');
  }
  return normalized.trim().slice(0, maxLength);
}

/**
 * 2. Strict HTML Context Escaper for Pre-Registered Templates (Defeats SSTI & Stored XSS)
 */
export function escapeHtmlEntities(raw: string): string {
  return raw
    .normalize('NFKC')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderSafePreRegisteredTemplate(
  templateBody: string,
  variables: Readonly<Record<string, string | number>>
): string {
  return templateBody.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_match, varName: string) => {
    if (!Object.prototype.hasOwnProperty.call(variables, varName)) {
      throw new Error(`TEMPLATE_RENDER_ERROR: Missing required variable "${varName}"`);
    }
    return escapeHtmlEntities(String(variables[varName]));
  });
}

/**
 * 3. Safe Action-URL Validator for In-App & Push Notifications (Blocks javascript: / data: / Open Redirects)
 */
export function validateSafeNotificationActionUrl(
  rawUrl: string,
  allowedHttpsOrigins: ReadonlySet<string>
): string {
  const trimmed = rawUrl.trim();
  // Allow strict relative paths starting with single '/' (not protocol-relative '//evil.com')
  if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.includes('\\')) {
    return trimmed;
  }
  const parsed = new URL(trimmed);
  if (parsed.protocol !== 'https:' || !allowedHttpsOrigins.has(parsed.origin)) {
    throw new Error(`UNSAFE_ACTION_URL_BLOCKED: Origin "${parsed.origin}" or protocol "${parsed.protocol}" is forbidden`);
  }
  return parsed.toString();
}

/**
 * 4. Keyed HMAC-SHA256 Suppression Hash & Masked PII Formatter
 */
export function computeRecipientSuppressionHmac(rawRecipient: string, kmsPepperSecret: string): {
  recipientHmac: string;
  recipientMasked: string;
} {
  const canonical = rawRecipient.normalize('NFKC').trim().toLowerCase();
  const recipientHmac = crypto
    .createHmac('sha256', kmsPepperSecret)
    .update(canonical, 'utf8')
    .digest('hex');

  let recipientMasked = '***';
  if (canonical.includes('@')) {
    const [local, domain] = canonical.split('@');
    recipientMasked = `${local.slice(0, 1)}***@${domain}`;
  } else if (canonical.startsWith('+')) {
    recipientMasked = `${canonical.slice(0, 4)}***${canonical.slice(-4)}`;
  }

  return { recipientHmac, recipientMasked };
}
```

---

## 4. SMS Toll-Fraud, International Pumping & Monetary Cost-Cap Guard

Attackers abuse OTP endpoints via **SMS Pumping / International Revenue Share Fraud (IRSF)** by scripting thousands of OTP requests to premium country prefixes (`+CC`). Enforce country-prefix allowlists, per-prefix velocity caps, and a hard tenant monetary budget circuit breaker:

```typescript
export interface SmsTollFraudPolicy {
  allowedDialingPrefixes: ReadonlySet<string>; // e.g., new Set(['+1', '+44', '+91', '+61', '+49'])
  maxSmsPerCountryPrefixPerMinute: number;     // e.g., 30 SMS/min per country prefix per tenant
  maxTenantDailySpendMicros: bigint;           // e.g., $50.00 = 50_000_000n micros
}

export function extractE164CountryPrefix(e164Phone: string, allowedPrefixes: ReadonlySet<string>): string {
  for (const len of [4, 3, 2]) {
    const candidate = e164Phone.slice(0, len);
    if (allowedPrefixes.has(candidate)) {
      return candidate;
    }
  }
  throw new Error(`SMS_TOLL_FRAUD_BLOCKED: Destination prefix for ${e164Phone.slice(0, 5)}*** is not on the tenant allowlist`);
}

export async function enforceSmsTollFraudAndBudgetGuard(params: {
  tenantId: string;
  e164Phone: string;
  estimatedCostMicros: bigint;
  policy: SmsTollFraudPolicy;
  incrementPrefixCounter: (key: string, ttlSeconds: number) => Promise<number>;
  incrementDailySpendMicros: (tenantId: string, costMicros: bigint) => Promise<bigint>;
}): Promise<{ countryPrefix: string }> {
  const countryPrefix = extractE164CountryPrefix(
    params.e164Phone,
    params.policy.allowedDialingPrefixes
  );

  // 1. Per-country-prefix velocity guard (stops botnet pumping to a single country code)
  const minuteBucket = Math.floor(Date.now() / 60_000);
  const prefixRateKey = `sms:rate:${params.tenantId}:${countryPrefix}:${minuteBucket}`;
  const currentPrefixCount = await params.incrementPrefixCounter(prefixRateKey, 90);
  if (currentPrefixCount > params.policy.maxSmsPerCountryPrefixPerMinute) {
    throw new Error(
      `SMS_PUMPING_CIRCUIT_TRIPPED: Velocity limit exceeded for prefix ${countryPrefix}`
    );
  }

  // 2. Hard Daily Monetary Spend Cap Circuit Breaker
  const cumulativeSpend = await params.incrementDailySpendMicros(
    params.tenantId,
    params.estimatedCostMicros
  );
  if (cumulativeSpend > params.policy.maxTenantDailySpendMicros) {
    throw new Error(
      `SMS_BUDGET_CAP_EXCEEDED: Tenant ${params.tenantId} exceeded daily SMS budget cap`
    );
  }

  return { countryPrefix };
}
```

---

## 5. Safe Multi-Provider Failover Router (Definitive vs. Ambiguous Failure Classifier)

```typescript
export type ProviderFailureClass =
  | 'DEFINITIVE_PRE_ACCEPTANCE' // Safe to fail over immediately to backup provider
  | 'AMBIGUOUS_POST_WRITE'      // Socket timed out after write / 502 / 504: DO NOT blind-resend!
  | 'PERMANENT_RECIPIENT_ERROR'; // 400 Invalid number/email: do not retry or fail over

export class ProviderDispatchError extends Error {
  constructor(
    message: string,
    public readonly providerId: string,
    public readonly failureClass: ProviderFailureClass
  ) {
    super(message);
  }
}

export interface MessagingProviderAdapter<TPayload> {
  readonly providerId: string;
  isCircuitOpen(): boolean;
  send(payload: TPayload, idempotencyKey: string): Promise<{ providerMessageId: string; costMicros: bigint }>;
}

export interface SafeDispatchResult {
  status: 'SENT' | 'AMBIGUOUS_PENDING_RECONCILIATION';
  providerUsed: string;
  providerMessageId?: string;
  failoverAttempted: boolean;
}

/**
 * Dispatches across Primary -> Backup providers safely:
 * - Never fails over on AMBIGUOUS_POST_WRITE (prevents duplicate OTPs/emails across providers).
 * - Immediately fails over on DEFINITIVE_PRE_ACCEPTANCE or when primary circuit breaker is OPEN.
 */
export async function dispatchWithSafeMultiProviderFailover<TPayload>(
  adapters: [MessagingProviderAdapter<TPayload>, ...MessagingProviderAdapter<TPayload>[]],
  payload: TPayload,
  idempotencyKey: string
): Promise<SafeDispatchResult> {
  let failoverAttempted = false;
  let lastError: Error | undefined;

  for (let i = 0; i < adapters.length; i++) {
    const adapter = adapters[i];
    if (adapter.isCircuitOpen()) {
      failoverAttempted = true;
      continue;
    }

    try {
      const res = await adapter.send(payload, idempotencyKey);
      return {
        status: 'SENT',
        providerUsed: adapter.providerId,
        providerMessageId: res.providerMessageId,
        failoverAttempted,
      };
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (err instanceof ProviderDispatchError) {
        if (err.failureClass === 'AMBIGUOUS_POST_WRITE') {
          // Stop! Provider may have accepted the message before connection drop.
          // Do not send to secondary provider; mark for status reconciliation.
          return {
            status: 'AMBIGUOUS_PENDING_RECONCILIATION',
            providerUsed: adapter.providerId,
            failoverAttempted,
          };
        }
        if (err.failureClass === 'PERMANENT_RECIPIENT_ERROR') {
          throw err;
        }
        // DEFINITIVE_PRE_ACCEPTANCE: safe to fail over to next provider in chain
        failoverAttempted = true;
        continue;
      }
      throw err;
    }
  }

  throw lastError ?? new Error('ALL_MESSAGING_PROVIDERS_UNAVAILABLE');
}
```

---

## 6. Two-Tier Suppression Gate with Automatic Cross-Channel Security Fallback

```typescript
export type PriorityLane = 'P0_CRITICAL_OTP' | 'P1_TRANSACTIONAL' | 'P2_BULK_MARKETING';
export type DeliveryChannel = 'EMAIL' | 'SMS' | 'PUSH' | 'IN_APP';

export function evaluateSuppressionAndChannelRouting(params: {
  requestedChannel: DeliveryChannel;
  priorityLane: PriorityLane;
  isHardBouncedOrComplained: boolean;
  userOptedInToMarketingTopic: boolean;
  isCurrentlyInUserQuietHours: boolean;
  availableFallbackChannels: DeliveryChannel[];
}): {
  decision: 'ALLOW_PRIMARY' | 'REROUTE_FALLBACK_CHANNEL' | 'HOLD_FOR_QUIET_HOURS' | 'DROP_OPTED_OUT' | 'BLOCK_ALL_SUPPRESSED';
  targetChannel?: DeliveryChannel;
  reason: string;
} {
  // 1. Transport-Level Suppression (HARD_BOUNCE / SPAM_COMPLAINT) MUST NEVER be bypassed on that channel
  if (params.isHardBouncedOrComplained) {
    if (params.priorityLane === 'P0_CRITICAL_OTP' || params.priorityLane === 'P1_TRANSACTIONAL') {
      const fallback = params.availableFallbackChannels.find((ch) => ch !== params.requestedChannel);
      if (fallback) {
        return {
          decision: 'REROUTE_FALLBACK_CHANNEL',
          targetChannel: fallback,
          reason: `Primary channel ${params.requestedChannel} is hard-bounced/suppressed; rerouted critical message to ${fallback}`,
        };
      }
    }
    return {
      decision: 'BLOCK_ALL_SUPPRESSED',
      reason: `Channel ${params.requestedChannel} is transport-suppressed (hard bounce or spam complaint)`,
    };
  }

  // 2. P0_CRITICAL_OTP and P1_TRANSACTIONAL bypass marketing opt-outs and Quiet Hours
  if (params.priorityLane === 'P0_CRITICAL_OTP' || params.priorityLane === 'P1_TRANSACTIONAL') {
    return {
      decision: 'ALLOW_PRIMARY',
      targetChannel: params.requestedChannel,
      reason: 'Critical/Transactional lane bypasses marketing preferences and quiet hours',
    };
  }

  // 3. P2_BULK_MARKETING respects user opt-in and Quiet Hours
  if (!params.userOptedInToMarketingTopic) {
    return { decision: 'DROP_OPTED_OUT', reason: 'User opted out of marketing topic' };
  }
  if (params.isCurrentlyInUserQuietHours) {
    return { decision: 'HOLD_FOR_QUIET_HOURS', reason: 'Deferred until user quiet hours end' };
  }

  return {
    decision: 'ALLOW_PRIMARY',
    targetChannel: params.requestedChannel,
    reason: 'Marketing consent verified and outside quiet hours',
  };
}
```
