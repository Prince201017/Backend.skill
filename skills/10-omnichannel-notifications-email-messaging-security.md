# Module 10: Omnichannel Notifications, Email, SMS & Messaging Security

## 1. Scope & Threat Model

This module establishes the architecture and security controls for transactional and bulk notifications across **Email** (SES, Postmark, SendGrid, Resend), **SMS / WhatsApp** (Twilio, MessageBird), **Push Notifications** (FCM, APNs, WebPush), and **In-App Notification Centers**.

### Trust Boundaries & Failure Modes
1. **SMS / Toll-Fraud Budget Exhaustion (Reserve vs. Commit/Release)**:
   - *Vulnerability*: Unconditionally deducting a tenant's SMS spend budget (`spentCents += estimatedCostCents`) before calling the provider causes permanent budget loss when a message is rejected pre-acceptance (e.g., invalid recipient, local validation error, or deterministic `400 Bad Request` / `422 Unprocessable Entity` from the provider). Conversely, checking budget without reserving it allows concurrent requests to race past the tenant's spend cap.
   - *Enforcement*: Implement a 3-phase **Reserve -> Commit / Release** atomic state machine (`reserveSmsQuotaAndBudgetAtomically`, `commitSmsBudgetReservation`, `releaseSmsBudgetReservationOnPreAcceptanceFailure`).
2. **Provider Acceptance vs. Terminal Handset/Inbox Delivery**:
   - *Vulnerability*: Treating a `200 OK` / `202 Accepted` response from Twilio, SES, or SendGrid as proof that the user received the message (`DELIVERED`), or failing over to a secondary provider on an ambiguous `502`/`504` response and double-sending an OTP or invoice.
   - *Enforcement*: Model `ACCEPTED_BY_PROVIDER` separately from terminal `DELIVERED` / `BOUNCED` / `UNDELIVERED` states updated via signed provider status webhooks.
3. **HTTP `502` / `503` / `504` Ambiguous Post-Write Failover Contradiction**:
   - *Vulnerability*: Treating `502 Bad Gateway`, `504 Gateway Timeout`, or post-write `503 Service Unavailable` as safe for immediate multi-provider failover causes duplicate messages when the primary provider already accepted the request upstream.
   - *Enforcement*: Classify pre-connection errors (`ECONNREFUSED`, DNS failure, pre-TLS reset) as `SAFE_PRE_SEND_FAILOVER`, and classify `502`, `504`, `ETIMEDOUT`, and post-write `503` strictly as `AMBIGUOUS_POST_WRITE` requiring provider status query or idempotency reconciliation before any retry or failover.
4. **Recipient Verification, Channel Eligibility & Consent / Opt-Out Enforcement**:
   - *Enforcement*: Before reserving budget or dispatching any message, verify that the recipient address/phone belongs to the target user/tenant (`verified === true` for security-critical or transactional SMS), the channel is enabled for the template category, and the recipient has not opted out (`STOP` / RFC 8058 `List-Unsubscribe-Post`) unless the message is a mandatory security/legal notice permitted by law.

---

## 2. Atomic SMS Budget Reservation (`Reserve -> Commit / Release`) & Recipient Consent Guard

```typescript
// Executable TypeScript — Atomic 3-Phase SMS Budget Reservation & Consent Guard
export type NotificationClassification = 'SECURITY_CRITICAL' | 'TRANSACTIONAL' | 'MARKETING';

export type DeliveryLifecycleStatus =
  | 'BUDGET_RESERVED'
  | 'PRE_SEND_RELEASED'
  | 'ACCEPTED_BY_PROVIDER'
  | 'AMBIGUOUS_RECONCILIATION_REQUIRED'
  | 'DELIVERED'
  | 'BOUNCED_OR_UNDELIVERED';

export interface RecipientChannelProfile {
  tenantId: string;
  recipientId: string;
  e164Phone: string;
  phoneVerified: boolean;
  smsOptedOut: boolean; // Set via inbound "STOP" webhook
  marketingConsentGranted: boolean;
}

export interface SmsBudgetReservationRecord {
  reservationId: string;
  tenantId: string;
  idempotencyKey: string;
  providerIdempotencyKey: string;
  reservedCostCents: number;
  status: DeliveryLifecycleStatus;
  providerMessageSid?: string;
  createdAtMs: number;
}

export interface SmsQuotaBudgetStore {
  getRecipientProfile(tenantId: string, recipientId: string): Promise<RecipientChannelProfile | null>;
  reserveBudgetAtomically(params: {
    reservationId: string;
    tenantId: string;
    recipientId: string;
    classification: NotificationClassification;
    idempotencyKey: string;
    providerIdempotencyKey: string;
    e164Phone: string;
    costCents: number;
    maxDailyBudgetCents: number;
    maxPhoneHourlyCount: number;
    maxSubnetHourlyCount: number;
    clientIpSubnet24: string;
    nowMs: number;
  }): Promise<
    | { outcome: 'RESERVED'; reservation: SmsBudgetReservationRecord }
    | { outcome: 'IDEMPOTENT_REPLAY'; reservation: SmsBudgetReservationRecord }
    | {
        outcome: 'REJECTED';
        reason:
          | 'DAILY_BUDGET_EXCEEDED'
          | 'PHONE_RATE_LIMIT'
          | 'SUBNET_RATE_LIMIT'
          | 'CONSENT_REVOKED_OR_OPTED_OUT';
      }
  >;
  commitReservation(params: {
    reservationId: string;
    tenantId: string;
    providerMessageSid: string;
    actualCommittedCents?: number;
  }): Promise<void>;
  releaseReservation(params: {
    reservationId: string;
    tenantId: string;
    reason: string;
  }): Promise<void>;
  markReservationAmbiguous(params: {
    reservationId: string;
    tenantId: string;
    reason: string;
    providerMessageSid?: string;
  }): Promise<void>;
}

const E164_REGEX = /^\+[1-9]\d{7,14}$/;
const BLOCKED_PREMIUM_PREFIXES = ['+1900', '+1976', '+4490', '+4470'] as const;

export function validateRecipientAndConsent(params: {
  profile: RecipientChannelProfile | null;
  classification: NotificationClassification;
  e164Phone: string;
  allowedCountryPrefixes: readonly string[];
}): void {
  const { profile, classification, e164Phone, allowedCountryPrefixes } = params;
  if (!E164_REGEX.test(e164Phone)) {
    throw new Error('SMS_INVALID_E164_PHONE');
  }
  if (BLOCKED_PREMIUM_PREFIXES.some((prefix) => e164Phone.startsWith(prefix))) {
    throw new Error('SMS_PREMIUM_NUMBER_BLOCKED');
  }
  if (!allowedCountryPrefixes.some((prefix) => e164Phone.startsWith(prefix))) {
    throw new Error('SMS_COUNTRY_PREFIX_NOT_ALLOWED');
  }
  if (!profile || profile.e164Phone !== e164Phone) {
    throw new Error('SMS_RECIPIENT_PROFILE_MISMATCH');
  }
  if (!profile.phoneVerified) {
    throw new Error('SMS_RECIPIENT_PHONE_NOT_VERIFIED');
  }
  // Enforce opt-out & marketing consent rules
  if (classification === 'MARKETING') {
    if (profile.smsOptedOut || !profile.marketingConsentGranted) {
      throw new Error('SMS_MARKETING_CONSENT_REQUIRED');
    }
  } else if (classification === 'TRANSACTIONAL' && profile.smsOptedOut) {
    throw new Error('SMS_RECIPIENT_OPTED_OUT');
  }
}
```

---

## 3. Provider Failover Classification & Ambiguous Write Handling (`DEVIL-18` Remediated)

```typescript
// Executable TypeScript — Deterministic Provider Error Classification & Safe Dispatch
export type ProviderFailureCategory =
  | 'DETERMINISTIC_PRE_ACCEPTANCE_REJECTION' // 400, 401, 403, 404, 422 -> Release budget reservation, do not failover
  | 'SAFE_PRE_SEND_FAILOVER'                 // DNS failure, ECONNREFUSED before bytes written -> Failover allowed
  | 'AMBIGUOUS_POST_WRITE';                  // 502, 503 (post-write), 504, ETIMEDOUT, ECONNRESET -> Hold reservation & reconcile!

export interface ProviderSendAttemptError {
  httpStatus?: number;
  networkCode?: 'ENOTFOUND' | 'ECONNREFUSED' | 'ETIMEDOUT' | 'ECONNRESET';
  requestBytesWritten: boolean;
  message: string;
}

export function classifyNotificationProviderFailure(
  err: ProviderSendAttemptError
): ProviderFailureCategory {
  if (err.httpStatus !== undefined) {
    if (err.httpStatus >= 400 && err.httpStatus < 500 && err.httpStatus !== 408 && err.httpStatus !== 429) {
      return 'DETERMINISTIC_PRE_ACCEPTANCE_REJECTION';
    }
    if (err.httpStatus === 429) {
      // Rate-limited before acceptance: safe to release or retry with backoff
      return 'SAFE_PRE_SEND_FAILOVER';
    }
    // 500, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout, 408 Request Timeout:
    // If request bytes were written to the socket, the upstream provider may have accepted the message!
    if (err.requestBytesWritten) {
      return 'AMBIGUOUS_POST_WRITE';
    }
    return 'SAFE_PRE_SEND_FAILOVER';
  }

  if (err.networkCode === 'ENOTFOUND' || (err.networkCode === 'ECONNREFUSED' && !err.requestBytesWritten)) {
    return 'SAFE_PRE_SEND_FAILOVER';
  }

  return 'AMBIGUOUS_POST_WRITE';
}

export interface SmsProviderAdapter {
  readonly providerName: string;
  sendSms(params: {
    idempotencyKey: string;
    to: string;
    body: string;
  }): Promise<{ providerMessageSid: string }>;
}

export async function dispatchSmsWithBudgetAndFailover(params: {
  store: SmsQuotaBudgetStore;
  primaryProvider: SmsProviderAdapter;
  secondaryProvider?: SmsProviderAdapter;
  reservationId: string;
  tenantId: string;
  recipientId: string;
  e164Phone: string;
  body: string;
  classification: NotificationClassification;
  idempotencyKey: string;
  costCents: number;
  maxDailyBudgetCents: number;
  maxPhoneHourlyCount: number;
  maxSubnetHourlyCount: number;
  clientIpSubnet24: string;
  allowedCountryPrefixes: readonly string[];
  nowMs?: number;
}): Promise<{
  status: DeliveryLifecycleStatus;
  providerMessageSid?: string;
  providerUsed?: string;
}> {
  const profile = await params.store.getRecipientProfile(params.tenantId, params.recipientId);
  validateRecipientAndConsent({
    profile,
    classification: params.classification,
    e164Phone: params.e164Phone,
    allowedCountryPrefixes: params.allowedCountryPrefixes,
  });

  const providerIdempotencyKey = `${params.tenantId}:${params.reservationId}:${params.idempotencyKey}`;

  // Phase 1: Atomic Budget, Consent & Rate-Limit Reservation
  const resResult = await params.store.reserveBudgetAtomically({
    reservationId: params.reservationId,
    tenantId: params.tenantId,
    recipientId: params.recipientId,
    classification: params.classification,
    idempotencyKey: params.idempotencyKey,
    providerIdempotencyKey,
    e164Phone: params.e164Phone,
    costCents: params.costCents,
    maxDailyBudgetCents: params.maxDailyBudgetCents,
    maxPhoneHourlyCount: params.maxPhoneHourlyCount,
    maxSubnetHourlyCount: params.maxSubnetHourlyCount,
    clientIpSubnet24: params.clientIpSubnet24,
    nowMs: params.nowMs ?? Date.now(),
  });

  if (resResult.outcome === 'REJECTED') {
    throw new Error(`SMS_BUDGET_OR_QUOTA_REJECTED:${resResult.reason}`);
  }
  if (resResult.outcome === 'IDEMPOTENT_REPLAY') {
    return {
      status: resResult.reservation.status,
      providerMessageSid: resResult.reservation.providerMessageSid,
    };
  }

  // DEVIL-18 Fix: Re-verify fresh recipient consent immediately before provider dispatch
  // so an inbound STOP webhook processed concurrently with reservation cancels the send and releases budget!
  try {
    const freshProfile = await params.store.getRecipientProfile(params.tenantId, params.recipientId);
    validateRecipientAndConsent({
      profile: freshProfile,
      classification: params.classification,
      e164Phone: params.e164Phone,
      allowedCountryPrefixes: params.allowedCountryPrefixes,
    });
  } catch (consentErr) {
    await params.store.releaseReservation({
      reservationId: params.reservationId,
      tenantId: params.tenantId,
      reason: consentErr instanceof Error ? consentErr.message : 'CONSENT_REVOKED_PRE_SEND',
    });
    throw consentErr;
  }

  // Phase 2: Primary Provider Attempt (Isolated from Phase 3a DB commit!)
  let primaryRes: { providerMessageSid: string } | null = null;
  let primarySendErr: ProviderSendAttemptError | null = null;
  try {
    primaryRes = await params.primaryProvider.sendSms({
      idempotencyKey: providerIdempotencyKey,
      to: params.e164Phone,
      body: params.body,
    });
  } catch (rawErr) {
    primarySendErr = rawErr as ProviderSendAttemptError;
  }

  // DEVIL-18 Fix: If primaryProvider.sendSms SUCCEEDED, NEVER enter provider failover if commitReservation throws!
  if (primaryRes !== null) {
    try {
      await params.store.commitReservation({
        reservationId: params.reservationId,
        tenantId: params.tenantId,
        providerMessageSid: primaryRes.providerMessageSid,
      });
      return {
        status: 'ACCEPTED_BY_PROVIDER',
        providerMessageSid: primaryRes.providerMessageSid,
        providerUsed: params.primaryProvider.providerName,
      };
    } catch (commitErr) {
      // Post-acceptance DB commit failure: record providerMessageSid in ambiguous state for reconciliation; NEVER re-send!
      await params.store
        .markReservationAmbiguous({
          reservationId: params.reservationId,
          tenantId: params.tenantId,
          reason: `POST_ACCEPTANCE_DB_COMMIT_FAILED:${commitErr instanceof Error ? commitErr.message : String(commitErr)}`,
          providerMessageSid: primaryRes.providerMessageSid,
        })
        .catch(() => undefined);
      return {
        status: 'AMBIGUOUS_RECONCILIATION_REQUIRED',
        providerMessageSid: primaryRes.providerMessageSid,
        providerUsed: params.primaryProvider.providerName,
      };
    }
  }

  const providerErr = primarySendErr!;
  const category = classifyNotificationProviderFailure(providerErr);

  if (category === 'DETERMINISTIC_PRE_ACCEPTANCE_REJECTION') {
    // Phase 3b: Release budget reservation immediately so rejected sends never permanently consume budget
    await params.store.releaseReservation({
      reservationId: params.reservationId,
      tenantId: params.tenantId,
      reason: providerErr.message,
    });
    throw new Error(`SMS_PROVIDER_REJECTED_PRE_ACCEPTANCE:${providerErr.message}`);
  }

  if (category === 'AMBIGUOUS_POST_WRITE') {
    // Phase 3c: 502 / 504 / post-write 503 / ETIMEDOUT -> NEVER blindly failover and double-send!
    await params.store.markReservationAmbiguous({
      reservationId: params.reservationId,
      tenantId: params.tenantId,
      reason: providerErr.message,
    });
    return {
      status: 'AMBIGUOUS_RECONCILIATION_REQUIRED',
    };
  }

  // SAFE_PRE_SEND_FAILOVER: Try secondary provider if configured
  if (!params.secondaryProvider) {
    await params.store.releaseReservation({
      reservationId: params.reservationId,
      tenantId: params.tenantId,
      reason: providerErr.message,
    });
    throw new Error(`SMS_PRE_SEND_FAILED_NO_SECONDARY:${providerErr.message}`);
  }

  let secondaryRes: { providerMessageSid: string } | null = null;
  try {
    secondaryRes = await params.secondaryProvider.sendSms({
      idempotencyKey: providerIdempotencyKey,
      to: params.e164Phone,
      body: params.body,
    });
  } catch (secRawErr) {
    const secErr = secRawErr as ProviderSendAttemptError;
    const secCategory = classifyNotificationProviderFailure(secErr);
    if (secCategory === 'AMBIGUOUS_POST_WRITE') {
      await params.store.markReservationAmbiguous({
        reservationId: params.reservationId,
        tenantId: params.tenantId,
        reason: secErr.message,
      });
      return { status: 'AMBIGUOUS_RECONCILIATION_REQUIRED' };
    }
    await params.store.releaseReservation({
      reservationId: params.reservationId,
      tenantId: params.tenantId,
      reason: secErr.message,
    });
    throw new Error(`SMS_SECONDARY_PROVIDER_REJECTED:${secErr.message}`);
  }

  try {
    await params.store.commitReservation({
      reservationId: params.reservationId,
      tenantId: params.tenantId,
      providerMessageSid: secondaryRes.providerMessageSid,
    });
    return {
      status: 'ACCEPTED_BY_PROVIDER',
      providerMessageSid: secondaryRes.providerMessageSid,
      providerUsed: params.secondaryProvider.providerName,
    };
  } catch (secCommitErr) {
    await params.store
      .markReservationAmbiguous({
        reservationId: params.reservationId,
        tenantId: params.tenantId,
        reason: `POST_ACCEPTANCE_DB_COMMIT_FAILED:${secCommitErr instanceof Error ? secCommitErr.message : String(secCommitErr)}`,
        providerMessageSid: secondaryRes.providerMessageSid,
      })
      .catch(() => undefined);
    return {
      status: 'AMBIGUOUS_RECONCILIATION_REQUIRED',
      providerMessageSid: secondaryRes.providerMessageSid,
      providerUsed: params.secondaryProvider.providerName,
    };
  }
}

/**
 * Orphaned SMS Budget Reservation Sweeper (PRESENT-WEAKNESS-08 Remediation):
 * Prevents tenant SMS budgets from leaking permanently if a worker crashes while holding
 * a BUDGET_RESERVED row or if an AMBIGUOUS_RECONCILIATION_REQUIRED row needs provider lookup.
 */
export async function reconcileStaleSmsBudgetReservations(params: {
  staleRecords: readonly SmsBudgetReservationRecord[];
  store: SmsQuotaBudgetStore;
  queryProviderStatusByIdempotencyKey: (idempotencyKey: string) => Promise<
    | { found: true; providerMessageSid: string }
    | { found: false }
    | { indeterminate: true }
  >;
}): Promise<{ committedCount: number; releasedCount: number; pendingCount: number }> {
  let committedCount = 0;
  let releasedCount = 0;
  let pendingCount = 0;

  for (const rec of params.staleRecords) {
    const lookup = await params.queryProviderStatusByIdempotencyKey(rec.idempotencyKey);
    if ('found' in lookup && lookup.found) {
      await params.store.commitReservation({
        reservationId: rec.reservationId,
        tenantId: rec.tenantId,
        providerMessageSid: lookup.providerMessageSid,
      });
      committedCount += 1;
    } else if ('found' in lookup && !lookup.found) {
      await params.store.releaseReservation({
        reservationId: rec.reservationId,
        tenantId: rec.tenantId,
        reason: 'STALE_RESERVATION_RECONCILED_NOT_SENT',
      });
      releasedCount += 1;
    } else {
      pendingCount += 1;
    }
  }
  return { committedCount, releasedCount, pendingCount };
}
```

---

## 4. Email Header Injection Defense & Strict Context Template Escaping

- **CRLF Header Guard**: Every `To`, `Cc`, `Bcc`, `Subject`, `Reply-To`, and custom header value MUST reject `\r`, `\n`, `%0a`, `%0d`, and null bytes (`\0`).
- **Context-Aware HTML Escaping**: Never concatenate user fields (`firstName`, `organizationName`, `invoiceMemo`) into HTML templates without escaping `&`, `<`, `>`, `"`, `'`, and `` ` ``. URLs injected into `href` attributes must be parsed with `new URL()` and restricted to `https:` (never `javascript:` or `data:`).
- **Authenticated Domain Alignment**: Enforce SPF (`-all`), DKIM (2048-bit RSA), and DMARC (`p=reject; pct=100`).
