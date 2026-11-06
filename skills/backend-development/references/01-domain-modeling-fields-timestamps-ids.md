# Module 01: Domain Modeling, Field Logic, Calculations, Timestamps & Cryptographic Generators

This reference provides production-grade implementations for designing the backend data model for any frontend, strict field-type logic, deterministic financial calculations, UTC temporal management, and cryptographic ID/Token/OTP/Reference generators.

---

## 1. Frontend-to-Backend Schema Reverse-Engineering Matrix

When presented with any frontend component or screen, map every element to backend infrastructure:

| Frontend Pattern | Required Backend Infrastructure |
| :--- | :--- |
| **Search Bar + Filter Sidebar + Sort Dropdown** | Whitelisted sortable columns (`ALLOWED_SORTS`), indexed filter columns, parameterized SQL/NoSQL queries, cursor pagination (`cursor`, `limit`), and full-text search index (`tsvector` GIN or Meilisearch/Elasticsearch). |
| **Multi-Step Wizard / Onboarding Form** | Draft state table (`onboarding_drafts` with `step`, `payload JSONB`, `updated_at`) + strict per-step Zod schema + atomic finalization transaction that promotes draft to permanent domain tables. |
| **Checkout / Cart / Subscription Upgrade** | Server-side price lookup from `products`/`plans` table (never accept price from request body), coupon validator with atomic `used_count < max_uses` increment, tax calculator, `Idempotency-Key` middleware, and payment intent creation. |
| **Dashboard KPI Cards & Time-Series Charts** | Pre-aggregated materialized views or Redis-cached rollups bucketed by user's requested IANA timezone (`AT TIME ZONE $tz`), backed by read replicas. |
| **Real-Time Status / Notifications Bell** | Outbox-backed `notifications` table (`read_at TIMESTAMPTZ NULL`) + SSE/WebSocket push channel + optimistic `PATCH /api/v1/notifications/read-all`. |

---

## 2. Field Type Logic Design & Validation Engine (TypeScript + Zod)

```typescript
import { z } from 'zod';

/**
 * Canonical Field Validators — Never trust raw strings, numbers, or client formats.
 */
export const FieldSchemas = {
  // UUIDv7 or UUIDv4 identifier
  id: z.string().uuid({ message: 'Invalid UUID identifier' }),

  // Normalized Email: NFC/NFKC normalized, trimmed, lowercased, max 254 chars (RFC 5321)
  email: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .transform((v) => v.normalize('NFKC').toLowerCase())
    .pipe(z.string().email()),

  // E.164 Phone Number (+14155552671)
  e164Phone: z
    .string()
    .trim()
    .regex(/^\+[1-9]\d{6,14}$/, 'Phone must be in E.164 format (e.g. +14155552671)'),

  // ISO-4217 Currency Code
  currencyCode: z
    .string()
    .trim()
    .toUpperCase()
    .regex(/^[A-Z]{3}$/, 'Must be a 3-letter ISO-4217 currency code'),

  // Monetary Minor Units (e.g., cents/paise as integer or BigInt string)
  moneyMinorUnits: z
    .union([z.number().int().nonnegative().safe(), z.string().regex(/^\d+$/)])
    .transform((v) => BigInt(v)),

  // Basis Points (0 to 10000 = 0.00% to 100.00%)
  basisPoints: z.number().int().min(0).max(100_000),

  // Strict UTC ISO-8601 Timestamp
  isoUtcTimestamp: z
    .string()
    .datetime({ offset: true })
    .transform((v) => new Date(v).toISOString()),

  // IANA Timezone Identifier (e.g., "America/New_York", "Asia/Kolkata")
  ianaTimezone: z.string().refine(
    (tz) => {
      try {
        Intl.DateTimeFormat(undefined, { timeZone: tz });
        return true;
      } catch {
        return false;
      }
    },
    { message: 'Invalid IANA timezone identifier' }
  ),
};
```

---

## 3. Deterministic Financial & Business Calculation Engine

Never use IEEE-754 floating-point math (`0.1 + 0.2 === 0.30000000000000004`) for money, inventory, or billing.

```typescript
export interface LineItemInput {
  skuId: string;
  quantity: bigint;
  unitPriceMinor: bigint; // Authoritative price fetched from DB, NEVER from client
  taxRateBps: bigint;     // e.g., 825n = 8.25%
}

export interface OrderCalculationResult {
  subtotalMinor: bigint;
  discountMinor: bigint;
  taxMinor: bigint;
  shippingMinor: bigint;
  grandTotalMinor: bigint;
}

/**
 * Banker's Rounding (Round Half to Even) for BigInt division:
 * Computes round(numerator / denominator) deterministically.
 */
export function divRoundHalfEven(numerator: bigint, denominator: bigint): bigint {
  if (denominator === 0n) throw new Error('Division by zero');
  const quotient = numerator / denominator;
  const remainder = numerator % denominator;
  const twiceRemainder = remainder * 2n;

  if (twiceRemainder > denominator) {
    return quotient + 1n;
  }
  if (twiceRemainder < denominator) {
    return quotient;
  }
  // Exact half-way: round to nearest even integer
  return quotient % 2n === 0n ? quotient : quotient + 1n;
}

export function calculateOrderTotals(
  items: LineItemInput[],
  discountBps: bigint,
  maxDiscountCapMinor: bigint | null,
  shippingMinor: bigint
): OrderCalculationResult {
  let subtotalMinor = 0n;
  for (const item of items) {
    if (item.quantity <= 0n || item.unitPriceMinor < 0n) {
      throw new Error(`Invalid quantity or unit price for SKU ${item.skuId}`);
    }
    subtotalMinor += item.quantity * item.unitPriceMinor;
  }

  // Calculate discount in minor units using basis points (10000 bps = 100%)
  let discountMinor = divRoundHalfEven(subtotalMinor * discountBps, 10_000n);
  if (maxDiscountCapMinor !== null && discountMinor > maxDiscountCapMinor) {
    discountMinor = maxDiscountCapMinor;
  }
  if (discountMinor > subtotalMinor) {
    discountMinor = subtotalMinor;
  }

  const discountedSubtotal = subtotalMinor - discountMinor;

  // Pro-rate discount across line items to compute accurate tax per item
  let taxMinor = 0n;
  for (const item of items) {
    const lineRaw = item.quantity * item.unitPriceMinor;
    const lineDiscounted =
      subtotalMinor > 0n
        ? divRoundHalfEven(lineRaw * discountedSubtotal, subtotalMinor)
        : 0n;
    taxMinor += divRoundHalfEven(lineDiscounted * item.taxRateBps, 10_000n);
  }

  const grandTotalMinor = discountedSubtotal + taxMinor + shippingMinor;

  return {
    subtotalMinor,
    discountMinor,
    taxMinor,
    shippingMinor,
    grandTotalMinor,
  };
}
```

---

## 4. Cryptographic ID, Token, OTP & Complex Generation Engines

```typescript
import crypto from 'node:crypto';

const CROCKFORD_BASE32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const UNAMBIGUOUS_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Excludes 0, O, 1, I, L

/**
 * 1. RFC 9562 UUIDv7 Generator (48-bit Unix ms timestamp + 74-bit CSPRNG)
 * Sortable, K-ordered, ideal for PostgreSQL Primary Keys without B-Tree fragmentation.
 */
export function generateUuidV7(nowMs: number = Date.now()): string {
  const bytes = crypto.randomBytes(16);
  const timeBig = BigInt(nowMs);

  // 48-bit timestamp big-endian
  bytes[0] = Number((timeBig >> 40n) & 0xffn);
  bytes[1] = Number((timeBig >> 32n) & 0xffn);
  bytes[2] = Number((timeBig >> 24n) & 0xffn);
  bytes[3] = Number((timeBig >> 16n) & 0xffn);
  bytes[4] = Number((timeBig >> 8n) & 0xffn);
  bytes[5] = Number(timeBig & 0xffn);

  // Version 7 (0111) in high nibble of byte 6
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  // Variant RFC 4122 (10xx) in high bits of byte 8
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * 2. 64-bit Snowflake ID Generator (Time-ordered distributed integer ID)
 * Layout: 1 bit sign (0) | 41 bits timestamp offset | 10 bits workerId | 12 bits sequence
 */
export class SnowflakeGenerator {
  private static readonly EPOCH = 1704067200000n; // 2024-01-01T00:00:00Z
  private sequence = 0n;
  private lastTimestamp = -1n;
  private readonly workerId: bigint;

  constructor(workerId: number) {
    if (workerId < 0 || workerId > 1023) {
      throw new Error('Worker ID must be between 0 and 1023 (10 bits)');
    }
    this.workerId = BigInt(workerId);
  }

  public nextId(): bigint {
    let now = BigInt(Date.now());
    if (now < this.lastTimestamp) {
      throw new Error(`Clock moved backwards by ${this.lastTimestamp - now}ms`);
    }
    if (now === this.lastTimestamp) {
      this.sequence = (this.sequence + 1n) & 0xfffn; // 4096 per ms
      if (this.sequence === 0n) {
        while (now <= this.lastTimestamp) {
          now = BigInt(Date.now());
        }
      }
    } else {
      this.sequence = 0n;
    }
    this.lastTimestamp = now;
    return ((now - SnowflakeGenerator.EPOCH) << 22n) | (this.workerId << 12n) | this.sequence;
  }
}

/**
 * 3. Prefix-Scoped Secret API Key Generator with SHA-256 Storage Hash
 * Example output: "sk_live_7b9f2a8c..." (show once to user, store only hash + hint in DB)
 */
export function generateScopedApiKey(prefix: 'sk_live' | 'sk_test' | 'pk_live' | 'whsec'): {
  plaintextKey: string;
  keyHash: string;
  displayHint: string;
} {
  const entropy = crypto.randomBytes(32).toString('base64url');
  const plaintextKey = `${prefix}_${entropy}`;
  const keyHash = crypto.createHash('sha256').update(plaintextKey).digest('hex');
  const displayHint = `${prefix}_...${entropy.slice(-4)}`;
  return { plaintextKey, keyHash, displayHint };
}

/**
 * 4. Cryptographic OTP Generator & Constant-Time Verifier
 */
export function generateOtpCode(digits: 6 | 8 = 6, pepperSecret: string, contextId: string): {
  code: string;
  hmacDigest: string;
  expiresAt: Date;
} {
  const max = 10 ** digits;
  const rawInt = crypto.randomInt(0, max);
  const code = rawInt.toString().padStart(digits, '0');
  const hmacDigest = crypto
    .createHmac('sha256', pepperSecret)
    .update(`${contextId}:${code}`)
    .digest('hex');
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes TTL
  return { code, hmacDigest, expiresAt };
}

export function verifyOtpCodeConstantTime(
  submittedCode: string,
  expectedHmacHex: string,
  pepperSecret: string,
  contextId: string
): boolean {
  const actualHmac = crypto
    .createHmac('sha256', pepperSecret)
    .update(`${contextId}:${submittedCode}`)
    .digest();
  const expectedBuffer = Buffer.from(expectedHmacHex, 'hex');
  if (actualHmac.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(actualHmac, expectedBuffer);
}

/**
 * 5. Human-Readable Reference Code with Luhn Mod N Check Character
 * Example: "INV-2026-9K4M7P-C" — catches typos before hitting the database.
 */
export function generateHumanReferenceCode(prefix: string, bodyLength = 8): string {
  let body = '';
  for (let i = 0; i < bodyLength; i++) {
    const idx = crypto.randomInt(0, UNAMBIGUOUS_ALPHABET.length);
    body += UNAMBIGUOUS_ALPHABET[idx];
  }
  const checkChar = computeLuhnModN(body, UNAMBIGUOUS_ALPHABET);
  return `${prefix}-${body}-${checkChar}`;
}

function computeLuhnModN(input: string, alphabet: string): string {
  const n = alphabet.length;
  let factor = 2;
  let sum = 0;
  for (let i = input.length - 1; i >= 0; i--) {
    const codePoint = alphabet.indexOf(input[i]);
    if (codePoint === -1) throw new Error(`Invalid character in code: ${input[i]}`);
    let addend = factor * codePoint;
    factor = factor === 2 ? 1 : 2;
    addend = Math.floor(addend / n) + (addend % n);
    sum += addend;
  }
  const remainder = sum % n;
  const checkCodePoint = (n - remainder) % n;
  return alphabet[checkCodePoint];
}
```

---

## 5. Timestamp, Date & Temporal Database Design

```sql
-- PostgreSQL Temporal Best-Practice Table Template
CREATE TABLE bookings (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    -- Always use TIMESTAMPTZ (UTC stored internally)
    starts_at_utc TIMESTAMPTZ NOT NULL,
    ends_at_utc TIMESTAMPTZ NOT NULL,
    -- Store original IANA timezone for recurring/calendar wall-clock semantics
    timezone_iana VARCHAR(64) NOT NULL DEFAULT 'UTC',
    -- Prevent invalid time ranges at the database engine level
    CONSTRAINT chk_valid_booking_window CHECK (ends_at_utc > starts_at_utc),
    -- Audit & Concurrency Columns
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    deleted_at TIMESTAMPTZ NULL
);

-- Prevent overlapping bookings for the same resource using PostgreSQL GiST exclusion constraint
CREATE EXTENSION IF NOT EXISTS btree_gist;
ALTER TABLE bookings
ADD CONSTRAINT excl_no_overlapping_bookings
EXCLUDE USING gist (
    organization_id WITH =,
    tstzrange(starts_at_utc, ends_at_utc, '[)') WITH &&
) WHERE (deleted_at IS NULL);
```
