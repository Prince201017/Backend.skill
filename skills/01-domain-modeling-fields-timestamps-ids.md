# Module 01: Domain Modeling, Financial Engine, Timestamps, OTPs & Composable Business Logic

This module provides production-grade TypeScript implementations for domain validation, currency-aware financial engines (with PostgreSQL `BIGINT` bounds checking, jurisdiction-configurable tax rounding, exact Largest-Remainder proration, and partial refund credit notes), atomic one-time OTP verification with attempt throttling, deterministic state machines, and atomic tenant-verified double-entry accounting journals.

---

## 1. Threat Model, Trust Boundaries & Failure Behavior

| Boundary / Component | Threat / Exploit Vector | Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **Currency Registry (`CURRENCY_EXPONENTS_MAP`)** | Passing `"toString"`, `"constructor"`, or `"__proto__"` as `currencyCode` passes `code in CURRENCY_EXPONENTS` on plain objects via `Object.prototype` inheritance. | Domain boundary & schema validation (`Map.has()`). | Rejects immediately with `UNSUPPORTED_CURRENCY_CODE`. |
| **PostgreSQL `BIGINT` Arithmetic** | Unbounded JavaScript `BigInt` (`10n ** 30n`) passes JS math but overflows signed 64-bit PostgreSQL `BIGINT` (`-2^63 .. 2^63 - 1`) at DB write time. | Domain boundary & post-calculation invariant (`assertPgBigIntRange`). | Rejects with `PG_BIGINT_OVERFLOW_REJECTED` before touching DB. |
| **OTP Verification & Consumption** | 1) Passing `expiresAt = undefined` or `new Date('invalid')` (`Date.now() > NaN === false`) bypasses expiry forever.<br>2) Non-atomic verify-then-update allows concurrent replay of the same 6-digit OTP.<br>3) Missing attempt counter allows brute-forcing $10^6$ codes. | Server-side persistence transaction (`verifyAndConsumeOtpAtomically`). | Fails closed on missing/invalid `expiresAt`; locks OTP after `maxAttempts` (default 5); marks `CONSUMED` atomically on match. |
| **Double-Entry Journal Persistence** | 1) `if (dir === 'DEBIT') ... else` treats typos (`'DEBT'`) as `'CREDIT'`.<br>2) Posting to an `accountId` owned by another tenant corrupts cross-tenant balances.<br>3) Validating in memory without atomic persistence + `UNIQUE (tenant_id, idempotency_key)` allows duplicate postings. | Transactional persistence boundary (`persistBalancedJournalAtomically`). | Rolls back transaction on unknown direction, cross-tenant account, currency mismatch, or duplicate `idempotency_key`. |

---

## 2. Field Type Logic Design, `Map`-Backed Currency Registry & PostgreSQL `BIGINT` Bounds

```typescript
import { z } from 'zod';

/**
 * Signed 64-bit PostgreSQL BIGINT limits (-9,223,372,036,854,775,808 to +9,223,372,036,854,775,807).
 * We also enforce a safe pre-multiplication ceiling (PG_BIGINT_SAFE_AMOUNT_MAX = 10^15 minor units)
 * on individual monetary inputs so intermediate multiplication by 10_000n basis points never overflows.
 */
export const PG_BIGINT_MIN = -9_223_372_036_854_775_808n;
export const PG_BIGINT_MAX = 9_223_372_036_854_775_807n;
export const PG_BIGINT_SAFE_INPUT_MAX = 900_000_000_000_000n; // 9 * 10^14 minor units ($9 trillion)

export function assertPgBigIntRange(
  value: bigint,
  fieldName: string,
  options: { allowNegative?: boolean; maxSafeInput?: boolean } = {}
): void {
  const minAllowed = options.allowNegative ? PG_BIGINT_MIN : 0n;
  const maxAllowed = options.maxSafeInput ? PG_BIGINT_SAFE_INPUT_MAX : PG_BIGINT_MAX;
  if (value < minAllowed || value > maxAllowed) {
    throw new Error(
      `PG_BIGINT_RANGE_ERROR: Field "${fieldName}" (${value.toString()}) is outside allowed range [${minAllowed.toString()}, ${maxAllowed.toString()}]`
    );
  }
}

/**
 * ISO-4217 Currency Exponent Registry stored in an immutable Map (never a plain object with 'in' checks,
 * which is vulnerable to Object.prototype property names like "toString", "valueOf", or "constructor").
 */
export const CURRENCY_EXPONENTS_MAP: ReadonlyMap<string, 0 | 2 | 3> = new Map<string, 0 | 2 | 3>([
  ['JPY', 0], ['KRW', 0], ['VND', 0], ['CLP', 0], ['ISK', 0],
  ['USD', 2], ['EUR', 2], ['GBP', 2], ['INR', 2], ['CAD', 2], ['AUD', 2], ['SGD', 2], ['CHF', 2],
  ['BHD', 3], ['KWD', 3], ['OMR', 3], ['JOD', 3], ['TND', 3],
]);

export function getCurrencyExponentStrict(currencyCode: string): 0 | 2 | 3 {
  if (typeof currencyCode !== 'string' || !/^[A-Z]{3}$/.test(currencyCode)) {
    throw new Error(`UNSUPPORTED_CURRENCY_CODE: "${String(currencyCode)}" is not a valid 3-letter ISO-4217 code`);
  }
  const exponent = CURRENCY_EXPONENTS_MAP.get(currencyCode);
  if (exponent === undefined) {
    throw new Error(`UNSUPPORTED_CURRENCY_CODE: "${currencyCode}" is not in the supported currency registry`);
  }
  return exponent;
}

export const FieldSchemas = {
  id: z.string().uuid({ message: 'Invalid UUID identifier' }),

  email: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .transform((v) => v.normalize('NFKC').toLowerCase())
    .pipe(z.string().email()),

  e164Phone: z
    .string()
    .trim()
    .regex(/^\+[1-9]\d{6,14}$/, 'Phone must be in E.164 format (e.g. +14155552671)'),

  currencyCode: z
    .string()
    .trim()
    .toUpperCase()
    .refine((code) => /^[A-Z]{3}$/.test(code) && CURRENCY_EXPONENTS_MAP.has(code), {
      message: 'Unsupported or invalid ISO-4217 currency code',
    }),

  nonNegativeMoneyMinor: z
    .union([z.number().int().nonnegative().safe(), z.string().regex(/^\d{1,19}$/)])
    .transform((v) => BigInt(v))
    .refine((val) => val >= 0n && val <= PG_BIGINT_SAFE_INPUT_MAX, {
      message: 'Monetary amount exceeds safe PostgreSQL BIGINT bounds',
    }),

  signedMoneyMinor: z
    .union([z.number().int().safe(), z.string().regex(/^-?\d{1,19}$/)])
    .transform((v) => BigInt(v))
    .refine((val) => val >= -PG_BIGINT_SAFE_INPUT_MAX && val <= PG_BIGINT_SAFE_INPUT_MAX, {
      message: 'Signed monetary amount exceeds safe PostgreSQL BIGINT bounds',
    }),

  percentageBasisPoints: z
    .number()
    .int()
    .min(0, 'Basis points cannot be negative')
    .max(10_000, 'Percentage basis points cannot exceed 10,000 (100.00%)'),

  strictIsoUtcTimestamp: z
    .string()
    .datetime({ offset: false, message: 'Timestamp must be strict UTC ending with Z' }),

  isoTimestampNormalizedToUtc: z
    .string()
    .datetime({ offset: true })
    .transform((v) => {
      const parsed = new Date(v);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error('Invalid ISO timestamp');
      }
      return parsed.toISOString();
    }),
};
```

---

## 3. Deterministic Financial Engine (Jurisdiction Tax Rounding, Proration & Credit Notes)

### Jurisdiction-Specific Tax Rounding Rules
Tax authorities do **not** mandate a single universal rounding rule across all jurisdictions:
- **US Sales Tax / Standard GAAP & IFRS Ledgers**: Commonly use `HALF_EVEN` (Banker's rounding) or `HALF_UP` (round `0.5` away from zero).
- **EU VAT / UK HMRC / India GST**: Often allow or require `HALF_UP` at the invoice/line level, or `FLOOR` (truncation) on specific statutory withholdings.
Always pass an explicit `taxRoundingMode: TaxRoundingMode` (`'HALF_EVEN' | 'HALF_UP' | 'FLOOR'`) configured for the tenant's tax jurisdiction.

```typescript
export type TaxPricingPolicy = 'TAX_EXCLUSIVE' | 'TAX_INCLUSIVE';
export type TaxRoundingMode = 'HALF_EVEN' | 'HALF_UP' | 'FLOOR';

export interface LineItemInput {
  lineId: string;
  skuId: string;
  quantity: bigint;
  unitPriceMinor: bigint; // Authoritative price from DB, >= 0n
  taxRateBps: bigint;     // 0n..10_000n (e.g., 1800n = 18.00% GST)
}

export interface CalculatedLineItem {
  lineId: string;
  skuId: string;
  quantity: bigint;
  unitPriceMinor: bigint;
  lineSubtotalMinor: bigint;
  proratedDiscountMinor: bigint;
  lineNetMinor: bigint;
  lineTaxMinor: bigint;
  lineTotalMinor: bigint;
}

export interface OrderCalculationInput {
  currencyCode: string;
  taxPolicy: TaxPricingPolicy;
  taxRoundingMode?: TaxRoundingMode; // Defaults to 'HALF_EVEN'; configurable per tax jurisdiction
  items: LineItemInput[];
  discountBps: bigint;               // 0n..10_000n
  fixedDiscountMinor?: bigint;       // Optional fixed voucher amount >= 0n
  maxDiscountCapMinor: bigint | null;
  shippingMinor: bigint;             // >= 0n
  shippingTaxRateBps: bigint;        // 0n..10_000n
}

export interface OrderCalculationResult {
  currencyCode: string;
  currencyExponent: 0 | 2 | 3;
  taxPolicy: TaxPricingPolicy;
  taxRoundingMode: TaxRoundingMode;
  lines: CalculatedLineItem[];
  subtotalMinor: bigint;
  totalDiscountMinor: bigint;
  netMerchandiseMinor: bigint;
  merchandiseTaxMinor: bigint;
  shippingNetMinor: bigint;
  shippingTaxMinor: bigint;
  totalTaxMinor: bigint;
  grandTotalMinor: bigint;
}

/**
 * Configurable integer division with explicit rounding mode ('HALF_EVEN', 'HALF_UP', 'FLOOR').
 */
export function divRoundBigInt(
  numerator: bigint,
  denominator: bigint,
  mode: TaxRoundingMode = 'HALF_EVEN'
): bigint {
  if (denominator <= 0n) throw new Error('Denominator must be a positive BigInt');
  const isNegative = numerator < 0n;
  const absNum = isNegative ? -numerator : numerator;

  const quotient = absNum / denominator;
  const remainder = absNum % denominator;

  if (remainder === 0n) {
    return isNegative ? -quotient : quotient;
  }

  let rounded = quotient;
  if (mode === 'FLOOR') {
    rounded = isNegative ? quotient + 1n : quotient;
  } else if (mode === 'HALF_UP') {
    if (remainder * 2n >= denominator) {
      rounded = quotient + 1n;
    }
  } else {
    // HALF_EVEN (Banker's rounding)
    const twiceRemainder = remainder * 2n;
    if (twiceRemainder > denominator) {
      rounded = quotient + 1n;
    } else if (twiceRemainder === denominator && quotient % 2n !== 0n) {
      rounded = quotient + 1n;
    }
  }

  const result = isNegative ? -rounded : rounded;
  assertPgBigIntRange(result, 'divRoundBigIntResult', { allowNegative: true });
  return result;
}

export function divRoundHalfEven(numerator: bigint, denominator: bigint): bigint {
  return divRoundBigInt(numerator, denominator, 'HALF_EVEN');
}

export function calculateOrderTotals(input: OrderCalculationInput): OrderCalculationResult {
  const currencyExponent = getCurrencyExponentStrict(input.currencyCode);
  const roundingMode: TaxRoundingMode = input.taxRoundingMode ?? 'HALF_EVEN';

  if (input.items.length === 0 || input.items.length > 1000) {
    throw new Error('Order must contain between 1 and 1000 line items');
  }
  if (input.discountBps < 0n || input.discountBps > 10_000n) {
    throw new Error(`Invalid discountBps: ${input.discountBps}. Must be between 0 and 10000`);
  }
  if (input.fixedDiscountMinor !== undefined) {
    assertPgBigIntRange(input.fixedDiscountMinor, 'fixedDiscountMinor', { maxSafeInput: true });
  }
  assertPgBigIntRange(input.shippingMinor, 'shippingMinor', { maxSafeInput: true });
  if (input.shippingTaxRateBps < 0n || input.shippingTaxRateBps > 10_000n) {
    throw new Error('shippingTaxRateBps must be between 0 and 10000');
  }
  if (input.maxDiscountCapMinor !== null) {
    assertPgBigIntRange(input.maxDiscountCapMinor, 'maxDiscountCapMinor', { maxSafeInput: true });
  }

  let subtotalMinor = 0n;
  const lineSubtotals: bigint[] = [];

  for (const item of input.items) {
    if (item.quantity <= 0n || item.quantity > 1_000_000_000n) {
      throw new Error(`Line ${item.lineId}: quantity must be between 1 and 1,000,000,000`);
    }
    assertPgBigIntRange(item.unitPriceMinor, `item[${item.lineId}].unitPriceMinor`, { maxSafeInput: true });
    if (item.taxRateBps < 0n || item.taxRateBps > 10_000n) {
      throw new Error(`Line ${item.lineId}: taxRateBps must be between 0 and 10000`);
    }
    const lineSub = item.quantity * item.unitPriceMinor;
    assertPgBigIntRange(lineSub, `item[${item.lineId}].lineSubtotalMinor`, { maxSafeInput: true });
    lineSubtotals.push(lineSub);
    subtotalMinor += lineSub;
    assertPgBigIntRange(subtotalMinor, 'subtotalMinor', { maxSafeInput: true });
  }

  const pctDiscount = divRoundBigInt(subtotalMinor * input.discountBps, 10_000n, roundingMode);
  let totalDiscountMinor = pctDiscount + (input.fixedDiscountMinor ?? 0n);
  if (input.maxDiscountCapMinor !== null && totalDiscountMinor > input.maxDiscountCapMinor) {
    totalDiscountMinor = input.maxDiscountCapMinor;
  }
  if (totalDiscountMinor > subtotalMinor) {
    totalDiscountMinor = subtotalMinor;
  }

  const allocatedDiscounts = allocateProratedAmountExact(lineSubtotals, subtotalMinor, totalDiscountMinor);

  const lines: CalculatedLineItem[] = [];
  let netMerchandiseMinor = 0n;
  let merchandiseTaxMinor = 0n;

  for (let i = 0; i < input.items.length; i++) {
    const item = input.items[i];
    const lineSubtotalMinor = lineSubtotals[i];
    const proratedDiscountMinor = allocatedDiscounts[i];
    const afterDiscountMinor = lineSubtotalMinor - proratedDiscountMinor;

    let lineNetMinor: bigint;
    let lineTaxMinor: bigint;
    let lineTotalMinor: bigint;

    if (input.taxPolicy === 'TAX_EXCLUSIVE') {
      lineNetMinor = afterDiscountMinor;
      lineTaxMinor = divRoundBigInt(lineNetMinor * item.taxRateBps, 10_000n, roundingMode);
      lineTotalMinor = lineNetMinor + lineTaxMinor;
    } else {
      lineTotalMinor = afterDiscountMinor;
      lineNetMinor = divRoundBigInt(lineTotalMinor * 10_000n, 10_000n + item.taxRateBps, roundingMode);
      lineTaxMinor = lineTotalMinor - lineNetMinor;
    }

    netMerchandiseMinor += lineNetMinor;
    merchandiseTaxMinor += lineTaxMinor;

    lines.push({
      lineId: item.lineId,
      skuId: item.skuId,
      quantity: item.quantity,
      unitPriceMinor: item.unitPriceMinor,
      lineSubtotalMinor,
      proratedDiscountMinor,
      lineNetMinor,
      lineTaxMinor,
      lineTotalMinor,
    });
  }

  let shippingNetMinor: bigint;
  let shippingTaxMinor: bigint;
  if (input.taxPolicy === 'TAX_EXCLUSIVE') {
    shippingNetMinor = input.shippingMinor;
    shippingTaxMinor = divRoundBigInt(shippingNetMinor * input.shippingTaxRateBps, 10_000n, roundingMode);
  } else {
    shippingNetMinor = divRoundBigInt(input.shippingMinor * 10_000n, 10_000n + input.shippingTaxRateBps, roundingMode);
    shippingTaxMinor = input.shippingMinor - shippingNetMinor;
  }

  const totalTaxMinor = merchandiseTaxMinor + shippingTaxMinor;
  const grandTotalMinor = netMerchandiseMinor + shippingNetMinor + totalTaxMinor;
  assertPgBigIntRange(grandTotalMinor, 'grandTotalMinor');

  return {
    currencyCode: input.currencyCode,
    currencyExponent,
    taxPolicy: input.taxPolicy,
    taxRoundingMode: roundingMode,
    lines,
    subtotalMinor,
    totalDiscountMinor,
    netMerchandiseMinor,
    merchandiseTaxMinor,
    shippingNetMinor,
    shippingTaxMinor,
    totalTaxMinor,
    grandTotalMinor,
  };
}

/**
 * Largest Remainder Method for Exact Proration:
 * Guarantees sum(allocated) === targetTotal with zero rounding drift.
 */
export function allocateProratedAmountExact(
  weights: bigint[],
  totalWeight: bigint,
  targetTotal: bigint
): bigint[] {
  assertPgBigIntRange(totalWeight, 'totalWeight', { maxSafeInput: true });
  assertPgBigIntRange(targetTotal, 'targetTotal', { maxSafeInput: true });

  if (weights.length === 0) {
    if (targetTotal > 0n || totalWeight > 0n) {
      throw new Error('PRORATION_REJECTED: Cannot allocate non-zero amount across an empty weights array');
    }
    return [];
  }
  if (targetTotal === 0n) {
    return weights.map(() => 0n);
  }
  if (totalWeight === 0n) {
    throw new Error('PRORATION_REJECTED: Cannot prorate positive targetTotal when totalWeight is 0');
  }

  let verifiedWeightSum = 0n;
  for (const w of weights) {
    assertPgBigIntRange(w, 'lineWeight', { maxSafeInput: true });
    verifiedWeightSum += w;
  }
  if (verifiedWeightSum !== totalWeight) {
    throw new Error('PRORATION_REJECTED: Sum of weights does not match totalWeight');
  }

  const floors: bigint[] = [];
  const remainders: { index: number; rem: bigint }[] = [];
  let sumFloors = 0n;

  for (let i = 0; i < weights.length; i++) {
    const numerator = weights[i] * targetTotal;
    const fl = numerator / totalWeight;
    const rem = numerator % totalWeight;
    floors.push(fl);
    remainders.push({ index: i, rem });
    sumFloors += fl;
  }

  const leftover = Number(targetTotal - sumFloors);
  remainders.sort((a, b) => {
    if (b.rem !== a.rem) return b.rem > a.rem ? 1 : -1;
    return a.index - b.index;
  });

  for (let i = 0; i < leftover; i++) {
    floors[remainders[i].index] += 1n;
  }

  return floors;
}
```

### Partial Refunds & Credit Note Engine
```typescript
export interface LineRefundState {
  lineId: string;
  capturedQuantity: bigint;
  capturedNetMinor: bigint;
  capturedTaxMinor: bigint;
  alreadyRefundedQuantity: bigint;
  alreadyRefundedNetMinor: bigint;
  alreadyRefundedTaxMinor: bigint;
}

export interface CreditNoteLine {
  lineId: string;
  refundQuantity: bigint;
  refundNetMinor: bigint;
  refundTaxMinor: bigint;
  refundTotalMinor: bigint;
}

export function calculatePartialRefundCreditNote(
  lineState: LineRefundState,
  requestedQuantityToRefund: bigint,
  roundingMode: TaxRoundingMode = 'HALF_EVEN'
): CreditNoteLine {
  if (requestedQuantityToRefund <= 0n) {
    throw new Error('Refund quantity must be positive');
  }
  const remainingQty = lineState.capturedQuantity - lineState.alreadyRefundedQuantity;
  if (requestedQuantityToRefund > remainingQty) {
    throw new Error(
      `Cannot refund ${requestedQuantityToRefund} units; only ${remainingQty} refundable units remain on line ${lineState.lineId}`
    );
  }

  const remainingNet = lineState.capturedNetMinor - lineState.alreadyRefundedNetMinor;
  const remainingTax = lineState.capturedTaxMinor - lineState.alreadyRefundedTaxMinor;
  const isFinalLineRefund = requestedQuantityToRefund === remainingQty;

  const rawRefundNet = isFinalLineRefund
    ? remainingNet
    : divRoundBigInt(lineState.capturedNetMinor * requestedQuantityToRefund, lineState.capturedQuantity, roundingMode);

  const rawRefundTax = isFinalLineRefund
    ? remainingTax
    : divRoundBigInt(lineState.capturedTaxMinor * requestedQuantityToRefund, lineState.capturedQuantity, roundingMode);

  const refundNetMinor = rawRefundNet > remainingNet ? remainingNet : rawRefundNet < 0n ? 0n : rawRefundNet;
  const refundTaxMinor = rawRefundTax > remainingTax ? remainingTax : rawRefundTax < 0n ? 0n : rawRefundTax;

  return {
    lineId: lineState.lineId,
    refundQuantity: requestedQuantityToRefund,
    refundNetMinor,
    refundTaxMinor,
    refundTotalMinor: refundNetMinor + refundTaxMinor,
  };
}
```

---

## 4. Cryptographic ID, Token, & Atomic One-Time OTP Engine (With Attempt Throttling)

```typescript
import crypto from 'node:crypto';

export function generateUuidV7(nowMs: number = Date.now()): string {
  const bytes = crypto.randomBytes(16);
  const timeBig = BigInt(nowMs);

  bytes[0] = Number((timeBig >> 40n) & 0xffn);
  bytes[1] = Number((timeBig >> 32n) & 0xffn);
  bytes[2] = Number((timeBig >> 24n) & 0xffn);
  bytes[3] = Number((timeBig >> 16n) & 0xffn);
  bytes[4] = Number((timeBig >> 8n) & 0xffn);
  bytes[5] = Number(timeBig & 0xffn);

  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function generateOtpCode(
  digits: 6 | 8 = 6,
  pepperSecret: string,
  contextId: string,
  ttlMs: number = 5 * 60 * 1000
): {
  code: string;
  hmacDigest: string;
  expiresAt: Date;
} {
  if (!pepperSecret || pepperSecret.length < 32) {
    throw new Error('OTP_CONFIG_ERROR: pepperSecret must be at least 32 characters');
  }
  if (!contextId || contextId.trim().length === 0) {
    throw new Error('OTP_CONFIG_ERROR: contextId must be non-empty to bind OTP to purpose/user');
  }
  if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > 15 * 60 * 1000) {
    throw new Error('OTP_CONFIG_ERROR: ttlMs must be between 1ms and 900,000ms (15 minutes)');
  }
  const max = 10 ** digits;
  const rawInt = crypto.randomInt(0, max);
  const code = rawInt.toString().padStart(digits, '0');
  const hmacDigest = crypto
    .createHmac('sha256', pepperSecret)
    .update(`${contextId}:${code}`)
    .digest('hex');
  const expiresAt = new Date(Date.now() + ttlMs);
  return { code, hmacDigest, expiresAt };
}

/**
 * Pure Constant-Time OTP Digest Verifier:
 * - expiresAt is MANDATORY (never optional).
 * - Explicitly rejects Invalid Date (where Number.isNaN(expiresAt.getTime()) is true!).
 */
export function verifyOtpCodeConstantTime(
  submittedCode: string,
  expectedHmacHex: string,
  pepperSecret: string,
  contextId: string,
  expiresAt: Date,
  nowMs: number = Date.now()
): boolean {
  if (!pepperSecret || pepperSecret.length < 32) {
    throw new Error('OTP_CONFIG_ERROR: pepperSecret must be at least 32 characters');
  }
  if (!contextId || contextId.trim().length === 0) {
    return false;
  }
  // CRITICAL: Reject missing Date or Invalid Date (NaN timestamp would make nowMs > NaN evaluate to false!)
  if (!(expiresAt instanceof Date) || Number.isNaN(expiresAt.getTime())) {
    return false;
  }
  if (nowMs >= expiresAt.getTime()) {
    return false;
  }
  if (!/^\d{6,8}$/.test(submittedCode) || !/^[0-9a-fA-F]{64}$/.test(expectedHmacHex)) {
    return false;
  }
  const actualHmac = crypto
    .createHmac('sha256', pepperSecret)
    .update(`${contextId}:${submittedCode}`)
    .digest();
  const expectedBuffer = Buffer.from(expectedHmacHex, 'hex');
  if (actualHmac.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(actualHmac, expectedBuffer);
}

export interface StoredOtpChallengeRecord {
  challengeId: string;
  contextId: string; // e.g., "tenant_1:user_1:password_reset"
  hmacDigest: string;
  expiresAt: Date;
  status: 'ACTIVE' | 'CONSUMED' | 'LOCKED_MAX_ATTEMPTS';
  failedAttempts: number;
  maxAttempts: number;
}

export interface OtpChallengeStore {
  /**
   * Executes inside a single database transaction with FOR UPDATE row lock on challengeId.
   */
  withLockedChallenge<T>(
    challengeId: string,
    fn: (
      record: StoredOtpChallengeRecord | null,
      updateRecord: (patch: Partial<Pick<StoredOtpChallengeRecord, 'status' | 'failedAttempts'>>) => Promise<void>
    ) => Promise<T>
  ): Promise<T>;
}

/**
 * Atomic OTP Verification, Brute-Force Attempt Throttling & Single-Use Consumption:
 * Prevents OTP replay and concurrent race conditions by locking the challenge row,
 * enforcing maxAttempts, and marking status = 'CONSUMED' in the same transaction.
 */
export async function verifyAndConsumeOtpAtomically(params: {
  challengeId: string;
  expectedContextId: string;
  submittedCode: string;
  pepperSecret: string;
  store: OtpChallengeStore;
  nowMs?: number;
}): Promise<
  | { verified: true }
  | {
      verified: false;
      reason:
        | 'CHALLENGE_NOT_FOUND'
        | 'ALREADY_CONSUMED_REPLAY_BLOCKED'
        | 'LOCKED_MAX_ATTEMPTS'
        | 'CONTEXT_MISMATCH'
        | 'EXPIRED_OR_INVALID_DATE'
        | 'INVALID_CODE';
    }
> {
  if (!params.pepperSecret || params.pepperSecret.length < 32) {
    throw new Error('OTP_CONFIG_ERROR: pepperSecret must be at least 32 characters');
  }
  const nowMs = params.nowMs ?? Date.now();

  return params.store.withLockedChallenge(params.challengeId, async (record, updateRecord) => {
    if (!record) {
      return { verified: false, reason: 'CHALLENGE_NOT_FOUND' };
    }
    if (record.status === 'CONSUMED') {
      return { verified: false, reason: 'ALREADY_CONSUMED_REPLAY_BLOCKED' };
    }
    if (record.status === 'LOCKED_MAX_ATTEMPTS' || record.failedAttempts >= record.maxAttempts) {
      return { verified: false, reason: 'LOCKED_MAX_ATTEMPTS' };
    }
    if (record.contextId !== params.expectedContextId) {
      return { verified: false, reason: 'CONTEXT_MISMATCH' };
    }
    if (!(record.expiresAt instanceof Date) || Number.isNaN(record.expiresAt.getTime()) || nowMs >= record.expiresAt.getTime()) {
      return { verified: false, reason: 'EXPIRED_OR_INVALID_DATE' };
    }

    const matched = verifyOtpCodeConstantTime(
      params.submittedCode,
      record.hmacDigest,
      params.pepperSecret,
      params.expectedContextId,
      record.expiresAt,
      nowMs
    );

    if (!matched) {
      const nextFailed = record.failedAttempts + 1;
      const nextStatus = nextFailed >= record.maxAttempts ? 'LOCKED_MAX_ATTEMPTS' : 'ACTIVE';
      await updateRecord({ failedAttempts: nextFailed, status: nextStatus });
      return {
        verified: false,
        reason: nextStatus === 'LOCKED_MAX_ATTEMPTS' ? 'LOCKED_MAX_ATTEMPTS' : 'INVALID_CODE',
      };
    }

    // Atomically consume the OTP so a second replay or concurrent request fails with ALREADY_CONSUMED_REPLAY_BLOCKED
    await updateRecord({ status: 'CONSUMED' });
    return { verified: true };
  });
}
```

---

## 5. Composable Business Logic Engine: State Machines & Atomic Double-Entry Ledgers

### A. Deterministic Finite State Machine with Server-Resolved Roles & Optimistic Concurrency
Never trust `actorRoles` supplied in a client payload; resolve roles from the authoritative server-side membership store before evaluating transition rules:

```typescript
export interface StateTransitionRule<TState extends string, TContext> {
  from: readonly TState[];
  to: TState;
  allowedRoles: readonly string[];
  guard?: (ctx: TContext) => { ok: boolean; reason?: string };
}

export async function executeDomainStateTransition<TState extends string, TContext>(params: {
  tenantId: string;
  actorUserId: string;
  resolveVerifiedActorRoles: (tenantId: string, actorUserId: string) => Promise<readonly string[]>;
  entityName: string;
  entityId: string;
  currentState: TState;
  targetState: TState;
  currentVersion: number;
  expectedVersion: number;
  context: TContext;
  rules: readonly StateTransitionRule<TState, TContext>[];
}): Promise<{
  nextState: TState;
  nextVersion: number;
  auditEvent: string;
}> {
  if (params.currentVersion !== params.expectedVersion) {
    throw new Error(
      `STATE_CONFLICT_STALE_VERSION: ${params.entityName} (${params.entityId}) expected v${params.expectedVersion}, found v${params.currentVersion}`
    );
  }

  const verifiedRoles = await params.resolveVerifiedActorRoles(params.tenantId, params.actorUserId);
  if (verifiedRoles.length === 0) {
    throw new Error('TRANSITION_ROLE_DENIED: Actor has no active roles in tenant');
  }

  const matchingRule = params.rules.find(
    (r) => r.to === params.targetState && r.from.includes(params.currentState)
  );
  if (!matchingRule) {
    throw new Error(
      `ILLEGAL_STATE_TRANSITION: Cannot transition ${params.entityName} from "${params.currentState}" to "${params.targetState}"`
    );
  }

  const hasRole = verifiedRoles.some((role) => matchingRule.allowedRoles.includes(role));
  if (!hasRole) {
    throw new Error(
      `TRANSITION_ROLE_DENIED: Verified actor roles [${verifiedRoles.join(',')}] cannot transition ${params.entityName} to "${params.targetState}"`
    );
  }

  if (matchingRule.guard) {
    const verdict = matchingRule.guard(params.context);
    if (!verdict.ok) {
      throw new Error(`BUSINESS_INVARIANT_REJECTED: ${verdict.reason ?? 'Guard predicate failed'}`);
    }
  }

  return {
    nextState: params.targetState,
    nextVersion: params.currentVersion + 1,
    auditEvent: `${params.entityName.toLowerCase()}.transitioned.${params.currentState.toLowerCase()}_to_${params.targetState.toLowerCase()}`,
  };
}
```

### B. Strict Double-Entry Accounting Journal Validator & Atomic Persistence Engine
1. **Explicit Direction Validation**: Reject any posting whose `direction` is not strictly `'DEBIT'` or `'CREDIT'` (never use `if (dir === 'DEBIT') ... else` which silently treats invalid strings as `'CREDIT'`).
2. **PostgreSQL `BIGINT` Bounds**: Validate every line's `amountMinor` and the cumulative `totalDebitMinor`/`totalCreditMinor` against `assertPgBigIntRange`.
3. **Tenant-Account Ownership & Atomic Persistence**: Lock all referenced accounts in deterministic lexicographical order (`ORDER BY account_id FOR UPDATE`), verify that every account belongs to `params.tenantId`, uses `currencyCode`, and is `'ACTIVE'`, enforce idempotency uniqueness (`UNIQUE (tenant_id, idempotency_key)`), and commit the journal header, posting lines, and account balance updates in a single ACID transaction.

```typescript
export interface JournalPostingLine {
  accountId: string;
  direction: 'DEBIT' | 'CREDIT';
  amountMinor: bigint;
  currencyCode: string;
}

export function validateBalancedDoubleEntryJournal(params: {
  journalId: string;
  tenantId: string;
  idempotencyKey: string;
  postings: readonly JournalPostingLine[];
}): {
  currencyCode: string;
  totalDebitMinor: bigint;
  totalCreditMinor: bigint;
  sortedAccountIds: string[];
} {
  if (!params.tenantId || params.tenantId.trim().length === 0) {
    throw new Error('LEDGER_REJECTED: tenantId is mandatory');
  }
  if (!params.idempotencyKey || !/^[a-zA-Z0-9_.:-]{8,128}$/.test(params.idempotencyKey)) {
    throw new Error('LEDGER_REJECTED: idempotencyKey (8..128 safe chars) is mandatory');
  }
  if (params.postings.length < 2 || params.postings.length > 500) {
    throw new Error('LEDGER_REJECTED: Double-entry journal requires between 2 and 500 posting lines');
  }

  const currencyCode = params.postings[0].currencyCode;
  getCurrencyExponentStrict(currencyCode);

  let totalDebitMinor = 0n;
  let totalCreditMinor = 0n;
  const debitAccounts = new Set<string>();
  const creditAccounts = new Set<string>();

  for (const line of params.postings) {
    if (line.currencyCode !== currencyCode) {
      throw new Error('LEDGER_REJECTED: Cross-currency postings require an explicit FX clearing pair');
    }
    if (!line.accountId || line.accountId.trim().length === 0) {
      throw new Error('LEDGER_REJECTED: accountId cannot be empty');
    }
    if (line.amountMinor <= 0n) {
      throw new Error(`LEDGER_REJECTED: Posting amount for account "${line.accountId}" must be > 0n`);
    }
    assertPgBigIntRange(line.amountMinor, `posting[${line.accountId}].amountMinor`, { maxSafeInput: true });

    // CRITICAL: Explicitly validate 'DEBIT' vs 'CREDIT' (never treat unknown strings as 'CREDIT'!)
    const rawDirection: string = line.direction;
    if (rawDirection === 'DEBIT') {
      totalDebitMinor += line.amountMinor;
      assertPgBigIntRange(totalDebitMinor, 'totalDebitMinor');
      debitAccounts.add(line.accountId);
    } else if (rawDirection === 'CREDIT') {
      totalCreditMinor += line.amountMinor;
      assertPgBigIntRange(totalCreditMinor, 'totalCreditMinor');
      creditAccounts.add(line.accountId);
    } else {
      throw new Error(`LEDGER_REJECTED: Invalid posting direction "${String(rawDirection)}"`);
    }
  }

  for (const acc of debitAccounts) {
    if (creditAccounts.has(acc)) {
      throw new Error(`LEDGER_REJECTED: Account "${acc}" cannot be both debited and credited in the same journal`);
    }
  }

  if (totalDebitMinor !== totalCreditMinor) {
    throw new Error(
      `LEDGER_UNBALANCED_ERROR: Total debits (${totalDebitMinor}) !== total credits (${totalCreditMinor}) ${currencyCode}`
    );
  }

  const sortedAccountIds = Array.from(new Set([...debitAccounts, ...creditAccounts])).sort();
  return { currencyCode, totalDebitMinor, totalCreditMinor, sortedAccountIds };
}

export interface LedgerAccountRow {
  accountId: string;
  tenantId: string;
  currencyCode: string;
  status: 'ACTIVE' | 'FROZEN' | 'CLOSED';
  balanceMinor: bigint;
  allowNegativeBalance: boolean;
}

export interface LedgerTransactionPort {
  runInTransaction<T>(
    fn: (tx: {
      findJournalByIdempotencyKey: (
        tenantId: string,
        idempotencyKey: string
      ) => Promise<{ journalId: string; totalDebitMinor: bigint; currencyCode: string } | null>;
      lockAccountsSortedForUpdate: (sortedAccountIds: readonly string[]) => Promise<LedgerAccountRow[]>;
      insertJournalAndUpdateBalances: (data: {
        journalId: string;
        tenantId: string;
        idempotencyKey: string;
        currencyCode: string;
        totalDebitMinor: bigint;
        postings: readonly JournalPostingLine[];
        updatedBalances: ReadonlyMap<string, bigint>;
      }) => Promise<void>;
    }) => Promise<T>
  ): Promise<T>;
}

/**
 * Atomic Double-Entry Journal Persistence with Tenant-Account Ownership & Idempotency Enforcement
 */
export async function persistBalancedJournalAtomically(params: {
  journalId: string;
  tenantId: string;
  idempotencyKey: string;
  postings: readonly JournalPostingLine[];
  ledgerPort: LedgerTransactionPort;
}): Promise<{
  journalId: string;
  currencyCode: string;
  totalDebitMinor: bigint;
  replayedIdempotent: boolean;
}> {
  const validated = validateBalancedDoubleEntryJournal(params);

  return params.ledgerPort.runInTransaction(async (tx) => {
    // 1. Check unique (tenant_id, idempotency_key) inside the transaction
    const existing = await tx.findJournalByIdempotencyKey(params.tenantId, params.idempotencyKey);
    if (existing) {
      return {
        journalId: existing.journalId,
        currencyCode: existing.currencyCode,
        totalDebitMinor: existing.totalDebitMinor,
        replayedIdempotent: true,
      };
    }

    // 2. Lock all referenced accounts in deterministic lexicographical order (prevents deadlocks)
    const lockedAccounts = await tx.lockAccountsSortedForUpdate(validated.sortedAccountIds);
    const accountMap = new Map<string, LedgerAccountRow>();
    for (const acc of lockedAccounts) {
      accountMap.set(acc.accountId, acc);
    }

    // 3. Enforce tenant ownership, currency match, and active status on every single account
    for (const accountId of validated.sortedAccountIds) {
      const acc = accountMap.get(accountId);
      if (!acc) {
        throw new Error(`LEDGER_ACCOUNT_NOT_FOUND: Account "${accountId}" does not exist`);
      }
      if (acc.tenantId !== params.tenantId) {
        throw new Error(
          `LEDGER_CROSS_TENANT_ACCOUNT_DENIED: Account "${accountId}" does not belong to tenant "${params.tenantId}"`
        );
      }
      if (acc.currencyCode !== validated.currencyCode) {
        throw new Error(
          `LEDGER_CURRENCY_MISMATCH: Account "${accountId}" currency (${acc.currencyCode}) !== journal currency (${validated.currencyCode})`
        );
      }
      if (acc.status !== 'ACTIVE') {
        throw new Error(`LEDGER_ACCOUNT_INACTIVE: Account "${accountId}" is ${acc.status}`);
      }
    }

    // 4. Compute new account balances and enforce overdraft / PostgreSQL BIGINT bounds
    const updatedBalances = new Map<string, bigint>();
    for (const acc of lockedAccounts) {
      updatedBalances.set(acc.accountId, acc.balanceMinor);
    }

    for (const line of params.postings) {
      const currentBal = updatedBalances.get(line.accountId)!;
      const delta = line.direction === 'DEBIT' ? -line.amountMinor : line.amountMinor;
      const nextBal = currentBal + delta;
      assertPgBigIntRange(nextBal, `account[${line.accountId}].balanceMinor`, { allowNegative: true });

      const accMeta = accountMap.get(line.accountId)!;
      if (!accMeta.allowNegativeBalance && nextBal < 0n) {
        throw new Error(`LEDGER_INSUFFICIENT_FUNDS: Account "${line.accountId}" balance would become negative (${nextBal})`);
      }
      updatedBalances.set(line.accountId, nextBal);
    }

    // 5. Atomically insert journal header, posting lines, and updated balances
    await tx.insertJournalAndUpdateBalances({
      journalId: params.journalId,
      tenantId: params.tenantId,
      idempotencyKey: params.idempotencyKey,
      currencyCode: validated.currencyCode,
      totalDebitMinor: validated.totalDebitMinor,
      postings: params.postings,
      updatedBalances,
    });

    return {
      journalId: params.journalId,
      currencyCode: validated.currencyCode,
      totalDebitMinor: validated.totalDebitMinor,
      replayedIdempotent: false,
    };
  });
}
```

---

## 6. Verification & Test Requirements

1. **Prototype Currency Bypass Test**: Assert that `getCurrencyExponentStrict('toString')`, `getCurrencyExponentStrict('constructor')`, and `FieldSchemas.currencyCode.safeParse('valueOf')` fail closed.
2. **PostgreSQL `BIGINT` Overflow Test**: Assert that `assertPgBigIntRange(9_223_372_036_854_775_808n, 'amount')` and `calculateOrderTotals` with overflowing quantities throw `PG_BIGINT_RANGE_ERROR`.
3. **OTP Replay, Invalid Date & Brute-Force Lockout Test (`TEST-05`, `TEST-06`)**:
   - Assert that `verifyOtpCodeConstantTime(..., new Date('invalid'))` returns `false`.
   - Assert that submitting a valid OTP twice to `verifyAndConsumeOtpAtomically` succeeds on the first call and returns `ALREADY_CONSUMED_REPLAY_BLOCKED` on the second call.
   - Assert that 5 failed OTP attempts transition the challenge to `LOCKED_MAX_ATTEMPTS`, rejecting a subsequent 6th attempt even with the correct OTP code.
4. **Journal Direction, Cross-Tenant Account & Idempotency Test**:
   - Assert that passing `direction: 'INVALID' as any` throws `LEDGER_REJECTED: Invalid posting direction`.
   - Assert that referencing an `accountId` owned by `tenant_B` inside `persistBalancedJournalAtomically` for `tenant_A` throws `LEDGER_CROSS_TENANT_ACCOUNT_DENIED`.

### Authoritative References
- **ISO 4217 Currency Codes & Minor Unit Exponents**: https://www.iso.org/iso-4217-currency-codes.html
- **PostgreSQL 16 Numeric Types (`bigint` 8-byte signed range)**: https://www.postgresql.org/docs/current/datatype-numeric.html
- **RFC 9562 — Universally Unique IDentifiers (UUIDv7)**: https://datatracker.ietf.org/doc/html/rfc9562
