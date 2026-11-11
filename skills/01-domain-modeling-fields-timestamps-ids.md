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
    .transform((v: string) => v.normalize('NFKC').toLowerCase())
    .pipe(z.string().email()),

  e164Phone: z
    .string()
    .trim()
    .regex(/^\+[1-9]\d{6,14}$/, 'Phone must be in E.164 format (e.g. +14155552671)'),

  currencyCode: z
    .string()
    .trim()
    .toUpperCase()
    .refine((code: string) => /^[A-Z]{3}$/.test(code) && CURRENCY_EXPONENTS_MAP.has(code), {
      message: 'Unsupported or invalid ISO-4217 currency code',
    }),

  nonNegativeMoneyMinor: z
    .union([z.number().int().nonnegative().safe(), z.string().regex(/^\d{1,19}$/)])
    .transform((v: number | string) => BigInt(v))
    .refine((val: bigint) => val >= 0n && val <= PG_BIGINT_SAFE_INPUT_MAX, {
      message: 'Monetary amount exceeds safe PostgreSQL BIGINT bounds',
    }),

  signedMoneyMinor: z
    .union([z.number().int().safe(), z.string().regex(/^-?\d{1,19}$/)])
    .transform((v: number | string) => BigInt(v))
    .refine((val: bigint) => val >= -PG_BIGINT_SAFE_INPUT_MAX && val <= PG_BIGINT_SAFE_INPUT_MAX, {
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
    .transform((v: string) => {
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
  if (
    lineState.capturedQuantity <= 0n ||
    lineState.alreadyRefundedQuantity < 0n ||
    lineState.alreadyRefundedQuantity > lineState.capturedQuantity ||
    lineState.capturedNetMinor < 0n ||
    lineState.alreadyRefundedNetMinor < 0n ||
    lineState.alreadyRefundedNetMinor > lineState.capturedNetMinor ||
    lineState.capturedTaxMinor < 0n ||
    lineState.alreadyRefundedTaxMinor < 0n ||
    lineState.alreadyRefundedTaxMinor > lineState.capturedTaxMinor
  ) {
    throw new Error(
      `INVALID_LINE_REFUND_STATE: Line ${lineState.lineId} has negative or over-refunded baseline quantities/amounts`
    );
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
  persistTransitionConditionally: (update: {
    tenantId: string;
    entityId: string;
    expectedCurrentState: TState;
    expectedVersion: number;
    nextState: TState;
    nextVersion: number;
    auditEvent: string;
  }) => Promise<{ updatedRowCount: number }>;
}): Promise<{
  nextState: TState;
  nextVersion: number;
  auditEvent: string;
}> {
  if (!Number.isInteger(params.expectedVersion) || params.expectedVersion < 0) {
    throw new Error('STATE_INVALID_EXPECTED_VERSION');
  }
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

  const nextVersion = params.expectedVersion + 1;
  const auditEvent = `${params.entityName.toLowerCase()}.transitioned.${params.currentState.toLowerCase()}_to_${params.targetState.toLowerCase()}`;

  // DEVIL-11 Fix: Enforce conditional database update (WHERE tenant_id=$1 AND id=$2 AND state=$3 AND version=$4)
  // and verify affected rowCount === 1 so concurrent transitions cannot overwrite each other!
  const writeResult = await params.persistTransitionConditionally({
    tenantId: params.tenantId,
    entityId: params.entityId,
    expectedCurrentState: params.currentState,
    expectedVersion: params.expectedVersion,
    nextState: params.targetState,
    nextVersion,
    auditEvent,
  });

  if (writeResult.updatedRowCount !== 1) {
    throw new Error(
      `STATE_CONFLICT_CONCURRENT_MODIFICATION: Conditional update for ${params.entityName} (${params.entityId}) at v${params.expectedVersion} affected ${writeResult.updatedRowCount} rows`
    );
  }

  return {
    nextState: params.targetState,
    nextVersion,
    auditEvent,
  };
}
```

### B. Strict Double-Entry Accounting Journal Validator & Atomic Persistence Engine
1. **Explicit Direction Validation**: Reject any posting whose `direction` is not strictly `'DEBIT'` or `'CREDIT'` (never use `if (dir === 'DEBIT') ... else` which silently treats invalid strings as `'CREDIT'`).
2. **PostgreSQL `BIGINT` Bounds**: Validate every line's `amountMinor` and the cumulative `totalDebitMinor`/`totalCreditMinor` against `assertPgBigIntRange`.
3. **Tenant-Account Ownership & Atomic Persistence**: Lock all referenced accounts in deterministic lexicographical order (`ORDER BY account_id FOR UPDATE`), verify that every account belongs to `params.tenantId`, uses `currencyCode`, and is `'ACTIVE'`, enforce idempotency uniqueness (`UNIQUE (tenant_id, idempotency_key)`), verify affected row counts on account updates (`updatedAccountCount === sortedAccountIds.length`), and commit the journal header, posting lines, and account balance updates in a single ACID transaction.

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
  normalBalance: 'DEBIT' | 'CREDIT'; // Mandatory: 'DEBIT' for Asset/Expense; 'CREDIT' for Liability/Equity/Revenue
  balanceMinor: bigint;
  version: number;
  allowNegativeBalance: boolean;
}

export interface LedgerTransactionPort {
  runInTransaction<T>(
    fn: (tx: {
      findJournalByIdempotencyKey: (
        tenantId: string,
        idempotencyKey: string
      ) => Promise<{
        journalId: string;
        totalDebitMinor: bigint;
        currencyCode: string;
        requestHash?: string;
      } | null>;
      lockAccountsSortedForUpdate: (sortedAccountIds: readonly string[]) => Promise<LedgerAccountRow[]>;
      insertJournalAndUpdateBalances: (data: {
        journalId: string;
        tenantId: string;
        idempotencyKey: string;
        requestHash: string;
        currencyCode: string;
        totalDebitMinor: bigint;
        postings: readonly JournalPostingLine[];
        expectedAccountVersions: ReadonlyMap<string, number>;
        updatedBalances: ReadonlyMap<string, bigint>;
      }) => Promise<{ updatedAccountCount: number }>;
    }) => Promise<T>
  ): Promise<T>;
}

export function computeJournalRequestHash(params: {
  tenantId: string;
  idempotencyKey: string;
  postings: readonly JournalPostingLine[];
}): string {
  const canonicalPayload = JSON.stringify({
    tenantId: params.tenantId,
    idempotencyKey: params.idempotencyKey,
    postings: params.postings.map((p) => ({
      accountId: p.accountId,
      direction: p.direction,
      amountMinor: p.amountMinor.toString(),
      currencyCode: p.currencyCode,
    })),
  });
  return crypto
    .createHash('sha256')
    .update(canonicalPayload, 'utf8')
    .digest('hex');
}

/**
 * Atomic Double-Entry Journal Persistence with Tenant-Account Ownership,
 * Normal-Balance Sign Enforcement (Asset DEBIT-normal vs Liability CREDIT-normal),
 * Conditional Version Verification, and Idempotency Payload-Hash Enforcement (DEVIL-10 & DEVIL-11).
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
  const requestHash = computeJournalRequestHash(params);

  return params.ledgerPort.runInTransaction(async (tx) => {
    // 1. Check unique (tenant_id, idempotency_key) inside the transaction and verify payload hash match!
    const existing = await tx.findJournalByIdempotencyKey(params.tenantId, params.idempotencyKey);
    if (existing) {
      if (existing.requestHash !== undefined && existing.requestHash !== requestHash) {
        throw new Error(
          `LEDGER_IDEMPOTENCY_PAYLOAD_MISMATCH: Idempotency key "${params.idempotencyKey}" was already used with a different journal payload`
        );
      }
      if (
        existing.totalDebitMinor !== validated.totalDebitMinor ||
        existing.currencyCode !== validated.currencyCode
      ) {
        throw new Error(
          `LEDGER_IDEMPOTENCY_PAYLOAD_MISMATCH: Idempotency key "${params.idempotencyKey}" amount/currency mismatch`
        );
      }
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
    const expectedAccountVersions = new Map<string, number>();
    for (const acc of lockedAccounts) {
      accountMap.set(acc.accountId, acc);
      expectedAccountVersions.set(acc.accountId, acc.version ?? 0);
    }

    // 3. Enforce tenant ownership, currency match, normalBalance presence, and active status on every account
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
      if (acc.normalBalance !== 'DEBIT' && acc.normalBalance !== 'CREDIT') {
        throw new Error(
          `LEDGER_INVALID_NORMAL_BALANCE: Account "${accountId}" must declare normalBalance 'DEBIT' or 'CREDIT'`
        );
      }
    }

    // 4. Compute new account balances respecting each account's normalBalance ('DEBIT' vs 'CREDIT')
    // and enforce overdraft / PostgreSQL BIGINT bounds
    const updatedBalances = new Map<string, bigint>();
    for (const acc of lockedAccounts) {
      updatedBalances.set(acc.accountId, acc.balanceMinor);
    }

    for (const line of params.postings) {
      const currentBal = updatedBalances.get(line.accountId)!;
      const accMeta = accountMap.get(line.accountId)!;
      const normalSide = accMeta.normalBalance;
      const delta = line.direction === normalSide ? line.amountMinor : -line.amountMinor;
      const nextBal = currentBal + delta;
      assertPgBigIntRange(nextBal, `account[${line.accountId}].balanceMinor`, { allowNegative: true });

      if (!accMeta.allowNegativeBalance && nextBal < 0n) {
        throw new Error(`LEDGER_INSUFFICIENT_FUNDS: Account "${line.accountId}" balance would become negative (${nextBal})`);
      }
      updatedBalances.set(line.accountId, nextBal);
    }

    // 5. Atomically insert journal header, posting lines, and conditionally update account balances + versions
    const writeRes = await tx.insertJournalAndUpdateBalances({
      journalId: params.journalId,
      tenantId: params.tenantId,
      idempotencyKey: params.idempotencyKey,
      requestHash,
      currencyCode: validated.currencyCode,
      totalDebitMinor: validated.totalDebitMinor,
      postings: params.postings,
      expectedAccountVersions,
      updatedBalances,
    });

    if (writeRes.updatedAccountCount !== validated.sortedAccountIds.length) {
      throw new Error(
        `LEDGER_CONCURRENT_VERSION_CONFLICT: Expected to update ${validated.sortedAccountIds.length} accounts, but updated ${writeRes.updatedAccountCount}`
      );
    }

    return {
      journalId: params.journalId,
      currencyCode: validated.currencyCode,
      totalDebitMinor: validated.totalDebitMinor,
      replayedIdempotent: false,
    };
  });
}
```

### C. Authoritative Database-Level Ledger Schema, Lifecycle, RLS & Canonical Role Architecture (`ARGON-LEDGER-001`, `ARGON-LEDGER-002`, `ARGON-LEDGER-003`, `ARGON-ROLE-004`)
Application validation alone cannot protect financial integrity if a bug, migration, or direct SQL statement attempts to post a journal line to an account owned by another tenant (`ARGON-LEDGER-001`), modify/delete postings on a finalized journal or move postings between journals (`ARGON-LEDGER-002`), read/write cross-tenant ledger accounts without cryptographic RLS MAC enforcement (`ARGON-LEDGER-003`), or use unsegregated database roles (`ARGON-ROLE-004`).

Enforce composite tenant-account-currency referential integrity, explicit journal lifecycle states (`POSTING` -> `FINALIZED`), OLD/NEW deferred commit-time posting triggers across `INSERT`, `UPDATE`, and `DELETE`, append-only finalized immutability, tenant-scoped Row Level Security (`FORCE ROW LEVEL SECURITY`), and a canonical least-privilege 3-role architecture (`db_migrator`, `app_runtime`, `app_login`):

```sql
SET lock_timeout = '3s';
SET statement_timeout = '10s';

-- ============================================================================
-- 0. CANONICAL DATABASE ROLE ARCHITECTURE (ARGON-ROLE-004)
-- Separation of schema migration owner (db_migrator), privilege group (app_runtime),
-- and authentication connection role (app_login). Fails safely on incompatible configs.
-- ============================================================================
DO $$
BEGIN
  -- 1. Schema migration owner role: NOLOGIN, owns tables and security definer functions
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'db_migrator') THEN
    CREATE ROLE db_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  ELSE
    IF EXISTS (
      SELECT 1 FROM pg_roles
      WHERE rolname = 'db_migrator'
        AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolcanlogin)
    ) THEN
      RAISE EXCEPTION 'ROLE_SECURITY_INVARIANT_VIOLATION: db_migrator has conflicting attributes (must be NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS)'
        USING ERRCODE = '28000';
    END IF;
  END IF;

  -- 2. Privilege-group role: NOLOGIN, holds explicit SELECT/INSERT/UPDATE grants, NOBYPASSRLS
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
    CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  ELSE
    IF EXISTS (
      SELECT 1 FROM pg_roles
      WHERE rolname = 'app_runtime'
        AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolcanlogin)
    ) OR pg_has_role('app_runtime', 'db_migrator', 'MEMBER') THEN
      RAISE EXCEPTION 'ROLE_SECURITY_INVARIANT_VIOLATION: app_runtime has conflicting attributes or inherits db_migrator'
        USING ERRCODE = '28000';
    END IF;
  END IF;

  -- 3. Application connection role: LOGIN role inheriting app_runtime, NOBYPASSRLS
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_login') THEN
    CREATE ROLE app_login LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS IN ROLE app_runtime;
  ELSE
    IF EXISTS (
      SELECT 1 FROM pg_roles
      WHERE rolname = 'app_login'
        AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR NOT rolcanlogin)
    ) OR pg_has_role('app_login', 'db_migrator', 'MEMBER') THEN
      RAISE EXCEPTION 'ROLE_SECURITY_INVARIANT_VIOLATION: app_login has conflicting attributes or inherits db_migrator'
        USING ERRCODE = '28000';
    END IF;
    IF NOT pg_has_role('app_login', 'app_runtime', 'MEMBER') THEN
      GRANT app_runtime TO app_login;
    END IF;
  END IF;
END
$$;

-- Create cryptographic extension schema
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
GRANT USAGE ON SCHEMA public TO db_migrator, app_runtime;
GRANT USAGE ON SCHEMA extensions TO db_migrator, app_runtime;

-- Create restricted security schema for HMAC verification keys
CREATE SCHEMA IF NOT EXISTS security AUTHORIZATION db_migrator;
REVOKE ALL ON SCHEMA security FROM PUBLIC;
GRANT USAGE ON SCHEMA security TO db_migrator, app_runtime;

CREATE TABLE IF NOT EXISTS security.guc_hmac_keys (
  key_id INT PRIMARY KEY DEFAULT 1 CHECK (key_id = 1),
  hmac_secret TEXT NOT NULL CHECK (char_length(hmac_secret) >= 32)
);
ALTER TABLE security.guc_hmac_keys OWNER TO db_migrator;
REVOKE ALL ON TABLE security.guc_hmac_keys FROM PUBLIC, app_runtime, app_login;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.guc_hmac_keys TO db_migrator;

-- Cryptographic GUC user & tenant verifiers (ARGON-LEDGER-003)
CREATE OR REPLACE FUNCTION security.constant_time_hex_equal_32(expected_hex TEXT, actual_hex TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
  v_expected BYTEA;
  v_actual BYTEA;
  v_diff INT := 0;
  v_i INT;
BEGIN
  IF expected_hex IS NULL OR actual_hex IS NULL THEN
    RETURN FALSE;
  END IF;
  IF pg_catalog.char_length(expected_hex) <> 64 OR pg_catalog.char_length(actual_hex) <> 64 THEN
    RETURN FALSE;
  END IF;
  IF expected_hex !~ '^[0-9a-fA-F]{64}$' OR actual_hex !~ '^[0-9a-fA-F]{64}$' THEN
    RETURN FALSE;
  END IF;
  v_expected := pg_catalog.decode(expected_hex, 'hex');
  v_actual := pg_catalog.decode(actual_hex, 'hex');
  IF pg_catalog.octet_length(v_expected) <> 32 OR pg_catalog.octet_length(v_actual) <> 32 THEN
    RETURN FALSE;
  END IF;
  FOR v_i IN 0..31 LOOP
    v_diff := v_diff | (pg_catalog.get_byte(v_expected, v_i) # pg_catalog.get_byte(v_actual, v_i));
  END LOOP;
  RETURN v_diff = 0;
END;
$$;

CREATE OR REPLACE FUNCTION security.verify_active_user_context(row_user_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_user_id TEXT;
  v_user_mac TEXT;
  v_secret TEXT;
  v_expected_mac TEXT;
BEGIN
  v_user_id := NULLIF(current_setting('app.current_user_id', true), '');
  v_user_mac := NULLIF(current_setting('app.current_user_mac', true), '');
  IF v_user_id IS NULL OR v_user_mac IS NULL OR row_user_id IS NULL THEN
    RETURN FALSE;
  END IF;
  IF v_user_id::uuid <> row_user_id THEN
    RETURN FALSE;
  END IF;
  SELECT hmac_secret INTO v_secret FROM security.guc_hmac_keys WHERE key_id = 1;
  IF v_secret IS NULL OR char_length(v_secret) < 32 THEN
    RETURN FALSE;
  END IF;
  v_expected_mac := encode(
    extensions.hmac(
      convert_to('user:' || v_user_id || ':' || txid_current()::text, 'UTF8'),
      convert_to(v_secret, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
  RETURN security.constant_time_hex_equal_32(v_expected_mac, v_user_mac);
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION security.verify_active_tenant_context(row_tenant_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_tenant_id TEXT;
  v_tenant_mac TEXT;
  v_user_id TEXT;
  v_secret TEXT;
  v_expected_mac TEXT;
BEGIN
  v_tenant_id := NULLIF(current_setting('app.current_tenant_id', true), '');
  v_tenant_mac := NULLIF(current_setting('app.current_tenant_mac', true), '');
  IF v_tenant_id IS NULL OR v_tenant_mac IS NULL OR row_tenant_id IS NULL THEN
    RETURN FALSE;
  END IF;
  IF v_tenant_id::uuid <> row_tenant_id THEN
    RETURN FALSE;
  END IF;
  -- If app.current_user_id is present in the session/transaction, verify its cryptographic MAC too (fail-closed on forged user GUC)
  v_user_id := NULLIF(current_setting('app.current_user_id', true), '');
  IF v_user_id IS NOT NULL THEN
    IF NOT security.verify_active_user_context(v_user_id::uuid) THEN
      RETURN FALSE;
    END IF;
  END IF;
  SELECT hmac_secret INTO v_secret FROM security.guc_hmac_keys WHERE key_id = 1;
  IF v_secret IS NULL OR char_length(v_secret) < 32 THEN
    RETURN FALSE;
  END IF;
  v_expected_mac := encode(
    extensions.hmac(
      convert_to(v_tenant_id || ':' || txid_current()::text, 'UTF8'),
      convert_to(v_secret, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
  RETURN security.constant_time_hex_equal_32(v_expected_mac, v_tenant_mac);
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
$$;

ALTER FUNCTION security.constant_time_hex_equal_32(TEXT, TEXT) OWNER TO db_migrator;
ALTER FUNCTION security.verify_active_user_context(UUID) OWNER TO db_migrator;
ALTER FUNCTION security.verify_active_tenant_context(UUID) OWNER TO db_migrator;

REVOKE ALL ON FUNCTION security.constant_time_hex_equal_32(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION security.verify_active_user_context(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION security.verify_active_tenant_context(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.constant_time_hex_equal_32(TEXT, TEXT) TO db_migrator;
GRANT EXECUTE ON FUNCTION security.verify_active_user_context(UUID) TO app_runtime, db_migrator;
GRANT EXECUTE ON FUNCTION security.verify_active_tenant_context(UUID) TO app_runtime, db_migrator;

-- ============================================================================
-- 1. BASE LEDGER SCHEMAS WITH LIFECYCLE & RATIONAL FX SETTLEMENTS (ARGON-LEDGER-001, 002, 005)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.ledger_accounts (
  account_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  currency_code CHAR(3) NOT NULL,
  status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'FROZEN', 'CLOSED')),
  normal_balance VARCHAR(6) NOT NULL CHECK (normal_balance IN ('DEBIT', 'CREDIT')),
  balance_minor BIGINT NOT NULL DEFAULT 0,
  version INT NOT NULL DEFAULT 0 CHECK (version >= 0),
  allow_negative_balance BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT chk_ledger_accounts_supported_currency CHECK (
    currency_code IN (
      'JPY', 'KRW', 'VND', 'CLP', 'ISK',
      'USD', 'EUR', 'GBP', 'INR', 'CAD', 'AUD', 'SGD', 'CHF',
      'BHD', 'KWD', 'OMR', 'JOD', 'TND'
    )
  ),
  CONSTRAINT chk_ledger_accounts_safe_bigint CHECK (
    balance_minor >= -900000000000000 AND balance_minor <= 900000000000000
  ),
  CONSTRAINT chk_ledger_non_negative_balance CHECK (allow_negative_balance OR balance_minor >= 0),
  CONSTRAINT uq_ledger_accounts_tenant_account UNIQUE (tenant_id, account_id),
  CONSTRAINT uq_ledger_accounts_tenant_account_currency UNIQUE (tenant_id, account_id, currency_code)
);

CREATE TABLE IF NOT EXISTS public.journal_entries (
  journal_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  idempotency_key VARCHAR(128) NOT NULL,
  request_hash CHAR(64) NOT NULL,
  currency_code CHAR(3) NOT NULL,
  total_debit_minor BIGINT NOT NULL,
  total_credit_minor BIGINT NOT NULL,
  -- ARGON-LEDGER-002: Explicit Journal Lifecycle State (POSTING -> FINALIZED)
  lifecycle_status VARCHAR(16) NOT NULL DEFAULT 'POSTING' CHECK (lifecycle_status IN ('POSTING', 'FINALIZED')),
  finalized_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT chk_journal_entries_idempotency_key CHECK (
    char_length(btrim(idempotency_key)) BETWEEN 8 AND 128
  ),
  CONSTRAINT chk_journal_entries_request_hash CHECK (
    request_hash ~ '^[0-9a-fA-F]{64}$'
  ),
  CONSTRAINT chk_journal_entries_supported_currency CHECK (
    currency_code IN (
      'JPY', 'KRW', 'VND', 'CLP', 'ISK',
      'USD', 'EUR', 'GBP', 'INR', 'CAD', 'AUD', 'SGD', 'CHF',
      'BHD', 'KWD', 'OMR', 'JOD', 'TND'
    )
  ),
  CONSTRAINT chk_journal_entries_totals_balanced CHECK (
    total_debit_minor > 0
    AND total_debit_minor <= 900000000000000
    AND total_credit_minor > 0
    AND total_credit_minor <= 900000000000000
    AND total_debit_minor = total_credit_minor
  ),
  CONSTRAINT uq_journal_entries_tenant_idempotency UNIQUE (tenant_id, idempotency_key),
  CONSTRAINT uq_journal_entries_tenant_journal UNIQUE (tenant_id, journal_id),
  CONSTRAINT uq_journal_entries_tenant_journal_currency UNIQUE (tenant_id, journal_id, currency_code)
);

CREATE TABLE IF NOT EXISTS public.journal_postings (
  posting_id BIGSERIAL PRIMARY KEY,
  journal_id UUID NOT NULL,
  tenant_id UUID NOT NULL,
  account_id UUID NOT NULL,
  direction VARCHAR(6) NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
  amount_minor BIGINT NOT NULL CHECK (amount_minor > 0 AND amount_minor <= 900000000000000),
  currency_code CHAR(3) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT chk_journal_postings_supported_currency CHECK (
    currency_code IN (
      'JPY', 'KRW', 'VND', 'CLP', 'ISK',
      'USD', 'EUR', 'GBP', 'INR', 'CAD', 'AUD', 'SGD', 'CHF',
      'BHD', 'KWD', 'OMR', 'JOD', 'TND'
    )
  ),
  CONSTRAINT uq_journal_postings_journal_account UNIQUE (journal_id, account_id),
  CONSTRAINT fk_journal_postings_tenant_account
    FOREIGN KEY (tenant_id, account_id)
    REFERENCES public.ledger_accounts (tenant_id, account_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT fk_journal_postings_tenant_account_currency
    FOREIGN KEY (tenant_id, account_id, currency_code)
    REFERENCES public.ledger_accounts (tenant_id, account_id, currency_code)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT fk_journal_postings_tenant_journal
    FOREIGN KEY (tenant_id, journal_id)
    REFERENCES public.journal_entries (tenant_id, journal_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT fk_journal_postings_tenant_journal_currency
    FOREIGN KEY (tenant_id, journal_id, currency_code)
    REFERENCES public.journal_entries (tenant_id, journal_id, currency_code)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);

-- Explicit Cross-Currency FX Settlement Bridge (ARGON-LEDGER-005):
-- Each journal remains strictly single-currency; cross-currency conversion links two same-tenant
-- single-currency journals via exact integer rational conversion (rate_numerator / rate_denominator).
CREATE TABLE IF NOT EXISTS public.fx_conversion_settlements (
  settlement_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  source_journal_id UUID NOT NULL,
  source_currency_code CHAR(3) NOT NULL,
  source_amount_minor BIGINT NOT NULL CHECK (source_amount_minor > 0 AND source_amount_minor <= 900000000000000),
  target_journal_id UUID NOT NULL,
  target_currency_code CHAR(3) NOT NULL,
  target_amount_minor BIGINT NOT NULL CHECK (target_amount_minor > 0 AND target_amount_minor <= 900000000000000),
  rate_numerator BIGINT NOT NULL CHECK (rate_numerator > 0 AND rate_numerator <= 900000000000000),
  rate_denominator BIGINT NOT NULL CHECK (rate_denominator > 0 AND rate_denominator <= 900000000000000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT chk_fx_distinct_currencies CHECK (source_currency_code <> target_currency_code),
  CONSTRAINT chk_fx_distinct_journals CHECK (source_journal_id <> target_journal_id),
  CONSTRAINT chk_fx_exact_rational_conversion CHECK (
    (source_amount_minor::numeric * rate_numerator::numeric) = (target_amount_minor::numeric * rate_denominator::numeric)
  ),
  CONSTRAINT fk_fx_source_journal
    FOREIGN KEY (tenant_id, source_journal_id, source_currency_code)
    REFERENCES public.journal_entries (tenant_id, journal_id, currency_code)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT fk_fx_target_journal
    FOREIGN KEY (tenant_id, target_journal_id, target_currency_code)
    REFERENCES public.journal_entries (tenant_id, journal_id, currency_code)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_journal_postings_tenant_journal
  ON public.journal_postings (tenant_id, journal_id);
CREATE INDEX IF NOT EXISTS idx_journal_postings_tenant_account
  ON public.journal_postings (tenant_id, account_id);

-- ============================================================================
-- 2. OWNERSHIP & LEAST-PRIVILEGE GRANTS (ARGON-ROLE-004)
-- ============================================================================
REVOKE ALL ON public.journal_entries, public.journal_postings, public.ledger_accounts FROM PUBLIC, app_runtime;
REVOKE ALL ON public.fx_conversion_settlements FROM PUBLIC, app_runtime;

ALTER TABLE public.ledger_accounts OWNER TO db_migrator;
ALTER TABLE public.journal_entries OWNER TO db_migrator;
ALTER TABLE public.journal_postings OWNER TO db_migrator;
ALTER TABLE public.fx_conversion_settlements OWNER TO db_migrator;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.ledger_accounts, public.journal_entries, public.journal_postings, public.fx_conversion_settlements TO db_migrator;
GRANT USAGE, SELECT ON SEQUENCE public.journal_postings_posting_id_seq TO db_migrator;

GRANT SELECT, INSERT, UPDATE (balance_minor, version, status, allow_negative_balance) ON public.ledger_accounts TO app_runtime;
GRANT SELECT, INSERT, UPDATE (lifecycle_status, finalized_at) ON public.journal_entries TO app_runtime;
GRANT SELECT, INSERT ON public.journal_postings TO app_runtime;
GRANT SELECT, INSERT ON public.fx_conversion_settlements TO app_runtime;
GRANT USAGE, SELECT ON SEQUENCE public.journal_postings_posting_id_seq TO app_runtime;

-- ============================================================================
-- 3. ROW LEVEL SECURITY POLICIES (ARGON-LEDGER-003)
-- Enforce tenant-scoped cryptographic verification on all ledger tables
-- ============================================================================
ALTER TABLE public.ledger_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ledger_accounts FORCE ROW LEVEL SECURITY;

ALTER TABLE public.journal_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.journal_entries FORCE ROW LEVEL SECURITY;

ALTER TABLE public.journal_postings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.journal_postings FORCE ROW LEVEL SECURITY;

ALTER TABLE public.fx_conversion_settlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fx_conversion_settlements FORCE ROW LEVEL SECURITY;

-- ledger_accounts RLS Policies (Permissive + Restrictive defense-in-depth)
CREATE POLICY ledger_accounts_tenant_isolation ON public.ledger_accounts
  AS PERMISSIVE
  FOR ALL
  TO app_runtime, db_migrator
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

CREATE POLICY ledger_accounts_tenant_restrictive ON public.ledger_accounts
  AS RESTRICTIVE
  FOR ALL
  TO PUBLIC
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

-- journal_entries RLS Policies
CREATE POLICY journal_entries_tenant_isolation ON public.journal_entries
  AS PERMISSIVE
  FOR ALL
  TO app_runtime, db_migrator
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

CREATE POLICY journal_entries_tenant_restrictive ON public.journal_entries
  AS RESTRICTIVE
  FOR ALL
  TO PUBLIC
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

-- journal_postings RLS Policies
CREATE POLICY journal_postings_tenant_isolation ON public.journal_postings
  AS PERMISSIVE
  FOR ALL
  TO app_runtime, db_migrator
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

CREATE POLICY journal_postings_tenant_restrictive ON public.journal_postings
  AS RESTRICTIVE
  FOR ALL
  TO PUBLIC
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

-- fx_conversion_settlements RLS Policies
CREATE POLICY fx_settlements_tenant_isolation ON public.fx_conversion_settlements
  AS PERMISSIVE
  FOR ALL
  TO app_runtime, db_migrator
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

CREATE POLICY fx_settlements_tenant_restrictive ON public.fx_conversion_settlements
  AS RESTRICTIVE
  FOR ALL
  TO PUBLIC
  USING (security.verify_active_tenant_context(tenant_id))
  WITH CHECK (security.verify_active_tenant_context(tenant_id));

-- ============================================================================
-- 4. ACCOUNT IDENTITY & JOURNAL IMMUTABILITY TRIGGERS
-- ============================================================================
CREATE OR REPLACE FUNCTION public.prevent_ledger_account_identity_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'LEDGER_ACCOUNT_IMMUTABLE_VIOLATION: Deleting ledger_accounts rows is forbidden (account_id=%)', OLD.account_id
      USING ERRCODE = '55000';
  END IF;

  IF NEW.account_id <> OLD.account_id
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.currency_code <> OLD.currency_code
     OR NEW.normal_balance <> OLD.normal_balance
     OR NEW.created_at <> OLD.created_at
  THEN
    RAISE EXCEPTION 'LEDGER_ACCOUNT_IDENTITY_IMMUTABLE: Cannot reassign tenant_id, currency_code, normal_balance, or account_id on ledger_accounts (account_id=%)', OLD.account_id
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_ledger_accounts_protect_identity
  BEFORE UPDATE OR DELETE ON public.ledger_accounts
  FOR EACH ROW EXECUTE FUNCTION public.prevent_ledger_account_identity_mutation();

-- Journal Entries Lifecycle & Immutability Trigger (ARGON-LEDGER-002)
CREATE OR REPLACE FUNCTION public.prevent_journal_entry_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'LEDGER_IMMUTABLE_VIOLATION: Deleting journal_entries rows is forbidden (journal_id=%)', OLD.journal_id
      USING ERRCODE = '55000';
  END IF;

  -- Disallow modifying core financial metadata
  IF NEW.journal_id <> OLD.journal_id
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.idempotency_key <> OLD.idempotency_key
     OR NEW.request_hash <> OLD.request_hash
     OR NEW.currency_code <> OLD.currency_code
     OR NEW.total_debit_minor <> OLD.total_debit_minor
     OR NEW.total_credit_minor <> OLD.total_credit_minor
     OR NEW.created_at <> OLD.created_at
  THEN
    RAISE EXCEPTION 'LEDGER_JOURNAL_CORE_IMMUTABLE: Core metadata on journal_entries cannot be updated (journal_id=%)', OLD.journal_id
      USING ERRCODE = '55000';
  END IF;

  -- Lifecycle state transition checks: POSTING -> FINALIZED permitted once; no downgrades
  IF OLD.lifecycle_status = 'FINALIZED' THEN
    IF NEW.lifecycle_status <> 'FINALIZED' THEN
      RAISE EXCEPTION 'LEDGER_LIFECYCLE_VIOLATION: Cannot downgrade journal % from FINALIZED to %', OLD.journal_id, NEW.lifecycle_status
        USING ERRCODE = '55000';
    END IF;
  ELSIF OLD.lifecycle_status = 'POSTING' AND NEW.lifecycle_status = 'FINALIZED' THEN
    NEW.finalized_at := clock_timestamp();
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_journal_entries_immutable
  BEFORE UPDATE OR DELETE ON public.journal_entries
  FOR EACH ROW EXECUTE FUNCTION public.prevent_journal_entry_mutation();

-- Journal Postings Mutation & Finalization Guard (ARGON-LEDGER-002)
CREATE OR REPLACE FUNCTION public.guard_journal_posting_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_journal public.journal_entries%ROWTYPE;
BEGIN
  -- If updating or deleting, ensure the associated journal is not FINALIZED
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    SELECT * INTO v_journal
    FROM public.journal_entries
    WHERE tenant_id = OLD.tenant_id AND journal_id = OLD.journal_id;

    IF FOUND AND v_journal.lifecycle_status = 'FINALIZED' THEN
      RAISE EXCEPTION 'LEDGER_POSTING_FINALIZED_IMMUTABLE: Cannot modify or delete postings of FINALIZED journal %', OLD.journal_id
        USING ERRCODE = '55000';
    END IF;
  END IF;

  -- If inserting or updating to a new journal, ensure target journal is not FINALIZED
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    SELECT * INTO v_journal
    FROM public.journal_entries
    WHERE tenant_id = NEW.tenant_id AND journal_id = NEW.journal_id;

    IF FOUND AND v_journal.lifecycle_status = 'FINALIZED' THEN
      RAISE EXCEPTION 'LEDGER_POSTING_FINALIZED_CLOSED: Cannot add or move postings to FINALIZED journal %', NEW.journal_id
        USING ERRCODE = '55000';
    END IF;
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_journal_postings_guard_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.journal_postings
  FOR EACH ROW EXECUTE FUNCTION public.guard_journal_posting_mutation();

-- Default Header Credit Total & Initial Lifecycle State Guard Trigger
CREATE OR REPLACE FUNCTION public.normalize_journal_entry_header_totals()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.total_credit_minor IS NULL THEN
    NEW.total_credit_minor := NEW.total_debit_minor;
  END IF;
  IF NEW.lifecycle_status <> 'POSTING' OR NEW.finalized_at IS NOT NULL THEN
    RAISE EXCEPTION 'LEDGER_LIFECYCLE_VIOLATION: New journal_entries row % must start in POSTING state before postings are verified at commit',
      NEW.journal_id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_journal_entries_default_credit_total
  BEFORE INSERT ON public.journal_entries
  FOR EACH ROW EXECUTE FUNCTION public.normalize_journal_entry_header_totals();

-- Pre-Insert/Update Posting Guard Trigger: Locks parent journal & account, rejects inactive accounts
CREATE OR REPLACE FUNCTION public.guard_journal_posting_before_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_account public.ledger_accounts%ROWTYPE;
  v_journal public.journal_entries%ROWTYPE;
BEGIN
  IF TG_OP = 'UPDATE' AND (OLD.journal_id IS DISTINCT FROM NEW.journal_id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id) THEN
    PERFORM 1
    FROM public.journal_entries
    WHERE tenant_id = OLD.tenant_id
      AND journal_id = OLD.journal_id
    FOR UPDATE;
  END IF;

  SELECT * INTO v_journal
  FROM public.journal_entries
  WHERE tenant_id = NEW.tenant_id
    AND journal_id = NEW.journal_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'LEDGER_JOURNAL_NOT_FOUND_OR_TENANT_MISMATCH: Journal % not found for tenant %',
      NEW.journal_id, NEW.tenant_id
      USING ERRCODE = '23503';
  END IF;

  IF v_journal.lifecycle_status = 'FINALIZED' THEN
    RAISE EXCEPTION 'LEDGER_POSTING_FINALIZED_CLOSED: Cannot insert or move postings into FINALIZED journal %',
      NEW.journal_id
      USING ERRCODE = '55000';
  END IF;

  IF v_journal.currency_code <> NEW.currency_code THEN
    RAISE EXCEPTION 'LEDGER_CURRENCY_MISMATCH: Posting currency (%) does not match journal currency (%)',
      NEW.currency_code, v_journal.currency_code
      USING ERRCODE = '23514';
  END IF;

  SELECT * INTO v_account
  FROM public.ledger_accounts
  WHERE tenant_id = NEW.tenant_id
    AND account_id = NEW.account_id
  FOR NO KEY UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'LEDGER_CROSS_TENANT_ACCOUNT_DENIED: Account % does not exist in tenant %',
      NEW.account_id, NEW.tenant_id
      USING ERRCODE = '23503';
  END IF;

  IF v_account.currency_code <> NEW.currency_code THEN
    RAISE EXCEPTION 'LEDGER_CURRENCY_MISMATCH: Posting currency (%) does not match account currency (%)',
      NEW.currency_code, v_account.currency_code
      USING ERRCODE = '23514';
  END IF;

  IF v_account.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'LEDGER_ACCOUNT_INACTIVE: Cannot post to non-active account % (status=%)',
      NEW.account_id, v_account.status
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_journal_postings_guard_before_insert
  BEFORE INSERT OR UPDATE ON public.journal_postings
  FOR EACH ROW EXECUTE FUNCTION public.guard_journal_posting_before_insert();

-- ============================================================================
-- 5. DEFERRED COMMIT-TIME JOURNAL INTEGRITY & AGGREGATE TRIGGER (ARGON-LEDGER-002 & 005)
-- Validates balanced debits/credits, stored totals, currency, and account ownership.
-- Validates both OLD and NEW journal IDs when postings move between journals.
-- Auto-finalizes valid journals upon successful verification.
-- ============================================================================
CREATE OR REPLACE FUNCTION public.verify_single_journal_integrity_at_commit(p_tenant_id UUID, p_journal_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_entry public.journal_entries%ROWTYPE;
  v_debit_sum BIGINT;
  v_credit_sum BIGINT;
  v_line_count INT;
  v_currency_mismatch_count INT;
  v_account_mismatch_count INT;
BEGIN
  IF p_tenant_id IS NULL OR p_journal_id IS NULL THEN
    RETURN;
  END IF;

  SELECT * INTO v_entry
  FROM public.journal_entries
  WHERE tenant_id = p_tenant_id
    AND journal_id = p_journal_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'LEDGER_DB_INVARIANT_VIOLATION: Parent journal_entries row % missing for tenant %',
      p_journal_id, p_tenant_id
      USING ERRCODE = '23503';
  END IF;

  SELECT
    COUNT(*),
    COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0),
    COUNT(*) FILTER (WHERE p.currency_code <> v_entry.currency_code),
    COUNT(*) FILTER (
      WHERE a.account_id IS NULL
         OR a.tenant_id <> v_entry.tenant_id
         OR a.currency_code <> v_entry.currency_code
         OR a.status <> 'ACTIVE'
    )
  INTO
    v_line_count,
    v_debit_sum,
    v_credit_sum,
    v_currency_mismatch_count,
    v_account_mismatch_count
  FROM public.journal_postings p
  LEFT JOIN public.ledger_accounts a
    ON a.tenant_id = p.tenant_id
   AND a.account_id = p.account_id
  WHERE p.journal_id = v_entry.journal_id
    AND p.tenant_id = v_entry.tenant_id;

  IF v_line_count < 2 OR v_line_count > 500 OR v_debit_sum <= 0 OR v_debit_sum <> v_credit_sum THEN
    RAISE EXCEPTION 'LEDGER_DB_INVARIANT_VIOLATION: Journal % is unbalanced at commit (debits=%, credits=%, lines=%)',
      v_entry.journal_id, v_debit_sum, v_credit_sum, v_line_count
      USING ERRCODE = '23514';
  END IF;

  IF v_debit_sum <> v_entry.total_debit_minor OR v_credit_sum <> v_entry.total_credit_minor THEN
    RAISE EXCEPTION 'LEDGER_STORED_AGGREGATE_MISMATCH: Journal % stored totals (debit=%, credit=%) do not match actual postings (debit=%, credit=%)',
      v_entry.journal_id, v_entry.total_debit_minor, v_entry.total_credit_minor, v_debit_sum, v_credit_sum
      USING ERRCODE = '23514';
  END IF;

  IF v_currency_mismatch_count > 0 OR v_account_mismatch_count > 0 THEN
    RAISE EXCEPTION 'LEDGER_OWNERSHIP_OR_CURRENCY_INVARIANT_VIOLATION: Journal % has currency_mismatches=% or account_mismatches=%',
      v_entry.journal_id, v_currency_mismatch_count, v_account_mismatch_count
      USING ERRCODE = '23514';
  END IF;

  -- Automatically seal verified journal to FINALIZED state to prevent post-commit append attacks
  IF v_entry.lifecycle_status = 'POSTING' THEN
    UPDATE public.journal_entries
       SET lifecycle_status = 'FINALIZED',
           finalized_at = clock_timestamp()
     WHERE tenant_id = v_entry.tenant_id
       AND journal_id = v_entry.journal_id;
  END IF;
END;
$$;

-- Constraint Trigger Function on journal_entries (Fires deferred at COMMIT)
CREATE OR REPLACE FUNCTION public.verify_journal_balanced_at_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM public.verify_single_journal_integrity_at_commit(NEW.tenant_id, NEW.journal_id);
  RETURN NULL;
END;
$$;

-- Constraint Trigger Function on journal_postings (Fires deferred at COMMIT on INSERT, UPDATE, DELETE)
-- Checks both OLD and NEW journal IDs when postings move or delete (ARGON-LEDGER-002)
CREATE OR REPLACE FUNCTION public.verify_postings_journal_balanced_at_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM public.verify_single_journal_integrity_at_commit(NEW.tenant_id, NEW.journal_id);
  ELSIF TG_OP = 'DELETE' THEN
    PERFORM public.verify_single_journal_integrity_at_commit(OLD.tenant_id, OLD.journal_id);
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.journal_id IS DISTINCT FROM NEW.journal_id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
      PERFORM public.verify_single_journal_integrity_at_commit(OLD.tenant_id, OLD.journal_id);
    END IF;
    PERFORM public.verify_single_journal_integrity_at_commit(NEW.tenant_id, NEW.journal_id);
  END IF;
  RETURN NULL;
END;
$$;

-- Constraint Trigger Function on fx_conversion_settlements (Fires deferred at COMMIT)
CREATE OR REPLACE FUNCTION public.verify_fx_settlement_at_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_src public.journal_entries%ROWTYPE;
  v_dst public.journal_entries%ROWTYPE;
BEGIN
  PERFORM public.verify_single_journal_integrity_at_commit(NEW.tenant_id, NEW.source_journal_id);
  PERFORM public.verify_single_journal_integrity_at_commit(NEW.tenant_id, NEW.target_journal_id);

  SELECT * INTO v_src FROM public.journal_entries
   WHERE tenant_id = NEW.tenant_id AND journal_id = NEW.source_journal_id;
  SELECT * INTO v_dst FROM public.journal_entries
   WHERE tenant_id = NEW.tenant_id AND journal_id = NEW.target_journal_id;

  IF v_src.total_debit_minor <> NEW.source_amount_minor OR v_dst.total_debit_minor <> NEW.target_amount_minor THEN
    RAISE EXCEPTION 'LEDGER_FX_SETTLEMENT_AMOUNT_MISMATCH: FX settlement % amounts (src=%, dst=%) do not match journal totals (src=%, dst=%)',
      NEW.settlement_id, NEW.source_amount_minor, NEW.target_amount_minor, v_src.total_debit_minor, v_dst.total_debit_minor
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_verify_journal_balanced_commit
  AFTER INSERT OR UPDATE ON public.journal_entries
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.verify_journal_balanced_at_commit();

CREATE CONSTRAINT TRIGGER trg_verify_posting_journal_balanced_commit
  AFTER INSERT OR UPDATE OR DELETE ON public.journal_postings
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.verify_postings_journal_balanced_at_commit();

CREATE CONSTRAINT TRIGGER trg_verify_fx_settlement_commit
  AFTER INSERT OR UPDATE ON public.fx_conversion_settlements
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION public.verify_fx_settlement_at_commit();
```

---

### D. Read-Only Data Preflight Detection Queries (`ARGON-LEDGER-001` & `ARGON-LEDGER-005`)
Before adding composite unique keys, composite foreign keys, or `CHECK` constraints to an existing production database, run these read-only diagnostic queries on a read replica or under `SET TRANSACTION READ ONLY` to identify any historical anomalies **without modifying or deleting financial records**:

```sql
-- PREFLIGHT-01: Detect NULL keys, duplicate (tenant_id, account_id), or unsupported currency codes in ledger_accounts
SELECT
  account_id,
  tenant_id,
  currency_code,
  balance_minor,
  allow_negative_balance,
  CASE
    WHEN account_id IS NULL OR tenant_id IS NULL THEN 'NULL_TENANT_OR_ACCOUNT_KEY'
    WHEN currency_code NOT IN ('JPY','KRW','VND','CLP','ISK','USD','EUR','GBP','INR','CAD','AUD','SGD','CHF','BHD','KWD','OMR','JOD','TND')
      THEN 'UNSUPPORTED_ACCOUNT_CURRENCY'
    WHEN NOT allow_negative_balance AND balance_minor < 0 THEN 'UNAUTHORIZED_NEGATIVE_ACCOUNT_BALANCE'
    WHEN balance_minor < -900000000000000 OR balance_minor > 900000000000000 THEN 'ACCOUNT_BALANCE_OUTSIDE_SAFE_BIGINT'
    ELSE 'DUPLICATE_TENANT_ACCOUNT_KEY'
  END AS anomaly_type
FROM public.ledger_accounts a
WHERE account_id IS NULL
   OR tenant_id IS NULL
   OR currency_code NOT IN ('JPY','KRW','VND','CLP','ISK','USD','EUR','GBP','INR','CAD','AUD','SGD','CHF','BHD','KWD','OMR','JOD','TND')
   OR (NOT allow_negative_balance AND balance_minor < 0)
   OR balance_minor < -900000000000000
   OR balance_minor > 900000000000000
   OR EXISTS (
     SELECT 1
     FROM public.ledger_accounts a2
     WHERE a2.tenant_id = a.tenant_id
       AND a2.account_id = a.account_id
       AND a2.ctid <> a.ctid
   );

-- PREFLIGHT-02: Detect cross-tenant or orphan journal_postings -> ledger_accounts references (ARGON-LEDGER-001)
SELECT
  p.posting_id,
  p.journal_id,
  p.tenant_id AS posting_tenant_id,
  p.account_id,
  a.tenant_id AS account_owner_tenant_id,
  p.currency_code AS posting_currency,
  a.currency_code AS account_currency,
  CASE
    WHEN a.account_id IS NULL THEN 'ORPHAN_ACCOUNT_REFERENCE'
    WHEN a.tenant_id <> p.tenant_id THEN 'CROSS_TENANT_ACCOUNT_POSTING'
    WHEN a.currency_code <> p.currency_code THEN 'ACCOUNT_CURRENCY_MISMATCH'
  END AS anomaly_type
FROM public.journal_postings p
LEFT JOIN public.ledger_accounts a
  ON a.account_id = p.account_id
WHERE a.account_id IS NULL
   OR a.tenant_id <> p.tenant_id
   OR a.currency_code <> p.currency_code;

-- PREFLIGHT-03: Detect cross-tenant, orphan, or currency-mismatched journal_postings -> journal_entries (ARGON-LEDGER-005)
SELECT
  p.posting_id,
  p.journal_id,
  p.tenant_id AS posting_tenant_id,
  j.tenant_id AS journal_tenant_id,
  p.currency_code AS posting_currency,
  j.currency_code AS journal_currency,
  CASE
    WHEN j.journal_id IS NULL THEN 'ORPHAN_JOURNAL_REFERENCE'
    WHEN j.tenant_id <> p.tenant_id THEN 'CROSS_TENANT_JOURNAL_POSTING'
    WHEN j.currency_code <> p.currency_code THEN 'JOURNAL_CURRENCY_MISMATCH'
  END AS anomaly_type
FROM public.journal_postings p
LEFT JOIN public.journal_entries j
  ON j.journal_id = p.journal_id
WHERE j.journal_id IS NULL
   OR j.tenant_id <> p.tenant_id
   OR j.currency_code <> p.currency_code;

-- PREFLIGHT-04: Detect historical journals violating double-entry balance, stored aggregate equality, or self-wash (ARGON-LEDGER-005)
SELECT
  j.journal_id,
  j.tenant_id,
  j.currency_code,
  j.total_debit_minor AS stored_total_debit_minor,
  COUNT(p.posting_id) AS posting_count,
  COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0) AS actual_debit_minor,
  COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0) AS actual_credit_minor,
  COUNT(p.posting_id) - COUNT(DISTINCT p.account_id) AS duplicate_account_postings
FROM public.journal_entries j
LEFT JOIN public.journal_postings p
  ON p.tenant_id = j.tenant_id
 AND p.journal_id = j.journal_id
GROUP BY j.journal_id, j.tenant_id, j.currency_code, j.total_debit_minor
HAVING COUNT(p.posting_id) < 2
    OR COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0) <= 0
    OR COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0)
       <> COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0)
    OR COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0)
       <> j.total_debit_minor
    OR COUNT(p.posting_id) <> COUNT(DISTINCT p.account_id);

-- PREFLIGHT-05: Detect unfinalized journals with invalid line counts, unbalanced totals, or lifecycle inconsistency (ARGON-LEDGER-002)
SELECT
  j.journal_id,
  j.tenant_id,
  j.lifecycle_status,
  j.total_debit_minor,
  j.total_credit_minor,
  COUNT(p.posting_id) AS posting_count,
  COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0) AS total_debit,
  COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0) AS total_credit,
  CASE
    WHEN j.lifecycle_status NOT IN ('POSTING', 'FINALIZED') THEN 'INVALID_LIFECYCLE_STATUS'
    WHEN COUNT(p.posting_id) < 2 THEN 'UNFINALIZED_INSUFFICIENT_POSTING_LINES'
    WHEN COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0) <> COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0)
      THEN 'UNFINALIZED_UNBALANCED_TOTALS'
    WHEN j.total_credit_minor IS NULL OR j.total_credit_minor <> j.total_debit_minor
      THEN 'MISSING_OR_UNBALANCED_HEADER_CREDIT_TOTAL'
    ELSE 'UNFINALIZED_POSTING_DEFECT'
  END AS anomaly_type
FROM public.journal_entries j
LEFT JOIN public.journal_postings p
  ON p.tenant_id = j.tenant_id
 AND p.journal_id = j.journal_id
GROUP BY j.journal_id, j.tenant_id, j.lifecycle_status, j.total_debit_minor, j.total_credit_minor
HAVING j.lifecycle_status NOT IN ('POSTING', 'FINALIZED')
    OR (j.lifecycle_status = 'FINALIZED' AND (COUNT(p.posting_id) < 2 OR COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0) <> COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0)))
    OR j.total_credit_minor IS NULL
    OR j.total_credit_minor <> j.total_debit_minor;

-- PREFLIGHT-06: Detect tables with missing FORCE ROW LEVEL SECURITY or missing RLS policies (ARGON-LEDGER-003)
SELECT
  c.relname AS table_name,
  c.relrowsecurity AS rls_enabled,
  c.relforcerowsecurity AS rls_forced,
  CASE
    WHEN NOT c.relrowsecurity THEN 'RLS_NOT_ENABLED'
    WHEN NOT c.relforcerowsecurity THEN 'RLS_NOT_FORCED'
    ELSE 'RLS_CONFIG_DEFECT'
  END AS anomaly_type
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname IN ('ledger_accounts', 'journal_entries', 'journal_postings')
  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);

-- PREFLIGHT-07: Detect roles with unexpected SUPERUSER, BYPASSRLS, CREATEDB, CREATEROLE, or conflicting LOGIN attributes (ARGON-ROLE-004)
SELECT
  rolname,
  rolsuper,
  rolbypassrls,
  rolcreatedb,
  rolcreaterole,
  rolcanlogin,
  CASE
    WHEN rolsuper THEN 'UNAUTHORIZED_SUPERUSER_ROLE'
    WHEN rolbypassrls THEN 'UNAUTHORIZED_BYPASSRLS_ROLE'
    WHEN rolcreatedb OR rolcreaterole THEN 'UNAUTHORIZED_DDL_ADMIN_ROLE'
    WHEN rolname IN ('db_migrator', 'app_runtime') AND rolcanlogin THEN 'UNEXPECTED_LOGIN_ON_NOLOGIN_ROLE'
    WHEN rolname = 'app_login' AND NOT rolcanlogin THEN 'MISSING_LOGIN_ON_APP_LOGIN_ROLE'
  END AS anomaly_type
FROM pg_roles
WHERE rolname IN ('db_migrator', 'app_runtime', 'app_login')
  AND (
    rolsuper
    OR rolbypassrls
    OR rolcreatedb
    OR rolcreaterole
    OR (rolname IN ('db_migrator', 'app_runtime') AND rolcanlogin)
    OR (rolname = 'app_login' AND NOT rolcanlogin)
  );
```

---

### E. Staged Production Migration, Lock-Duration Analysis & Failure Recovery Plan (`ARGON-LEDGER-001` & `ARGON-LEDGER-005`)

#### 1. Lock Duration & Table-Size Impact Analysis
| Migration Step | SQL Operation | PostgreSQL Lock Acquired | Concurrent Read/Write Impact | Table-Size Scaling Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **Step 1 (Concurrent Candidate Indexes)** | `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_ledger_accounts_tenant_account ...` | `SHARE UPDATE EXCLUSIVE` | **Non-blocking**: Concurrent `SELECT`, `INSERT`, `UPDATE` continue normally. | Two table scans in background; safe on $10^8+$ rows. |
| **Step 2 (Attach Unique Constraints)** | `ALTER TABLE ... ADD CONSTRAINT ... UNIQUE USING INDEX ...` | Brief `ACCESS EXCLUSIVE` (`< 50ms` metadata catalog update, guarded by `SET lock_timeout = '3s'`) | Instant metadata-only attachment because uniqueness is already proven by the concurrent index. | $O(1)$ constant time regardless of table size. |
| **Step 3 (Add `NOT VALID` Composite FKs & `CHECK`s)** | `ALTER TABLE public.journal_postings ADD CONSTRAINT fk_journal_postings_tenant_account FOREIGN KEY (tenant_id, account_id) REFERENCES public.ledger_accounts (tenant_id, account_id) ON UPDATE RESTRICT ON DELETE RESTRICT NOT VALID;` | Brief `SHARE ROW EXCLUSIVE` / `ACCESS EXCLUSIVE` (`< 50ms` catalog update) | Immediately enforces the constraint on all **new** `INSERT`/`UPDATE` writes without scanning historical rows. | $O(1)$ constant time regardless of table size. |
| **Step 4 (Online Constraint Validation)** | `ALTER TABLE public.journal_postings VALIDATE CONSTRAINT fk_journal_postings_tenant_account;` | `SHARE UPDATE EXCLUSIVE` | **Non-blocking**: Scans historical rows while allowing concurrent reads and writes. | Linear scan $O(N)$ with zero write downtime. |

#### 2. Staged Production Migration Script (Expand -> Validate -> Contract, Idempotent)
```sql
-- ============================================================================
-- PHASE 1: Build Unique Candidate Indexes Concurrently (Outside Transaction Block)
-- ============================================================================
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_ledger_accounts_tenant_account
  ON public.ledger_accounts (tenant_id, account_id);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_ledger_accounts_tenant_account_currency
  ON public.ledger_accounts (tenant_id, account_id, currency_code);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_journal_entries_tenant_journal_currency
  ON public.journal_entries (tenant_id, journal_id, currency_code);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_journal_postings_journal_account
  ON public.journal_postings (journal_id, account_id);

-- ============================================================================
-- PHASE 2: Attach Candidate Keys & NOT VALID Composite FKs / CHECKs (Fast Metadata Lock, Idempotent)
-- ============================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '15s';

ALTER TABLE public.journal_entries
  ADD COLUMN IF NOT EXISTS total_credit_minor BIGINT,
  ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(16) NOT NULL DEFAULT 'POSTING',
  ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_ledger_accounts_tenant_account') THEN
    ALTER TABLE public.ledger_accounts
      ADD CONSTRAINT uq_ledger_accounts_tenant_account UNIQUE USING INDEX idx_ledger_accounts_tenant_account;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_ledger_accounts_tenant_account_currency') THEN
    ALTER TABLE public.ledger_accounts
      ADD CONSTRAINT uq_ledger_accounts_tenant_account_currency UNIQUE USING INDEX idx_ledger_accounts_tenant_account_currency;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ledger_accounts_supported_currency') THEN
    ALTER TABLE public.ledger_accounts
      ADD CONSTRAINT chk_ledger_accounts_supported_currency
        CHECK (currency_code IN ('JPY','KRW','VND','CLP','ISK','USD','EUR','GBP','INR','CAD','AUD','SGD','CHF','BHD','KWD','OMR','JOD','TND')) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ledger_accounts_safe_bigint') THEN
    ALTER TABLE public.ledger_accounts
      ADD CONSTRAINT chk_ledger_accounts_safe_bigint
        CHECK (balance_minor >= -900000000000000 AND balance_minor <= 900000000000000) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_journal_entries_tenant_journal_currency') THEN
    ALTER TABLE public.journal_entries
      ADD CONSTRAINT uq_journal_entries_tenant_journal_currency UNIQUE USING INDEX idx_journal_entries_tenant_journal_currency;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_journal_entries_supported_currency') THEN
    ALTER TABLE public.journal_entries
      ADD CONSTRAINT chk_journal_entries_supported_currency
        CHECK (currency_code IN ('JPY','KRW','VND','CLP','ISK','USD','EUR','GBP','INR','CAD','AUD','SGD','CHF','BHD','KWD','OMR','JOD','TND')) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_journal_entries_totals_balanced') THEN
    ALTER TABLE public.journal_entries
      ADD CONSTRAINT chk_journal_entries_totals_balanced
        CHECK (
          total_debit_minor > 0
          AND total_debit_minor <= 900000000000000
          AND total_credit_minor > 0
          AND total_credit_minor <= 900000000000000
          AND total_debit_minor = total_credit_minor
        ) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_journal_postings_journal_account') THEN
    ALTER TABLE public.journal_postings
      ADD CONSTRAINT uq_journal_postings_journal_account UNIQUE USING INDEX idx_journal_postings_journal_account;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_journal_postings_supported_currency') THEN
    ALTER TABLE public.journal_postings
      ADD CONSTRAINT chk_journal_postings_supported_currency
        CHECK (currency_code IN ('JPY','KRW','VND','CLP','ISK','USD','EUR','GBP','INR','CAD','AUD','SGD','CHF','BHD','KWD','OMR','JOD','TND')) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_journal_postings_tenant_account') THEN
    ALTER TABLE public.journal_postings
      ADD CONSTRAINT fk_journal_postings_tenant_account
        FOREIGN KEY (tenant_id, account_id)
        REFERENCES public.ledger_accounts (tenant_id, account_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_journal_postings_tenant_account_currency') THEN
    ALTER TABLE public.journal_postings
      ADD CONSTRAINT fk_journal_postings_tenant_account_currency
        FOREIGN KEY (tenant_id, account_id, currency_code)
        REFERENCES public.ledger_accounts (tenant_id, account_id, currency_code)
        ON UPDATE RESTRICT ON DELETE RESTRICT NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_journal_postings_tenant_journal_currency') THEN
    ALTER TABLE public.journal_postings
      ADD CONSTRAINT fk_journal_postings_tenant_journal_currency
        FOREIGN KEY (tenant_id, journal_id, currency_code)
        REFERENCES public.journal_entries (tenant_id, journal_id, currency_code)
        ON UPDATE RESTRICT ON DELETE RESTRICT NOT VALID;
  END IF;
END
$$;
COMMIT;

-- ============================================================================
-- PHASE 3: Validate Constraints Online (SHARE UPDATE EXCLUSIVE — Non-Blocking)
-- ============================================================================
ALTER TABLE public.ledger_accounts VALIDATE CONSTRAINT chk_ledger_accounts_supported_currency;
ALTER TABLE public.ledger_accounts VALIDATE CONSTRAINT chk_ledger_accounts_safe_bigint;
ALTER TABLE public.journal_entries VALIDATE CONSTRAINT chk_journal_entries_supported_currency;
ALTER TABLE public.journal_entries VALIDATE CONSTRAINT chk_journal_entries_totals_balanced;
ALTER TABLE public.journal_postings VALIDATE CONSTRAINT chk_journal_postings_supported_currency;
ALTER TABLE public.journal_postings VALIDATE CONSTRAINT fk_journal_postings_tenant_account;
ALTER TABLE public.journal_postings VALIDATE CONSTRAINT fk_journal_postings_tenant_account_currency;
ALTER TABLE public.journal_postings VALIDATE CONSTRAINT fk_journal_postings_tenant_journal_currency;
```

#### 3. Non-Destructive Exception Handling & Failed Migration Recovery Strategy
1. **Strict Prohibition on Silent Rewrites**: Never `DELETE` or `UPDATE` historical rows in `journal_entries` or `journal_postings` to force a constraint to validate. If `PREFLIGHT-01`..`PREFLIGHT-04` return rows:
   - Abort Phase 3 (`VALIDATE CONSTRAINT`) while keeping Phase 2 (`NOT VALID` constraints) active so **all new writes are immediately protected**.
   - Record detected historical anomalies in an immutable audit table `public.ledger_migration_exceptions` for Finance Controller + Security Architect review and formal **compensating journal entry** resolution.
2. **Recovering from Interrupted `CREATE UNIQUE INDEX CONCURRENTLY`**:
   - Inspect `SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;` and run `DROP INDEX CONCURRENTLY IF EXISTS public.idx_ledger_accounts_tenant_account;` before re-running Phase 1.
3. **Rolling Back Phase 2 `NOT VALID` Constraints Without Table Rewrite**:
   - Executing `ALTER TABLE public.journal_postings DROP CONSTRAINT IF EXISTS fk_journal_postings_tenant_account;` is a metadata-only operation requiring zero table rewrite.

---

## 6. Verification & Test Requirements

1. **Prototype Currency Bypass Test**: Assert that `getCurrencyExponentStrict('toString')`, `getCurrencyExponentStrict('constructor')`, and `FieldSchemas.currencyCode.safeParse('valueOf')` fail closed.
2. **PostgreSQL `BIGINT` Overflow Test**: Assert that `assertPgBigIntRange(9_223_372_036_854_775_808n, 'amount')` and `calculateOrderTotals` with overflowing quantities throw `PG_BIGINT_RANGE_ERROR`.
3. **OTP Replay, Invalid Date & Brute-Force Lockout Test (`TEST-05`, `TEST-06`)**:
   - Assert that `verifyOtpCodeConstantTime(..., new Date('invalid'))` returns `false`.
   - Assert that submitting a valid OTP twice to `verifyAndConsumeOtpAtomically` succeeds on the first call and returns `ALREADY_CONSUMED_REPLAY_BLOCKED` on the second call.
   - Assert that 5 failed OTP attempts transition the challenge to `LOCKED_MAX_ATTEMPTS`, rejecting a subsequent 6th attempt even with the correct OTP code.
4. **PostgreSQL Database-Layer Ledger Acceptance Suite (`ARGON-LEDGER-001` & `ARGON-LEDGER-005` — `VERIFY-22`)**:
   - Execute the complete ledger DDL, preflight queries, composite foreign keys, `CHECK` constraints, and deferred constraint triggers against PostgreSQL (`@electric-sql/pglite` / PostgreSQL 16+) and verify all 10 acceptance criteria:
     1. Cross-tenant account posting rejected (`23503` / `LEDGER_CROSS_TENANT_ACCOUNT_DENIED`).
     2. Valid same-tenant balanced posting accepted.
     3. Invalid historical records detected by `PREFLIGHT-01`..`PREFLIGHT-04` without mutating rows.
     4. Account tenant reassignment rejected when referenced (`LEDGER_ACCOUNT_IDENTITY_IMMUTABLE` / `ON UPDATE RESTRICT`).
     5. Mismatched journal/account currency rejected (`LEDGER_CURRENCY_MISMATCH` / `fk_journal_postings_tenant_journal_currency`).
     6. Unsupported account/journal currency rejected (`chk_ledger_accounts_supported_currency`).
     7. Incorrect stored header totals (`total_debit_minor <> SUM(DEBIT)` or `total_debit_minor <> total_credit_minor`) rejected at commit (`LEDGER_STORED_AGGREGATE_MISMATCH`).
     8. Floating-point monetary columns/arithmetic absent (`BIGINT` minor units verified via `information_schema.columns`).
     9. Valid multi-line balanced journal accepted at `COMMIT`.
     10. Out-of-band / concurrent posting appended to an existing journal rejected at `COMMIT` without corrupting aggregate integrity.
5. **PostgreSQL Database-Layer Deferred Enforcement, RLS & Canonical Roles (`ARGON-LEDGER-002`, `ARGON-LEDGER-003`, `ARGON-ROLE-004` — `VERIFY-23`)**:
   - Execute the complete canonical role setup, `security.verify_active_tenant_context()`, forced RLS policies, journal lifecycle state engine, and deferred commit triggers against PostgreSQL (`@electric-sql/pglite` / PostgreSQL 16+):
     1. Unbalanced postings deferred failure at transaction `COMMIT` (`LEDGER_DB_INVARIANT_VIOLATION` / `23514`).
     2. Balanced journal auto-finalizes to `FINALIZED` and stamps `finalized_at`.
     3. Appending postings to a `FINALIZED` journal blocked immediately (`LEDGER_POSTING_FINALIZED_CLOSED`).
     4. Modifying or deleting postings on a `FINALIZED` journal blocked (`LEDGER_POSTING_FINALIZED_IMMUTABLE`).
     5. Relocating a posting between journals evaluates both `OLD` and `NEW` parent journals at `COMMIT`.
     6. Restrictive tenant RLS isolation: `app_runtime` / `app_login` sees 0 rows from other tenants.
     7. Cross-tenant mutation blocked by RLS `WITH CHECK`.
     8. Missing or forged GUC HMAC (`app.current_tenant_mac`) fails closed (0 rows returned).
     9. Direct access to `security.guc_hmac_keys` denied to `app_runtime` (`42501`).
     10. Runtime roles verify `NOBYPASSRLS` and `NOSUPERUSER` in `pg_roles`.

### Authoritative References
- **ISO 4217 Currency Codes & Minor Unit Exponents**: https://www.iso.org/iso-4217-currency-codes.html
- **PostgreSQL 16 Numeric Types (`bigint` 8-byte signed range)**: https://www.postgresql.org/docs/current/datatype-numeric.html
- **PostgreSQL 16 `CREATE CONSTRAINT TRIGGER ... DEFERRABLE INITIALLY DEFERRED`**: https://www.postgresql.org/docs/current/sql-createtrigger.html
- **RFC 9562 — Universally Unique IDentifiers (UUIDv7)**: https://datatracker.ietf.org/doc/html/rfc9562

