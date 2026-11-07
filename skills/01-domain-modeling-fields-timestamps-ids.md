# Module 01: Domain Modeling, Financial Engine, Timestamps & Cryptographic Generators

This reference provides production-grade implementations for domain modeling, strict field-type logic, currency-aware financial calculations (with exact prorated discount reconciliation, GST/VAT inclusive/exclusive policies, and partial refunds/credit notes), strict UTC vs. offset timestamps, and CSPRNG generators.

---

## 1. Field Type Logic Design & Validation Engine (TypeScript + Zod)

```typescript
import { z } from 'zod';

/**
 * ISO-4217 Currency Exponent Registry:
 * Defines how many decimal places (minor unit exponent) each currency uses.
 * - 0 decimals: JPY, KRW, VND, CLP, ISK
 * - 2 decimals: USD, EUR, GBP, INR, CAD, AUD, SGD, CHF
 * - 3 decimals: BHD, KWD, OMR, JOD, TND
 */
export const CURRENCY_EXPONENTS: Record<string, 0 | 2 | 3> = {
  JPY: 0, KRW: 0, VND: 0, CLP: 0, ISK: 0,
  USD: 2, EUR: 2, GBP: 2, INR: 2, CAD: 2, AUD: 2, SGD: 2, CHF: 2,
  BHD: 3, KWD: 3, OMR: 3, JOD: 3, TND: 3,
};

export const FieldSchemas = {
  // UUIDv7 or UUIDv4 identifier
  id: z.string().uuid({ message: 'Invalid UUID identifier' }),

  // Normalized Email: NFKC normalized, trimmed, lowercased, max 254 chars (RFC 5321)
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
    .refine((code) => code in CURRENCY_EXPONENTS, {
      message: 'Unsupported or invalid ISO-4217 currency code',
    }),

  // Non-negative Monetary Minor Units (cents/paise/fils as integer or BigInt string)
  nonNegativeMoneyMinor: z
    .union([z.number().int().nonnegative().safe(), z.string().regex(/^\d+$/)])
    .transform((v) => BigInt(v)),

  // Signed Monetary Minor Units (for ledger adjustments or credit notes)
  signedMoneyMinor: z
    .union([z.number().int().safe(), z.string().regex(/^-?\d+$/)])
    .transform((v) => BigInt(v)),

  // Standard Percentage Basis Points: strictly 0 to 10,000 (0.00% to 100.00%)
  percentageBasisPoints: z
    .number()
    .int()
    .min(0, 'Basis points cannot be negative')
    .max(10_000, 'Percentage basis points cannot exceed 10,000 (100.00%)'),

  // Strict UTC ISO-8601 Timestamp: MUST end with literal 'Z' (no arbitrary timezone offsets allowed)
  strictIsoUtcTimestamp: z
    .string()
    .datetime({ offset: false, message: 'Timestamp must be strict UTC ending with Z' }),

  // Offset-Aware ISO-8601 Timestamp normalized to canonical UTC on ingest
  isoTimestampNormalizedToUtc: z
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

## 2. Deterministic Financial Calculation Engine (Exact Proration, GST/VAT Inclusive/Exclusive & Refunds)

### Key Financial Engineering Invariants
1. **Strict Input Validation**: Reject negative quantities, negative unit prices, discount basis points outside `[0, 10_000]`, tax rates outside `[0, 10_000]`, or negative shipping amounts.
2. **Zero Penny-Drift Prorated Discount Reconciliation**:
   - When an order-level discount (`totalDiscountMinor`) is prorated across multiple line items, independently rounding each line's share can produce a sum that differs from `totalDiscountMinor` by $1..N$ minor units.
   - **Solution (Largest Remainder Allocation)**:
     1. Compute exact floor share for each line: $\text{floorShare}_i = \lfloor \frac{\text{lineGross}_i \times \text{totalDiscount}}{\text{subtotal}} \rfloor$
     2. Compute exact remainder for each line: $\text{rem}_i = (\text{lineGross}_i \times \text{totalDiscount}) \bmod \text{subtotal}$
     3. Compute leftover minor units: $\Delta = \text{totalDiscount} - \sum \text{floorShare}_i$
     4. Sort lines by $\text{rem}_i$ descending (breaking ties deterministically by line index) and add `1n` minor unit to the top $\Delta$ lines.
     5. Guarantee: $\sum_{i} \text{allocatedDiscount}_i \equiv \text{totalDiscountMinor}$ with zero discrepancy.
3. **Tax / GST Exclusive vs. Inclusive Policies**:
   - `TAX_EXCLUSIVE`: Unit price is net of tax. $\text{LineTax} = \text{roundHalfEven}(\frac{\text{LineNetAfterDiscount} \times \text{taxRateBps}}{10000})$.
   - `TAX_INCLUSIVE` (common in GST/VAT jurisdictions like EU, UK, India, Australia): Unit price already includes tax. After subtracting the prorated gross discount ($\text{LineGrossAfterDiscount}$), extract the embedded tax:
     $$\text{LineNet} = \text{roundHalfEven}\left(\frac{\text{LineGrossAfterDiscount} \times 10000}{10000 + \text{taxRateBps}}\right)$$
     $$\text{LineTax} = \text{LineGrossAfterDiscount} - \text{LineNet}$$

```typescript
export type TaxPricingPolicy = 'TAX_EXCLUSIVE' | 'TAX_INCLUSIVE';

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
 * Banker's Rounding (Round Half to Even) for non-negative and signed BigInt values.
 */
export function divRoundHalfEven(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) throw new Error('Denominator must be a positive BigInt');
  const isNegative = numerator < 0n;
  const absNum = isNegative ? -numerator : numerator;

  const quotient = absNum / denominator;
  const remainder = absNum % denominator;
  const twiceRemainder = remainder * 2n;

  let rounded = quotient;
  if (twiceRemainder > denominator) {
    rounded = quotient + 1n;
  } else if (twiceRemainder === denominator && quotient % 2n !== 0n) {
    rounded = quotient + 1n;
  }

  return isNegative ? -rounded : rounded;
}

export function calculateOrderTotals(input: OrderCalculationInput): OrderCalculationResult {
  const currencyExponent = CURRENCY_EXPONENTS[input.currencyCode];
  if (currencyExponent === undefined) {
    throw new Error(`Unsupported currency code: ${input.currencyCode}`);
  }
  if (input.items.length === 0) {
    throw new Error('Order must contain at least one line item');
  }
  if (input.discountBps < 0n || input.discountBps > 10_000n) {
    throw new Error(`Invalid discountBps: ${input.discountBps}. Must be between 0 and 10000`);
  }
  if (input.fixedDiscountMinor !== undefined && input.fixedDiscountMinor < 0n) {
    throw new Error('fixedDiscountMinor cannot be negative');
  }
  if (input.shippingMinor < 0n) {
    throw new Error('shippingMinor cannot be negative');
  }
  if (input.shippingTaxRateBps < 0n || input.shippingTaxRateBps > 10_000n) {
    throw new Error('shippingTaxRateBps must be between 0 and 10000');
  }
  if (input.maxDiscountCapMinor !== null && input.maxDiscountCapMinor < 0n) {
    throw new Error('maxDiscountCapMinor cannot be negative');
  }

  let subtotalMinor = 0n;
  const lineSubtotals: bigint[] = [];

  for (const item of input.items) {
    if (item.quantity <= 0n) {
      throw new Error(`Line ${item.lineId}: quantity must be > 0`);
    }
    if (item.unitPriceMinor < 0n) {
      throw new Error(`Line ${item.lineId}: unitPriceMinor cannot be negative`);
    }
    if (item.taxRateBps < 0n || item.taxRateBps > 10_000n) {
      throw new Error(`Line ${item.lineId}: taxRateBps must be between 0 and 10000`);
    }
    const lineSub = item.quantity * item.unitPriceMinor;
    lineSubtotals.push(lineSub);
    subtotalMinor += lineSub;
  }

  // Compute total order-level discount (percentage + optional fixed discount, capped at subtotal)
  const pctDiscount = divRoundHalfEven(subtotalMinor * input.discountBps, 10_000n);
  let totalDiscountMinor = pctDiscount + (input.fixedDiscountMinor ?? 0n);
  if (input.maxDiscountCapMinor !== null && totalDiscountMinor > input.maxDiscountCapMinor) {
    totalDiscountMinor = input.maxDiscountCapMinor;
  }
  if (totalDiscountMinor > subtotalMinor) {
    totalDiscountMinor = subtotalMinor;
  }

  // Prorate totalDiscountMinor across lines using Largest Remainder Method (exact reconciliation)
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
      lineTaxMinor = divRoundHalfEven(lineNetMinor * item.taxRateBps, 10_000n);
      lineTotalMinor = lineNetMinor + lineTaxMinor;
    } else {
      // TAX_INCLUSIVE (GST/VAT embedded in price)
      lineTotalMinor = afterDiscountMinor;
      lineNetMinor = divRoundHalfEven(lineTotalMinor * 10_000n, 10_000n + item.taxRateBps);
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

  // Shipping tax calculation
  let shippingNetMinor: bigint;
  let shippingTaxMinor: bigint;
  if (input.taxPolicy === 'TAX_EXCLUSIVE') {
    shippingNetMinor = input.shippingMinor;
    shippingTaxMinor = divRoundHalfEven(shippingNetMinor * input.shippingTaxRateBps, 10_000n);
  } else {
    shippingNetMinor = divRoundHalfEven(input.shippingMinor * 10_000n, 10_000n + input.shippingTaxRateBps);
    shippingTaxMinor = input.shippingMinor - shippingNetMinor;
  }

  const totalTaxMinor = merchandiseTaxMinor + shippingTaxMinor;
  const grandTotalMinor = netMerchandiseMinor + shippingNetMinor + totalTaxMinor;

  return {
    currencyCode: input.currencyCode,
    currencyExponent,
    taxPolicy: input.taxPolicy,
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
  if (targetTotal < 0n || totalWeight < 0n) {
    throw new Error('PRORATION_REJECTED: targetTotal and totalWeight must be non-negative');
  }
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
    if (w < 0n) {
      throw new Error('PRORATION_REJECTED: Individual line weight cannot be negative');
    }
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
    return a.index - b.index; // Deterministic tie-breaker
  });

  for (let i = 0; i < leftover; i++) {
    floors[remainders[i].index] += 1n;
  }

  return floors;
}
```

### Partial Refunds & Credit Note Engine
Never mutate historical invoices on refund. Track cumulative refunded amounts per line and issue an immutable **Credit Note**:

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
  requestedQuantityToRefund: bigint
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

  // If refunding the final remaining units on the line, refund the exact remaining net & tax to prevent penny drift
  const isFinalLineRefund = requestedQuantityToRefund === remainingQty;

  const rawRefundNet = isFinalLineRefund
    ? remainingNet
    : divRoundHalfEven(lineState.capturedNetMinor * requestedQuantityToRefund, lineState.capturedQuantity);

  const rawRefundTax = isFinalLineRefund
    ? remainingTax
    : divRoundHalfEven(lineState.capturedTaxMinor * requestedQuantityToRefund, lineState.capturedQuantity);

  // Clamp to remaining refundable balance so cumulative partial refunds can never exceed captured amount
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

## 3. Cryptographic ID, Token, OTP & Complex Generation Engines

```typescript
import crypto from 'node:crypto';

const UNAMBIGUOUS_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Excludes 0, O, 1, I, L

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

export function generateOtpCode(digits: 6 | 8 = 6, pepperSecret: string, contextId: string): {
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
  const max = 10 ** digits;
  const rawInt = crypto.randomInt(0, max);
  const code = rawInt.toString().padStart(digits, '0');
  const hmacDigest = crypto
    .createHmac('sha256', pepperSecret)
    .update(`${contextId}:${code}`)
    .digest('hex');
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  return { code, hmacDigest, expiresAt };
}

export function verifyOtpCodeConstantTime(
  submittedCode: string,
  expectedHmacHex: string,
  pepperSecret: string,
  contextId: string,
  expiresAt?: Date
): boolean {
  if (pepperSecret.length < 32) {
    throw new Error('OTP_CONFIG_ERROR: pepperSecret must be at least 32 characters');
  }
  if (!contextId || contextId.trim().length === 0) {
    return false;
  }
  if (expiresAt && Date.now() > expiresAt.getTime()) {
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

## 4. Composable Business Logic Engine: State Machines, Double-Entry Ledgers & Domain Rule Pipelines

A backend is only as secure as its domain invariants. Even when SQL injection and JWT forgery are blocked, attackers exploit **Business Logic Flaws** (illegal state transitions like refunding an unpaid or cancelled order, unbalanced ledger postings that create money out of thin air, or bypassing multi-condition eligibility rules).

### A. Deterministic Finite State Machine Engine with Optimistic Concurrency & Guard Predicates
Never mutate status columns with ad-hoc `UPDATE orders SET status = $1` statements. Enforce a strict transition graph with role checks, domain invariant guards, and monotonic `version` increment:

```typescript
export interface StateTransitionRule<TState extends string, TContext> {
  from: readonly TState[];
  to: TState;
  allowedRoles: readonly string[];
  guard?: (ctx: TContext) => { ok: boolean; reason?: string };
}

export function executeDomainStateTransition<TState extends string, TContext>(params: {
  entityName: string;
  entityId: string;
  currentState: TState;
  targetState: TState;
  currentVersion: number;
  expectedVersion: number;
  actorRoles: readonly string[];
  context: TContext;
  rules: readonly StateTransitionRule<TState, TContext>[];
}): {
  nextState: TState;
  nextVersion: number;
  auditEvent: string;
} {
  // 1. Optimistic Concurrency Control (prevents lost updates & race conditions)
  if (params.currentVersion !== params.expectedVersion) {
    throw new Error(
      `STATE_CONFLICT_STALE_VERSION: ${params.entityName} (${params.entityId}) expected v${params.expectedVersion}, found v${params.currentVersion}`
    );
  }

  // 2. Locate matching transition rule
  const matchingRule = params.rules.find(
    (r) => r.to === params.targetState && r.from.includes(params.currentState)
  );
  if (!matchingRule) {
    throw new Error(
      `ILLEGAL_STATE_TRANSITION: Cannot transition ${params.entityName} from "${params.currentState}" to "${params.targetState}"`
    );
  }

  // 3. Verify actor role authorization for this specific state transition
  const hasRole = params.actorRoles.some((role) => matchingRule.allowedRoles.includes(role));
  if (!hasRole) {
    throw new Error(
      `TRANSITION_ROLE_DENIED: Actor roles [${params.actorRoles.join(',')}] cannot transition ${params.entityName} to "${params.targetState}"`
    );
  }

  // 4. Evaluate business invariant guard predicate
  if (matchingRule.guard) {
    const verdict = matchingRule.guard(params.context);
    if (!verdict.ok) {
      throw new Error(
        `BUSINESS_INVARIANT_REJECTED: ${verdict.reason ?? 'Guard predicate failed'}`
      );
    }
  }

  return {
    nextState: params.targetState,
    nextVersion: params.currentVersion + 1,
    auditEvent: `${params.entityName.toLowerCase()}.transitioned.${params.currentState.toLowerCase()}_to_${params.targetState.toLowerCase()}`,
  };
}
```

### B. Zero-Discrepancy Double-Entry Accounting Journal Validator
Never update wallet or account balances without recording a balanced double-entry journal (`SUM(DEBIT) === SUM(CREDIT)` per currency within the same ACID transaction):

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
} {
  if (!params.idempotencyKey || params.idempotencyKey.trim().length < 8) {
    throw new Error('LEDGER_REJECTED: idempotencyKey (>= 8 chars) is mandatory');
  }
  if (params.postings.length < 2) {
    throw new Error('LEDGER_REJECTED: Double-entry journal requires at least 2 posting lines');
  }

  const currencyCode = params.postings[0].currencyCode;
  if (!(currencyCode in CURRENCY_EXPONENTS)) {
    throw new Error(`LEDGER_REJECTED: Unsupported currency "${currencyCode}"`);
  }

  let totalDebitMinor = 0n;
  let totalCreditMinor = 0n;
  const debitAccounts = new Set<string>();
  const creditAccounts = new Set<string>();

  for (const line of params.postings) {
    if (line.currencyCode !== currencyCode) {
      throw new Error('LEDGER_REJECTED: Cross-currency postings require an explicit FX clearing pair');
    }
    if (line.amountMinor <= 0n) {
      throw new Error(`LEDGER_REJECTED: Posting amount for account "${line.accountId}" must be > 0n`);
    }
    if (!line.accountId || line.accountId.trim().length === 0) {
      throw new Error('LEDGER_REJECTED: accountId cannot be empty');
    }
    if (line.direction === 'DEBIT') {
      totalDebitMinor += line.amountMinor;
      debitAccounts.add(line.accountId);
    } else {
      totalCreditMinor += line.amountMinor;
      creditAccounts.add(line.accountId);
    }
  }

  // Prevent self-transfer no-op loops (debiting and crediting the exact same account in a 2-line transfer)
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

  return { currencyCode, totalDebitMinor, totalCreditMinor };
}
```

