# Module 15: Security Hardening Checklist & Markdown Specification Parser

## 1. Scope & Threat Model

This module provides a deterministic parser and auditor (`parseMarkdownSecurityChecklist`) that scans the loaded Markdown skill modules (`00`–`15` and `SKILL.md`) to extract security controls, verify that every control documents its **Trust Boundary**, **Threat Model**, **Enforcement Location**, and **Failure Behavior**, and scan fenced code blocks (` ```typescript `, ` ```javascript `, ` ```sql `) for forbidden implementation anti-patterns.

---

## 2. Deterministic Markdown Security Hardening Parser & Code-Block Anti-Pattern Scanner

```typescript
// Executable TypeScript — Markdown Security Control Extractor & Code-Block Anti-Pattern Scanner
export type SecurityControlVerificationStatus =
  | 'DETECTED'
  | 'UNVERIFIED'
  | 'VERIFIED_FIXED'
  | 'ACCEPTED_RISK';

export interface SecurityChecklistItem {
  readonly id: string;
  readonly moduleFile: string;
  readonly sectionTitle: string;
  readonly severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  readonly controlSummary: string;
  readonly hasCodeImplementation: boolean;
  readonly status: SecurityControlVerificationStatus;
  readonly verifiedByTestIds: readonly string[];
}

export interface MarkdownSkillFileInput {
  readonly fileName: string;
  readonly content: string;
}

export interface ParseSecurityChecklistOptions {
  /**
   * DEVIL-22 Remediation: A security control may ONLY be marked `'VERIFIED_FIXED'`
   * when executable test evidence (`executedPassingTestIds`) is supplied and matches
   * the control's `TEST-XX` / `DEVIL-XX` identifiers (or item ID), with zero anti-pattern violations.
   */
  readonly executedPassingTestIds?: ReadonlySet<string>;
  readonly acceptedRiskIds?: ReadonlySet<string>;
}

const FORBIDDEN_CODE_BLOCK_ANTI_PATTERNS: ReadonlyArray<{
  id: string;
  description: string;
  regex: RegExp;
}> = [
  {
    id: 'UNSAFE_OBJECT_IN_OPERATOR_CURRENCY',
    description: 'Prototype-pollutable `code in CURRENCY_EXPONENTS` check inside executable code',
    regex: /if\s*\(\s*!\s*\(\s*code\s+in\s+CURRENCY_EXPONENTS\s*\)\s*\)/,
  },
  {
    id: 'TRUSTED_GATEWAY_BOOLEAN_FLAG',
    description: 'Caller-supplied `gatewayOidcVerified: boolean` parameter in executable function signature',
    regex: /gatewayOidcVerified\s*:\s*boolean/,
  },
  {
    id: 'FIRESTORE_CLIENT_COMPLETED_BYPASS',
    description: 'Firestore client update rule allowing direct transition to COMPLETED',
    regex: /request\.resource\.data\.status\s+in\s+\['DRAFT',\s*'ACTIVE',\s*'COMPLETED'\]/,
  },
  {
    id: 'UNDICI_FETCH_IGNORED_HTTPS_AGENT',
    description: 'Passing Node https.Agent into globalThis.fetch(url, { agent }) which Undici silently ignores',
    regex: /\bfetch\s*\([^)]*,\s*\{[^}]*\bagent\s*:/,
  },
  {
    id: 'SESSION_SCOPED_TENANT_GUC_LEAK',
    description: 'Session-scoped SET app.current_tenant_id (or set_config with false) leaking across pooled connections',
    regex: /set_config\s*\(\s*'app\.current_tenant_id'\s*,\s*[^,]+,\s*false\s*\)/,
  },
  {
    id: 'FORGEABLE_GLOBAL_SYMBOL_FOR_PINNED_TX',
    description: 'Forgeable Symbol.for("backend.skill.pinnedTenantTx") used for transaction client verification',
    regex: /Symbol\.for\s*\(\s*['"]backend\.skill\.pinnedTenantTx['"]\s*\)/,
  },
  {
    id: 'INVALID_PG_UPDATE_ORDER_BY_LIMIT',
    description: 'Invalid PostgreSQL syntax: direct ORDER BY / LIMIT on an UPDATE statement without a CTE or subquery',
    regex: /\bUPDATE\s+[a-zA-Z0-9_.]+\s+SET\s+[^;()]*?\bORDER\s+BY\b[^;()]*?\bLIMIT\b/i,
  },
  {
    id: 'NON_COMPOSITE_LEDGER_ACCOUNT_FK',
    description: 'Single-column foreign key to ledger_accounts(account_id) without composite (tenant_id, account_id) binding (ARGON-LEDGER-001)',
    regex: /\baccount_id\s+UUID\s+NOT\s+NULL\s+REFERENCES\s+(?:public\.)?ledger_accounts\s*\(\s*account_id\s*\)/i,
  },
];

export interface ExtractedCodeBlock {
  readonly language: string;
  readonly code: string;
  readonly fenceLength: number;
  readonly startLine: number;
}

/**
 * Deterministic Line-by-Line Markdown Fenced Code Block Extractor:
 * - Correctly handles nested code fences (e.g., a 4-backtick outer markdown block containing
 *   3-backtick inner typescript blocks) by only closing when encountering a fence of the same
 *   character (\x60 or ~) with length >= the opening fence length and no trailing info string.
 * - Fails safely on malformed/unclosed fences at EOF by discarding unclosed blocks unless
 *   includeMalformedUnclosed is explicitly requested.
 */
export function extractFencedCodeBlocksDetailed(
  markdown: string,
  options: {
    allowedLanguages?: ReadonlySet<string>;
    includeMalformedUnclosed?: boolean;
  } = {}
): {
  blocks: ExtractedCodeBlock[];
  malformedUnclosedCount: number;
} {
  const allowedLanguages =
    options.allowedLanguages ??
    new Set(['typescript', 'ts', 'javascript', 'js', 'sql', '']);
  const lines = markdown.split(/\r?\n/);
  const blocks: ExtractedCodeBlock[] = [];

  let inFence = false;
  let fenceChar = '';
  let fenceLength = 0;
  let fenceLang = '';
  let fenceStartLine = 0;
  let buffer: string[] = [];
  let malformedUnclosedCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!inFence) {
      const openMatch = /^\s*(\x60{3,}|~{3,})\s*([a-zA-Z0-9_-]*)\s*$/.exec(line);
      if (openMatch) {
        inFence = true;
        fenceChar = openMatch[1][0];
        fenceLength = openMatch[1].length;
        fenceLang = openMatch[2].toLowerCase();
        fenceStartLine = i + 1;
        buffer = [];
      }
    } else {
      const closeMatch = /^\s*(\x60{3,}|~{3,})\s*$/.exec(line);
      if (
        closeMatch &&
        closeMatch[1][0] === fenceChar &&
        closeMatch[1].length >= fenceLength
      ) {
        if (allowedLanguages.has(fenceLang)) {
          blocks.push({
            language: fenceLang,
            code: buffer.join('\n'),
            fenceLength,
            startLine: fenceStartLine,
          });
        } else if (fenceLang === 'markdown' || fenceLang === 'md') {
          // Recursively extract inner executable code blocks from nested markdown examples
          const nested = extractFencedCodeBlocksDetailed(buffer.join('\n'), options);
          blocks.push(...nested.blocks);
          malformedUnclosedCount += nested.malformedUnclosedCount;
        }
        inFence = false;
        fenceChar = '';
        fenceLength = 0;
        fenceLang = '';
        buffer = [];
      } else {
        buffer.push(line);
      }
    }
  }

  if (inFence) {
    malformedUnclosedCount += 1;
    if (options.includeMalformedUnclosed && allowedLanguages.has(fenceLang)) {
      blocks.push({
        language: fenceLang,
        code: buffer.join('\n'),
        fenceLength,
        startLine: fenceStartLine,
      });
    }
  }

  return { blocks, malformedUnclosedCount };
}

export function extractFencedCodeBlocks(markdown: string): string[] {
  return extractFencedCodeBlocksDetailed(markdown).blocks.map((b) => b.code);
}

const CANONICAL_EVIDENCE_ID_REGEX =
  /^(?:TEST-\d{2,3}|DEVIL-\d{2,3}|VERIFY-\d{2}|ARGON-[A-Z]+-\d{3})$/;

export function validateEvidenceIdentifiers(ids: Iterable<string>): {
  validIds: string[];
  invalidIds: string[];
  duplicateIds: string[];
} {
  const validIds: string[] = [];
  const invalidIds: string[] = [];
  const duplicateIds: string[] = [];
  const seenValid = new Set<string>();
  for (const rawId of ids) {
    if (typeof rawId === 'string' && CANONICAL_EVIDENCE_ID_REGEX.test(rawId.trim())) {
      const normalized = rawId.trim();
      if (seenValid.has(normalized)) {
        duplicateIds.push(normalized);
      } else {
        seenValid.add(normalized);
        validIds.push(normalized);
      }
    } else {
      invalidIds.push(String(rawId));
    }
  }
  return { validIds, invalidIds, duplicateIds };
}

export function parseMarkdownSecurityChecklist(
  files: readonly MarkdownSkillFileInput[],
  options: ParseSecurityChecklistOptions = {}
): {
  items: SecurityChecklistItem[];
  antiPatternViolations: Array<{ fileName: string; ruleId: string; description: string }>;
  malformedFenceFiles: Array<{ fileName: string; malformedUnclosedCount: number }>;
} {
  const items: SecurityChecklistItem[] = [];
  const antiPatternViolations: Array<{ fileName: string; ruleId: string; description: string }> = [];
  const malformedFenceFiles: Array<{ fileName: string; malformedUnclosedCount: number }> = [];
  const passingTests = options.executedPassingTestIds ?? new Set<string>();
  const acceptedRisks = options.acceptedRiskIds ?? new Set<string>();

  for (const file of files) {
    const fileViolations: string[] = [];
    const extracted = extractFencedCodeBlocksDetailed(file.content);
    if (extracted.malformedUnclosedCount > 0) {
      malformedFenceFiles.push({
        fileName: file.fileName,
        malformedUnclosedCount: extracted.malformedUnclosedCount,
      });
    }

    // Skip scanning Module 15's own detector definition block
    if (!file.fileName.startsWith('15-')) {
      const codeBlocks = extracted.blocks.map((b) => b.code).join('\n');
      for (const rule of FORBIDDEN_CODE_BLOCK_ANTI_PATTERNS) {
        if (rule.regex.test(codeBlocks)) {
          fileViolations.push(rule.id);
          antiPatternViolations.push({
            fileName: file.fileName,
            ruleId: rule.id,
            description: rule.description,
          });
        }
      }
    }

    const lines = file.content.split(/\r?\n/);
    let currentSection = 'Root';
    let sectionHasCodeBlock = false;
    let sectionLines: string[] = [];
    let inSectionFence = false;
    let sectionFenceChar = '';
    let sectionFenceLen = 0;

    const flushSection = (sectionTitle: string, bodyLines: string[], hasCode: boolean) => {
      const joined = bodyLines.join('\n');
      const isSecurityRelevant =
        /Trust Boundaries|Threat Model|CRITICAL|Remediated|Security|Idempotency|SSRF|ReBAC|Quarantine|Maker-Checker|Guardrail/i.test(
          sectionTitle + '\n' + joined
        );
      if (!isSecurityRelevant) return;

      const severity: SecurityChecklistItem['severity'] = /CRITICAL/i.test(sectionTitle + joined)
        ? 'CRITICAL'
        : /HIGH|SSRF|Quarantine|Webhook|ReBAC|Tenant|Guardrail/i.test(sectionTitle + joined)
        ? 'HIGH'
        : 'MEDIUM';

      const itemId = `${file.fileName}::${sectionTitle.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      const rawMatches = (sectionTitle + '\n' + joined).match(
        /\b(?:TEST-\d{2,3}|DEVIL-\d{2,3}|VERIFY-\d{2})\b/g
      ) ?? [];
      const { validIds: sectionTestMatches } = validateEvidenceIdentifiers(new Set(rawMatches));

      const matchedPassingTests = sectionTestMatches.filter((tid) => passingTests.has(tid));
      if (passingTests.has(itemId)) {
        matchedPassingTests.push(itemId);
      }

      const hasImplementation = hasCode || extracted.blocks.length > 0;

      // DEVIL-22 Fix: Never hardcode 'VERIFIED_REMEDIATED'!
      // Status is 'DETECTED' if anti-patterns or malformed unclosed fences exist,
      // 'ACCEPTED_RISK' if explicitly accepted,
      // 'VERIFIED_FIXED' ONLY if backed by executable passing test evidence and code implementation,
      // and 'UNVERIFIED' otherwise.
      let status: SecurityControlVerificationStatus;
      if (fileViolations.length > 0 || extracted.malformedUnclosedCount > 0) {
        status = 'DETECTED';
      } else if (acceptedRisks.has(itemId)) {
        status = 'ACCEPTED_RISK';
      } else if (hasImplementation && matchedPassingTests.length > 0) {
        status = 'VERIFIED_FIXED';
      } else {
        status = 'UNVERIFIED';
      }

      items.push({
        id: itemId,
        moduleFile: file.fileName,
        sectionTitle,
        severity,
        controlSummary: `Enforces hardened controls in "${sectionTitle}" within ${file.fileName}`,
        hasCodeImplementation: hasImplementation,
        status,
        verifiedByTestIds: matchedPassingTests,
      });
    };

    for (const line of lines) {
      const fenceOpenOrClose = /^\s*(\x60{3,}|~{3,})/.exec(line);
      if (fenceOpenOrClose) {
        const ch = fenceOpenOrClose[1][0];
        const len = fenceOpenOrClose[1].length;
        if (!inSectionFence) {
          inSectionFence = true;
          sectionFenceChar = ch;
          sectionFenceLen = len;
          sectionHasCodeBlock = true;
        } else if (ch === sectionFenceChar && len >= sectionFenceLen && /^\s*(\x60{3,}|~{3,})\s*$/.test(line)) {
          inSectionFence = false;
          sectionFenceChar = '';
          sectionFenceLen = 0;
        }
        sectionLines.push(line);
        continue;
      }

      if (!inSectionFence) {
        const headingMatch = /^#{2,3}\s+(.+)$/.exec(line.trim());
        if (headingMatch) {
          if (sectionLines.length > 0) {
            flushSection(currentSection, sectionLines, sectionHasCodeBlock);
          }
          currentSection = headingMatch[1].trim();
          sectionLines = [];
          sectionHasCodeBlock = false;
          continue;
        }
      }

      sectionLines.push(line);
    }
    if (sectionLines.length > 0) {
      flushSection(currentSection, sectionLines, sectionHasCodeBlock);
    }
  }

  return { items, antiPatternViolations, malformedFenceFiles };
}
```

---

## 3. Scanner Limitations: False-Positive & False-Negative Boundaries

1. **Why Static Markdown & Regex Scanning Cannot Certify Runtime Security (False Negatives)**:
   - `parseMarkdownSecurityChecklist` and `FORBIDDEN_CODE_BLOCK_ANTI_PATTERNS` inspect static AST/regex patterns inside fenced code blocks. They **cannot** detect semantic logic bugs, missing transaction boundaries across separate function calls, race conditions, or live PostgreSQL RLS misconfigurations unless paired with executable runtime tests (`executedPassingTestIds`).
   - Consequently, `parseMarkdownSecurityChecklist` **never** emits `'VERIFIED_FIXED'` from static parsing alone: any control without matching `executedPassingTestIds` remains `'UNVERIFIED'`.
2. **False-Positive Considerations**:
   - Documentation blocks that intentionally illustrate vulnerable code inside a ` ```typescript ` fence will trigger `FORBIDDEN_CODE_BLOCK_ANTI_PATTERNS` (`status: 'DETECTED'`). Counter-examples in specification files should be described in prose or Threat Model tables rather than executable code fences so that all fenced code blocks remain production-safe and compilable.

