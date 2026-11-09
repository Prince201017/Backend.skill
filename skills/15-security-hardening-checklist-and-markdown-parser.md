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
];

export function extractFencedCodeBlocks(markdown: string): string[] {
  const blocks: string[] = [];
  const regex = /\x60{3}(?:typescript|ts|javascript|js|sql)?\r?\n([\s\S]*?)\x60{3}/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(markdown)) !== null) {
    blocks.push(match[1]);
  }
  return blocks;
}

export function parseMarkdownSecurityChecklist(
  files: readonly MarkdownSkillFileInput[],
  options: ParseSecurityChecklistOptions = {}
): {
  items: SecurityChecklistItem[];
  antiPatternViolations: Array<{ fileName: string; ruleId: string; description: string }>;
} {
  const items: SecurityChecklistItem[] = [];
  const antiPatternViolations: Array<{ fileName: string; ruleId: string; description: string }> = [];
  const passingTests = options.executedPassingTestIds ?? new Set<string>();
  const acceptedRisks = options.acceptedRiskIds ?? new Set<string>();

  for (const file of files) {
    const fileViolations: string[] = [];
    // Skip scanning Module 15's own detector definition block
    if (!file.fileName.startsWith('15-')) {
      const codeBlocks = extractFencedCodeBlocks(file.content).join('\n');
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

    const fileReferencedIds = Array.from(
      new Set(
        (file.content.match(/\b(?:TEST-\d{2,3}|DEVIL-\d{2})\b/g) ?? [])
      )
    );

    const lines = file.content.split(/\r?\n/);
    let currentSection = 'Root';
    let sectionHasCodeBlock = false;
    let sectionLines: string[] = [];

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
      const sectionTestMatches = Array.from(
        new Set(
          ((sectionTitle + '\n' + joined).match(/\b(?:TEST-\d{2,3}|DEVIL-\d{2})\b/g) ?? fileReferencedIds)
        )
      );
      const matchedPassingTests = sectionTestMatches.filter((tid) => passingTests.has(tid));
      if (passingTests.has(itemId)) {
        matchedPassingTests.push(itemId);
      }

      const hasImplementation = hasCode || /\x60{3}(?:typescript|sql|javascript)/.test(file.content);

      // DEVIL-22 Fix: Never hardcode 'VERIFIED_REMEDIATED'!
      // Status is 'DETECTED' if anti-patterns exist, 'ACCEPTED_RISK' if explicitly accepted,
      // 'VERIFIED_FIXED' ONLY if backed by executable passing test evidence and code implementation,
      // and 'UNVERIFIED' otherwise.
      let status: SecurityControlVerificationStatus;
      if (fileViolations.length > 0) {
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
      const headingMatch = /^#{2,3}\s+(.+)$/.exec(line.trim());
      if (headingMatch) {
        if (sectionLines.length > 0) {
          flushSection(currentSection, sectionLines, sectionHasCodeBlock);
        }
        currentSection = headingMatch[1].trim();
        sectionLines = [];
        sectionHasCodeBlock = false;
      } else {
        if (/^\x60{3}/.test(line.trim())) {
          sectionHasCodeBlock = true;
        }
        sectionLines.push(line);
      }
    }
    if (sectionLines.length > 0) {
      flushSection(currentSection, sectionLines, sectionHasCodeBlock);
    }
  }

  return { items, antiPatternViolations };
}
```
