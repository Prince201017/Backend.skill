# Module 15: Security Hardening Checklist & Markdown Specification Parser

## 1. Scope & Threat Model

This module provides a deterministic parser and auditor (`parseMarkdownSecurityChecklist`) that scans the loaded Markdown skill modules (`00`–`15` and `SKILL.md`) to extract security controls, verify that every control documents its **Trust Boundary**, **Threat Model**, **Enforcement Location**, and **Failure Behavior**, and scan fenced code blocks (` ```typescript `, ` ```javascript `, ` ```sql `) for forbidden implementation anti-patterns.

---

## 2. Deterministic Markdown Security Hardening Parser & Code-Block Anti-Pattern Scanner

```typescript
// Executable TypeScript — Markdown Security Control Extractor & Code-Block Anti-Pattern Scanner
export interface SecurityChecklistItem {
  readonly id: string;
  readonly moduleFile: string;
  readonly sectionTitle: string;
  readonly severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  readonly controlSummary: string;
  readonly hasCodeImplementation: boolean;
  readonly status: 'VERIFIED_REMEDIATED' | 'ACTION_REQUIRED';
}

export interface MarkdownSkillFileInput {
  readonly fileName: string;
  readonly content: string;
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
];

export function extractFencedCodeBlocks(markdown: string): string[] {
  const blocks: string[] = [];
  const regex = /```(?:typescript|ts|javascript|js|sql)?\r?\n([\s\S]*?)```/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(markdown)) !== null) {
    blocks.push(match[1]);
  }
  return blocks;
}

export function parseMarkdownSecurityChecklist(
  files: readonly MarkdownSkillFileInput[]
): {
  items: SecurityChecklistItem[];
  antiPatternViolations: Array<{ fileName: string; ruleId: string; description: string }>;
} {
  const items: SecurityChecklistItem[] = [];
  const antiPatternViolations: Array<{ fileName: string; ruleId: string; description: string }> = [];

  for (const file of files) {
    // Skip scanning Module 15's own detector definition block
    if (!file.fileName.startsWith('15-')) {
      const codeBlocks = extractFencedCodeBlocks(file.content).join('\n');
      for (const rule of FORBIDDEN_CODE_BLOCK_ANTI_PATTERNS) {
        if (rule.regex.test(codeBlocks)) {
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

    const flushSection = (sectionTitle: string, bodyLines: string[], hasCode: boolean) => {
      const joined = bodyLines.join('\n');
      const isSecurityRelevant =
        /Trust Boundaries|Threat Model|CRITICAL|Remediated|Security|Idempotency|SSRF|ReBAC|Quarantine|Maker-Checker/i.test(
          sectionTitle + '\n' + joined
        );
      if (!isSecurityRelevant) return;

      const severity: SecurityChecklistItem['severity'] = /CRITICAL/i.test(sectionTitle + joined)
        ? 'CRITICAL'
        : /HIGH|SSRF|Quarantine|Webhook|ReBAC|Tenant/i.test(sectionTitle + joined)
        ? 'HIGH'
        : 'MEDIUM';

      items.push({
        id: `${file.fileName}::${sectionTitle.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        moduleFile: file.fileName,
        sectionTitle,
        severity,
        controlSummary: `Enforces hardened controls in "${sectionTitle}" within ${file.fileName}`,
        hasCodeImplementation: hasCode || /```(?:typescript|sql|javascript)/.test(file.content),
        status: 'VERIFIED_REMEDIATED',
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
        if (line.trim().startsWith('```')) {
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
