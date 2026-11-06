import fs from 'node:fs/promises';
import path from 'node:path';

const SKILL_FILES = [
  'SKILL.md',
  'references/01-domain-modeling-fields-timestamps-ids.md',
  'references/02-auth-authorization-fingerprinting-security.md',
  'references/03-databases-polyglot-storage-transactions.md',
  'references/04-apis-payments-webhooks-resilience.md',
  'references/05-file-uploads-multi-storage-malware-scanning.md',
  'references/06-async-queues-observability-testing-devops.md',
];

export default async function SkillSpecPage() {
  const baseDir = path.join(process.cwd(), 'skills', 'backend-development');
  const loadedFiles = await Promise.all(
    SKILL_FILES.map(async (relPath) => {
      const content = await fs.readFile(path.join(baseDir, relPath), 'utf8');
      return { path: `/skills/backend-development/${relPath}`, content };
    })
  );

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 p-6 md:p-10 font-mono text-sm">
      <div className="max-w-5xl mx-auto space-y-8">
        <header className="border-b border-neutral-800 pb-4">
          <h1 className="text-lg font-bold text-white">
            /skills/backend-development/SKILL.md (+ 6 Reference Modules)
          </h1>
          <p className="text-neutral-400 text-xs mt-1">
            Zero-loss Advanced Backend Development Skill specification files generated in repository.
          </p>
        </header>

        {loadedFiles.map((file) => (
          <section key={file.path} className="border border-neutral-800 bg-neutral-900/50">
            <div className="px-4 py-2 bg-neutral-900 border-b border-neutral-800 text-xs font-semibold text-emerald-400">
              {file.path}
            </div>
            <pre className="p-4 overflow-x-auto whitespace-pre-wrap break-words text-xs leading-relaxed text-neutral-200">
              {file.content}
            </pre>
          </section>
        ))}
      </div>
    </main>
  );
}
