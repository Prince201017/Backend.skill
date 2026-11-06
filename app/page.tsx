import fs from 'node:fs/promises';
import path from 'node:path';

async function collectMarkdownFiles(dirPath: string, relativePrefix = ''): Promise<{ path: string; content: string }[]> {
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    const sorted = [...entries].sort((a, b) => {
      if (a.name === 'SKILL.md') return -1;
      if (b.name === 'SKILL.md') return 1;
      return a.name.localeCompare(b.name);
    });

    const results: { path: string; content: string }[] = [];
    for (const entry of sorted) {
      const fullPath = path.join(dirPath, entry.name);
      const relPath = `${relativePrefix}/${entry.name}`;
      if (entry.isDirectory()) {
        const nested = await collectMarkdownFiles(fullPath, relPath);
        results.push(...nested);
      } else if (entry.isFile() && entry.name.endsWith('.md')) {
        const content = await fs.readFile(fullPath, 'utf8');
        results.push({ path: relPath, content });
      }
    }
    return results;
  } catch {
    return [];
  }
}

export default async function SkillSpecPage() {
  const skillsRoot = path.join(process.cwd(), 'skills');
  const loadedFiles = await collectMarkdownFiles(skillsRoot, '/skills');

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 p-6 md:p-10 font-mono text-sm">
      <div className="max-w-5xl mx-auto space-y-8">
        <header className="border-b border-neutral-800 pb-4">
          <h1 className="text-lg font-bold text-white">
            /skills/backendevelopment/SKILL.md (+ {Math.max(0, loadedFiles.length - 1)} Reference Modules)
          </h1>
          <p className="text-neutral-400 text-xs mt-1">
            Zero-loss Advanced Backend Development Skill specification files in repository.
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
