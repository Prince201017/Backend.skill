import fs from 'node:fs/promises';
import path from 'node:path';
import BackendSkillWorkspace, { SkillMarkdownFile } from '@/components/BackendSkillWorkspace';

async function collectMarkdownFiles(
  dirPath: string,
  relativePrefix = ''
): Promise<SkillMarkdownFile[]> {
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    const sorted = [...entries].sort((a, b) => {
      if (a.name === 'SKILL.md') return -1;
      if (b.name === 'SKILL.md') return 1;
      return a.name.localeCompare(b.name);
    });

    const results: SkillMarkdownFile[] = [];
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

  return <BackendSkillWorkspace files={loadedFiles} />;
}
