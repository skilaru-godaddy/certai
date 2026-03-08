import { describe, it, expect } from 'vitest';
import { buildAnalysisPrompt } from '../claude.js';
import type { RepoSnapshot } from '../../types.js';

describe('buildAnalysisPrompt', () => {
  it('includes all priority file paths in the prompt', () => {
    const snapshot: RepoSnapshot = {
      ref: { host: 'github.secureserver.net', owner: 'org', repo: 'repo' },
      allPaths: ['src/index.ts', 'README.md'],
      priorityFiles: [
        { path: 'README.md', content: '# My Service\nHandles payments.', sizeBytes: 30 },
        { path: 'src/index.ts', content: 'export const app = () => {}', sizeBytes: 27 },
      ],
      treeText: 'README.md\nsrc/index.ts',
    };

    const prompt = buildAnalysisPrompt(snapshot);

    expect(prompt).toContain('README.md');
    expect(prompt).toContain('src/index.ts');
    expect(prompt).toContain('My Service');
  });

  it('asks for risk category in the prompt', () => {
    const snapshot: RepoSnapshot = {
      ref: { host: 'github.secureserver.net', owner: 'org', repo: 'repo' },
      allPaths: [],
      priorityFiles: [],
      treeText: '',
    };
    const prompt = buildAnalysisPrompt(snapshot);
    expect(prompt.toLowerCase()).toContain('risk category');
    expect(prompt.toLowerCase()).toContain('cat 0');
  });
});
