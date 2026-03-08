import { describe, it, expect } from 'vitest';
import { parseRepoUrl, prioritizeFiles } from '../github.js';

describe('parseRepoUrl', () => {
  it('parses internal GitHub URL', () => {
    const result = parseRepoUrl('github.secureserver.net/my-org/my-repo');
    expect(result).toEqual({
      host: 'github.secureserver.net',
      owner: 'my-org',
      repo: 'my-repo',
    });
  });

  it('parses full https URL', () => {
    const result = parseRepoUrl('https://github.secureserver.net/my-org/my-repo');
    expect(result).toEqual({
      host: 'github.secureserver.net',
      owner: 'my-org',
      repo: 'my-repo',
    });
  });

  it('throws on invalid URL', () => {
    expect(() => parseRepoUrl('not-a-repo')).toThrow('Invalid repo URL');
  });
});

describe('prioritizeFiles', () => {
  it('returns README first', () => {
    const paths = ['src/index.ts', 'README.md', 'package.json'];
    const result = prioritizeFiles(paths);
    expect(result[0]).toBe('README.md');
  });

  it('prioritizes Dockerfile over source files', () => {
    const paths = ['src/index.ts', 'src/utils.ts', 'Dockerfile'];
    const result = prioritizeFiles(paths);
    expect(result.indexOf('Dockerfile')).toBeLessThan(result.indexOf('src/index.ts'));
  });

  it('caps at 14 files', () => {
    const paths = Array.from({ length: 30 }, (_, i) => `src/file${i}.ts`);
    expect(prioritizeFiles(paths).length).toBeLessThanOrEqual(14);
  });

  it('always includes package.json when present', () => {
    const paths = ['package.json', ...Array.from({ length: 20 }, (_, i) => `src/file${i}.ts`)];
    const result = prioritizeFiles(paths);
    expect(result).toContain('package.json');
  });
});
