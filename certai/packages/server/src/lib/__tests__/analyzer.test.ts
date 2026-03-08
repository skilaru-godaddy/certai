import { describe, it, expect } from 'vitest';
import { createJob, getJob, JobStatus } from '../analyzer.js';

describe('job store', () => {
  it('creates a job with pending status', () => {
    const job = createJob('github.secureserver.net/org/repo');
    expect(job.status).toBe(JobStatus.Pending);
    expect(job.id).toBeTruthy();
    expect(job.repoUrl).toBe('github.secureserver.net/org/repo');
  });

  it('retrieves a job by id', () => {
    const job = createJob('github.secureserver.net/org/repo2');
    const found = getJob(job.id);
    expect(found?.id).toBe(job.id);
  });

  it('returns undefined for unknown job', () => {
    expect(getJob('nonexistent-id')).toBeUndefined();
  });
});
