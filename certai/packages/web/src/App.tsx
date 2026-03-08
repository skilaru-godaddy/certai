import { useState } from 'react';

export default function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [jobId, setJobId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleAnalyze(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl }),
    });
    const { jobId } = await res.json();
    setJobId(jobId);
    setLoading(false);
  }

  return (
    <div className="max-w-5xl mx-auto px-6 py-12">
      <header className="mb-10">
        <h1 className="text-3xl font-bold text-white">
          🔐 CertAI
        </h1>
        <p className="text-gray-400 mt-1">
          Security Certification Copilot — from repo to cert package in 60 seconds
        </p>
      </header>

      <form onSubmit={handleAnalyze} className="flex gap-3 mb-10">
        <input
          type="text"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="github.secureserver.net/org/repo"
          className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-3
                     text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500"
        />
        <button
          type="submit"
          disabled={loading || !repoUrl.trim()}
          className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50
                     text-white font-semibold px-6 py-3 rounded-lg transition-colors"
        >
          {loading ? 'Starting...' : 'Analyze →'}
        </button>
      </form>

      {jobId && (
        <div className="text-gray-400">
          Job started: <code className="text-indigo-400">{jobId}</code>
          {/* AnalysisStream will go here in Task 7 */}
        </div>
      )}
    </div>
  );
}
