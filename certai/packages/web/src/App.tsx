import { useState, useCallback } from 'react';
import { AnalysisStream } from './components/AnalysisStream.js';
import { ResultView } from './components/ResultView.js';
import type { AnalysisResult } from './types.js';

export default function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [jobId, setJobId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [publishing, setPublishing] = useState(false);

  async function handleAnalyze(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setJobId(null);
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoUrl }),
    });
    const data = await res.json();
    setJobId(data.jobId);
    setLoading(false);
  }

  async function handlePublish(space: string) {
    setPublishing(true);
    const res = await fetch('/publish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jobId, space }),
    });
    const data = await res.json();
    setPublishing(false);
    if (data.pageUrl) {
      window.open(data.pageUrl, '_blank');
      alert(`Published!\nConfluence: ${data.pageUrl}\nJira: ${data.ticketKey}`);
    } else if (data.error) {
      alert(`Publish failed: ${data.error}`);
    }
  }

  const handleResult = useCallback((r: AnalysisResult) => setResult(r), []);

  return (
    <div className="max-w-5xl mx-auto px-6 py-12">
      <header className="mb-10">
        <h1 className="text-3xl font-bold text-white">🔐 CertAI</h1>
        <p className="text-gray-400 mt-1">
          Security Certification Copilot — repo to cert package in 60 seconds
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

      {jobId && !result && (
        <AnalysisStream jobId={jobId} onResult={handleResult} />
      )}

      {result && (
        <ResultView
          result={result}
          repoUrl={repoUrl}
          onPublish={handlePublish}
          publishing={publishing}
        />
      )}
    </div>
  );
}
