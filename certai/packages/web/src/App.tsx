import { useState, useCallback, useEffect } from 'react';
import { AnalysisStream } from './components/AnalysisStream.js';
import { ResultView } from './components/ResultView.js';
import type { AnalysisResult } from './types.js';

export default function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [jobId, setJobId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [publishedLinks, setPublishedLinks] = useState<{ pageUrl: string; ticketKey: string; ticketUrl: string } | null>(null);

  const [autoJobId] = useState(() => new URLSearchParams(window.location.search).get('jobId'));

  useEffect(() => {
    if (!autoJobId) return;
    setJobId(autoJobId);
    fetch(`/job/${autoJobId}`)
      .then((r) => r.json())
      .then((data) => {
        if (data.repoUrl) setRepoUrl(data.repoUrl);
        if (data.status === 'done' && data.result) setResult(data.result);
      });
  }, [autoJobId]);

  async function handleAnalyze(e: React.FormEvent) {
    e.preventDefault();
    if (!repoUrl.trim()) return;
    setLoading(true);
    setResult(null);
    setJobId(null);
    setPublishedLinks(null);
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
    if (data.pageUrl) setPublishedLinks(data);
  }

  const handleResult = useCallback((r: AnalysisResult) => setResult(r), []);

  const isAnalyzing = jobId && !result;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Top nav */}
      <nav className="border-b border-gray-800 px-6 py-4 flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🔐</span>
          <span className="text-xl font-bold text-white tracking-tight">CertAI</span>
        </div>
        <span className="text-gray-600 text-sm hidden sm:block">|</span>
        <span className="text-gray-500 text-sm hidden sm:block">Security Certification Copilot</span>
        <div className="ml-auto flex items-center gap-2 text-xs text-gray-600">
          <span className="w-2 h-2 rounded-full bg-green-500 inline-block" />
          GoDaddy Internal
        </div>
      </nav>

      <div className="max-w-5xl mx-auto px-6 py-10">
        {/* Hero input — always visible */}
        <div className={`transition-all duration-500 ${result ? 'mb-6' : 'mb-16'}`}>
          {!result && (
            <div className="text-center mb-10">
              <h1 className="text-5xl font-black text-white mb-3 tracking-tight">
                From repo to cert package<br />
                <span className="text-indigo-400">in 60 seconds.</span>
              </h1>
              <p className="text-gray-400 text-lg max-w-xl mx-auto">
                Paste any internal GitHub repo. CertAI reads your code, generates the full
                security certification package, and publishes it to Confluence.
              </p>
            </div>
          )}

          <form onSubmit={handleAnalyze} className="flex gap-3">
            <div className="flex-1 relative">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 text-sm font-mono">
                github.secureserver.net/
              </span>
              <input
                type="text"
                value={repoUrl.replace(/^https?:\/\/github\.secureserver\.net\//, '').replace(/^github\.secureserver\.net\//, '')}
                onChange={(e) => setRepoUrl(`github.secureserver.net/${e.target.value}`)}
                placeholder="org/repo-name"
                className="w-full bg-gray-900 border border-gray-700 rounded-xl pl-52 pr-4 py-4
                           text-white placeholder-gray-600 text-sm
                           focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30
                           transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !repoUrl.trim()}
              className="bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700
                         disabled:opacity-40 disabled:cursor-not-allowed
                         text-white font-semibold px-7 py-4 rounded-xl
                         transition-all duration-150 whitespace-nowrap text-sm
                         shadow-lg shadow-indigo-900/40"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Starting...
                </span>
              ) : (
                'Analyze →'
              )}
            </button>
          </form>

          {!result && !isAnalyzing && (
            <p className="text-center text-xs text-gray-600 mt-4">
              Uses Claude Sonnet 4.6 via GoCode proxy · Read-only GitHub access · Results published to Confluence
            </p>
          )}
        </div>

        {/* Analysis progress */}
        {isAnalyzing && (
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 mb-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-8 h-8 rounded-full bg-indigo-600 flex items-center justify-center">
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin block" />
              </div>
              <div>
                <p className="text-white font-semibold">Analyzing {repoUrl.split('/').slice(-1)[0]}</p>
                <p className="text-gray-500 text-sm">Claude is reading your codebase...</p>
              </div>
            </div>
            <AnalysisStream jobId={jobId} onResult={handleResult} />
          </div>
        )}

        {/* Published banner */}
        {publishedLinks && (
          <div className="bg-green-950 border border-green-800 rounded-xl p-4 mb-6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-green-400 text-xl">✅</span>
              <div>
                <p className="text-green-300 font-semibold text-sm">Published successfully</p>
                <p className="text-green-600 text-xs">Confluence page created · Jira ticket {publishedLinks.ticketKey}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <a href={publishedLinks.pageUrl} target="_blank" rel="noreferrer"
                 className="text-xs bg-green-900 hover:bg-green-800 text-green-300 px-3 py-1.5 rounded-lg transition-colors">
                View in Confluence →
              </a>
              <a href={publishedLinks.ticketUrl} target="_blank" rel="noreferrer"
                 className="text-xs bg-green-900 hover:bg-green-800 text-green-300 px-3 py-1.5 rounded-lg transition-colors">
                {publishedLinks.ticketKey} →
              </a>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <ResultView
            result={result}
            repoUrl={repoUrl}
            onPublish={handlePublish}
            publishing={publishing}
          />
        )}
      </div>
    </div>
  );
}
