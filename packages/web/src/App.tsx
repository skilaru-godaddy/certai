import { useState, useCallback, useEffect } from 'react';
import { AnalysisStream } from './components/AnalysisStream.js';
import { ResultView } from './components/ResultView.js';
import type { AnalysisResult } from './types.js';

export default function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [userInput, setUserInput] = useState('');
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobCreatedAt, setJobCreatedAt] = useState<Date | undefined>(undefined);
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
        if (data.branch) setBranch(data.branch);
        if (data.userInput) setUserInput(data.userInput);
        if (data.createdAt) setJobCreatedAt(new Date(data.createdAt));
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
      body: JSON.stringify({ repoUrl, branch, userInput }),
    });
    const data = await res.json();
    setJobId(data.jobId);
    setJobCreatedAt(new Date());
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
    <div className="min-h-screen bg-white text-[#111]">
      {/* Top nav — GoDaddy Antares style */}
      <nav className="bg-white border-b border-[#D4DBE0] px-6 py-0 flex items-center" style={{ height: 56 }}>
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-[#111] rounded-[6px] flex items-center justify-center">
            <span className="text-white text-sm font-bold">C</span>
          </div>
          <span className="text-[15px] font-semibold text-[#111] tracking-tight">CertAI</span>
        </div>
        <span className="mx-3 text-[#D4DBE0] select-none">|</span>
        <span className="text-[#666] text-[14px] hidden sm:block">Security Certification Copilot</span>
        <div className="ml-auto flex items-center gap-2 text-[13px] text-[#666]">
          <span className="w-2 h-2 rounded-full bg-green-500 inline-block" />
          <span>GoDaddy Internal</span>
        </div>
      </nav>

      <div className="max-w-5xl mx-auto px-6 py-10">
        {/* Hero input — always visible */}
        <div className={`transition-all duration-500 ${result ? 'mb-6' : 'mb-16'}`}>
          {!result && (
            <div className="text-center mb-10">
              <h1 className="text-[40px] font-bold text-[#111] mb-3 leading-tight tracking-tight">
                From repo to cert package<br />
                <span className="text-[#444]">in 60 seconds.</span>
              </h1>
              <p className="text-[#666] text-[16px] max-w-xl mx-auto leading-relaxed">
                Paste any internal GitHub repo. CertAI reads your code, generates the full
                security certification package, and publishes it to Confluence.
              </p>
            </div>
          )}

          <form onSubmit={handleAnalyze} className="space-y-3">
            <div className="flex gap-3">
              <div className="flex-1">
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.secureserver.net/org/repo-name"
                  className="w-full bg-white border border-[#D6D6D6] rounded-[6px] px-4 py-3
                             text-[#111] placeholder-[#999] text-[14px] font-mono
                             focus:outline-none focus:border-[#111] focus:ring-2 focus:ring-[#111]/10
                             transition-colors"
                />
              </div>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
                className="w-[180px] bg-white border border-[#D6D6D6] rounded-[6px] px-3 py-3
                           text-[#111] placeholder-[#999] text-[14px] font-mono
                           focus:outline-none focus:border-[#111] focus:ring-2 focus:ring-[#111]/10
                           transition-colors"
              />
              <button
                type="submit"
                disabled={loading || !repoUrl.trim()}
                className="bg-[#111] hover:bg-[#333] active:bg-[#000]
                         disabled:opacity-40 disabled:cursor-not-allowed
                         text-white font-medium px-6 py-3 rounded-[6px]
                         transition-all duration-150 whitespace-nowrap text-[14px]"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                    Starting...
                  </span>
                ) : (
                  'Analyze →'
                )}
              </button>
            </div>
            <textarea
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              placeholder="Optional context: e.g. focus on recently added billing webhook module"
              rows={3}
              className="w-full bg-white border border-[#D6D6D6] rounded-[6px] px-4 py-3
                         text-[#111] placeholder-[#999] text-[13px]
                         focus:outline-none focus:border-[#111] focus:ring-2 focus:ring-[#111]/10
                         transition-colors resize-y"
            />
          </form>

          {!result && !isAnalyzing && (
            <p className="text-center text-[13px] text-[#999] mt-4">
              Uses Claude Sonnet 4.6 via GoCode proxy · Read-only GitHub access · Results published to Confluence
            </p>
          )}
        </div>

        {/* Analysis progress */}
        {isAnalyzing && (
          <div className="bg-white border border-[#D4DBE0] rounded-2xl p-8 mb-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-8 h-8 rounded-full bg-[#111] flex items-center justify-center">
                <span className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin block" />
              </div>
              <div>
                <p className="text-[#111] font-semibold text-[15px]">Analyzing {repoUrl.split('/').slice(-1)[0]}</p>
                <p className="text-[#666] text-[13px]">Claude is reading your codebase...</p>
              </div>
            </div>
            <AnalysisStream jobId={jobId} onResult={handleResult} />
          </div>
        )}

        {/* Published banner */}
        {publishedLinks && (
          <div className="bg-green-50 border border-green-200 rounded-2xl p-4 mb-6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded-full bg-green-100 flex items-center justify-center text-green-600 text-sm">✓</div>
              <div>
                <p className="text-green-800 font-semibold text-[14px]">Published successfully</p>
                <p className="text-green-600 text-[13px]">Confluence page created · Jira ticket {publishedLinks.ticketKey}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <a href={publishedLinks.pageUrl} target="_blank" rel="noreferrer"
                 className="text-[13px] bg-white hover:bg-green-50 border border-green-200 text-green-700 px-3 py-1.5 rounded-[6px] transition-colors">
                View in Confluence →
              </a>
              <a href={publishedLinks.ticketUrl} target="_blank" rel="noreferrer"
                 className="text-[13px] bg-white hover:bg-green-50 border border-green-200 text-green-700 px-3 py-1.5 rounded-[6px] transition-colors">
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
            jobId={jobId ?? undefined}
            createdAt={jobCreatedAt}
          />
        )}
      </div>
    </div>
  );
}
