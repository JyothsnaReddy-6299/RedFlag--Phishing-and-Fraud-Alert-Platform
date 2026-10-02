import { useEffect, useState } from 'react';
import type { AnalysisResult, HealthState } from './types';
import { getHealth } from './api';
import { AnalyzeHub } from './AnalyzeHub';
import { CampaignView } from './CampaignView';
import { FeedView, ModerateView, PulseView, ReportForm } from './Community';
import { ResultView } from './ResultView';
import { Chip, Panel } from './ui';

type Tab = 'analyze' | 'campaigns' | 'feed' | 'pulse' | 'moderate';

const TABS: { key: Tab; label: string; hint: string }[] = [
  { key: 'analyze', label: 'Analyze', hint: 'Message · Link · Screenshot · QR' },
  { key: 'campaigns', label: 'Campaigns', hint: 'Graph, timeline, shared indicators' },
  { key: 'feed', label: 'Community', hint: 'Moderated reports & entity search' },
  { key: 'pulse', label: 'Threat pulse', hint: 'Trends and measured metrics' },
  { key: 'moderate', label: 'Moderate', hint: 'Approve, merge, reject' },
];

export function IntelConsole({ onExitToClassic }: { onExitToClassic: () => void }) {
  const [tab, setTab] = useState<Tab>('analyze');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [reporting, setReporting] = useState(false);
  const [campaignId, setCampaignId] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthState | null>(null);

  useEffect(() => {
    const load = () => getHealth().then(setHealth).catch(() => setHealth(null));
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  function openCampaign(id: string) {
    setCampaignId(id);
    setTab('campaigns');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      {/* ------------------------------- header ------------------------------- */}
      <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
          <button onClick={() => { setTab('analyze'); setResult(null); setReporting(false); }}
            className="flex items-center gap-2.5">
            <svg viewBox="0 0 24 24" className="h-7 w-7" aria-hidden="true">
              <path d="M5 3v18" stroke="#94a3b8" strokeWidth="2" strokeLinecap="round" />
              <path d="M6 4h12l-3 4 3 4H6z" fill="#ef4444" />
            </svg>
            <div className="leading-tight">
              <p className="text-sm font-black tracking-wide text-slate-50">RED<span className="text-red-500">FLAG</span></p>
              <p className="text-[10px] uppercase tracking-widest text-slate-500">Fraud Intelligence</p>
            </div>
          </button>

          <nav className="order-3 flex w-full gap-1 overflow-x-auto md:order-none md:w-auto">
            {TABS.map((t) => (
              <button key={t.key} onClick={() => { setTab(t.key); setReporting(false); }}
                title={t.hint}
                className={`whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-semibold transition ${tab === t.key
                  ? 'bg-red-600 text-white'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'}`}>
                {t.label}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <HealthPill health={health} />
            <button onClick={onExitToClassic}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 hover:border-slate-500 hover:text-slate-200">
              Classic scanner
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        {tab === 'analyze' && (
          <div className="space-y-6">
            {!result && !reporting && (
              <div className="rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-950 p-6">
                <h1 className="text-2xl font-black leading-tight text-slate-50 sm:text-3xl">
                  Paste it, screenshot it, or scan it.
                </h1>
                <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">
                  RedFlag tells you what is suspicious, <strong className="text-slate-200">why</strong> it is
                  suspicious, whether it resembles a known campaign, and what to do next — in Tamil,
                  English and Tanglish.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Chip tone="red">Detect</Chip><Chip tone="amber">Explain</Chip>
                  <Chip tone="violet">Correlate</Chip><Chip tone="sky">Report</Chip>
                  <Chip tone="emerald">Protect</Chip>
                </div>
              </div>
            )}

            {reporting ? (
              <ReportForm analysis={result} onDone={() => setReporting(false)} />
            ) : (
              <>
                <AnalyzeHub onResult={(r) => { setResult(r); window.scrollTo({ top: 0, behavior: 'smooth' }); }} />
                {result && (
                  <ResultView result={result} onReport={() => setReporting(true)}
                    onOpenCampaign={openCampaign} />
                )}
              </>
            )}
          </div>
        )}

        {tab === 'campaigns' && (
          <CampaignView selectedId={campaignId} onSelectCampaign={setCampaignId} />
        )}
        {tab === 'feed' && <FeedView />}
        {tab === 'pulse' && <PulseView onOpenCampaign={openCampaign} />}
        {tab === 'moderate' && <ModerateView />}
      </main>

      <footer className="mt-10 border-t border-slate-800">
        <div className="mx-auto max-w-7xl space-y-3 px-4 py-6 text-xs text-slate-500">
          <p>
            <strong className="text-slate-300">RedFlag is decision support, not legal adjudication.</strong>{' '}
            It assesses risk from observable evidence. It does not prove fraud and never identifies
            the owner of an indicator.
          </p>
          <p>
            Report cyber-fraud in India on <span className="font-mono text-red-400">1930</span> or at{' '}
            <span className="font-mono text-red-400">cybercrime.gov.in</span>.
          </p>
          {health && (
            <p className="font-mono text-[10px] text-slate-600">
              {health.service} · {health.model_version} · status {health.status}
              {health.degraded.length > 0 && ` · degraded: ${health.degraded.join(', ')}`}
            </p>
          )}
        </div>
      </footer>
    </div>
  );
}

function HealthPill({ health }: { health: HealthState | null }) {
  const [open, setOpen] = useState(false);
  const ok = health?.status === 'online';
  return (
    <div className="relative">
      <button onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-300 hover:border-slate-500">
        <span className={`h-2 w-2 rounded-full ${health ? (ok ? 'bg-emerald-400' : 'bg-amber-400') : 'bg-red-500'}`} />
        {health ? (ok ? 'All systems' : 'Degraded') : 'Offline'}
      </button>
      {open && health && (
        <div className="absolute right-0 top-full z-30 mt-2 w-80">
          <Panel title="Dependency state" subtitle="No secrets are exposed.">
            <ul className="space-y-2 text-[11px]">
              {Object.entries(health.checks).map(([k, v]) => (
                <li key={k} className="flex items-start justify-between gap-3">
                  <span className="text-slate-300">{k}</span>
                  <span className="text-right">
                    <Chip tone={v.status === 'ok' ? 'emerald' : v.status === 'local_only' ? 'amber' : 'red'}>
                      {v.status}
                    </Chip>
                    {(v.reason || v.note) && (
                      <p className="mt-1 max-w-[12rem] text-[10px] text-slate-500">{v.reason || v.note}</p>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      )}
    </div>
  );
}
