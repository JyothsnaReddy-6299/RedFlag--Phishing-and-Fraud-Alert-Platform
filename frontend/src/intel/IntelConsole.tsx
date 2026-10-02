import { useEffect, useState } from 'react';
import type { AnalysisResult, HealthState } from './types';
import { getHealth } from './api';
import { AnalyzeHub } from './AnalyzeHub';
import { CampaignView } from './CampaignView';
import { FeedView, ModerateView, PulseView, ReportForm } from './Community';
import { ResultView } from './ResultView';
import { Chip, Panel } from './ui';
import { RedFlagIcon } from '../components/RedFlagIcon';

type Tab = 'analyze' | 'campaigns' | 'feed' | 'pulse' | 'moderate';

const TABS: { key: Tab; label: string; hint: string }[] = [
  { key: 'analyze', label: 'Analyse', hint: 'Message · Link · Screenshot · QR' },
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
    <div className="min-h-screen bg-[#F5F5F5] text-slate-900">
      {/* ------------------------------- header ------------------------------- */}
      <header className="sticky top-0 z-20 border-b border-[#BBD5DA] bg-[#F5F5F5]/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
          <button
            onClick={() => { setTab('analyze'); setResult(null); setReporting(false); }}
            className="flex items-center gap-2.5 text-left cursor-pointer"
          >
            <RedFlagIcon size={28} />
            <div className="leading-tight">
              <p className="text-sm font-black tracking-wide text-slate-900">RED<span className="text-[#D10000]">FLAG</span></p>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">Threat Defense Radar</p>
            </div>
          </button>

          <nav className="order-3 flex w-full gap-1 overflow-x-auto md:order-none md:w-auto">
            {TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => { setTab(t.key); setReporting(false); }}
                title={t.hint}
                className={`whitespace-nowrap rounded-xl px-3.5 py-1.5 text-xs font-bold transition cursor-pointer ${
                  tab === t.key
                    ? 'bg-[#D10000] text-white shadow-sm'
                    : 'text-slate-700 hover:bg-white hover:text-[#D10000]'
                }`}
              >
                {t.label}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <HealthPill health={health} />
            <button
              onClick={onExitToClassic}
              className="rounded-full border border-[#BBD5DA] bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-700 hover:border-[#D10000] hover:text-[#D10000] transition cursor-pointer"
            >
              Overview View
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-8">
        {tab === 'analyze' && (
          <div className="space-y-6">
            {reporting ? (
              <ReportForm analysis={result} onDone={() => setReporting(false)} />
            ) : result ? (
              <ResultView
                result={result}
                onReport={() => setReporting(true)}
                onOpenCampaign={openCampaign}
                onScanAnother={() => setResult(null)}
              />
            ) : (
              <AnalyzeHub onResult={(r) => { setResult(r); window.scrollTo({ top: 0, behavior: 'smooth' }); }} />
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

      <footer className="mt-12 border-t border-[#BBD5DA] bg-white">
        <div className="mx-auto max-w-7xl space-y-3 px-4 py-8 text-xs text-slate-500">
          <p>
            <strong className="text-slate-800">RedFlag is decision support, not legal adjudication.</strong>{' '}
            It assesses risk from observable structural heuristics and AI intent models. It does not prove fraud and never identifies the owner of an indicator.
          </p>
          <p>
            Report cyber-fraud in India on <span className="font-mono font-bold text-[#D10000]">1930</span> or at{' '}
            <span className="font-mono font-bold text-slate-800">cybercrime.gov.in</span>.
          </p>
          {health && (
            <p className="font-mono text-[10px] text-slate-400">
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
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 rounded-full border border-[#BBD5DA] bg-white px-3 py-1.5 text-[11px] font-bold text-slate-700 hover:border-slate-400 cursor-pointer shadow-2xs"
      >
        <span className={`h-2 w-2 rounded-full ${health ? (ok ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500') : 'bg-red-500'}`} />
        {health ? (ok ? 'Radar Online' : 'Degraded') : 'Offline'}
      </button>
      {open && health && (
        <div className="absolute right-0 top-full z-30 mt-2 w-80 shadow-xl">
          <Panel title="Dependency Status" subtitle="Heuristic services and endpoints.">
            <ul className="space-y-2 text-xs">
              {Object.entries(health.checks).map(([k, v]) => (
                <li key={k} className="flex items-start justify-between gap-3 border-b border-slate-100 pb-1.5">
                  <span className="text-slate-800 font-semibold">{k}</span>
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
