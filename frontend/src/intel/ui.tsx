import type { ReactNode } from 'react';
import type { Verdict } from './types';

/* ------------------------------------------------------------------ */
/* Dark security theme tokens (contract s.22)                          */
/* ------------------------------------------------------------------ */
export const BAND: Record<Verdict, { text: string; bg: string; ring: string; stroke: string; label: string }> = {
  LOW: { text: 'text-emerald-300', bg: 'bg-emerald-500/10', ring: 'ring-emerald-500/30', stroke: '#34d399', label: 'Low' },
  CAUTION: { text: 'text-amber-300', bg: 'bg-amber-500/10', ring: 'ring-amber-500/30', stroke: '#fbbf24', label: 'Caution' },
  HIGH: { text: 'text-orange-300', bg: 'bg-orange-500/10', ring: 'ring-orange-500/30', stroke: '#fb923c', label: 'High' },
  CRITICAL: { text: 'text-red-300', bg: 'bg-red-500/10', ring: 'ring-red-500/30', stroke: '#f87171', label: 'Critical' },
};

export const FAMILY_LABEL: Record<string, string> = {
  message_intent: 'Message intent',
  url_technical: 'URL technical risk',
  entity_reputation: 'Entity reputation',
  campaign_similarity: 'Campaign similarity',
  context_anomaly: 'Context anomalies',
};

export function Panel({ children, className = '', title, subtitle, right }: {
  children: ReactNode; className?: string; title?: string; subtitle?: string; right?: ReactNode;
}) {
  return (
    <section className={`rounded-xl border border-slate-700/60 bg-slate-900/60 backdrop-blur ${className}`}>
      {(title || right) && (
        <header className="flex items-start justify-between gap-4 border-b border-slate-700/60 px-5 py-3">
          <div>
            {title && <h3 className="text-sm font-semibold tracking-wide text-slate-100 uppercase">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Chip({ children, tone = 'slate', title }: {
  children: ReactNode; tone?: 'slate' | 'red' | 'amber' | 'emerald' | 'sky' | 'violet'; title?: string;
}) {
  const tones = {
    slate: 'bg-slate-800 text-slate-200 border-slate-600',
    red: 'bg-red-950/70 text-red-200 border-red-700/70',
    amber: 'bg-amber-950/70 text-amber-200 border-amber-700/70',
    emerald: 'bg-emerald-950/70 text-emerald-200 border-emerald-700/70',
    sky: 'bg-sky-950/70 text-sky-200 border-sky-700/70',
    violet: 'bg-violet-950/70 text-violet-200 border-violet-700/70',
  };
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Evidence({ children }: { children: ReactNode }) {
  if (!children) return null;
  return (
    <mark className="rounded bg-red-500/15 px-1.5 py-0.5 font-mono text-[11px] text-red-200 ring-1 ring-red-500/30">
      {children}
    </mark>
  );
}

/** Big risk indicator. Always paired with the band label — never a bare number. */
export function RiskDial({ score, verdict, confidence }: {
  score: number; verdict: Verdict; confidence: number;
}) {
  const band = BAND[verdict] ?? BAND.LOW;
  const r = 62;
  const c = 2 * Math.PI * r;
  const filled = (score / 100) * c;
  return (
    <div className="flex items-center gap-5">
      <div className="relative h-[160px] w-[160px] shrink-0">
        <svg viewBox="0 0 160 160" className="h-full w-full -rotate-90">
          <circle cx="80" cy="80" r={r} fill="none" stroke="#1e293b" strokeWidth="13" />
          <circle
            cx="80" cy="80" r={r} fill="none" stroke={band.stroke} strokeWidth="13"
            strokeLinecap="round" strokeDasharray={`${filled} ${c}`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-black tabular-nums ${band.text}`}>{score}</span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">/ 100</span>
        </div>
      </div>
      <div>
        <div className={`inline-flex rounded-md px-3 py-1 text-sm font-bold uppercase tracking-wider ring-1 ${band.bg} ${band.text} ${band.ring}`}>
          {band.label} risk
        </div>
        <dl className="mt-3 space-y-1 text-xs text-slate-400">
          <div className="flex gap-2">
            <dt className="w-24">Confidence</dt>
            <dd className="font-mono text-slate-200">{(confidence * 100).toFixed(0)}%</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-24">Bands</dt>
            <dd className="font-mono text-slate-300">0–24 / 25–49 / 50–74 / 75–100</dd>
          </div>
        </dl>
        <p className="mt-2 max-w-[18rem] text-[11px] leading-relaxed text-slate-500">
          Product thresholds, not a legal determination.
        </p>
      </div>
    </div>
  );
}

export function Meter({ label, value, max }: { label: string; value: number; max: number }) {
  const pct = max ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between text-xs">
        <span className="text-slate-300">{label}</span>
        <span className="font-mono text-slate-400">{value.toFixed(1)} / {max}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-800">
        <div className="h-full rounded-full bg-gradient-to-r from-red-600 to-red-400" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function Spinner({ label = 'Analyzing…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-red-500" />
      {label}
    </div>
  );
}

export function Banner({ tone, children }: { tone: 'warn' | 'error' | 'info'; children: ReactNode }) {
  const tones = {
    warn: 'border-amber-700/60 bg-amber-950/40 text-amber-200',
    error: 'border-red-700/60 bg-red-950/40 text-red-200',
    info: 'border-sky-700/60 bg-sky-950/40 text-sky-200',
  };
  return <div className={`rounded-lg border px-4 py-3 text-sm ${tones[tone]}`}>{children}</div>;
}

export function Btn({ children, onClick, variant = 'primary', disabled, type = 'button', className = '' }: {
  children: ReactNode; onClick?: () => void; variant?: 'primary' | 'ghost' | 'danger' | 'subtle';
  disabled?: boolean; type?: 'button' | 'submit'; className?: string;
}) {
  const v = {
    primary: 'bg-red-600 text-white hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500',
    danger: 'bg-red-950 text-red-200 ring-1 ring-red-700 hover:bg-red-900',
    ghost: 'bg-transparent text-slate-300 ring-1 ring-slate-600 hover:bg-slate-800',
    subtle: 'bg-slate-800 text-slate-200 hover:bg-slate-700',
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`rounded-lg px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed ${v} ${className}`}>
      {children}
    </button>
  );
}

export const fmtDate = (s?: string | null) =>
  s ? new Date(s).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }) : '—';

export const fmtDay = (s?: string | null) =>
  s ? new Date(s).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) : '—';

export const titleCase = (s: string) =>
  s.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
