import type { ReactNode } from 'react';
import type { Verdict } from './types';

/* ------------------------------------------------------------------ */
/* RedFlag Brand Light Theme Tokens (Render link design system)       */
/* ------------------------------------------------------------------ */
export const BAND: Record<Verdict, { text: string; bg: string; ring: string; stroke: string; label: string }> = {
  LOW: { text: 'text-emerald-700', bg: 'bg-emerald-50', ring: 'ring-emerald-300', stroke: '#10b981', label: 'Safe / Low' },
  CAUTION: { text: 'text-amber-800', bg: 'bg-amber-50', ring: 'ring-amber-300', stroke: '#f59e0b', label: 'Caution' },
  HIGH: { text: 'text-orange-800', bg: 'bg-orange-50', ring: 'ring-orange-300', stroke: '#f97316', label: 'High Risk' },
  CRITICAL: { text: 'text-[#D10000]', bg: 'bg-red-50', ring: 'ring-red-300', stroke: '#d10000', label: 'Critical Threat' },
};

export const FAMILY_LABEL: Record<string, string> = {
  message_intent: 'Message intent & coercion',
  url_technical: 'URL technical heuristics',
  entity_reputation: 'Entity & domain reputation',
  campaign_similarity: 'Campaign cluster similarity',
  context_anomaly: 'Structural & timing anomalies',
};

export function Panel({ children, className = '', title, subtitle, right }: {
  children: ReactNode; className?: string; title?: string; subtitle?: string; right?: ReactNode;
}) {
  return (
    <section className={`rounded-3xl border border-[#BBD5DA] bg-white shadow-sm overflow-hidden ${className}`}>
      {(title || right) && (
        <header className="flex items-start justify-between gap-4 border-b border-[#BBD5DA] bg-[#F5F5F5]/60 px-6 py-4">
          <div>
            {title && <h3 className="text-sm font-black tracking-wide text-slate-900 uppercase">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-6">{children}</div>
    </section>
  );
}

export function Chip({ children, tone = 'slate', title }: {
  children: ReactNode; tone?: 'slate' | 'red' | 'amber' | 'emerald' | 'sky' | 'violet'; title?: string;
}) {
  const tones = {
    slate: 'bg-slate-100 text-slate-700 border-slate-200',
    red: 'bg-red-50 text-[#D10000] border-red-200',
    amber: 'bg-amber-50 text-amber-800 border-amber-200',
    emerald: 'bg-emerald-50 text-emerald-800 border-emerald-200',
    sky: 'bg-sky-50 text-sky-800 border-sky-200',
    violet: 'bg-purple-50 text-purple-800 border-purple-200',
  };
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 font-mono text-[11px] font-semibold ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Evidence({ children }: { children: ReactNode }) {
  if (!children) return null;
  return (
    <mark className="rounded-md bg-red-100 px-1.5 py-0.5 font-mono text-[11px] text-red-900 ring-1 ring-red-300">
      {children}
    </mark>
  );
}

/** Big risk indicator with circular progress dial. Always paired with the band label. */
export function RiskDial({ score, verdict, confidence }: {
  score: number; verdict: Verdict; confidence: number;
}) {
  const band = BAND[verdict] ?? BAND.LOW;
  const r = 62;
  const c = 2 * Math.PI * r;
  const filled = (score / 100) * c;
  return (
    <div className="flex items-center gap-6">
      <div className="relative h-[160px] w-[160px] shrink-0">
        <svg viewBox="0 0 160 160" className="h-full w-full -rotate-90">
          <circle cx="80" cy="80" r={r} fill="none" stroke="#e2e8f0" strokeWidth="13" />
          <circle
            cx="80" cy="80" r={r} fill="none" stroke={band.stroke} strokeWidth="13"
            strokeLinecap="round" strokeDasharray={`${filled} ${c}`}
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-black tabular-nums ${band.text}`}>{score}</span>
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">/ 100</span>
        </div>
      </div>
      <div>
        <div className={`inline-flex items-center gap-1.5 rounded-full px-3.5 py-1 text-xs font-black uppercase tracking-wider border ${band.bg} ${band.text} ${band.ring.replace('ring-', 'border-')}`}>
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: band.stroke }} />
          {band.label}
        </div>
        <dl className="mt-3 space-y-1 text-xs text-slate-600">
          <div className="flex gap-2">
            <dt className="w-24 font-medium text-slate-500">Confidence</dt>
            <dd className="font-mono font-bold text-slate-800">{(confidence * 100).toFixed(0)}%</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-24 font-medium text-slate-500">Risk Bands</dt>
            <dd className="font-mono text-slate-600 text-[11px]">0–24 / 25–49 / 50–74 / 75–100</dd>
          </div>
        </dl>
        <p className="mt-2 max-w-[18rem] text-[11px] leading-relaxed text-slate-400">
          Evaluated via real-time Shannon entropy & heuristic engine.
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
        <span className="font-semibold text-slate-700">{label}</span>
        <span className="font-mono font-bold text-slate-600">{value.toFixed(1)} / {max}</span>
      </div>
      <div className="h-2.5 overflow-hidden rounded-full bg-slate-100 border border-[#BBD5DA]/40">
        <div className="h-full rounded-full bg-gradient-to-r from-[#D10000] to-rose-500 transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function Spinner({ label = 'Analyzing…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-sm font-semibold text-slate-600">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-[#D10000]" />
      {label}
    </div>
  );
}

export function Banner({ tone, children }: { tone: 'warn' | 'error' | 'info'; children: ReactNode }) {
  const tones = {
    warn: 'border-amber-300 bg-amber-50 text-amber-900',
    error: 'border-red-300 bg-red-50 text-red-900',
    info: 'border-[#BBD5DA] bg-[#DFF1F1]/70 text-slate-800',
  };
  return <div className={`rounded-2xl border px-4 py-3.5 text-sm ${tones[tone]}`}>{children}</div>;
}

export function Btn({ children, onClick, variant = 'primary', disabled, type = 'button', className = '' }: {
  children: ReactNode; onClick?: () => void; variant?: 'primary' | 'ghost' | 'danger' | 'subtle';
  disabled?: boolean; type?: 'button' | 'submit'; className?: string;
}) {
  const v = {
    primary: 'btn-redflag-glow disabled:opacity-50 disabled:pointer-events-none',
    danger: 'bg-red-50 text-red-700 border border-red-300 hover:bg-red-100',
    ghost: 'bg-white text-slate-700 border border-[#BBD5DA] hover:bg-[#F5F5F5]',
    subtle: 'bg-[#DFF1F1] text-teal-900 border border-[#BBD5DA] hover:bg-[#DFF1F1]/80',
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`rounded-full px-5 py-2.5 text-xs sm:text-sm font-bold tracking-wide transition-all cursor-pointer inline-flex items-center justify-center gap-2 ${v} ${className}`}>
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
