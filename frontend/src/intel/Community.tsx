import { useEffect, useState } from 'react';
import type { AnalysisResult, Pulse, ReportRow } from './types';
import {
  approveReport, communityFeed, getPulse, mergeReport, moderationQueue, rejectReport,
  searchEntities, submitReport,
} from './api';
import { Banner, Btn, Chip, Panel, Spinner, fmtDate, fmtDay, titleCase } from './ui';

const CHANNELS = ['sms', 'whatsapp', 'email', 'call', 'social', 'qr', 'web', 'other'];

const LOCALITIES = [
  'Adyar', 'Velachery', 'Thoraipakkam', 'Sholinganallur', 'Perungudi', 'Pallikaranai',
  'Medavakkam', 'Madipakkam', 'Guindy', 'Besant Nagar', 'Thiruvanmiyur', 'Alwarpet',
  'Mylapore', 'Tambaram', 'Navalur', 'Other',
];

/* ------------------------------------------------------------------ */
/* Report incident                                                     */
/* ------------------------------------------------------------------ */
export function ReportForm({ analysis, onDone }: {
  analysis: AnalysisResult | null; onDone: () => void;
}) {
  const [channel, setChannel] = useState('sms');
  const [locality, setLocality] = useState('Velachery');
  const [narrative, setNarrative] = useState(analysis?.input_preview ?? '');
  const [consent, setConsent] = useState(true);
  const [visibility, setVisibility] = useState<'private' | 'public'>('public');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ id: string; dupes: number; note: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!analysis) {
    return <Banner tone="info">Analyze something first, then report it from the result screen.</Banner>;
  }

  async function submit() {
    if (!analysis) return;
    setBusy(true);
    setError(null);
    try {
      const res = await submitReport({
        analysis_id: analysis.analysis_id,
        category: analysis.scam_category,
        channel, narrative, locality,
        consent, visibility,
      });
      setDone({
        id: res.report.id,
        dupes: res.duplicate_candidates.length,
        note: res.note,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Submission failed.');
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Panel title="Report submitted">
        <Banner tone="info">
          <p>Report <code className="text-sky-100">{done.id}</code> is in the moderation queue.</p>
          {done.dupes > 0 && (
            <p className="mt-2">
              {done.dupes} possible duplicate(s) were detected by indicator and template matching —
              a moderator can merge them so one campaign holds many sightings.
            </p>
          )}
          <p className="mt-2 text-xs opacity-80">{done.note}</p>
        </Banner>
        <div className="mt-4"><Btn onClick={onDone}>Back to analysis</Btn></div>
      </Panel>
    );
  }

  return (
    <Panel title="Report this incident"
      subtitle="Evidence preview, extracted indicators, category, locality and consent.">
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Field label="Evidence (editable before you submit)">
            <textarea value={narrative} onChange={(e) => setNarrative(e.target.value)} rows={6}
              className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-red-600 focus:outline-none" />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Channel">
              <select value={channel} onChange={(e) => setChannel(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-red-600 focus:outline-none">
                {CHANNELS.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
            <Field label="Locality">
              <select value={locality} onChange={(e) => setLocality(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-red-600 focus:outline-none">
                {LOCALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
          </div>
        </div>

        <div className="space-y-4">
          <Field label="Detected category">
            <div className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200">
              {analysis.scam_category_label}
              <span className="ml-2 text-xs text-slate-500">
                (risk {analysis.risk_score}, {analysis.verdict_label})
              </span>
            </div>
          </Field>
          <Field label="Indicators that will be shared">
            <div className="flex flex-wrap gap-1.5 rounded-lg border border-slate-700 bg-slate-950 p-3">
              {analysis.entities.filter((e) => ['domain', 'phone', 'upi', 'email', 'handle'].includes(e.type))
                .map((e, i) => <Chip key={i} tone="amber">{e.type}: {e.display_value}</Chip>)}
              {analysis.entities.length === 0 && <span className="text-xs text-slate-500">none</span>}
            </div>
          </Field>
          <label className="flex items-start gap-3 rounded-lg border border-slate-700 bg-slate-950 p-3">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)}
              className="mt-0.5 h-4 w-4 accent-red-600" />
            <span className="text-xs text-slate-300">
              I consent to RedFlag publishing the <strong>normalized indicators</strong> from this
              report after moderation. My narrative stays private and contact details are masked.
            </span>
          </label>
          <Field label="Visibility">
            <div className="flex gap-2">
              {(['public', 'private'] as const).map((v) => (
                <button key={v} onClick={() => setVisibility(v)}
                  className={`flex-1 rounded-lg border px-3 py-2 text-xs ${visibility === v
                    ? 'border-red-600 bg-red-950/40 text-red-200'
                    : 'border-slate-700 text-slate-300'}`}>
                  {v}
                </button>
              ))}
            </div>
          </Field>
        </div>
      </div>

      {error && <div className="mt-4"><Banner tone="error">{error}</Banner></div>}
      <div className="mt-5 flex gap-3">
        <Btn disabled={busy} onClick={submit}>{busy ? 'Submitting…' : 'Submit report'}</Btn>
        <Btn variant="ghost" onClick={onDone}>Cancel</Btn>
      </div>
      <p className="mt-3 text-[11px] text-slate-500">
        Reports enter moderation before they become shared intelligence. This is how RedFlag
        resists report poisoning.
      </p>
    </Panel>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
        {label}
      </label>
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Community feed + entity search                                      */
/* ------------------------------------------------------------------ */
export function FeedView() {
  const [rows, setRows] = useState<ReportRow[]>([]);
  const [note, setNote] = useState('');
  const [q, setQ] = useState('');
  const [hits, setHits] = useState<Pulse['top_indicators']>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    communityFeed().then((d) => { setRows(d.reports); setNote(d.note); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      if (q.trim().length >= 2) searchEntities(q.trim()).then((d) => setHits(d.entities));
      else setHits([]);
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  if (loading) return <Spinner label="Loading community feed…" />;

  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <Panel className="lg:col-span-2" title="Community feed" subtitle={note}>
        {rows.length === 0 ? (
          <p className="text-sm text-slate-400">No moderated public reports yet.</p>
        ) : (
          <ul className="space-y-3">
            {rows.map((r) => (
              <li key={r.id} className="rounded-lg border border-slate-700/60 bg-slate-950/50 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="red">{titleCase(r.category)}</Chip>
                  <Chip>{r.channel}</Chip>
                  {r.locality && <Chip tone="sky">{r.locality}</Chip>}
                  {r.campaign_id && <Chip tone="violet">campaign</Chip>}
                  <span className="ml-auto text-[11px] text-slate-500">{fmtDate(r.created_at)}</span>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-slate-300">{r.narrative_excerpt}</p>
                <p className="mt-1 font-mono text-[10px] text-slate-600">
                  fingerprint {r.message_fingerprint}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Entity search" subtitle="Look up a number, domain or UPI ID.">
        <input value={q} onChange={(e) => setQ(e.target.value)}
          placeholder="e.g. 9123456780 or sbi-kyc"
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-red-600 focus:outline-none" />
        <ul className="mt-3 space-y-2">
          {hits.map((e, i) => (
            <li key={i} className="rounded-lg border border-slate-700/60 bg-slate-950/50 p-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-slate-200">{e.display_value}</span>
                <Chip tone={e.report_count > 0 ? 'red' : 'slate'}>{e.type}</Chip>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">
                {e.report_count} report(s) · {e.sighting_count} sighting(s) ·
                {' '}{fmtDay(e.first_seen)} → {fmtDay(e.last_seen)}
              </p>
            </li>
          ))}
          {q.length >= 2 && hits.length === 0 && (
            <li className="text-xs text-slate-500">Nothing tracked under that value yet.</li>
          )}
        </ul>
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Moderator queue                                                     */
/* ------------------------------------------------------------------ */
export function ModerateView() {
  const [rows, setRows] = useState<ReportRow[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = () => moderationQueue('pending')
    .then((d) => setRows(d.reports))
    .finally(() => setLoading(false));

  useEffect(() => { reload(); }, []);

  async function act(kind: 'approve' | 'reject' | 'merge', r: ReportRow) {
    setBusyId(r.id);
    try {
      if (kind === 'approve') {
        const res = await approveReport(r.id);
        setMsg(res.campaign
          ? `Approved. Attached to campaign "${res.campaign.label}" (${res.campaign.report_count} reports).`
          : 'Approved.');
      } else if (kind === 'reject') {
        await rejectReport(r.id, 'Not enough corroborating evidence.');
        setMsg('Rejected and excluded from shared intelligence.');
      } else {
        const target = r.moderation_state?.duplicate_candidates?.[0]?.report_id;
        if (!target) { setMsg('No duplicate candidate to merge into.'); return; }
        await mergeReport(r.id, target);
        setMsg(`Merged into ${target} as another sighting of the same campaign.`);
      }
      await reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Action failed.');
    } finally {
      setBusyId(null);
    }
  }

  if (loading) return <Spinner label="Loading moderation queue…" />;

  return (
    <div className="space-y-5">
      {msg && <Banner tone="info">{msg}</Banner>}
      <Panel title="Review queue" subtitle={`${rows.length} report(s) awaiting moderation`}>
        {rows.length === 0 ? (
          <p className="text-sm text-slate-400">Queue is clear.</p>
        ) : (
          <ul className="space-y-4">
            {rows.map((r) => {
              const dupes = r.moderation_state?.duplicate_candidates ?? [];
              return (
                <li key={r.id} className="rounded-lg border border-slate-700/60 bg-slate-950/50 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Chip tone="red">{titleCase(r.category)}</Chip>
                    <Chip>{r.channel}</Chip>
                    {r.locality && <Chip tone="sky">{r.locality}</Chip>}
                    <Chip tone={r.visibility === 'public' ? 'emerald' : 'slate'}>{r.visibility}</Chip>
                    <span className="ml-auto font-mono text-[11px] text-slate-500">{r.id}</span>
                  </div>
                  <p className="mt-2 max-h-24 overflow-auto text-xs leading-relaxed text-slate-300">
                    {r.narrative}
                  </p>
                  {dupes.length > 0 && (
                    <div className="mt-3 rounded-md border border-amber-800/50 bg-amber-950/30 p-2.5">
                      <p className="text-[11px] font-semibold text-amber-200">
                        {dupes.length} duplicate candidate(s)
                      </p>
                      <ul className="mt-1 space-y-0.5 text-[11px] text-amber-100/70">
                        {dupes.slice(0, 4).map((d) => (
                          <li key={d.report_id}>
                            <code>{d.report_id}</code> — {d.reason} ({d.relation})
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Btn disabled={busyId === r.id} onClick={() => act('approve', r)}>Approve</Btn>
                    <Btn variant="subtle" disabled={busyId === r.id || dupes.length === 0}
                      onClick={() => act('merge', r)}>Merge duplicate</Btn>
                    <Btn variant="danger" disabled={busyId === r.id} onClick={() => act('reject', r)}>Reject</Btn>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Threat pulse                                                        */
/* ------------------------------------------------------------------ */
export function PulseView({ onOpenCampaign }: { onOpenCampaign: (id: string) => void }) {
  const [pulse, setPulse] = useState<Pulse | null>(null);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getPulse(30).then(setPulse).finally(() => setLoading(false));
    fetch('/metrics.json').then((r) => (r.ok ? r.json() : null)).then(setMetrics).catch(() => null);
  }, []);

  if (loading || !pulse) return <Spinner label="Loading threat pulse…" />;

  const maxDay = Math.max(1, ...pulse.reports_by_day.map((d) => d.count));
  const m = metrics as null | {
    binary_scam_detection: { precision: number; recall: number; f1: number; false_positive_rate: number };
    latency_ms: { p50: number; p95: number };
    explanation_coverage: number;
    dataset: { samples: number; provenance: string };
    ocr_accuracy: { status: string };
    generated_at: string;
  };

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {Object.entries(pulse.totals).map(([k, v]) => (
          <div key={k} className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-4">
            <p className="text-2xl font-black tabular-nums text-slate-100">{v}</p>
            <p className="mt-1 text-[11px] uppercase tracking-wider text-slate-500">{titleCase(k)}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel className="lg:col-span-2" title="Report volume" subtitle={`Last ${pulse.window_days} days`}>
          <div className="flex h-40 items-end gap-1.5">
            {pulse.reports_by_day.map((d) => (
              <div key={d.date} className="group flex h-full flex-1 flex-col items-center justify-end">
                <span className="mb-1 text-[10px] text-slate-400">{d.count}</span>
                <div className="w-full rounded-t bg-gradient-to-t from-red-900 to-red-500"
                  style={{ height: `${Math.max(6, (d.count / maxDay) * 100)}%` }} />
                <span className="mt-1 text-[9px] text-slate-600">{d.date.slice(5)}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="By category">
          <ul className="space-y-2">
            {pulse.by_category.map((c) => (
              <li key={c.key} className="flex items-center justify-between text-xs">
                <span className="text-slate-300">{c.label}</span>
                <Chip tone="red">{c.count}</Chip>
              </li>
            ))}
          </ul>
          <div className="mt-4 border-t border-slate-800 pt-3">
            <p className="mb-2 text-[11px] uppercase tracking-wider text-slate-500">By language</p>
            <div className="flex flex-wrap gap-1.5">
              {pulse.by_language.map((l) => <Chip key={l.key} tone="sky">{l.key}: {l.count}</Chip>)}
            </div>
          </div>
          <div className="mt-4 border-t border-slate-800 pt-3">
            <p className="mb-2 text-[11px] uppercase tracking-wider text-slate-500">By locality</p>
            <div className="flex flex-wrap gap-1.5">
              {pulse.by_locality.map((l) => <Chip key={l.key}>{l.key}: {l.count}</Chip>)}
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Top indicators" subtitle="Most-reported normalized indicators.">
          <ul className="space-y-2">
            {pulse.top_indicators.map((e, i) => (
              <li key={i} className="flex items-center justify-between rounded-lg border border-slate-700/60 bg-slate-950/50 px-3 py-2">
                <div>
                  <span className="font-mono text-xs text-slate-200">{e.display_value}</span>
                  <p className="text-[10px] text-slate-500">
                    {e.type} · {fmtDay(e.first_seen)} → {fmtDay(e.last_seen)}
                  </p>
                </div>
                <Chip tone="red">{e.report_count}</Chip>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Emerging campaigns" subtitle="Ranked by report volume and recency.">
          <ul className="space-y-2">
            {pulse.emerging_campaigns.map((c) => (
              <li key={c.id}>
                <button onClick={() => onOpenCampaign(c.id)}
                  className="w-full rounded-lg border border-slate-700/60 bg-slate-950/50 p-3 text-left hover:border-red-600">
                  <p className="text-xs font-semibold text-slate-100">{c.label}</p>
                  <div className="mt-1.5 flex gap-1.5">
                    <Chip tone={c.status === 'active' ? 'red' : 'amber'}>{c.status}</Chip>
                    <Chip>{c.report_count} reports</Chip>
                    <Chip tone="violet">score {c.score}</Chip>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <Panel title="Measured evaluation" subtitle="Produced by backend/evaluate.py. Never hand-written.">
        {!m ? (
          <Banner tone="warn">
            Metrics file not published. Run <code>python backend/evaluate.py</code> and copy
            <code> backend/data/metrics.json</code> to <code>frontend/public/metrics.json</code>.
            Until then these values are <strong>not measured</strong>.
          </Banner>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
              <Metric label="Precision" value={m.binary_scam_detection.precision.toFixed(3)} />
              <Metric label="Recall" value={m.binary_scam_detection.recall.toFixed(3)} />
              <Metric label="F1" value={m.binary_scam_detection.f1.toFixed(3)} />
              <Metric label="False-positive rate" value={m.binary_scam_detection.false_positive_rate.toFixed(3)} />
              <Metric label="Latency P95" value={`${m.latency_ms.p95} ms`} />
              <Metric label="Explanation coverage" value={`${(m.explanation_coverage * 100).toFixed(0)}%`} />
            </div>
            <p className="mt-4 text-[11px] leading-relaxed text-slate-500">
              Measured on {m.dataset.samples} held-out samples · {m.dataset.provenance} ·
              generated {fmtDate(m.generated_at)}. OCR accuracy: <strong>{m.ocr_accuracy.status}</strong> —
              no labeled screenshot set ships with this build. Community reputation and campaign
              boosts are disabled during evaluation, so live scores can be higher.
            </p>
          </>
        )}
      </Panel>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-700/60 bg-slate-950/60 p-4">
      <p className="text-xl font-black tabular-nums text-red-300">{value}</p>
      <p className="mt-1 text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
    </div>
  );
}
