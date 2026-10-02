import { useState } from 'react';
import type { AnalysisResult } from './types';
import { getEvidenceBundle } from './api';
import {
  BAND, Banner, Btn, Chip, Evidence, FAMILY_LABEL, Meter, Panel, RiskDial, fmtDate, titleCase,
} from './ui';

const PRIORITY_TONE = {
  critical: 'border-red-600/70 bg-red-950/50',
  high: 'border-orange-600/60 bg-orange-950/40',
  medium: 'border-sky-700/50 bg-sky-950/30',
  low: 'border-slate-700/60 bg-slate-900/40',
} as const;

const ENTITY_TONE: Record<string, 'red' | 'amber' | 'sky' | 'violet' | 'emerald' | 'slate'> = {
  url: 'red', domain: 'red', upi: 'amber', phone: 'amber', email: 'sky',
  brand: 'violet', handle: 'sky', amount: 'emerald', locality: 'slate',
};

export function ResultView({ result, onReport, onOpenCampaign }: {
  result: AnalysisResult;
  onReport: (r: AnalysisResult) => void;
  onOpenCampaign: (id: string) => void;
}) {
  const [showHow, setShowHow] = useState(false);
  const [bundle, setBundle] = useState<string | null>(null);
  const band = BAND[result.verdict] ?? BAND.LOW;

  async function exportBundle() {
    const data = await getEvidenceBundle(result.analysis_id);
    const text = JSON.stringify(data, null, 2);
    setBundle(text);
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `redflag-evidence-${result.analysis_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-5">
      {/* ---------- Top: score + verdict + one-sentence explanation ---------- */}
      <Panel className={`ring-1 ${band.ring}`}>
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
            <RiskDial score={result.risk_score} verdict={result.verdict}
              confidence={result.confidence} />
          </div>
          <div className="flex-1 lg:max-w-xl">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone="red">{result.scam_category_label}</Chip>
              <Chip tone="sky">{result.language_detail.label}</Chip>
              <Chip>{titleCase(result.input_type)} input</Chip>
              {result.language_detail.is_code_switched && <Chip tone="violet">code-switched</Chip>}
            </div>
            <p className="mt-3 text-[15px] leading-relaxed text-slate-100">{result.summary}</p>
            <p className="mt-3 text-xs text-slate-500">
              Analysis {result.analysis_id} · {fmtDate(result.created_at)} · {result.latency_ms} ms ·
              model {result.model_version}
            </p>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap gap-3 border-t border-slate-700/60 pt-5">
          <Btn onClick={() => onReport(result)}>Report this incident</Btn>
          <Btn variant="ghost" onClick={() => setShowHow((v) => !v)}>
            {showHow ? 'Hide' : 'Show'} how we know
          </Btn>
          <Btn variant="ghost" onClick={exportBundle}>Export evidence bundle</Btn>
          {result.campaign_links[0] && (
            <Btn variant="subtle" onClick={() => onOpenCampaign(result.campaign_links[0].campaign_id)}>
              Open campaign: {result.campaign_links[0].label}
            </Btn>
          )}
        </div>
      </Panel>

      {result.degraded_checks.length > 0 && (
        <Banner tone="warn">
          <strong>Some checks were unavailable.</strong> The verdict was produced from the
          remaining evidence.
          <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs">
            {result.degraded_checks.map((d, i) => (
              <li key={i}><code className="text-amber-100">{d.check}</code> — {d.status}
                {d.reason ? `: ${d.reason}` : ''}</li>
            ))}
          </ul>
        </Banner>
      )}

      {result.ocr && (
        <Banner tone={result.ocr.mean_confidence >= 60 ? 'info' : 'warn'}>
          <strong>OCR: </strong>
          {result.ocr.available
            ? <>mean confidence {result.ocr.mean_confidence}% across {result.ocr.word_count} words
              ({result.ocr.languages_used.join(' + ')}).
              {result.ocr.user_corrected && ' Text was corrected by you before analysis.'}
              {' '}{result.ocr.warning}</>
            : result.ocr.reason}
        </Banner>
      )}

      {result.qr && result.qr.payloads.length > 0 && (
        <Banner tone="warn">
          <strong>QR destination (not opened): </strong>
          <code className="break-all text-amber-100">{result.qr.payloads.map((p) => p.data).join(' · ')}</code>
          <div className="mt-1 text-xs opacity-80">{result.qr.note}</div>
        </Banner>
      )}

      <div className="grid gap-5 lg:grid-cols-5">
        {/* ---------------- Red flags ---------------- */}
        <Panel className="lg:col-span-3" title="Red flags"
          subtitle="Highest-value signals first. Every row shows the exact evidence it came from.">
          {result.red_flags.length === 0 ? (
            <p className="text-sm text-slate-400">
              No scam pattern matched. That is an absence of evidence, not a guarantee of safety.
            </p>
          ) : (
            <ul className="space-y-3">
              {result.red_flags.slice(0, 7).map((f, i) => (
                <li key={i} className="rounded-lg border border-slate-700/60 bg-slate-950/50 p-3">
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-sm font-semibold text-slate-100">{f.title}</span>
                    <Chip tone={f.kind === 'observed' ? 'emerald' : 'violet'}>
                      {f.kind === 'observed' ? 'observed' : 'inferred'}
                    </Chip>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-slate-400">{f.detail}</p>
                  {f.evidence_span && (
                    <div className="mt-2"><Evidence>{f.evidence_span}</Evidence></div>
                  )}
                  <div className="mt-2 text-[10px] uppercase tracking-wider text-slate-600">
                    {FAMILY_LABEL[f.family] ?? f.family}
                    {f.weight != null && ` · +${f.weight} pts`}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        {/* ---------------- Score breakdown ---------------- */}
        <div className="space-y-5 lg:col-span-2">
          <Panel title="Score breakdown" subtitle="Risk = weighted evidence sum, capped per family.">
            <div className="space-y-3">
              {result.score_breakdown.map((b) => (
                <Meter key={b.family} label={FAMILY_LABEL[b.family] ?? b.family}
                  value={b.points} max={b.cap} />
              ))}
            </div>
            {result.benign_adjustment !== 0 && (
              <p className="mt-3 rounded-md bg-emerald-950/40 px-3 py-2 text-xs text-emerald-200">
                Legitimate-message markers reduced the score by {Math.abs(result.benign_adjustment)} points.
              </p>
            )}
            <p className="mt-3 text-[11px] text-slate-500">
              Total {result.risk_score}/100 — {result.verdict_label}.
            </p>
          </Panel>

          <Panel title="Entities extracted"
            subtitle="Normalized for matching; the raw value is kept as evidence.">
            {result.entities.length === 0
              ? <p className="text-sm text-slate-400">No indicators were found.</p>
              : (
                <div className="flex flex-wrap gap-2">
                  {result.entities.map((e, i) => (
                    <Chip key={i} tone={ENTITY_TONE[e.type] ?? 'slate'}
                      title={`raw: ${e.raw_value} · confidence ${e.confidence}`}>
                      <span className="opacity-60">{e.type}</span> {e.display_value}
                    </Chip>
                  ))}
                </div>
              )}
            {result.entity_reputation.length > 0 && (
              <div className="mt-4 rounded-lg border border-red-800/50 bg-red-950/30 p-3">
                <p className="text-xs font-semibold text-red-200">Seen before in community reports</p>
                <ul className="mt-2 space-y-1 text-xs text-red-100/80">
                  {result.entity_reputation.map((r, i) => (
                    <li key={i}>
                      <span className="font-mono">{r.display_value}</span> — {r.report_count} report(s),
                      first seen {(r.first_seen || '').slice(0, 10)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <p className="mt-3 text-[11px] text-slate-500">
              Appearing here means an indicator was reported. Ownership is never inferred.
            </p>
          </Panel>
        </div>
      </div>

      {/* ---------------- Recommended actions ---------------- */}
      <Panel title="What to do next" subtitle="Detection ends with concrete safety actions.">
        <ul className="grid gap-3 md:grid-cols-2">
          {result.recommended_actions.map((a, i) => (
            <li key={i} className={`rounded-lg border p-3 ${PRIORITY_TONE[a.priority]}`}>
              <div className="flex items-start gap-2">
                <Chip tone={a.priority === 'critical' ? 'red' : a.priority === 'high' ? 'amber' : 'slate'}>
                  {a.priority}
                </Chip>
              </div>
              <p className="mt-2 text-sm font-medium text-slate-100">{a.action}</p>
              <p className="mt-1 text-xs text-slate-400">{a.why}</p>
            </li>
          ))}
        </ul>
        <div className="mt-4 rounded-lg border border-slate-700 bg-slate-950/60 p-3 text-xs text-slate-300">
          <strong className="text-slate-100">Official reporting in India:</strong> call{' '}
          <span className="font-mono text-red-300">1930</span> (National Cyber Crime Helpline) or file at{' '}
          <span className="font-mono text-red-300">cybercrime.gov.in</span>.
        </div>
      </Panel>

      {/* ---------------- How we know (expandable) ---------------- */}
      {showHow && (
        <div className="grid gap-5 lg:grid-cols-2">
          <Panel title="Risk factors (audit trail)"
            subtitle="Every contribution with its weight, observed value, evidence and source.">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="pb-2 pr-3">Factor</th>
                    <th className="pb-2 pr-3">Family</th>
                    <th className="pb-2 pr-3 text-right">Weight</th>
                    <th className="pb-2 pr-3">Observed</th>
                    <th className="pb-2">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {result.risk_factors.map((f, i) => (
                    <tr key={i} className="align-top">
                      <td className="py-2 pr-3 text-slate-200">{f.name}
                        {f.evidence_span && <div className="mt-1"><Evidence>{f.evidence_span}</Evidence></div>}
                      </td>
                      <td className="py-2 pr-3 text-slate-500">{FAMILY_LABEL[f.family] ?? f.family}</td>
                      <td className="py-2 pr-3 text-right font-mono text-red-300">+{f.weight}</td>
                      <td className="py-2 pr-3 text-slate-400">{f.observed_value}</td>
                      <td className="py-2 font-mono text-[10px] text-slate-500">{f.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="space-y-5">
            <Panel title="Language handling"
              subtitle="Language is a routing signal, never a verdict.">
              <dl className="space-y-2 text-xs text-slate-300">
                <div className="flex gap-3"><dt className="w-32 text-slate-500">Detected</dt>
                  <dd>{result.language_detail.label} ({(result.language_detail.confidence * 100).toFixed(0)}%)</dd></div>
                <div className="flex gap-3"><dt className="w-32 text-slate-500">Scripts</dt>
                  <dd>{result.language_detail.scripts.join(', ') || '—'}</dd></div>
                <div className="flex gap-3"><dt className="w-32 text-slate-500">Tamil / Latin</dt>
                  <dd className="font-mono">{(result.language_detail.tamil_char_ratio * 100).toFixed(0)}% / {(result.language_detail.latin_char_ratio * 100).toFixed(0)}%</dd></div>
              </dl>
              {result.normalization.replacements.length > 0 && (
                <>
                  <p className="mt-4 text-xs font-semibold text-slate-200">Transliteration normalization</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {result.normalization.replacements.slice(0, 24).map((r, i) => (
                      <Chip key={i} tone="violet">{r.from} → {r.to}</Chip>
                    ))}
                  </div>
                  <p className="mt-2 text-[11px] text-slate-500">
                    The original wording is retained as evidence; only the analysis copy is folded.
                  </p>
                </>
              )}
            </Panel>

            <Panel title="Uncertainty" subtitle="What this result does not know.">
              <ul className="list-disc space-y-1 pl-5 text-xs text-slate-400">
                {result.uncertainties.length === 0
                  ? <li>No specific limitation was recorded for this analysis.</li>
                  : result.uncertainties.map((u, i) => <li key={i}>{u}</li>)}
              </ul>
              <div className="mt-3 space-y-1 text-[11px] text-slate-500">
                <p>Classifier: {result.intent.classifier_used
                  ? `${result.intent.classifier_category} @ ${(result.intent.classifier_confidence * 100).toFixed(0)}% (advisory only)`
                  : 'not used — rule engine alone'}</p>
                <p>Message fingerprint: <code>{result.message_fingerprint.slice(0, 16)}</code></p>
                <p>{result.disclaimer}</p>
              </div>
            </Panel>
          </div>
        </div>
      )}

      {bundle && (
        <Panel title="Evidence bundle" subtitle="Downloaded as JSON. Preview below.">
          <pre className="max-h-72 overflow-auto rounded-lg bg-slate-950 p-3 text-[10px] leading-relaxed text-slate-400">
            {bundle.slice(0, 4000)}
          </pre>
        </Panel>
      )}
    </div>
  );
}
