import { useState } from 'react';
import type { AnalysisResult } from './types';
import { getEvidenceBundle } from './api';
import {
  BAND, Banner, Chip, Evidence, FAMILY_LABEL, Meter, Panel, RiskDial, fmtDate, titleCase,
} from './ui';
import { ShieldAlert, ArrowLeft, Download, Eye, EyeOff, ExternalLink, Flag, ShieldCheck, AlertTriangle } from 'lucide-react';

const PRIORITY_TONE = {
  critical: 'border-red-200 bg-red-50/70',
  high: 'border-orange-200 bg-orange-50/70',
  medium: 'border-sky-200 bg-sky-50/70',
  low: 'border-slate-200 bg-slate-50/70',
} as const;

const ENTITY_TONE: Record<string, 'red' | 'amber' | 'sky' | 'violet' | 'emerald' | 'slate'> = {
  url: 'red', domain: 'red', upi: 'amber', phone: 'amber', email: 'sky',
  brand: 'violet', handle: 'sky', amount: 'emerald', locality: 'slate',
};

export function ResultView({ result, onReport, onOpenCampaign, onScanAnother }: {
  result: AnalysisResult;
  onReport: (r: AnalysisResult) => void;
  onOpenCampaign: (id: string) => void;
  onScanAnother?: () => void;
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
    <div className="space-y-6">
      {/* Top Navigation Bar for Results */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2">
        {onScanAnother && (
          <button
            onClick={onScanAnother}
            className="inline-flex items-center gap-2 text-sm font-bold text-slate-600 hover:text-[#D10000] transition-colors cursor-pointer"
          >
            <ArrowLeft size={16} />
            <span>Scan Another Target</span>
          </button>
        )}

        <div className="flex items-center gap-2 text-xs font-semibold text-slate-500 ml-auto">
          <ShieldAlert size={15} className="text-[#D10000]" />
          <span>Analysis ID: <code className="font-mono text-slate-700">{result.analysis_id.slice(0, 12)}…</code></span>
        </div>
      </div>

      {/* ---------- Primary Verdict Banner ---------- */}
      <Panel className={`border-2 ${band.ring.replace('ring-', 'border-')} shadow-md`}>
        <div className="flex flex-col gap-8 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
            <RiskDial
              score={result.risk_score}
              verdict={result.verdict}
              confidence={result.confidence}
            />
          </div>

          <div className="flex-1 lg:max-w-xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-3 py-1 rounded-full text-xs font-bold border ${band.bg} ${band.text} ${band.ring.replace('ring-', 'border-')}`}>
                {result.scam_category_label || 'Threat Assessment'}
              </span>
              <Chip tone="sky">{result.language_detail.label}</Chip>
              <Chip tone="slate">{titleCase(result.input_type)} input</Chip>
              {result.language_detail.is_code_switched && <Chip tone="violet">code-switched</Chip>}
            </div>

            <h3 className="mt-4 text-xl font-black text-slate-900 leading-snug">
              {result.summary}
            </h3>

            <p className="mt-3 text-xs text-slate-500">
              Evaluated {fmtDate(result.created_at)} · Latency {result.latency_ms} ms · Model {result.model_version}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="mt-8 flex flex-wrap items-center gap-3 border-t border-[#BBD5DA]/60 pt-6">
          <button
            type="button"
            onClick={() => onReport(result)}
            className="btn-redflag-glow px-6 py-2.5 rounded-full text-xs sm:text-sm font-bold flex items-center gap-2 cursor-pointer shadow-md"
          >
            <Flag size={15} />
            <span>Report Threat Incident</span>
          </button>

          <button
            type="button"
            onClick={() => setShowHow((v) => !v)}
            className="px-5 py-2.5 rounded-full text-xs sm:text-sm font-bold border border-[#BBD5DA] bg-white text-slate-700 hover:bg-[#F5F5F5] flex items-center gap-2 transition-all cursor-pointer shadow-2xs"
          >
            {showHow ? <EyeOff size={15} /> : <Eye size={15} />}
            <span>{showHow ? 'Hide Audit Trail' : 'Show How We Know'}</span>
          </button>

          <button
            type="button"
            onClick={exportBundle}
            className="px-5 py-2.5 rounded-full text-xs sm:text-sm font-bold border border-[#BBD5DA] bg-white text-slate-700 hover:bg-[#F5F5F5] flex items-center gap-2 transition-all cursor-pointer shadow-2xs"
          >
            <Download size={15} />
            <span>Export Evidence JSON</span>
          </button>

          {result.campaign_links[0] && (
            <button
              type="button"
              onClick={() => onOpenCampaign(result.campaign_links[0].campaign_id)}
              className="px-5 py-2.5 rounded-full text-xs sm:text-sm font-bold bg-[#DFF1F1] text-teal-900 border border-[#BBD5DA] hover:bg-[#DFF1F1]/80 flex items-center gap-2 transition-all cursor-pointer"
            >
              <ExternalLink size={15} />
              <span>Campaign: {result.campaign_links[0].label}</span>
            </button>
          )}
        </div>
      </Panel>

      {/* Degraded Checks Warning */}
      {result.degraded_checks.length > 0 && (
        <Banner tone="warn">
          <strong>Some checks were unavailable:</strong> Verdict calculated from available heuristics.
          <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-amber-900">
            {result.degraded_checks.map((d, i) => (
              <li key={i}>
                <span className="font-semibold">{d.check}</span> — {d.status} {d.reason ? `(${d.reason})` : ''}
              </li>
            ))}
          </ul>
        </Banner>
      )}

      {/* OCR Info */}
      {result.ocr && (
        <Banner tone={result.ocr.mean_confidence >= 60 ? 'info' : 'warn'}>
          <strong>OCR Verification: </strong>
          {result.ocr.available
            ? <>Confidence {result.ocr.mean_confidence}% across {result.ocr.word_count} words ({result.ocr.languages_used.join(' + ')}).
              {result.ocr.user_corrected && ' Text was verified/edited by you before analysis.'} {result.ocr.warning}</>
            : result.ocr.reason}
        </Banner>
      )}

      {/* QR Code Details */}
      {result.qr && result.qr.payloads.length > 0 && (
        <Banner tone="warn">
          <strong>Decoded QR Target (Never opened automatically): </strong>
          <code className="break-all font-bold text-[#D10000]">{result.qr.payloads.map((p) => p.data).join(' · ')}</code>
          <div className="mt-1 text-xs opacity-90">{result.qr.note}</div>
        </Banner>
      )}

      {/* Red Flags & Breakdown Grid */}
      <div className="grid gap-6 lg:grid-cols-5">
        {/* Left: Red Flags Signals */}
        <Panel
          className="lg:col-span-3"
          title="Flagged Threat Indicators"
          subtitle="Specific triggers matched by the real-time heuristic radar."
        >
          {result.red_flags.length === 0 ? (
            <div className="text-center py-8">
              <ShieldCheck className="w-12 h-12 text-emerald-600 mx-auto mb-2" />
              <p className="text-sm font-bold text-slate-800">No malicious pattern signatures matched.</p>
              <p className="text-xs text-slate-500 mt-1">Legitimate communication pattern or benign link structure.</p>
            </div>
          ) : (
            <ul className="space-y-3.5">
              {result.red_flags.slice(0, 7).map((f, i) => (
                <li key={i} className="rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5]/50 p-4 hover:border-slate-400 transition-all">
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-sm font-black text-slate-900">{f.title}</span>
                    <Chip tone={f.kind === 'observed' ? 'emerald' : 'violet'}>
                      {f.kind === 'observed' ? 'observed signal' : 'heuristic inference'}
                    </Chip>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{f.detail}</p>
                  {f.evidence_span && (
                    <div className="mt-2.5">
                      <Evidence>{f.evidence_span}</Evidence>
                    </div>
                  )}
                  <div className="mt-2 text-[10px] uppercase font-bold tracking-wider text-slate-500">
                    {FAMILY_LABEL[f.family] ?? f.family}
                    {f.weight != null && ` · +${f.weight} points`}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        {/* Right: Score Breakdown & Entities */}
        <div className="space-y-6 lg:col-span-2">
          {/* Score breakdown */}
          <Panel title="Score Breakdown" subtitle="Algorithmic weight per heuristic family.">
            <div className="space-y-3.5">
              {result.score_breakdown.map((b) => (
                <Meter
                  key={b.family}
                  label={FAMILY_LABEL[b.family] ?? b.family}
                  value={b.points}
                  max={b.cap}
                />
              ))}
            </div>

            {result.benign_adjustment !== 0 && (
              <div className="mt-4 rounded-xl bg-emerald-50 border border-emerald-200 px-3.5 py-2 text-xs font-medium text-emerald-800">
                Verified brand & whitelist markers reduced risk score by {Math.abs(result.benign_adjustment)} pts.
              </div>
            )}
            <p className="mt-4 text-xs font-semibold text-slate-500">
              Total Risk: {result.risk_score}/100 — {result.verdict_label}.
            </p>
          </Panel>

          {/* Extracted Entities */}
          <Panel title="Extracted Entities & IOCs" subtitle="Identified phones, links, UPI addresses, and brands.">
            {result.entities.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No IOC entities were found.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {result.entities.map((e, i) => (
                  <Chip
                    key={i}
                    tone={ENTITY_TONE[e.type] ?? 'slate'}
                    title={`raw: ${e.raw_value} · confidence ${e.confidence}`}
                  >
                    <span className="opacity-60 font-normal">{e.type}:</span> {e.display_value}
                  </Chip>
                ))}
              </div>
            )}

            {result.entity_reputation.length > 0 && (
              <div className="mt-4 rounded-2xl border border-red-200 bg-red-50 p-4">
                <p className="text-xs font-black text-red-900 uppercase tracking-wide flex items-center gap-1.5">
                  <AlertTriangle size={14} className="text-[#D10000]" />
                  Previously Reported in Community Feed
                </p>
                <ul className="mt-2 space-y-1.5 text-xs text-red-900">
                  {result.entity_reputation.map((r, i) => (
                    <li key={i} className="flex justify-between items-center">
                      <span className="font-mono font-bold">{r.display_value}</span>
                      <span className="text-[11px] opacity-80">{r.report_count} report(s)</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>
        </div>
      </div>

      {/* ---------------- Recommended Actions ---------------- */}
      <Panel title="Recommended Safety Actions" subtitle="Actionable precautions for citizens and administrators.">
        <ul className="grid gap-3.5 sm:grid-cols-2">
          {result.recommended_actions.map((a, i) => (
            <li key={i} className={`rounded-2xl border p-4 ${PRIORITY_TONE[a.priority]} transition-all`}>
              <div className="flex items-center gap-2 mb-2">
                <Chip tone={a.priority === 'critical' ? 'red' : a.priority === 'high' ? 'amber' : 'slate'}>
                  {a.priority.toUpperCase()}
                </Chip>
              </div>
              <h4 className="text-sm font-black text-slate-900">{a.action}</h4>
              <p className="mt-1 text-xs text-slate-600 leading-relaxed">{a.why}</p>
            </li>
          ))}
        </ul>

        <div className="mt-6 rounded-2xl border border-[#BBD5DA] bg-[#DFF1F1]/50 p-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-700">
          <div>
            <strong className="text-slate-900 font-bold">Official Indian Cybercrime Helplines:</strong> Call{' '}
            <span className="font-mono font-bold text-[#D10000] text-sm">1930</span> or lodge formal grievance at{' '}
            <span className="font-mono font-bold text-slate-900">cybercrime.gov.in</span>.
          </div>
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider shrink-0">
            Govt of India · I4C
          </span>
        </div>
      </Panel>

      {/* ---------------- How We Know (Audit Trail) ---------------- */}
      {showHow && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel
            title="Complete Risk Factors Audit Trail"
            subtitle="Granular contribution of each rule, formula, and heuristic."
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#BBD5DA] text-slate-500 font-bold uppercase text-[10px] tracking-wider">
                    <th className="pb-3 pr-2">Factor</th>
                    <th className="pb-3 pr-2">Family</th>
                    <th className="pb-3 pr-2 text-right">Points</th>
                    <th className="pb-3 pr-2">Observed Signal</th>
                    <th className="pb-3">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  {result.risk_factors.map((f, i) => (
                    <tr key={i} className="hover:bg-[#F5F5F5] transition-colors">
                      <td className="py-2.5 pr-2 font-sans font-bold text-slate-900">
                        {f.name}
                        {f.evidence_span && <div className="mt-1"><Evidence>{f.evidence_span}</Evidence></div>}
                      </td>
                      <td className="py-2.5 pr-2 font-sans text-slate-600">{FAMILY_LABEL[f.family] ?? f.family}</td>
                      <td className="py-2.5 pr-2 text-right font-bold text-[#D10000]">+{f.weight}</td>
                      <td className="py-2.5 pr-2 text-slate-700 max-w-[120px] truncate">{f.observed_value}</td>
                      <td className="py-2.5 text-slate-500 text-[10px]">{f.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="space-y-6">
            <Panel title="NLP & Language Breakdown" subtitle="Linguistic routing and transliteration normalization.">
              <dl className="space-y-2.5 text-xs text-slate-700">
                <div className="flex justify-between border-b border-slate-100 pb-1.5">
                  <dt className="text-slate-500">Detected Language</dt>
                  <dd className="font-bold text-slate-900">{result.language_detail.label} ({(result.language_detail.confidence * 100).toFixed(0)}%)</dd>
                </div>
                <div className="flex justify-between border-b border-slate-100 pb-1.5">
                  <dt className="text-slate-500">Scripts Encountered</dt>
                  <dd className="font-bold text-slate-900">{result.language_detail.scripts.join(', ') || 'Latin'}</dd>
                </div>
                <div className="flex justify-between border-b border-slate-100 pb-1.5">
                  <dt className="text-slate-500">Tamil / Latin Ratio</dt>
                  <dd className="font-mono font-bold text-slate-900">
                    {(result.language_detail.tamil_char_ratio * 100).toFixed(0)}% / {(result.language_detail.latin_char_ratio * 100).toFixed(0)}%
                  </dd>
                </div>
              </dl>

              {result.normalization.replacements.length > 0 && (
                <div className="mt-4 pt-4 border-t border-[#BBD5DA]/60">
                  <p className="text-xs font-bold text-slate-800 mb-2">Transliterated Tanglish Replacements</p>
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                    {result.normalization.replacements.slice(0, 20).map((r, i) => (
                      <Chip key={i} tone="violet">{r.from} → {r.to}</Chip>
                    ))}
                  </div>
                </div>
              )}
            </Panel>

            <Panel title="Engine Uncertainty & Disclaimers" subtitle="Operational boundaries of this scan.">
              <ul className="list-disc space-y-1 pl-5 text-xs text-slate-600">
                {result.uncertainties.length === 0
                  ? <li>No known edge-case limitations reported for this evaluation.</li>
                  : result.uncertainties.map((u, i) => <li key={i}>{u}</li>)}
              </ul>
              <div className="mt-4 pt-3 border-t border-[#BBD5DA]/60 text-[11px] text-slate-500 space-y-1">
                <p>Fingerprint: <code className="font-mono">{result.message_fingerprint.slice(0, 16)}</code></p>
                <p>{result.disclaimer}</p>
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* Evidence Bundle JSON */}
      {bundle && (
        <Panel title="Downloaded Evidence Bundle" subtitle="Standardized JSON schema for law enforcement or CERT-In.">
          <pre className="max-h-64 overflow-auto rounded-2xl bg-slate-900 text-slate-200 p-4 font-mono text-xs leading-relaxed">
            {bundle.slice(0, 3000)}
          </pre>
        </Panel>
      )}
    </div>
  );
}
