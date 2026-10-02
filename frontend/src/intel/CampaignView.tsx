import { useEffect, useMemo, useState } from 'react';
import type { Campaign, CampaignDetail, GraphNode } from './types';
import { campaignDetail, listCampaigns, setCampaignStatus } from './api';
import { Banner, Btn, Chip, Panel, Spinner, fmtDate, fmtDay, titleCase } from './ui';

const NODE_COLOR: Record<string, string> = {
  campaign: '#ef4444', report: '#64748b', domain: '#f59e0b', phone: '#38bdf8',
  upi: '#a78bfa', email: '#34d399', handle: '#f472b6', ifsc: '#fbbf24',
};

/** Deterministic radial layout — reproducible across reloads, no physics needed. */
function layout(detail: CampaignDetail, w: number, h: number) {
  const cx = w / 2;
  const cy = h / 2;
  const pos: Record<string, { x: number; y: number }> = {};
  const campaign = detail.nodes.find((n) => n.type === 'campaign');
  if (campaign) pos[campaign.id] = { x: cx, y: cy };

  const indicators = detail.nodes.filter((n) => !['campaign', 'report'].includes(n.type));
  const reportsN = detail.nodes.filter((n) => n.type === 'report');

  indicators.forEach((n, i) => {
    const a = (i / Math.max(1, indicators.length)) * Math.PI * 2 - Math.PI / 2;
    pos[n.id] = { x: cx + Math.cos(a) * (Math.min(w, h) * 0.22), y: cy + Math.sin(a) * (Math.min(w, h) * 0.22) };
  });
  reportsN.forEach((n, i) => {
    const a = (i / Math.max(1, reportsN.length)) * Math.PI * 2 - Math.PI / 2 + 0.35;
    pos[n.id] = { x: cx + Math.cos(a) * (Math.min(w, h) * 0.42), y: cy + Math.sin(a) * (Math.min(w, h) * 0.42) };
  });
  return pos;
}

function Graph({ detail, onSelect }: { detail: CampaignDetail; onSelect: (n: GraphNode) => void }) {
  const W = 760;
  const H = 480;
  const pos = useMemo(() => layout(detail, W, H), [detail]);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-[480px] w-full rounded-lg bg-slate-950">
      <defs>
        <radialGradient id="glow">
          <stop offset="0%" stopColor="#ef4444" stopOpacity="0.22" />
          <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx={W / 2} cy={H / 2} r={170} fill="url(#glow)" />
      {detail.edges.map((e, i) => {
        const a = pos[e.source];
        const b = pos[e.target];
        if (!a || !b) return null;
        const shared = e.relation === 'same_indicator';
        return (
          <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
            stroke={shared ? '#ef4444' : '#334155'}
            strokeWidth={shared ? 2 : 1}
            strokeDasharray={e.relation === 'mentions' ? '3 3' : undefined}
            opacity={shared ? 0.8 : 0.6} />
        );
      })}
      {detail.nodes.map((n) => {
        const p = pos[n.id];
        if (!p) return null;
        const r = Math.max(6, Math.min(22, n.size / 1.4));
        return (
          <g key={n.id} transform={`translate(${p.x},${p.y})`} className="cursor-pointer"
            onClick={() => onSelect(n)}>
            <circle r={r} fill={NODE_COLOR[n.type] ?? '#64748b'}
              stroke="#0f172a" strokeWidth="2" />
            {(n.shared_by ?? 0) > 1 && <circle r={r + 4} fill="none" stroke="#ef4444" strokeWidth="1.5" opacity="0.7" />}
            <text y={r + 13} textAnchor="middle" className="fill-slate-400"
              style={{ fontSize: 10, fontFamily: 'ui-monospace, monospace' }}>
              {n.label.length > 24 ? `${n.label.slice(0, 22)}…` : n.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export function CampaignView({ selectedId, onSelectCampaign }: {
  selectedId: string | null; onSelectCampaign: (id: string | null) => void;
}) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const [node, setNode] = useState<GraphNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listCampaigns()
      .then((d) => {
        // Largest cluster first: the most useful default for a demo or triage.
        const sorted = [...d.campaigns].sort((a, b) => b.report_count - a.report_count);
        setCampaigns(sorted);
        if (!selectedId && sorted[0]) onSelectCampaign(sorted[0].id);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    setNode(null);
    campaignDetail(selectedId).then(setDetail).catch((e) => setError(e.message));
  }, [selectedId]);

  async function cycleStatus() {
    if (!detail) return;
    const order = ['monitoring', 'active', 'closed'];
    const next = order[(order.indexOf(detail.campaign.status) + 1) % order.length];
    await setCampaignStatus(detail.campaign.id, next);
    const fresh = await campaignDetail(detail.campaign.id);
    setDetail(fresh);
    setCampaigns((cs) => cs.map((c) => (c.id === fresh.campaign.id ? { ...c, status: next } : c)));
  }

  if (loading) return <Spinner label="Loading campaigns…" />;
  if (error) return <Banner tone="error">{error}</Banner>;
  if (campaigns.length === 0) {
    return <Banner tone="info">No campaigns yet. Run <code>python seed_demo.py</code> or approve a report.</Banner>;
  }

  return (
    <div className="grid gap-5 lg:grid-cols-4">
      <Panel className="lg:col-span-1" title="Campaigns" subtitle={`${campaigns.length} tracked`}>
        <ul className="space-y-2">
          {campaigns.map((c) => (
            <li key={c.id}>
              <button onClick={() => onSelectCampaign(c.id)}
                className={`w-full rounded-lg border p-3 text-left transition ${c.id === selectedId
                  ? 'border-red-600 bg-red-950/40'
                  : 'border-slate-700/60 bg-slate-950/40 hover:border-slate-500'}`}>
                <p className="text-xs font-semibold text-slate-100">{c.label}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <Chip tone={c.status === 'active' ? 'red' : c.status === 'closed' ? 'slate' : 'amber'}>{c.status}</Chip>
                  <Chip>{c.report_count} reports</Chip>
                  {(c.languages || []).map((l) => <Chip key={l} tone="sky">{l}</Chip>)}
                </div>
              </button>
            </li>
          ))}
        </ul>
      </Panel>

      <div className="space-y-5 lg:col-span-3">
        {detail && (
          <>
            <Panel title={detail.campaign.label}
              subtitle={`${detail.campaign.report_count} moderated reports · first seen ${fmtDay(detail.campaign.first_seen)} · last seen ${fmtDay(detail.campaign.last_seen)}`}
              right={<Btn variant="ghost" onClick={cycleStatus}>Status: {detail.campaign.status}</Btn>}>
              <Graph detail={detail} onSelect={setNode} />
              <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-slate-500">
                {Object.entries(NODE_COLOR).map(([k, v]) => (
                  <span key={k} className="inline-flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ background: v }} />{k}
                  </span>
                ))}
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full ring-1 ring-red-500" />shared by 2+ reports
                </span>
              </div>
              {node && (
                <div className="mt-4 rounded-lg border border-slate-700 bg-slate-950/70 p-3 text-xs">
                  <p className="font-semibold text-slate-100">{titleCase(node.type)}: {node.label}</p>
                  <p className="mt-1 text-slate-400">
                    {node.shared_by ? `Shared by ${node.shared_by} reports. ` : ''}
                    {node.report_count != null ? `${node.report_count} community report(s). ` : ''}
                    {node.first_seen ? `First seen ${fmtDay(node.first_seen)}, last seen ${fmtDay(node.last_seen)}.` : ''}
                    {node.locality ? ` Locality: ${node.locality}.` : ''}
                  </p>
                </div>
              )}
            </Panel>

            <div className="grid gap-5 md:grid-cols-2">
              <Panel title="Shared indicators" subtitle="The overlap that created this cluster.">
                {detail.shared_indicators.length === 0
                  ? <p className="text-xs text-slate-400">No indicator is shared by more than one report yet.</p>
                  : (
                    <ul className="space-y-2">
                      {detail.shared_indicators.map((n) => (
                        <li key={n.id} className="flex items-center justify-between rounded-lg border border-slate-700/60 bg-slate-950/50 px-3 py-2">
                          <span className="font-mono text-xs text-slate-200">{n.label}</span>
                          <Chip tone="red">{n.shared_by} reports · {n.type}</Chip>
                        </li>
                      ))}
                    </ul>
                  )}
                <div className="mt-3 rounded-md bg-slate-950/60 p-2 text-[11px] text-slate-500">
                  {detail.infrastructure_rotation.note}
                </div>
              </Panel>

              <Panel title="Timeline" subtitle="Sighting order reveals bursts and rotation.">
                <ol className="relative space-y-3 border-l border-slate-700 pl-4">
                  {detail.timeline.map((t) => (
                    <li key={t.report_id} className="relative">
                      <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-red-500" />
                      <p className="text-xs text-slate-200">{fmtDate(t.at)}</p>
                      <p className="text-[11px] text-slate-500">
                        {titleCase(t.category || 'unclassified')} · {t.channel}
                        {t.locality ? ` · ${t.locality}` : ''}
                      </p>
                    </li>
                  ))}
                </ol>
              </Panel>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
