import { useEffect, useMemo, useState } from 'react';
import type { Campaign, CampaignDetail, GraphNode } from './types';
import { campaignDetail, listCampaigns, setCampaignStatus } from './api';
import { Banner, Chip, Panel, Spinner, fmtDate, fmtDay, titleCase } from './ui';
import { Network } from 'lucide-react';

const NODE_COLOR: Record<string, string> = {
  campaign: '#d10000', report: '#64748b', domain: '#f59e0b', phone: '#0284c7',
  upi: '#7c3aed', email: '#059669', handle: '#db2777', ifsc: '#d97706',
};

/** Deterministic radial layout — reproducible across reloads */
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
    <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 shadow-inner">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-[480px] w-full">
        <defs>
          <radialGradient id="glow">
            <stop offset="0%" stopColor="#d10000" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#d10000" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle cx={W / 2} cy={H / 2} r={170} fill="url(#glow)" />
        {detail.edges.map((e, i) => {
          const a = pos[e.source];
          const b = pos[e.target];
          if (!a || !b) return null;
          const shared = e.relation === 'same_indicator';
          return (
            <line
              key={i}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={shared ? '#d10000' : '#475569'}
              strokeWidth={shared ? 2.5 : 1}
              strokeDasharray={e.relation === 'mentions' ? '3 3' : undefined}
              opacity={shared ? 0.9 : 0.6}
            />
          );
        })}
        {detail.nodes.map((n) => {
          const p = pos[n.id];
          if (!p) return null;
          const r = Math.max(7, Math.min(22, n.size / 1.4));
          return (
            <g
              key={n.id}
              transform={`translate(${p.x},${p.y})`}
              className="cursor-pointer transition-transform hover:scale-125"
              onClick={() => onSelect(n)}
            >
              <circle
                r={r}
                fill={NODE_COLOR[n.type] ?? '#64748b'}
                stroke="#ffffff"
                strokeWidth="1.5"
              />
              {(n.shared_by ?? 0) > 1 && (
                <circle r={r + 5} fill="none" stroke="#d10000" strokeWidth="2" opacity="0.8" />
              )}
              <text
                y={r + 14}
                textAnchor="middle"
                className="fill-slate-300 font-mono text-[10px] select-none font-semibold"
              >
                {n.label.length > 24 ? `${n.label.slice(0, 22)}…` : n.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
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
        const sorted = [...d.campaigns].sort((a, b) => b.report_count - a.report_count);
        setCampaigns(sorted);
        if (!selectedId && sorted[0]) onSelectCampaign(sorted[0].id);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
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

  if (loading) {
    return (
      <div className="p-12 text-center flex items-center justify-center">
        <Spinner label="Loading Threat Campaign Clusters…" />
      </div>
    );
  }

  if (error) return <Banner tone="error">{error}</Banner>;

  if (campaigns.length === 0) {
    return (
      <div className="bg-white rounded-3xl border border-[#BBD5DA] p-10 text-center max-w-xl mx-auto shadow-sm">
        <Network className="w-12 h-12 text-slate-400 mx-auto mb-3" />
        <h3 className="text-lg font-black text-slate-900">No Tracked Campaigns Found</h3>
        <p className="text-sm text-slate-600 mt-1">
          Approve reports from the moderation queue or execute seed data to populate campaign correlation graphs.
        </p>
      </div>
    );
  }

  return (
    <div className="grid gap-6 lg:grid-cols-4">
      {/* Left Column: Tracked Campaigns List */}
      <Panel
        className="lg:col-span-1"
        title="Campaigns"
        subtitle={`${campaigns.length} clusters tracked`}
      >
        <ul className="space-y-3">
          {campaigns.map((c) => {
            const isSelected = c.id === selectedId;
            return (
              <li key={c.id}>
                <button
                  type="button"
                  onClick={() => onSelectCampaign(c.id)}
                  className={`w-full rounded-2xl border p-4 text-left transition-all cursor-pointer ${
                    isSelected
                      ? 'border-2 border-[#D10000] bg-[#DFF1F1]/40 shadow-sm'
                      : 'border-[#BBD5DA] bg-white hover:bg-[#F5F5F5]'
                  }`}
                >
                  <p className="text-sm font-black text-slate-900 leading-snug">{c.label}</p>
                  <div className="mt-2.5 flex flex-wrap gap-1.5">
                    <Chip tone={c.status === 'active' ? 'red' : c.status === 'closed' ? 'slate' : 'amber'}>
                      {c.status.toUpperCase()}
                    </Chip>
                    <Chip tone="slate">{c.report_count} reports</Chip>
                    {(c.languages || []).map((l) => (
                      <Chip key={l} tone="sky">{l}</Chip>
                    ))}
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      </Panel>

      {/* Right Column: Active Campaign Graph & Details */}
      <div className="space-y-6 lg:col-span-3">
        {detail && (
          <>
            <Panel
              title={detail.campaign.label}
              subtitle={`${detail.campaign.report_count} incident sightings · First seen ${fmtDay(detail.campaign.first_seen)} · Last seen ${fmtDay(detail.campaign.last_seen)}`}
              right={
                <button
                  type="button"
                  onClick={cycleStatus}
                  className="rounded-full border border-[#BBD5DA] bg-white px-4 py-1.5 text-xs font-bold text-slate-700 hover:border-[#D10000] hover:text-[#D10000] transition-all shadow-2xs"
                >
                  Status: <span className="uppercase text-[#D10000]">{detail.campaign.status}</span>
                </button>
              }
            >
              <Graph detail={detail} onSelect={setNode} />

              {/* Graph Legend */}
              <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-slate-600 bg-[#F5F5F5] p-3 rounded-2xl border border-[#BBD5DA]">
                {Object.entries(NODE_COLOR).map(([k, v]) => (
                  <span key={k} className="inline-flex items-center gap-1.5 font-medium">
                    <span className="h-3 w-3 rounded-full shadow-xs" style={{ background: v }} />
                    {titleCase(k)}
                  </span>
                ))}
                <span className="inline-flex items-center gap-1.5 font-medium">
                  <span className="h-3 w-3 rounded-full border-2 border-[#D10000]" />
                  Shared across 2+ reports
                </span>
              </div>

              {/* Selected Node Details */}
              {node && (
                <div className="mt-4 rounded-2xl border border-[#BBD5DA] bg-[#DFF1F1]/60 p-4 text-xs">
                  <p className="font-black text-slate-900 text-sm">
                    {titleCase(node.type)}: <span className="font-mono text-[#D10000]">{node.label}</span>
                  </p>
                  <p className="mt-1 text-slate-700 leading-relaxed">
                    {node.shared_by ? `Overlapping across ${node.shared_by} incident sightings. ` : ''}
                    {node.report_count != null ? `Linked to ${node.report_count} citizen reports. ` : ''}
                    {node.first_seen ? `Active from ${fmtDay(node.first_seen)} to ${fmtDay(node.last_seen)}. ` : ''}
                    {node.locality ? `Geographic Locality: ${node.locality}.` : ''}
                  </p>
                </div>
              )}
            </Panel>

            <div className="grid gap-6 md:grid-cols-2">
              {/* Shared Indicators Overlap */}
              <Panel title="Correlated Shared Indicators" subtitle="Network elements linking multiple victims.">
                {detail.shared_indicators.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No multi-sighting overlap detected yet.</p>
                ) : (
                  <ul className="space-y-2.5">
                    {detail.shared_indicators.map((n) => (
                      <li
                        key={n.id}
                        className="flex items-center justify-between rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]/60 px-3.5 py-2.5"
                      >
                        <span className="font-mono text-xs font-bold text-slate-900">{n.label}</span>
                        <Chip tone="red">{n.shared_by} sightings · {n.type}</Chip>
                      </li>
                    ))}
                  </ul>
                )}
                <div className="mt-4 rounded-xl bg-slate-100 p-3 text-xs text-slate-600 font-medium border border-slate-200">
                  {detail.infrastructure_rotation.note}
                </div>
              </Panel>

              {/* Activity Timeline */}
              <Panel title="Incident Sighting Timeline" subtitle="Chronological cadence of incoming reports.">
                <ol className="relative space-y-4 border-l-2 border-[#BBD5DA] pl-4 ml-1">
                  {detail.timeline.map((t) => (
                    <li key={t.report_id} className="relative">
                      <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full bg-[#D10000] ring-4 ring-white" />
                      <p className="text-xs font-bold text-slate-900">{fmtDate(t.at)}</p>
                      <p className="text-[11px] text-slate-600 mt-0.5">
                        <span className="font-semibold text-[#D10000]">{titleCase(t.category || 'unclassified')}</span> · {t.channel.toUpperCase()}
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
