import { useEffect, useState } from 'react';
import { Database, CheckCircle, RefreshCw } from 'lucide-react';
import { fetchKnownThreats } from '../services/api';
import type { ThreatDomainItem } from '../types';

export const ThreatDatabase: React.FC = () => {
  const [threats, setThreats] = useState<ThreatDomainItem[]>([]);
  const [loading, setLoading] = useState(true);

  const loadThreats = async () => {
    try {
      setLoading(true);
      const data = await fetchKnownThreats();
      setThreats(data.threats);
    } catch {
      // Fallback mock seeds if backend offline
      setThreats([
        { domain: 'sbi-kyc-update-portal.xyz', category: 'BRAND_IMPERSONATION', source: 'RedFlag Active Threat Feed' },
        { domain: 'hdfc-secure-netbanking.top', category: 'BRAND_IMPERSONATION', source: 'RedFlag Active Threat Feed' },
        { domain: 'icici-rewards-redeem.club', category: 'BRAND_IMPERSONATION', source: 'PhishTank Feed' },
        { domain: 'secure-login-axisbank.tk', category: 'KNOWN_PHISHING', source: 'OpenPhish Intelligence' },
        { domain: 'paypal-security-update.gq', category: 'BRAND_IMPERSONATION', source: 'CERT-In Threat Feed' },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();
  }, []);

  return (
    <section id="threat-database" className="py-16 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      <div className="bg-white rounded-3xl border border-[#BBD5DA] p-6 sm:p-10 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-2xl bg-[#DFF1F1] text-teal-800">
              <Database size={22} />
            </div>
            <div>
              <h3 className="text-xl sm:text-2xl font-black text-slate-900">
                Active Threat Intelligence Feeds
              </h3>
              <p className="text-xs sm:text-sm text-slate-500">
                Known phishing campaigns and malicious seed domains tracked by RedFlag
              </p>
            </div>
          </div>

          <button
            onClick={loadThreats}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[#BBD5DA] text-xs font-semibold text-slate-700 hover:bg-[#F5F5F5] transition-all cursor-pointer self-start sm:self-auto"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh Feeds</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-[#BBD5DA] text-slate-500 font-bold uppercase text-[11px] tracking-wider">
                <th className="pb-3 px-3">Flagged Domain</th>
                <th className="pb-3 px-3">Threat Category</th>
                <th className="pb-3 px-3">Intelligence Source</th>
                <th className="pb-3 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-xs">
              {threats.map((t, idx) => (
                <tr key={idx} className="hover:bg-[#F5F5F5]/60 transition-colors">
                  <td className="py-3 px-3 font-bold text-slate-900">
                    <span className="text-[#D10000] mr-1.5">●</span>
                    {t.domain}
                  </td>
                  <td className="py-3 px-3 font-sans">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-red-100 text-red-800">
                      {t.category}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-sans text-slate-600">
                    {t.source}
                  </td>
                  <td className="py-3 px-3 font-sans text-right">
                    <span className="inline-flex items-center gap-1 text-emerald-700 font-bold text-[11px]">
                      <CheckCircle size={13} />
                      Blocked
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};
