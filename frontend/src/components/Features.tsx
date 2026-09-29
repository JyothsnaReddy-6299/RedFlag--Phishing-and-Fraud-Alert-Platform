import { ShieldCheck, Network, Cpu, AlertOctagon, CheckCircle } from 'lucide-react';

export const Features: React.FC = () => {
  const pillars = [
    {
      title: 'Shannon Entropy Engine',
      description:
        'Calculates algorithmic bit randomness across domain labels to flag Domain Generation Algorithms (DGA) used by malware command-and-control networks.',
      badge: 'Statistical Heuristics',
      icon: <Cpu className="w-6 h-6 text-slate-800" />,
    },
    {
      title: 'Brand Impersonation Defense',
      description:
        'Computes Levenshtein edit distance and token similarity against major banks (SBI, HDFC, ICICI, Axis, PayPal) to detect deceptive lookalike domains.',
      badge: 'Anti-Typosquatting',
      icon: <AlertOctagon className="w-6 h-6 text-[#D10000]" />,
    },
    {
      title: 'Evasion & Structure Analysis',
      description:
        'Detects raw IPv4/IPv6 host masks, non-standard attack ports, credential injection (@), hex obfuscation, and high-abuse top-level domains (.xyz, .top, .club).',
      badge: 'Network Heuristics',
      icon: <Network className="w-6 h-6 text-slate-800" />,
    },
    {
      title: 'Verified Banking Whitelist',
      description:
        'Built-in recognition of verified Reserve Bank of India & official banking infrastructure (.bank.in, onlinesbi.sbi.bank.in) preventing false positives.',
      badge: 'Zero False Positives',
      icon: <ShieldCheck className="w-6 h-6 text-emerald-700" />,
    },
  ];

  return (
    <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      <div className="text-center max-w-3xl mx-auto mb-16">
        <span className="text-xs font-black uppercase tracking-widest text-[#D10000] mb-2 block">
          Defense Architecture
        </span>
        <h2 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
          How RedFlag Evaluates URLs & Messages in Real-Time
        </h2>
        <p className="mt-4 text-base sm:text-lg text-slate-600">
          Unlike slow blacklist lookups, RedFlag inspects structural DNA, algorithmic entropy, and brand proximity before malicious sites can even load.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {pillars.map((pillar, idx) => (
          <div
            key={idx}
            className="p-8 rounded-3xl bg-[#DFF1F1]/40 border border-[#BBD5DA] hover:border-slate-400 hover:shadow-lg transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="w-12 h-12 rounded-2xl bg-white border border-[#BBD5DA] flex items-center justify-center shadow-xs">
                  {pillar.icon}
                </div>
                <span className="text-xs font-bold px-3 py-1 rounded-full bg-white border border-[#BBD5DA] text-slate-700">
                  {pillar.badge}
                </span>
              </div>
              <h3 className="text-xl font-black text-slate-900 mb-2">
                {pillar.title}
              </h3>
              <p className="text-slate-600 text-sm leading-relaxed">
                {pillar.description}
              </p>
            </div>

            <div className="mt-6 pt-4 border-t border-[#BBD5DA]/60 flex items-center gap-2 text-xs font-semibold text-slate-600">
              <CheckCircle size={14} className="text-emerald-600" />
              <span>Evaluated under 15ms</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};
