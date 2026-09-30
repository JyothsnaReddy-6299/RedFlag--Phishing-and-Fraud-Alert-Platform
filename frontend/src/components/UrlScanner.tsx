import { useState, forwardRef } from 'react';
import {
  Search,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  Copy,
  Sparkles,
  RotateCcw
} from 'lucide-react';
import type { URLScanResponse, RiskLevel } from '../types';
import { scanUrl } from '../services/api';

interface UrlScannerProps {
  // scanner props
}

export const UrlScanner = forwardRef<HTMLDivElement, UrlScannerProps>((_, ref) => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<URLScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleScan = async (targetUrl?: string) => {
    const urlToScan = (targetUrl !== undefined ? targetUrl : urlInput).trim();
    if (!urlToScan) {
      setError('Please enter a valid URL to analyze.');
      return;
    }

    setUrlInput(urlToScan);
    setError(null);
    setLoading(true);

    try {
      const data = await scanUrl(urlToScan);
      setResult(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to scan URL';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyUrl = () => {
    if (result) {
      navigator.clipboard.writeText(result.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleReset = () => {
    setUrlInput('');
    setResult(null);
    setError(null);
  };

  // Helper styles based on RiskLevel
  const getRiskStyles = (level: RiskLevel) => {
    switch (level) {
      case 'SAFE_LOW':
        return {
          badgeBg: 'bg-emerald-50 text-emerald-800 border-emerald-300',
          badgeText: 'SAFE',
          barColor: 'bg-emerald-500',
          cardBorder: 'border-emerald-200',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-600 inline mr-1" />,
          scoreText: 'text-emerald-700',
        };
      case 'SUSPICIOUS':
        return {
          badgeBg: 'bg-amber-50 text-amber-900 border-amber-300',
          badgeText: 'SUSPICIOUS',
          barColor: 'bg-amber-500',
          cardBorder: 'border-amber-200',
          icon: <AlertTriangle className="w-5 h-5 text-amber-600 inline mr-1" />,
          scoreText: 'text-amber-700',
        };
      case 'HIGH_RISK':
        return {
          badgeBg: 'bg-orange-50 text-orange-900 border-orange-300',
          badgeText: 'HIGH RISK',
          barColor: 'bg-orange-500',
          cardBorder: 'border-orange-200',
          icon: <AlertCircle className="w-5 h-5 text-orange-600 inline mr-1" />,
          scoreText: 'text-orange-700',
        };
      case 'CRITICAL':
      default:
        return {
          badgeBg: 'bg-red-50 text-red-900 border-red-300',
          badgeText: 'CRITICAL THREAT',
          barColor: 'bg-[#D10000]',
          cardBorder: 'border-red-300',
          icon: <ShieldAlert className="w-5 h-5 text-[#D10000] inline mr-1" />,
          scoreText: 'text-[#D10000]',
        };
    }
  };

  return (
    <div id="scanner-section" ref={ref} className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6">
      {/* Scanner Card Container */}
      <div className="bg-white rounded-3xl shadow-xl border border-[#BBD5DA] overflow-hidden p-6 sm:p-10">
        
        {/* Section Heading */}
        <div className="text-center max-w-2xl mx-auto mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#DFF1F1] text-teal-800 text-xs font-bold tracking-wide uppercase mb-3">
            <Sparkles size={14} />
            <span>Real-Time URL Threat Inspector</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
            Inspect Suspicious Links
          </h2>
          <p className="text-slate-600 text-sm sm:text-base mt-2">
            Paste any link from an SMS, WhatsApp message, or email to uncover spoofed banking domains, Shannon entropy anomalies, and phishing triggers.
          </p>
        </div>

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="relative flex flex-col sm:flex-row items-stretch gap-3 mb-6"
        >
          <div className="relative flex-grow">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
              <Search size={20} />
            </div>
            <input
              type="text"
              id="url-scan-input"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Paste link here (e.g., https://onlinesbi.sbi.bank.in/ or http://sbi-kyc.xyz)"
              className="w-full pl-11 pr-24 py-4 rounded-2xl bg-[#F5F5F5] border-2 border-[#BBD5DA] focus:border-[#D10000] focus:bg-white focus:outline-none text-slate-900 font-mono text-sm sm:text-base transition-all"
            />
            {urlInput && (
              <button
                type="button"
                onClick={handleReset}
                className="absolute inset-y-0 right-3 flex items-center text-xs font-semibold text-slate-400 hover:text-slate-700 px-2 cursor-pointer"
              >
                <RotateCcw size={16} className="mr-1" />
                Clear
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-redflag-glow px-8 py-4 rounded-2xl font-bold text-base flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 whitespace-nowrap shadow-md"
          >
            {loading ? (
              <>
                <Loader2 size={20} className="animate-spin" />
                <span>Inspecting...</span>
              </>
            ) : (
              <>
                <ShieldAlert size={20} />
                <span>Scan Link</span>
              </>
            )}
          </button>
        </form>

        {/* Error Alert */}
        {error && (
          <div className="p-4 rounded-2xl bg-red-50 border border-red-200 text-red-700 text-sm flex items-center gap-3 mb-6 animate-fadeIn">
            <AlertCircle size={20} className="text-[#D10000] shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* RESULT CARD - MATCHING USER REFERENCE IMAGE 2 EXACTLY */}
        {result && (
          <div className="mt-8 pt-8 border-t border-[#BBD5DA] animate-fadeIn">
            
            {/* Top Row: Badges, Category, URL, and Threat Score */}
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-4">
              <div className="space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  {/* Risk Badge (e.g. SUSPICIOUS / SAFE) */}
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider border ${
                      getRiskStyles(result.risk_level).badgeBg
                    }`}
                  >
                    {result.risk_level === 'SAFE_LOW' ? 'SAFE' : result.risk_level}
                  </span>

                  {/* Category Name */}
                  <span className="text-sm font-black uppercase tracking-wider text-slate-800">
                    {result.category.replace(/_/g, ' ')}
                  </span>
                </div>

                {/* Scanned URL Monospace */}
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-2 group">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Target:</span>
                    <p className="font-mono text-sm sm:text-base text-slate-700 break-all select-all font-medium">
                      {result.original_url || result.url}
                    </p>
                    <button
                      onClick={handleCopyUrl}
                      title="Copy URL"
                      className="text-slate-400 hover:text-slate-700 transition-colors p-1"
                    >
                      <Copy size={15} />
                    </button>
                    {copied && <span className="text-xs text-emerald-600 font-bold">Copied!</span>}
                  </div>

                  {/* Canonical Normalized URL if different from original */}
                  {result.normalized_url && result.original_url && result.normalized_url !== result.original_url && (
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-600 bg-slate-100 px-2.5 py-1 rounded-lg border border-slate-200">
                      <span className="text-[10px] font-black uppercase tracking-wider text-emerald-800 bg-emerald-100 px-1.5 py-0.5 rounded">
                        Normalized Canonical
                      </span>
                      <span className="break-all text-slate-800">{result.normalized_url}</span>
                    </div>
                  )}

                  {/* Stripped Tracking Parameters chip */}
                  {result.stripped_tracking_params && result.stripped_tracking_params.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-500 mt-0.5">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">Stripped Trackers:</span>
                      {result.stripped_tracking_params.map((param, idx) => (
                        <span key={idx} className="bg-slate-200/80 text-slate-700 px-1.5 py-0.5 rounded text-[11px] font-mono">
                          {param}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* HOMOGRAPH RISK & CONFUSABLES CARD / BANNER */}
                  {result.homograph_risk === 'CRITICAL' || result.homograph_risk === 'SUSPICIOUS' || result.url_features?.has_homograph_attack ? (
                    <div className="p-3 rounded-xl bg-red-50 border border-red-300 mt-2 space-y-1.5 animate-fadeIn">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider bg-[#D10000] text-white">
                          HOMOGRAPH RISK
                        </span>
                        <span className="text-xs font-black text-[#D10000]">
                          Mixed/Confusable characters detected
                        </span>
                      </div>

                      <div className="text-xs text-slate-700 flex flex-wrap items-center gap-x-4 gap-y-1">
                        {result.url_features?.detected_scripts && result.url_features.detected_scripts.length > 0 && (
                          <span>
                            <span className="font-semibold text-slate-500">Mixed Scripts:</span>{' '}
                            <span className="font-mono font-bold text-red-800">
                              {result.url_features.detected_scripts.join(' + ')}
                            </span>
                          </span>
                        )}

                        {result.url_features?.punycode_domain && result.url_features.punycode_domain.startsWith('xn--') && (
                          <span>
                            <span className="font-semibold text-slate-500">Punycode (xn--):</span>{' '}
                            <span className="font-mono font-bold text-slate-800">
                              {result.url_features.punycode_domain}
                            </span>
                          </span>
                        )}

                        {result.url_features?.unicode_domain && (
                          <span>
                            <span className="font-semibold text-slate-500">Unicode Host:</span>{' '}
                            <span className="font-mono font-bold text-slate-900 bg-white px-1.5 py-0.5 rounded border border-slate-200">
                              {result.url_features.unicode_domain}
                            </span>
                          </span>
                        )}
                      </div>

                      {result.url_features?.confusables_detected && result.url_features.confusables_detected.length > 0 && (
                        <div className="pt-1 border-t border-red-200/60 flex items-center gap-1.5 flex-wrap text-xs text-slate-700">
                          <span className="text-[10px] font-bold uppercase text-red-700">Lookalike Homoglyphs:</span>
                          {result.url_features.confusables_detected.map((conf, idx) => (
                            <span key={idx} className="bg-red-100 text-red-900 px-1.5 py-0.5 rounded text-[11px] font-mono border border-red-200" title={`${conf.name} (${conf.codepoint}) mimics Latin '${conf.target_char}'`}>
                              '{conf.char}' ({conf.script} {conf.codepoint}) &rarr; '{conf.target_char}'
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : result.homograph_risk === 'LOW' || result.url_features?.homograph_analysis?.has_unicode ? (
                    <div className="p-2.5 rounded-xl bg-blue-50 border border-blue-200 mt-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-600 text-white">
                          IDN UNICODE DOMAIN
                        </span>
                        <span className="text-xs font-semibold text-blue-900">
                          Valid single-script Unicode hostname (non-confusable)
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        Punycode: {result.url_features?.punycode_domain || result.punycode_domain}
                      </p>
                    </div>
                  ) : null}

                  {/* BRAND IMPERSONATION & TYPOSQUATTING INTELLIGENCE CARD */}
                  {(result.brand_impersonated || result.url_features?.brand_impersonated) && !result.url_features?.is_official_domain && (
                    <div className="p-3 rounded-xl bg-amber-50/90 border border-amber-300 mt-2 space-y-2 animate-fadeIn">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider bg-[#D10000] text-white">
                          BRAND SIMILARITY: {result.brand_similarity_rating || result.url_features?.brand_similarity_rating || 'HIGH'}
                        </span>
                        <span className="text-xs font-black text-slate-800">
                          Target Brand: <span className="text-[#D10000] underline decoration-dotted">{result.url_features?.brand_display_name || result.brand_display_name || result.brand_impersonated || result.url_features?.brand_impersonated}</span>
                        </span>
                        {(result.url_features?.brand_similarity_score ?? result.brand_similarity_score ?? 0) > 0 && (
                          <span className="text-[11px] font-mono font-bold bg-white px-1.5 py-0.5 rounded border border-amber-300 text-amber-900">
                            {Math.round(((result.url_features?.brand_similarity_score ?? result.brand_similarity_score) || 0) * 100)}% Match
                          </span>
                        )}
                        {(result.tld_mismatch ?? result.url_features?.tld_mismatch) && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider bg-red-100 text-red-800 border border-red-300">
                            TLD MISMATCH
                          </span>
                        )}
                      </div>

                      {/* Domain Stem & TLD breakdown */}
                      <div className="text-xs text-slate-700 flex flex-wrap items-center gap-x-4 gap-y-1 pt-1 border-t border-amber-200">
                        <span>
                          <span className="font-semibold text-slate-500">Evaluated Domain Stem:</span>{' '}
                          <span className="font-mono font-bold text-slate-900 bg-white px-1.5 py-0.5 rounded border border-slate-200">
                            {result.url_features?.brand_analysis?.candidate_stem || result.registered_domain || result.url_features?.registered_domain}
                          </span>
                        </span>

                        {(result.tld_mismatch ?? result.url_features?.tld_mismatch) && (
                          <span>
                            <span className="font-semibold text-slate-500">TLD Comparison:</span>{' '}
                            <span className="font-mono font-bold text-red-700">
                              .{result.tld || result.url_features?.tld} (Candidate)
                            </span>{' '}
                            <span className="text-slate-400 font-semibold">vs</span>{' '}
                            <span className="font-mono font-bold text-emerald-700">
                              {result.url_features?.brand_analysis?.official_tlds?.length
                                ? result.url_features.brand_analysis.official_tlds.map(t => '.' + t).slice(0, 4).join(', ')
                                : '.com, .in'} (Official)
                            </span>
                          </span>
                        )}
                      </div>

                      {/* Additional Deceptive Tokens */}
                      {((result.deceptive_tokens && result.deceptive_tokens.length > 0) ||
                        (result.url_features?.deceptive_tokens && result.url_features.deceptive_tokens.length > 0)) && (
                        <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-700 pt-1 border-t border-amber-200">
                          <span className="text-[10px] font-bold uppercase text-amber-900">Additional Deceptive Tokens:</span>
                          {(result.deceptive_tokens || result.url_features?.deceptive_tokens || []).map((token, idx) => (
                            <span key={idx} className="bg-amber-100 text-amber-900 px-1.5 py-0.5 rounded text-[11px] font-mono font-bold border border-amber-300">
                              {token}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Deceptive Manipulations Detected */}
                      {((result.manipulation_types && result.manipulation_types.length > 0) ||
                        (result.url_features?.manipulation_types && result.url_features.manipulation_types.length > 0)) && (
                        <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-700 pt-1 border-t border-amber-200">
                          <span className="text-[10px] font-bold uppercase text-slate-600">Manipulations Detected:</span>
                          {(result.manipulation_types || result.url_features?.manipulation_types || []).map((manip, idx) => (
                            <span key={idx} className="bg-white text-slate-800 px-1.5 py-0.5 rounded text-[11px] font-mono border border-slate-300">
                              {manip}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Threat Score Top Right */}
              <div className="flex flex-col items-start md:items-end shrink-0">
                <span className="text-[11px] font-black uppercase tracking-wider text-slate-400">
                  THREAT SCORE
                </span>
                <div className="flex items-baseline gap-1">
                  <span
                    className={`text-4xl sm:text-5xl font-black ${
                      getRiskStyles(result.risk_level).scoreText
                    }`}
                  >
                    {result.risk_score}
                  </span>
                  <span className="text-base font-bold text-slate-400">/ 100</span>
                </div>
              </div>
            </div>

            {/* Score Progress Bar */}
            <div className="w-full h-3 bg-slate-200 rounded-full overflow-hidden mb-6">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out ${
                  getRiskStyles(result.risk_level).barColor
                }`}
                style={{ width: `${Math.max(result.risk_score, 4)}%` }}
              />
            </div>

            {/* REDFLAG DETECTION VERDICT Box */}
            <div className="p-4 sm:p-5 rounded-2xl bg-[#DFF1F1]/50 border border-[#BBD5DA] mb-6">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 text-slate-800 shrink-0">
                  {getRiskStyles(result.risk_level).icon}
                </div>
                <div>
                  <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 mb-1">
                    REDFLAG DETECTION VERDICT
                  </h4>
                  <p className="text-sm text-slate-700 leading-relaxed font-normal">
                    {result.explanation}
                  </p>
                </div>
              </div>
            </div>

            {/* 8-PART URL ARCHITECTURAL DECOMPOSITION */}
            <div className="mb-6">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-black uppercase tracking-wider text-slate-800">
                  URL ARCHITECTURAL DECOMPOSITION:
                </h4>
                <span className="text-[10px] font-bold text-slate-500 uppercase bg-slate-200/60 px-2 py-0.5 rounded">
                  8-Part Discrete Parsing
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {/* 1. Scheme */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    SCHEME
                  </span>
                  <p className="font-mono text-xs font-bold text-indigo-700 truncate">
                    {result.scheme || result.url_features.scheme || result.url_features.protocol || 'http'}
                  </p>
                </div>

                {/* 2. Subdomain */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    SUBDOMAIN
                  </span>
                  <p className="font-mono text-xs font-bold text-slate-800 truncate" title={result.subdomain || result.url_features.subdomain || '(none)'}>
                    {result.subdomain || result.url_features.subdomain || <span className="text-slate-400 font-normal italic">none</span>}
                  </p>
                </div>

                {/* 3. Registered Domain */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    REGISTERED DOMAIN
                  </span>
                  <p className="font-mono text-xs font-bold text-slate-900 truncate" title={result.registered_domain || result.url_features.registered_domain || result.domain}>
                    {result.registered_domain || result.url_features.registered_domain || result.domain}
                  </p>
                </div>

                {/* 4. TLD */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    TLD
                  </span>
                  <p className="font-mono text-xs font-bold text-emerald-700 truncate">
                    .{result.tld || result.url_features.tld || result.url_features.detected_tld || 'unknown'}
                  </p>
                </div>

                {/* 5. Port */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    PORT
                  </span>
                  <p className="font-mono text-xs font-bold text-slate-800">
                    {result.port || result.url_features.port || <span className="text-slate-400 font-normal italic">default</span>}
                  </p>
                </div>

                {/* 6. Path */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    PATH
                  </span>
                  <p className="font-mono text-xs font-bold text-slate-800 truncate" title={result.path || result.url_features.path || '/'}>
                    {result.path || result.url_features.path || '/'}
                  </p>
                </div>

                {/* 7. Query */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    QUERY
                  </span>
                  <p className="font-mono text-xs font-bold text-slate-800 truncate" title={result.query || result.url_features.query || '(none)'}>
                    {result.query || result.url_features.query || <span className="text-slate-400 font-normal italic">none</span>}
                  </p>
                </div>

                {/* 8. Fragment */}
                <div className="p-2.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-0.5">
                    FRAGMENT
                  </span>
                  <p className="font-mono text-xs font-bold text-slate-800 truncate" title={result.fragment || result.url_features.fragment || '(none)'}>
                    {result.fragment || result.url_features.fragment || <span className="text-slate-400 font-normal italic">none</span>}
                  </p>
                </div>
              </div>
            </div>

            {/* STRUCTURAL HEURISTIC BREAKDOWN (6 CARDS) */}
            <div className="mb-6">
              <h4 className="text-xs font-black uppercase tracking-wider text-slate-800 mb-3">
                STRUCTURAL HEURISTIC BREAKDOWN:
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
                {/* 1. HOST DOMAIN */}
                <div className="p-3.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                    HOST DOMAIN
                  </span>
                  <p className="font-mono text-sm font-bold text-slate-900 break-all">
                    {result.url_features.domain}
                  </p>
                </div>

                {/* 2. SHANNON ENTROPY */}
                <div className="p-3.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block">
                      SHANNON ENTROPY
                    </span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                        result.url_features.entropy > 4.0
                          ? 'bg-red-100 text-red-700'
                          : result.url_features.entropy > 3.3
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-emerald-100 text-emerald-800'
                      }`}
                    >
                      {result.url_features.entropy > 4.0 ? 'High' : 'Normal'}
                    </span>
                  </div>
                  <p className="font-mono text-sm font-bold text-slate-900">
                    {result.url_features.entropy.toFixed(3)}
                  </p>
                </div>

                {/* 3. BRAND MIMICKED */}
                <div className="p-3.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                    BRAND MIMICKED
                  </span>
                  {result.url_features.is_official_domain ? (
                    <p className="text-sm font-bold text-emerald-700 flex items-center gap-1">
                      <CheckCircle2 size={15} />
                      <span>Official {result.url_features.official_brand_name || 'Portal'}</span>
                    </p>
                  ) : result.url_features.brand_impersonated ? (
                    <div>
                      <p className="text-sm font-bold text-[#D10000] flex items-center gap-1">
                        <AlertTriangle size={15} />
                        <span>Mimics {result.url_features.brand_display_name || result.url_features.brand_impersonated}</span>
                      </p>
                      <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                        Similarity: {result.url_features.brand_similarity_rating || 'HIGH'} ({Math.round(result.url_features.brand_similarity_score * 100)}%)
                      </p>
                    </div>
                  ) : (
                    <p className="text-sm font-medium text-slate-600">None detected</p>
                  )}
                </div>

                {/* 4. TOP-LEVEL DOMAIN */}
                <div className="p-3.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block">
                      TOP-LEVEL DOMAIN
                    </span>
                    {result.url_features.suspicious_tld && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-red-100 text-red-700">
                        High-Abuse
                      </span>
                    )}
                  </div>
                  <p className="font-mono text-sm font-bold text-slate-900">
                    .{result.url_features.detected_tld || 'unknown'}
                  </p>
                </div>

                {/* 5. SUBDOMAINS & LENGTH */}
                <div className="p-3.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                    SUBDOMAINS & LENGTH
                  </span>
                  <p className="font-mono text-sm font-bold text-slate-900">
                    {result.url_features.subdomain_count} (Len: {result.url_features.url_length})
                  </p>
                </div>

                {/* 6. PROTOCOL & PORT */}
                <div className="p-3.5 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5]">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                    PROTOCOL & PORT
                  </span>
                  <p className="font-mono text-sm font-bold text-slate-900 flex items-center gap-1.5">
                    <span
                      className={
                        result.url_features.protocol.toUpperCase() === 'HTTPS'
                          ? 'text-emerald-700'
                          : 'text-amber-700'
                      }
                    >
                      {result.url_features.protocol.toUpperCase()}
                    </span>
                    {result.url_features.port && (
                      <span className="text-xs text-red-600 bg-red-50 px-1 rounded">
                        Port {result.url_features.port}
                      </span>
                    )}
                    {result.url_features.ip_based && (
                      <span className="text-xs text-red-700 font-bold bg-red-100 px-1.5 rounded">
                        IP Host
                      </span>
                    )}
                  </p>
                </div>
              </div>
            </div>

            {/* DETECTED THREAT SIGNALS */}
            {result.url_features.threat_signals && result.url_features.threat_signals.length > 0 && (
              <div className="mb-6">
                <h4 className="text-xs font-black uppercase tracking-wider text-slate-800 mb-2.5">
                  DETECTED THREAT SIGNALS:
                </h4>
                <div className="p-4 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5] space-y-2">
                  {result.url_features.threat_signals.map((signal, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs sm:text-sm text-slate-800 font-medium">
                      <AlertTriangle size={15} className="text-[#D10000] shrink-0 mt-0.5" />
                      <span>{signal}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* RECOMMENDED SAFETY ACTIONS */}
            {result.mitigation_advice && result.mitigation_advice.length > 0 && (
              <div>
                <div
                  className={`p-4 sm:p-5 rounded-2xl border ${
                    result.risk_level === 'SAFE_LOW'
                      ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                      : 'bg-red-50/70 border-red-200 text-red-950'
                  }`}
                >
                  <h4 className="text-xs font-black uppercase tracking-wider flex items-center gap-1.5 mb-2.5">
                    {result.risk_level === 'SAFE_LOW' ? (
                      <>
                        <ShieldCheck size={16} className="text-emerald-700" />
                        <span>VERIFIED CITIZEN ADVICE:</span>
                      </>
                    ) : (
                      <>
                        <AlertCircle size={16} className="text-[#D10000]" />
                        <span className="text-[#D10000]">RECOMMENDED SAFETY ACTIONS:</span>
                      </>
                    )}
                  </h4>

                  <ul className="space-y-1.5 text-xs sm:text-sm pl-2">
                    {result.mitigation_advice.map((advice, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-slate-400 font-bold">•</span>
                        <span>{advice}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
});

UrlScanner.displayName = 'UrlScanner';
