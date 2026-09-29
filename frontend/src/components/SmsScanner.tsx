import { useState } from 'react';
import {
  MessageSquare,
  Loader2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  Link as LinkIcon,
  RotateCcw,
  Sparkles,
  Phone
} from 'lucide-react';
import type { SMSScanResponse, RiskLevel } from '../types';
import { scanSms } from '../services/api';

export const SmsScanner: React.FC = () => {
  const [smsText, setSmsText] = useState('');
  const [senderId, setSenderId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SMSScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (overrideText?: string, overrideSender?: string) => {
    const textToScan = (overrideText !== undefined ? overrideText : smsText).trim();
    if (!textToScan) {
      setError('Please paste an SMS or message text to analyze.');
      return;
    }

    setSmsText(textToScan);
    if (overrideSender !== undefined) {
      setSenderId(overrideSender);
    }
    setError(null);
    setLoading(true);

    try {
      const data = await scanSms(textToScan, overrideSender !== undefined ? overrideSender : senderId);
      setResult(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to scan message';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setSmsText('');
    setSenderId('');
    setResult(null);
    setError(null);
  };

  const getRiskStyles = (level: RiskLevel) => {
    switch (level) {
      case 'SAFE_LOW':
        return {
          badgeBg: 'bg-emerald-50 text-emerald-800 border-emerald-300',
          badgeText: 'SAFE',
          barColor: 'bg-emerald-500',
          scoreText: 'text-emerald-700',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-600 inline mr-1" />,
        };
      case 'SUSPICIOUS':
        return {
          badgeBg: 'bg-amber-50 text-amber-900 border-amber-300',
          badgeText: 'SUSPICIOUS',
          barColor: 'bg-amber-500',
          scoreText: 'text-amber-700',
          icon: <AlertTriangle className="w-5 h-5 text-amber-600 inline mr-1" />,
        };
      case 'HIGH_RISK':
        return {
          badgeBg: 'bg-orange-50 text-orange-900 border-orange-300',
          badgeText: 'HIGH RISK SCAM',
          barColor: 'bg-orange-500',
          scoreText: 'text-orange-700',
          icon: <AlertCircle className="w-5 h-5 text-orange-600 inline mr-1" />,
        };
      case 'CRITICAL':
      default:
        return {
          badgeBg: 'bg-red-50 text-red-900 border-red-300',
          badgeText: 'CRITICAL SCAM ATTEMPT',
          barColor: 'bg-[#D10000]',
          scoreText: 'text-[#D10000]',
          icon: <ShieldAlert className="w-5 h-5 text-[#D10000] inline mr-1" />,
        };
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6">
      <div className="bg-white rounded-3xl shadow-xl border border-[#BBD5DA] overflow-hidden p-6 sm:p-10">
        
        {/* Section Heading */}
        <div className="text-center max-w-2xl mx-auto mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#DFF1F1] text-teal-800 text-xs font-bold tracking-wide uppercase mb-3">
            <Sparkles size={14} />
            <span>SMS & Scam Message Radar</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
            Inspect Suspicious Messages
          </h2>
          <p className="text-slate-600 text-sm sm:text-base mt-2">
            Paste SMS text, WhatsApp forwards, or urgent notices to detect psychological coercion, fake electricity disconnections, and embedded phishing links.
          </p>
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="space-y-4 mb-6"
        >
          {/* Optional Sender ID input */}
          <div className="flex items-center gap-2">
            <div className="relative w-full sm:w-72">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                <Phone size={16} />
              </div>
              <input
                type="text"
                value={senderId}
                onChange={(e) => setSenderId(e.target.value)}
                placeholder="Sender ID or Phone (Optional)"
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-[#F5F5F5] border border-[#BBD5DA] focus:border-[#D10000] focus:bg-white text-xs sm:text-sm font-mono text-slate-900 outline-none transition-all"
              />
            </div>
            <span className="text-xs text-slate-400 hidden sm:inline">
              (e.g., +919876543210 or VK-SBIINB)
            </span>
          </div>

          {/* Text Area */}
          <div className="relative">
            <textarea
              rows={4}
              value={smsText}
              onChange={(e) => setSmsText(e.target.value)}
              placeholder="Paste SMS or message content here (e.g., 'Dear customer, your electricity power will be disconnected tonight...')"
              className="w-full p-4 rounded-2xl bg-[#F5F5F5] border-2 border-[#BBD5DA] focus:border-[#D10000] focus:bg-white focus:outline-none text-slate-900 font-sans text-sm sm:text-base leading-relaxed transition-all resize-y"
            />
            {smsText && (
              <button
                type="button"
                onClick={handleReset}
                className="absolute top-3 right-3 flex items-center text-xs font-semibold text-slate-400 hover:text-slate-700 bg-white/80 px-2 py-1 rounded-md border border-slate-200 cursor-pointer shadow-xs"
              >
                <RotateCcw size={13} className="mr-1" />
                Clear
              </button>
            )}
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="btn-redflag-glow px-8 py-3.5 rounded-2xl font-bold text-base flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 whitespace-nowrap shadow-md"
            >
              {loading ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  <span>Analyzing Message...</span>
                </>
              ) : (
                <>
                  <MessageSquare size={18} />
                  <span>Analyse Message</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Error Alert */}
        {error && (
          <div className="p-4 rounded-2xl bg-red-50 border border-red-200 text-red-700 text-sm flex items-center gap-3 mb-6 animate-fadeIn">
            <AlertCircle size={20} className="text-[#D10000] shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* RESULT CARD */}
        {result && (
          <div className="mt-8 pt-8 border-t border-[#BBD5DA] animate-fadeIn">
            
            {/* Header: Badges & Threat Score */}
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-4">
              <div className="space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider border ${
                      getRiskStyles(result.risk_level).badgeBg
                    }`}
                  >
                    {result.risk_level === 'SAFE_LOW' ? 'SAFE' : result.risk_level}
                  </span>

                  <span className="text-sm font-black uppercase tracking-wider text-slate-800">
                    {result.scam_category.replace(/_/g, ' ')}
                  </span>
                </div>

                <p className="text-xs font-medium text-slate-500">
                  Scanned message: &quot;{result.text.slice(0, 100)}...&quot;
                </p>
              </div>

              {/* Threat Score */}
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

            {/* Verdict Box */}
            <div className="p-4 sm:p-5 rounded-2xl bg-[#DFF1F1]/50 border border-[#BBD5DA] mb-6">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 text-slate-800 shrink-0">
                  {getRiskStyles(result.risk_level).icon}
                </div>
                <div>
                  <h4 className="text-xs font-black uppercase tracking-wider text-slate-900 mb-1">
                    REDFLAG SMS DETECTION VERDICT
                  </h4>
                  <p className="text-sm text-slate-700 leading-relaxed font-normal">
                    {result.explanation}
                  </p>
                </div>
              </div>
            </div>

            {/* UNPACKED EMBEDDED URLS */}
            {result.extracted_urls && result.extracted_urls.length > 0 && (
              <div className="mb-6">
                <h4 className="text-xs font-black uppercase tracking-wider text-slate-800 mb-3 flex items-center gap-1.5">
                  <LinkIcon size={14} className="text-[#D10000]" />
                  <span>UNPACKED EMBEDDED LINKS DETECTED IN SMS:</span>
                </h4>

                <div className="space-y-3">
                  {result.extracted_urls.map((urlItem, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-black uppercase ${
                              urlItem.risk_score >= 80
                                ? 'bg-red-100 text-red-800'
                                : urlItem.risk_score >= 40
                                ? 'bg-amber-100 text-amber-800'
                                : 'bg-emerald-100 text-emerald-800'
                            }`}
                          >
                            {urlItem.risk_level}
                          </span>
                          <span className="font-mono text-xs font-bold text-slate-900">
                            {urlItem.domain}
                          </span>
                        </div>
                        <p className="font-mono text-xs text-slate-600 break-all select-all">
                          {urlItem.url}
                        </p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0 self-start sm:self-center">
                        <div className="text-right">
                          <span className="text-[10px] uppercase font-bold text-slate-400 block">Link Score</span>
                          <span
                            className={`text-lg font-black ${
                              urlItem.risk_score >= 60 ? 'text-[#D10000]' : 'text-emerald-700'
                            }`}
                          >
                            {urlItem.risk_score} / 100
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* DETECTED SIGNALS */}
            {result.threat_signals && result.threat_signals.length > 0 && (
              <div className="mb-6">
                <h4 className="text-xs font-black uppercase tracking-wider text-slate-800 mb-2.5">
                  DETECTED SOCIAL ENGINEERING SIGNALS:
                </h4>
                <div className="p-4 rounded-xl border border-[#BBD5DA] bg-[#F5F5F5] space-y-2">
                  {result.threat_signals.map((signal, idx) => (
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
};
