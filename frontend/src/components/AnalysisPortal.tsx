import React from 'react';
import { UrlScanner } from './UrlScanner';
import { SmsScanner } from './SmsScanner';
import { Link2, MessageSquare, ArrowLeft, Shield } from 'lucide-react';

interface AnalysisPortalProps {
  activeTab: 'link' | 'sms';
  onTabChange: (tab: 'link' | 'sms') => void;
  onBackToHome: () => void;
}

export const AnalysisPortal: React.FC<AnalysisPortalProps> = ({
  activeTab,
  onTabChange,
  onBackToHome,
}) => {
  return (
    <div className="min-h-[85vh] py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* Top Breadcrumb & Back Button */}
      <div className="flex items-center justify-between mb-8 pb-4 border-b border-[#BBD5DA]">
        <button
          onClick={onBackToHome}
          className="inline-flex items-center gap-2 text-sm font-bold text-slate-600 hover:text-[#D10000] transition-colors cursor-pointer"
        >
          <ArrowLeft size={16} />
          <span>Back to Home</span>
        </button>

        <div className="flex items-center gap-2 text-xs font-semibold text-slate-500">
          <Shield size={14} className="text-emerald-600" />
          <span>RedFlag Analysis Center</span>
        </div>
      </div>

      {/* Two Options Selector */}
      <div className="max-w-2xl mx-auto mb-10 text-center">
        <h1 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight mb-3">
          What would you like to analyse?
        </h1>
        <p className="text-slate-600 text-sm sm:text-base mb-6">
          Select an inspection mode below to run real-time heuristics against deceptive cyber threats.
        </p>

        {/* The Two Tab Option Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-1.5 bg-[#DFF1F1]/60 rounded-3xl border border-[#BBD5DA]">
          {/* Option 1: Analyse a Malicious Link */}
          <button
            type="button"
            onClick={() => onTabChange('link')}
            className={`flex items-center gap-3.5 p-4 rounded-2xl text-left transition-all cursor-pointer ${
              activeTab === 'link'
                ? 'bg-white shadow-md border-2 border-[#D10000] text-slate-900'
                : 'hover:bg-white/60 text-slate-600 border border-transparent'
            }`}
          >
            <div
              className={`p-3 rounded-xl shrink-0 ${
                activeTab === 'link' ? 'bg-[#D10000] text-white' : 'bg-white text-slate-500 border border-[#BBD5DA]'
              }`}
            >
              <Link2 size={22} />
            </div>
            <div>
              <span className="block text-base font-black leading-tight">
                Analyse a Malicious Link
              </span>
              <span className="text-xs text-slate-500 mt-0.5 block">
                URLs, typosquats, & phishing domains
              </span>
            </div>
          </button>

          {/* Option 2: Analyse SMS / Scam Text */}
          <button
            type="button"
            onClick={() => onTabChange('sms')}
            className={`flex items-center gap-3.5 p-4 rounded-2xl text-left transition-all cursor-pointer ${
              activeTab === 'sms'
                ? 'bg-white shadow-md border-2 border-[#D10000] text-slate-900'
                : 'hover:bg-white/60 text-slate-600 border border-transparent'
            }`}
          >
            <div
              className={`p-3 rounded-xl shrink-0 ${
                activeTab === 'sms' ? 'bg-[#D10000] text-white' : 'bg-white text-slate-500 border border-[#BBD5DA]'
              }`}
            >
              <MessageSquare size={22} />
            </div>
            <div>
              <span className="block text-base font-black leading-tight">
                Analyse SMS / Scam Text
              </span>
              <span className="text-xs text-slate-500 mt-0.5 block">
                KYC traps, electricity cuts & urgency bait
              </span>
            </div>
          </button>
        </div>
      </div>

      {/* Active Scanner Content */}
      <div className="transition-all duration-300">
        {activeTab === 'link' ? (
          <UrlScanner />
        ) : (
          <SmsScanner />
        )}
      </div>
    </div>
  );
};
