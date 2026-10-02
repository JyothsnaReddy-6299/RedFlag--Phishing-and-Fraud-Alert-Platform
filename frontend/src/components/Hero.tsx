import React, { useState } from 'react';
import { RedFlagIcon } from './RedFlagIcon';
import { CheckCircle2, Search, ArrowRight } from 'lucide-react';

interface HeroProps {
  onAnalyseClick: (initialInput?: string) => void;
}

export const Hero: React.FC<HeroProps> = ({ onAnalyseClick }) => {
  const [quickInput, setQuickInput] = useState('');

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onAnalyseClick(quickInput.trim() || undefined);
  };

  return (
    <section className="relative min-h-[75vh] flex flex-col items-center justify-center text-center px-4 pt-10 pb-16 overflow-hidden">
      {/* Subtle radial ambient glow behind flag */}
      <div 
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[520px] h-[520px] rounded-full pointer-events-none -z-10"
        style={{
          background: 'radial-gradient(circle, rgba(223, 241, 241, 0.7) 0%, rgba(245, 245, 245, 0) 70%)',
        }}
      />

      <div className="max-w-3xl mx-auto flex flex-col items-center">
        {/* Waving Red Flag SVG Symbol */}
        <div className="mb-6 transform hover:scale-105 transition-transform duration-300">
          <RedFlagIcon size={76} className="animate-flag" />
        </div>

        {/* Huge Bold Heading 'RedFlag' */}
        <h1 className="text-6xl sm:text-7xl md:text-8xl font-black text-slate-900 tracking-tight leading-none mb-6">
          Red<span className="text-[#D10000]">Flag</span>
        </h1>

        {/* Subtitle */}
        <p className="text-xl sm:text-2xl text-slate-600 font-normal tracking-normal max-w-xl mx-auto mb-8 leading-relaxed">
          Detect malicious links and scam messages instantly.
        </p>

        {/* Quick Search / Scan Input Box */}
        <form
          onSubmit={handleQuickSubmit}
          className="w-full max-w-2xl bg-white rounded-full border-2 border-[#BBD5DA] hover:border-slate-400 focus-within:border-[#D10000] p-1.5 sm:p-2 flex items-center shadow-md transition-all mb-8"
        >
          <div className="pl-3.5 pr-2 text-slate-400">
            <Search size={20} />
          </div>
          <input
            type="text"
            value={quickInput}
            onChange={(e) => setQuickInput(e.target.value)}
            placeholder="Paste suspicious URL or scam text (e.g. sbi-kyc-verify.xyz)..."
            className="flex-1 bg-transparent px-2 py-2 text-sm sm:text-base text-slate-900 placeholder:text-slate-400 focus:outline-none"
          />
          <button
            type="submit"
            className="btn-redflag-glow px-5 sm:px-7 py-2.5 sm:py-3 rounded-full text-xs sm:text-sm font-bold tracking-wide flex items-center gap-1.5 cursor-pointer shrink-0 shadow-sm"
          >
            <span>Scan Now</span>
            <ArrowRight size={16} />
          </button>
        </form>

        {/* Security Trust Badges */}
        <div className="flex flex-wrap items-center justify-center gap-4 sm:gap-6 text-xs sm:text-sm text-slate-500 font-medium">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Real-Time Heuristic Engine</span>
          </div>
          <span className="text-[#BBD5DA] hidden sm:inline">•</span>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Shannon Entropy & Typosquatting</span>
          </div>
          <span className="text-[#BBD5DA] hidden sm:inline">•</span>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Indian Banking Whitelist</span>
          </div>
          <span className="text-[#BBD5DA] hidden sm:inline">•</span>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Tamil & Tanglish NLP</span>
          </div>
        </div>
      </div>
    </section>
  );
};
