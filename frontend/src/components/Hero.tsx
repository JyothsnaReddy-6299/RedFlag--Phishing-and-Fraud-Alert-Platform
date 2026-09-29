import React from 'react';
import { RedFlagIcon } from './RedFlagIcon';
import { ArrowDown, CheckCircle2 } from 'lucide-react';

interface HeroProps {
  onAnalyseClick: () => void;
}

export const Hero: React.FC<HeroProps> = ({ onAnalyseClick }) => {
  return (
    <section className="relative min-h-[75vh] flex flex-col items-center justify-center text-center px-4 pt-12 pb-16 overflow-hidden">
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
          RedFlag
        </h1>

        {/* Subtitle */}
        <p className="text-xl sm:text-2xl text-slate-600 font-normal tracking-normal max-w-xl mx-auto mb-10 leading-relaxed">
          Detect malicious links and scam messages instantly.
        </p>

        {/* Glowing Red Pill Button: 'Analyse Now' */}
        <button
          onClick={onAnalyseClick}
          className="btn-redflag-glow px-10 py-4 rounded-full text-lg sm:text-xl font-bold tracking-wide cursor-pointer transition-all duration-300 mb-10 inline-flex items-center gap-2 group"
          id="hero-analyse-btn"
        >
          <span>Analyse Now</span>
          <ArrowDown size={20} className="transform group-hover:translate-y-1 transition-transform" />
        </button>

        {/* Security Trust Badges */}
        <div className="flex flex-wrap items-center justify-center gap-6 text-xs sm:text-sm text-slate-500 font-medium">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Real-Time Heuristic Engine</span>
          </div>
          <span className="text-[#BBD5DA]">•</span>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Shannon Entropy & Typosquatting</span>
          </div>
          <span className="text-[#BBD5DA]">•</span>
          <div className="flex items-center gap-1.5">
            <CheckCircle2 size={16} className="text-emerald-600" />
            <span>Indian Banking Whitelist</span>
          </div>
        </div>
      </div>
    </section>
  );
};
