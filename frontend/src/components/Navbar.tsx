import React from 'react';
import { RedFlagIcon } from './RedFlagIcon';
import { ShieldAlert, ExternalLink, Activity, Link2, MessageSquare, Home } from 'lucide-react';

interface NavbarProps {
  currentPage: 'home' | 'analyse';
  activeAnalysisTab?: 'link' | 'sms';
  onNavigate: (page: 'home' | 'analyse', tab?: 'link' | 'sms') => void;
  isBackendOnline: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentPage,
  activeAnalysisTab,
  onNavigate,
  isBackendOnline,
}) => {
  return (
    <header className="sticky top-0 z-50 w-full backdrop-blur-md bg-[#F5F5F5]/90 border-b border-[#BBD5DA] transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between">
        
        {/* Logo & Brand */}
        <button
          onClick={() => onNavigate('home')}
          className="flex items-center gap-3 group cursor-pointer text-left"
        >
          <div className="transform group-hover:rotate-[-6deg] transition-transform duration-200">
            <RedFlagIcon size={34} />
          </div>
          <div className="flex flex-col">
            <span className="text-2xl font-black tracking-tight text-slate-900 leading-none">
              RedFlag
            </span>
            <span className="text-[10px] tracking-wider uppercase text-slate-500 font-semibold mt-0.5">
              Threat Defense Radar
            </span>
          </div>
        </button>

        {/* Center Nav Links */}
        <nav className="hidden md:flex items-center gap-6">
          <button
            onClick={() => onNavigate('home')}
            className={`text-sm font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
              currentPage === 'home' ? 'text-[#D10000]' : 'text-slate-700 hover:text-[#D10000]'
            }`}
          >
            <Home size={15} />
            <span>Home</span>
          </button>

          <button
            onClick={() => onNavigate('analyse', 'link')}
            className={`text-sm font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
              currentPage === 'analyse' && activeAnalysisTab === 'link'
                ? 'text-[#D10000] font-bold'
                : 'text-slate-700 hover:text-[#D10000]'
            }`}
          >
            <Link2 size={15} />
            <span>Link Scanner</span>
          </button>

          <button
            onClick={() => onNavigate('analyse', 'sms')}
            className={`text-sm font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
              currentPage === 'analyse' && activeAnalysisTab === 'sms'
                ? 'text-[#D10000] font-bold'
                : 'text-slate-700 hover:text-[#D10000]'
            }`}
          >
            <MessageSquare size={15} />
            <span>SMS Scanner</span>
          </button>

          <a 
            href="/#features"
            onClick={(e) => {
              if (currentPage !== 'home') {
                e.preventDefault();
                onNavigate('home');
                setTimeout(() => {
                  const el = document.getElementById('features');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }
            }}
            className="text-sm font-semibold text-slate-700 hover:text-[#D10000] transition-colors"
          >
            Engine
          </a>

          <a 
            href="/api/v1/docs" 
            target="_blank" 
            rel="noreferrer"
            className="text-sm font-semibold text-slate-700 hover:text-[#D10000] transition-colors inline-flex items-center gap-1"
          >
            API Docs
            <ExternalLink size={13} className="text-slate-400" />
          </a>
        </nav>

        {/* Right Section: Status Indicator & Analyse CTA */}
        <div className="flex items-center gap-4">
          <div 
            className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border"
            style={{ 
              backgroundColor: isBackendOnline ? '#DFF1F1' : '#FEE2E2',
              borderColor: isBackendOnline ? '#BBD5DA' : '#FCA5A5',
              color: isBackendOnline ? '#0F766E' : '#B91C1C'
            }}
            title={isBackendOnline ? 'FastAPI link detection backend is active' : 'Connecting to backend engine...'}
          >
            <span className={`w-2 h-2 rounded-full ${isBackendOnline ? 'bg-emerald-500 animate-ping' : 'bg-red-500'}`} />
            <Activity size={13} />
            <span>{isBackendOnline ? 'Engine Online' : 'Engine Offline'}</span>
          </div>

          <button
            onClick={() => onNavigate('analyse', 'link')}
            className="btn-redflag-glow px-5 py-2.5 rounded-full text-sm font-bold tracking-wide flex items-center gap-2 cursor-pointer shadow-md"
          >
            <ShieldAlert size={16} />
            <span>Analyse Now</span>
          </button>
        </div>

      </div>
    </header>
  );
};
