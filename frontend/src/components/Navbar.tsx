import React from 'react';
import { RedFlagIcon } from './RedFlagIcon';
import { ShieldAlert, Link2, MessageSquare, Home } from 'lucide-react';

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
        </nav>

        {/* Right Section: Analyse CTA Button */}
        <div className="flex items-center gap-4">
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
