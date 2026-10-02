import React, { useState } from 'react';
import { RedFlagIcon } from './RedFlagIcon';
import {
  ShieldAlert,
  Home,
  Network,
  Users,
  Activity,
  Sliders,
  Menu,
  X,
} from 'lucide-react';

export type NavTab = 'home' | 'analyse' | 'campaigns' | 'community' | 'pulse' | 'moderate';

interface NavbarProps {
  currentTab: NavTab;
  onNavigate: (tab: NavTab) => void;
  isBackendOnline: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onNavigate,
  isBackendOnline,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems: { key: NavTab; label: string; icon: React.ReactNode }[] = [
    { key: 'home', label: 'Home', icon: <Home size={15} /> },
    { key: 'analyse', label: 'Analyse', icon: <ShieldAlert size={15} /> },
    { key: 'campaigns', label: 'Campaigns', icon: <Network size={15} /> },
    { key: 'community', label: 'Community', icon: <Users size={15} /> },
    { key: 'pulse', label: 'Threat Pulse', icon: <Activity size={15} /> },
    { key: 'moderate', label: 'Moderate', icon: <Sliders size={15} /> },
  ];

  const handleSelectTab = (tab: NavTab) => {
    onNavigate(tab);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-50 w-full backdrop-blur-md bg-[#F5F5F5]/90 border-b border-[#BBD5DA] transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between">
        {/* Logo & Brand */}
        <button
          onClick={() => handleSelectTab('home')}
          className="flex items-center gap-3 group cursor-pointer text-left"
        >
          <div className="transform group-hover:rotate-[-6deg] transition-transform duration-200">
            <RedFlagIcon size={34} />
          </div>
          <div className="flex flex-col">
            <span className="text-2xl font-black tracking-tight text-slate-900 leading-none">
              Red<span className="text-[#D10000]">Flag</span>
            </span>
            <span className="text-[10px] tracking-wider uppercase text-slate-500 font-semibold mt-0.5">
              Threat Defense Radar
            </span>
          </div>
        </button>

        {/* Center Desktop Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1 xl:gap-2">
          {navItems.map((item) => {
            const isActive = currentTab === item.key;
            return (
              <button
                key={item.key}
                onClick={() => handleSelectTab(item.key)}
                className={`text-xs xl:text-sm font-semibold transition-all cursor-pointer flex items-center gap-1.5 px-3 py-2 rounded-xl ${
                  isActive
                    ? 'text-[#D10000] font-black bg-white shadow-2xs border border-[#BBD5DA]/60'
                    : 'text-slate-700 hover:text-[#D10000] hover:bg-white/50'
                }`}
              >
                <span className={isActive ? 'text-[#D10000]' : 'text-slate-500'}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Right Section: Status Indicator & Analyse CTA Button */}
        <div className="hidden sm:flex items-center gap-3">
          {/* Health Pill */}
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-[#BBD5DA] bg-white text-xs font-semibold text-slate-700 shadow-2xs">
            <span
              className={`h-2 w-2 rounded-full ${
                isBackendOnline
                  ? 'bg-emerald-500 animate-pulse'
                  : 'bg-amber-500'
              }`}
            />
            <span className="text-[11px] font-bold">
              {isBackendOnline ? 'Radar Online' : 'Connecting'}
            </span>
          </div>

          <button
            onClick={() => handleSelectTab('analyse')}
            className="btn-redflag-glow px-5 py-2.5 rounded-full text-xs sm:text-sm font-bold tracking-wide flex items-center gap-2 cursor-pointer shadow-md"
          >
            <ShieldAlert size={16} />
            <span>Analyse Now</span>
          </button>
        </div>

        {/* Mobile Hamburger Toggle */}
        <div className="flex lg:hidden items-center gap-2">
          <button
            onClick={() => handleSelectTab('analyse')}
            className="btn-redflag-glow sm:hidden px-3.5 py-1.5 rounded-full text-xs font-bold"
          >
            Analyse
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-xl border border-[#BBD5DA] text-slate-700 hover:bg-white cursor-pointer"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Dropdown */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-t border-[#BBD5DA] bg-white px-4 py-4 space-y-2 shadow-lg animate-in slide-in-from-top duration-200">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-100">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-700">
              <span
                className={`h-2 w-2 rounded-full ${
                  isBackendOnline ? 'bg-emerald-500' : 'bg-amber-500'
                }`}
              />
              <span>Engine Status: {isBackendOnline ? 'Operational' : 'Offline'}</span>
            </div>
          </div>
          {navItems.map((item) => {
            const isActive = currentTab === item.key;
            return (
              <button
                key={item.key}
                onClick={() => handleSelectTab(item.key)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-semibold transition-colors text-left cursor-pointer ${
                  isActive
                    ? 'bg-red-50 text-[#D10000] font-black border border-red-200'
                    : 'text-slate-700 hover:bg-[#F5F5F5]'
                }`}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </header>
  );
};
