import { useState, useEffect } from 'react';
import { Navbar, type NavTab } from './components/Navbar';
import { Hero } from './components/Hero';
import { Features } from './components/Features';
import { ThreatDatabase } from './components/ThreatDatabase';
import { Footer } from './components/Footer';
import { checkBackendHealth } from './services/api';

import { AnalyzeHub, type AnalyzeMode } from './intel/AnalyzeHub';
import { ResultView } from './intel/ResultView';
import { CampaignView } from './intel/CampaignView';
import { FeedView, ModerateView, PulseView, ReportForm } from './intel/Community';
import type { AnalysisResult } from './intel/types';

export function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('home');
  const [analyseMode, setAnalyseMode] = useState<AnalyzeMode>('url');
  const [analyseInitialValue, setAnalyseInitialValue] = useState<string>('');
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [isReporting, setIsReporting] = useState<boolean>(false);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);
  const [isBackendOnline, setIsBackendOnline] = useState<boolean>(true);

  // Periodic health check
  useEffect(() => {
    const verifyHealth = async () => {
      const online = await checkBackendHealth();
      setIsBackendOnline(online);
    };

    verifyHealth();
    const interval = setInterval(verifyHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // Handle navigation from Navbar or internal actions
  const handleNavigate = (tab: NavTab) => {
    setCurrentTab(tab);
    if (tab !== 'analyse') {
      setIsReporting(false);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Launch analyse from Hero quick-bar or CTA button
  const handleHeroAnalyse = (initialInput?: string) => {
    if (initialInput) {
      const isUrl =
        initialInput.startsWith('http://') ||
        initialInput.startsWith('https://') ||
        (initialInput.includes('.') && !initialInput.includes(' '));
      setAnalyseMode(isUrl ? 'url' : 'message');
      setAnalyseInitialValue(initialInput);
    } else {
      setAnalyseMode('url');
      setAnalyseInitialValue('');
    }
    setAnalysisResult(null);
    setIsReporting(false);
    setCurrentTab('analyse');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Switch to campaign view from an analysis result or pulse item
  const handleOpenCampaign = (campaignId: string) => {
    setSelectedCampaignId(campaignId);
    setCurrentTab('campaigns');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#F5F5F5] text-slate-900 selection:bg-[#D10000] selection:text-white flex flex-col">
      {/* Top Universal Navbar */}
      <Navbar
        currentTab={currentTab}
        onNavigate={handleNavigate}
        isBackendOnline={isBackendOnline}
      />

      {/* Main Content Area */}
      <main className="flex-grow">
        {/* ================= TAB 1: HOME ================= */}
        {currentTab === 'home' && (
          <div className="space-y-12">
            {/* Landing Hero Section */}
            <Hero onAnalyseClick={handleHeroAnalyse} />

            {/* Defense Architecture Heuristic Pillars */}
            <Features />

            {/* Live Threat Intelligence Feeds Database */}
            <ThreatDatabase />
          </div>
        )}

        {/* ================= TAB 2: ANALYSE ================= */}
        {currentTab === 'analyse' && (
          <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
            {isReporting ? (
              <ReportForm
                analysis={analysisResult}
                onDone={() => setIsReporting(false)}
              />
            ) : analysisResult ? (
              <ResultView
                result={analysisResult}
                onReport={() => setIsReporting(true)}
                onOpenCampaign={handleOpenCampaign}
                onScanAnother={() => {
                  setAnalysisResult(null);
                  setAnalyseInitialValue('');
                }}
              />
            ) : (
              <AnalyzeHub
                initialMode={analyseMode}
                initialValue={analyseInitialValue}
                onResult={(res) => {
                  setAnalysisResult(res);
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }}
              />
            )}
          </div>
        )}

        {/* ================= TAB 3: CAMPAIGNS ================= */}
        {currentTab === 'campaigns' && (
          <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
            <div className="text-center max-w-2xl mx-auto mb-8">
              <span className="text-xs font-black uppercase tracking-widest text-[#D10000] mb-2 block">
                Correlation Radar
              </span>
              <h1 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
                Threat Campaigns & Syndicated Networks
              </h1>
              <p className="mt-2 text-sm sm:text-base text-slate-600">
                Correlates shared infrastructure, phone numbers, UPI identifiers, and typosquatting domains into threat actor clusters.
              </p>
            </div>

            <CampaignView
              selectedId={selectedCampaignId}
              onSelectCampaign={(id) => setSelectedCampaignId(id)}
            />
          </div>
        )}

        {/* ================= TAB 4: COMMUNITY ================= */}
        {currentTab === 'community' && (
          <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
            <div className="text-center max-w-2xl mx-auto mb-8">
              <span className="text-xs font-black uppercase tracking-widest text-[#D10000] mb-2 block">
                Crowdsourced Protection
              </span>
              <h1 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
                Community Scam Radar & Feeds
              </h1>
              <p className="mt-2 text-sm sm:text-base text-slate-600">
                Verified citizen reports, entity search across known fraudulent handles, and crowdsourced intelligence.
              </p>
            </div>

            <FeedView />
          </div>
        )}

        {/* ================= TAB 5: THREAT PULSE ================= */}
        {currentTab === 'pulse' && (
          <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
            <div className="text-center max-w-2xl mx-auto mb-8">
              <span className="text-xs font-black uppercase tracking-widest text-[#D10000] mb-2 block">
                Telemetry & Analytics
              </span>
              <h1 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
                Threat Pulse & Real-Time Metrics
              </h1>
              <p className="mt-2 text-sm sm:text-base text-slate-600">
                Aggregated 30-day radar metrics, attack vectors breakdown, geographic distribution, and heuristic precision benchmarks.
              </p>
            </div>

            <PulseView onOpenCampaign={handleOpenCampaign} />
          </div>
        )}

        {/* ================= TAB 6: MODERATE ================= */}
        {currentTab === 'moderate' && (
          <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
            <div className="text-center max-w-2xl mx-auto mb-8">
              <span className="text-xs font-black uppercase tracking-widest text-[#D10000] mb-2 block">
                Triage & Governance
              </span>
              <h1 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight">
                Threat Moderation Queue
              </h1>
              <p className="mt-2 text-sm sm:text-base text-slate-600">
                Audit citizen submissions, merge duplicate indicators into campaign graphs, and approve verified threat intelligence.
              </p>
            </div>

            <ModerateView />
          </div>
        )}
      </main>

      {/* Universal Footer */}
      <Footer />
    </div>
  );
}

export default App;
