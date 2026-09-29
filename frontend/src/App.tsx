import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { AnalysisPortal } from './components/AnalysisPortal';
import { ThreatDatabase } from './components/ThreatDatabase';
import { Footer } from './components/Footer';
import { checkBackendHealth } from './services/api';

export function App() {
  const [currentPage, setCurrentPage] = useState<'home' | 'analyse'>('home');
  const [analysisTab, setAnalysisTab] = useState<'link' | 'sms'>('link');
  const [isBackendOnline, setIsBackendOnline] = useState(true);

  useEffect(() => {
    const verifyHealth = async () => {
      const online = await checkBackendHealth();
      setIsBackendOnline(online);
    };

    verifyHealth();
    const interval = setInterval(verifyHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleNavigate = (page: 'home' | 'analyse', tab: 'link' | 'sms' = 'link') => {
    setCurrentPage(page);
    setAnalysisTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#F5F5F5] text-slate-900 selection:bg-[#D10000] selection:text-white flex flex-col">
      {/* Top Navigation Bar */}
      <Navbar
        currentPage={currentPage}
        activeAnalysisTab={analysisTab}
        onNavigate={handleNavigate}
        isBackendOnline={isBackendOnline}
      />

      {/* Main Content Area */}
      <main className="flex-grow">
        {currentPage === 'home' ? (
          <>
            {/* Landing Hero Section matching User Reference Image 1 */}
            <Hero onAnalyseClick={() => handleNavigate('analyse', 'link')} />

            {/* Live Seed Threat Feeds */}
            <ThreatDatabase />
          </>
        ) : (
          /* Dedicated Analysis Portal Page with Link & SMS options */
          <AnalysisPortal
            activeTab={analysisTab}
            onTabChange={(tab) => setAnalysisTab(tab)}
            onBackToHome={() => handleNavigate('home')}
          />
        )}
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}

export default App;
