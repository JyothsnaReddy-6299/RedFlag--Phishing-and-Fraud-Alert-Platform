import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { AnalysisPortal } from './components/AnalysisPortal';
import { Features } from './components/Features';
import { Footer } from './components/Footer';
import { checkBackendHealth } from './services/api';
import { IntelConsole } from './intel/IntelConsole';

export function App() {
  // The RedFlag Intelligence console is the primary experience (NextGen AI
  // Hacks 2026 contract). The original light-theme scanner is preserved and
  // reachable from the console header via "Classic scanner".
  const [shell, setShell] = useState<'intel' | 'classic'>('intel');
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

  if (shell === 'intel') {
    return <IntelConsole onExitToClassic={() => setShell('classic')} />;
  }

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
            {/* Landing Hero Section */}
            <Hero onAnalyseClick={() => handleNavigate('analyse', 'link')} />

            {/* Defense Architecture Features Cards */}
            <Features />
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

      {/* Back to the intelligence console */}
      <div className="border-t border-[#BBD5DA] bg-[#DFF1F1] px-4 py-3 text-center">
        <button
          onClick={() => setShell('intel')}
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
        >
          ← Back to RedFlag Intelligence console
        </button>
      </div>

      {/* Footer */}
      <Footer />
    </div>
  );
}

export default App;
