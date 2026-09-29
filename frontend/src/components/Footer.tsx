import { RedFlagIcon } from './RedFlagIcon';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-[#BBD5DA] bg-[#F5F5F5] py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
        
        {/* Brand */}
        <div className="flex items-center gap-3">
          <RedFlagIcon size={30} />
          <div>
            <span className="text-xl font-black text-slate-900">RedFlag</span>
            <p className="text-xs text-slate-500">
              Autonomous Real-Time Phishing Link & Scam Message Inspection Engine
            </p>
          </div>
        </div>

        {/* Copyright & Info */}
        <div className="text-xs text-slate-500 text-center md:text-right">
          <p>© {new Date().getFullYear()} RedFlag Cyber Defense Platform.</p>
          <p className="text-[11px] text-slate-400 mt-1">
            Always verify banking links and notices through official channels before entering credentials.
          </p>
        </div>

      </div>
    </footer>
  );
};
