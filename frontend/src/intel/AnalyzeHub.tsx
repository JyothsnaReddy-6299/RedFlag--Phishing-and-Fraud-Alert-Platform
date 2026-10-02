import { useRef, useState, useEffect } from 'react';
import type { AnalysisResult } from './types';
import { analyzeImage, analyzeQr, analyzeText, analyzeUrl } from './api';
import { Banner, Chip, Spinner } from './ui';
import { Link2, MessageSquare, Image, QrCode, Sparkles, ArrowRight, Upload } from 'lucide-react';

export type AnalyzeMode = 'url' | 'message' | 'screenshot' | 'qr';

interface AnalyzeHubProps {
  initialMode?: AnalyzeMode;
  initialValue?: string;
  onResult: (r: AnalysisResult) => void;
}

const MODES: { key: AnalyzeMode; title: string; blurb: string; icon: typeof Link2 }[] = [
  { key: 'url', title: 'Malicious Link', blurb: 'URLs, typosquats, & phishing domains', icon: Link2 },
  { key: 'message', title: 'SMS / Scam Text', blurb: 'KYC traps, electricity cuts & urgency bait', icon: MessageSquare },
  { key: 'screenshot', title: 'Screenshot OCR', blurb: 'Upload fake portals, SMS or chat images', icon: Image },
  { key: 'qr', title: 'QR Code Scanner', blurb: 'Safely inspect destination & UPI QR targets', icon: QrCode },
];

const SAMPLES: { label: string; mode: AnalyzeMode; text: string; sender?: string; url?: string }[] = [
  {
    label: 'Tanglish KYC freeze', mode: 'message', sender: '+919123456780',
    text: 'Dear SBI user, unga account KYC kaalavadhi mudinjiduchu. Udane http://sbi-kyc-verify.xyz/login la update pannunga illana account block aagidum. Call 9123456780.',
  },
  {
    label: 'Tamil electricity cut', mode: 'message', sender: 'TN-TNEB',
    text: 'உங்கள் மின்சார இணைப்பு இன்று இரவு நிறுத்தப்படும். Rs.1,980 கட்டணத்தை http://tneb-billpay.online/now இல் செலுத்தவும். அதிகாரி 9994561230.',
  },
  {
    label: 'English courier duty', mode: 'message', sender: 'BD-ALERT',
    text: 'Blue Dart: your parcel is on hold because the address is incomplete. Pay customs duty of Rs.850 at http://bluedart-clearance.site/pay or it will be returned. UPI refund.help@ybl',
  },
  {
    label: 'Legitimate bank SMS', mode: 'message', sender: 'AD-SBIBNK',
    text: 'Rs.2,340.00 debited from A/c XX4521 on 14-02-26 to VPA grocery@okicici. Not you? Call 18001234. Do not share your OTP with anyone.',
  },
  {
    label: 'Typosquat Bank URL', mode: 'url', url: 'http://sbi-kyc-update-portal.xyz/login',
    text: '',
  },
];

export function AnalyzeHub({ initialMode = 'url', initialValue = '', onResult }: AnalyzeHubProps) {
  const [mode, setMode] = useState<AnalyzeMode>(initialMode);
  const [text, setText] = useState(initialMode === 'message' ? initialValue : '');
  const [sender, setSender] = useState('');
  const [url, setUrl] = useState(initialMode === 'url' ? initialValue : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingOcr, setPendingOcr] = useState<{ file: File; text: string; conf: number; reason?: string | null } | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (initialMode) setMode(initialMode);
    if (initialValue) {
      if (initialMode === 'url') setUrl(initialValue);
      else if (initialMode === 'message') setText(initialValue);
    }
  }, [initialMode, initialValue]);

  async function run(fn: () => Promise<AnalysisResult>) {
    setBusy(true);
    setError(null);
    try {
      const r = await fn();
      if (r.needs_input) {
        setError(r.message || 'Nothing could be extracted from that input.');
        return;
      }
      onResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis request failed.');
    } finally {
      setBusy(false);
    }
  }

  async function onFile(file: File) {
    setError(null);
    setPreview(URL.createObjectURL(file));
    if (mode === 'qr') {
      await run(() => analyzeQr(file));
      return;
    }
    // Screenshot: OCR first so the user can correct the text before analysis.
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/analyze/image', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Image OCR processing failed.');
      const ocrText = data.ocr?.text ?? '';
      setPendingOcr({
        file,
        text: ocrText,
        conf: data.ocr?.mean_confidence ?? 0,
        reason: data.ocr?.reason,
      });
      if (!ocrText) setError(data.message || data.ocr?.reason || 'No legible text found in this image.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
    }
  }

  const handleSelectSample = (s: typeof SAMPLES[0]) => {
    setMode(s.mode);
    if (s.mode === 'message') {
      setText(s.text);
      setSender(s.sender || '');
    } else if (s.mode === 'url') {
      setUrl(s.url || '');
    }
  };

  return (
    <div className="space-y-8">
      {/* Selector Header */}
      <div className="text-center max-w-2xl mx-auto">
        <h1 className="text-3xl sm:text-4xl font-black text-slate-900 tracking-tight mb-3">
          What would you like to analyse?
        </h1>
        <p className="text-slate-600 text-sm sm:text-base">
          Select an inspection mode below to run real-time heuristics against deceptive cyber threats.
        </p>
      </div>

      {/* 4 Mode Option Cards (Render Link Style) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 p-2 bg-[#DFF1F1]/60 rounded-3xl border border-[#BBD5DA]">
        {MODES.map((mdef) => {
          const active = mode === mdef.key;
          const IconComponent = mdef.icon;
          return (
            <button
              key={mdef.key}
              type="button"
              onClick={() => {
                setMode(mdef.key);
                setError(null);
                setPendingOcr(null);
                setPreview(null);
              }}
              className={`flex items-center gap-3.5 p-4 rounded-2xl text-left transition-all cursor-pointer ${
                active
                  ? 'bg-white shadow-md border-2 border-[#D10000] text-slate-900'
                  : 'hover:bg-white/60 text-slate-600 border border-transparent'
              }`}
            >
              <div
                className={`p-3 rounded-xl shrink-0 transition-colors ${
                  active
                    ? 'bg-[#D10000] text-white shadow-sm'
                    : 'bg-white text-slate-600 border border-[#BBD5DA]'
                }`}
              >
                <IconComponent size={22} />
              </div>
              <div className="min-w-0">
                <span className="block text-sm sm:text-base font-black leading-tight text-slate-900">
                  {mdef.title}
                </span>
                <span className="text-xs text-slate-500 mt-0.5 line-clamp-1 block">
                  {mdef.blurb}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Main Analysis Card */}
      <div className="bg-white rounded-3xl border border-[#BBD5DA] p-6 sm:p-10 shadow-sm">
        {mode === 'url' && (
          <div className="space-y-6">
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-2">
                Target URL to Inspect
              </label>
              <div className="relative">
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="e.g. http://sbi-kyc-update-portal.xyz/login"
                  className="w-full rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5]/40 px-4 py-3.5 font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:bg-white focus:border-[#D10000] focus:outline-none transition-all"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-2">
                Optional Context (e.g. SMS / Message where you received the link)
              </label>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={3}
                placeholder="Paste the accompanying message or sender info for richer correlation…"
                className="w-full resize-y rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5]/40 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:bg-white focus:border-[#D10000] focus:outline-none transition-all"
              />
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-2">
              <button
                type="button"
                disabled={busy || !url.trim()}
                onClick={() => run(() => analyzeUrl(url, text))}
                className="btn-redflag-glow px-8 py-3.5 rounded-full text-base font-bold tracking-wide flex items-center justify-center gap-2 cursor-pointer shadow-md disabled:opacity-50 disabled:pointer-events-none"
              >
                <span>Analyse Link</span>
                <ArrowRight size={18} />
              </button>

              <div className="text-xs text-slate-500 leading-relaxed max-w-md">
                Evaluates Shannon entropy, Levenshtein brand proximity, punycode spoofing, and Reserve Bank of India whitelists.
              </div>
            </div>
          </div>
        )}

        {mode === 'message' && (
          <div className="space-y-6">
            <div>
              <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-2">
                Message Content (Tamil, English or Tanglish)
              </label>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={6}
                placeholder="Paste the SMS, WhatsApp or email message here… e.g. 'Dear SBI user, unga account KYC freeze aagidum...'"
                className="w-full resize-y rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5]/40 px-4 py-3.5 text-sm text-slate-900 placeholder:text-slate-400 focus:bg-white focus:border-[#D10000] focus:outline-none transition-all"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-black uppercase tracking-wider text-slate-700 mb-2">
                  Sender Header / Number (Optional)
                </label>
                <input
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  placeholder="e.g. AD-SBIBNK or +919123456780"
                  className="w-full rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5]/40 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:bg-white focus:border-[#D10000] focus:outline-none transition-all"
                />
              </div>

              <div className="flex items-end">
                <button
                  type="button"
                  disabled={busy || !text.trim()}
                  onClick={() => run(() => analyzeText(text, sender))}
                  className="btn-redflag-glow w-full sm:w-auto px-8 py-3.5 rounded-full text-base font-bold tracking-wide flex items-center justify-center gap-2 cursor-pointer shadow-md disabled:opacity-50 disabled:pointer-events-none"
                >
                  <span>Analyse Message</span>
                  <ArrowRight size={18} />
                </button>
              </div>
            </div>
          </div>
        )}

        {mode === 'screenshot' && (
          <div className="space-y-6">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const f = e.dataTransfer.files?.[0];
                if (f) onFile(f);
              }}
              onClick={() => fileRef.current?.click()}
              className="flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-[#BBD5DA] bg-[#DFF1F1]/30 p-8 sm:p-12 text-center hover:border-[#D10000] hover:bg-[#DFF1F1]/50 transition-all group"
            >
              <div className="w-14 h-14 rounded-2xl bg-white border border-[#BBD5DA] flex items-center justify-center text-slate-600 group-hover:text-[#D10000] group-hover:scale-105 transition-all shadow-xs mb-3">
                <Upload size={26} />
              </div>
              <p className="text-base font-bold text-slate-800">
                Drop your screenshot here, or <span className="text-[#D10000] underline">browse</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">PNG, JPEG, WebP or BMP · up to 8 MB</p>
              <input
                ref={fileRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/bmp"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) onFile(f);
                }}
              />
            </div>

            {preview && (
              <div className="flex flex-col items-center gap-2 p-4 bg-[#F5F5F5] rounded-2xl border border-[#BBD5DA]">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Uploaded Screenshot</span>
                <img src={preview} alt="Uploaded evidence" className="max-h-64 rounded-xl border border-[#BBD5DA] object-contain shadow-xs" />
              </div>
            )}

            {pendingOcr && (
              <div className="rounded-2xl border border-[#BBD5DA] bg-[#F5F5F5]/60 p-6 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h4 className="text-sm font-black text-slate-900 uppercase tracking-wide">
                    Extracted Text (Verify & Edit Before Scan)
                  </h4>
                  <Chip tone={pendingOcr.conf >= 60 ? 'emerald' : 'amber'}>
                    OCR confidence {pendingOcr.conf}%
                  </Chip>
                </div>
                <textarea
                  value={pendingOcr.text}
                  rows={5}
                  onChange={(e) => setPendingOcr({ ...pendingOcr, text: e.target.value })}
                  className="w-full resize-y rounded-2xl border border-[#BBD5DA] bg-white px-4 py-3 text-sm text-slate-900 focus:border-[#D10000] focus:outline-none"
                />
                <p className="text-xs text-amber-800 bg-amber-50 p-2.5 rounded-xl border border-amber-200">
                  ⚠️ Note: Optical character recognition can introduce typos. Please edit any garbled links or phone numbers before proceeding.
                </p>
                <button
                  type="button"
                  disabled={busy || !pendingOcr.text.trim()}
                  onClick={() => run(() => analyzeImage(pendingOcr.file, pendingOcr.text))}
                  className="btn-redflag-glow px-6 py-3 rounded-full text-sm font-bold tracking-wide flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
                >
                  <span>Analyse Extracted Text</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            )}
          </div>
        )}

        {mode === 'qr' && (
          <div className="space-y-6">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const f = e.dataTransfer.files?.[0];
                if (f) onFile(f);
              }}
              onClick={() => fileRef.current?.click()}
              className="flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-[#BBD5DA] bg-[#DFF1F1]/30 p-8 sm:p-12 text-center hover:border-[#D10000] hover:bg-[#DFF1F1]/50 transition-all group"
            >
              <div className="w-14 h-14 rounded-2xl bg-white border border-[#BBD5DA] flex items-center justify-center text-slate-600 group-hover:text-[#D10000] group-hover:scale-105 transition-all shadow-xs mb-3">
                <QrCode size={26} />
              </div>
              <p className="text-base font-bold text-slate-800">
                Drop suspicious QR Code image here, or <span className="text-[#D10000] underline">browse</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">Decodes payload safely without visiting malicious hosts</p>
              <input
                ref={fileRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/bmp"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) onFile(f);
                }}
              />
            </div>

            {preview && (
              <div className="flex flex-col items-center gap-2 p-4 bg-[#F5F5F5] rounded-2xl border border-[#BBD5DA]">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Uploaded QR Image</span>
                <img src={preview} alt="QR code" className="max-h-56 rounded-xl border border-[#BBD5DA] object-contain shadow-xs" />
              </div>
            )}
          </div>
        )}

        {/* Quick Preset Samples Bar */}
        <div className="mt-8 pt-6 border-t border-[#BBD5DA]/60">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-xs font-black uppercase tracking-wider text-slate-500 flex items-center gap-1.5 mr-1">
              <Sparkles size={14} className="text-[#D10000]" />
              Quick Samples:
            </span>
            {SAMPLES.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => handleSelectSample(s)}
                className="rounded-full border border-[#BBD5DA] bg-[#F5F5F5] hover:bg-white hover:border-[#D10000] hover:text-[#D10000] px-3.5 py-1.5 text-xs font-semibold text-slate-700 transition-all cursor-pointer shadow-2xs"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* Status Indicators */}
        {busy && (
          <div className="mt-6 p-4 rounded-2xl bg-[#DFF1F1]/50 border border-[#BBD5DA] flex items-center justify-center">
            <Spinner label="Executing real-time heuristic pipeline & Shannon entropy calculation…" />
          </div>
        )}

        {error && (
          <div className="mt-6">
            <Banner tone="error">{error}</Banner>
          </div>
        )}
      </div>
    </div>
  );
}
