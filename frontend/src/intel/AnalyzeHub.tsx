import { useRef, useState } from 'react';
import type { AnalysisResult } from './types';
import { analyzeImage, analyzeQr, analyzeText, analyzeUrl } from './api';
import { Banner, Btn, Chip, Panel, Spinner } from './ui';

type Mode = 'message' | 'url' | 'screenshot' | 'qr';

const MODES: { key: Mode; title: string; blurb: string; icon: string }[] = [
  { key: 'message', title: 'Message', blurb: 'SMS, WhatsApp or email text — Tamil, English or Tanglish.', icon: 'chat' },
  { key: 'url', title: 'Link', blurb: 'Check a URL before you open it.', icon: 'link' },
  { key: 'screenshot', title: 'Screenshot', blurb: 'Upload an image; OCR extracts the text you can edit.', icon: 'image' },
  { key: 'qr', title: 'QR code', blurb: 'Decode the destination locally before anything opens.', icon: 'qr' },
];

const SAMPLES: { label: string; mode: Mode; text: string; sender?: string }[] = [
  {
    label: 'Tanglish KYC freeze', mode: 'message', sender: '+919123456780',
    text: 'Dear SBI user, unga account KYC kaalavadhi mudinjiduchu. Udane '
      + 'http://sbi-kyc-verify.xyz/login la update pannunga illana account block aagidum. Call 9123456780.',
  },
  {
    label: 'Tamil electricity cut', mode: 'message', sender: 'TN-TNEB',
    text: 'உங்கள் மின்சார இணைப்பு இன்று இரவு நிறுத்தப்படும். Rs.1,980 கட்டணத்தை '
      + 'http://tneb-billpay.online/now இல் செலுத்தவும். அதிகாரி 9994561230.',
  },
  {
    label: 'English courier duty', mode: 'message', sender: 'BD-ALERT',
    text: 'Blue Dart: your parcel is on hold because the address is incomplete. Pay customs duty of '
      + 'Rs.850 at http://bluedart-clearance.site/pay or it will be returned. UPI refund.help@ybl',
  },
  {
    label: 'Legitimate bank SMS', mode: 'message', sender: 'AD-SBIBNK',
    text: 'Rs.2,340.00 debited from A/c XX4521 on 14-02-26 to VPA grocery@okicici. '
      + 'Not you? Call 18001234. Do not share your OTP with anyone.',
  },
];

function Icon({ name, className = 'h-6 w-6' }: { name: string; className?: string }) {
  const paths: Record<string, string> = {
    chat: 'M8 10h8M8 14h5M21 12a8 8 0 1 1-3.1-6.3L21 5l-1 4',
    link: 'M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.8 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7',
    image: 'M3 5h18v14H3zM3 16l5-5 4 4 3-3 6 6',
    qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM14 18h2v2h-2zM18 18h2v2h-2z',
  };
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}

export function AnalyzeHub({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [mode, setMode] = useState<Mode>('message');
  const [text, setText] = useState('');
  const [sender, setSender] = useState('');
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingOcr, setPendingOcr] = useState<{ file: File; text: string; conf: number; reason?: string | null } | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function run(fn: () => Promise<AnalysisResult>) {
    setBusy(true);
    setError(null);
    try {
      const r = await fn();
      if (r.needs_input) {
        setError(r.message || 'Nothing could be extracted from that image.');
        return;
      }
      onResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed.');
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
      const res = await fetch('/api/analyze/image', (() => {
        const fd = new FormData();
        fd.append('file', file);
        return { method: 'POST', body: fd };
      })());
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Upload failed.');
      const ocrText = data.ocr?.text ?? '';
      setPendingOcr({
        file, text: ocrText, conf: data.ocr?.mean_confidence ?? 0,
        reason: data.ocr?.reason,
      });
      if (!ocrText) setError(data.message || data.ocr?.reason || 'No text found in this image.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      {/* ------- Four first-class input cards ------- */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {MODES.map((mdef) => {
          const active = mode === mdef.key;
          return (
            <button key={mdef.key} onClick={() => { setMode(mdef.key); setError(null); setPendingOcr(null); setPreview(null); }}
              className={`rounded-xl border p-4 text-left transition ${active
                ? 'border-red-600 bg-red-950/40 ring-1 ring-red-600/50'
                : 'border-slate-700/60 bg-slate-900/50 hover:border-slate-500'}`}>
              <span className={active ? 'text-red-400' : 'text-slate-400'}><Icon name={mdef.icon} /></span>
              <h3 className="mt-3 text-sm font-bold text-slate-100">{mdef.title}</h3>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{mdef.blurb}</p>
            </button>
          );
        })}
      </div>

      <Panel title={`Analyze: ${MODES.find((x) => x.key === mode)!.title}`}
        subtitle="One pipeline. Every input type produces the same evidence-backed result.">
        {mode === 'message' && (
          <div className="space-y-3">
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows={6}
              placeholder="Paste the SMS or WhatsApp message here — Tamil, English or Tanglish…"
              className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-red-600 focus:outline-none" />
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <input value={sender} onChange={(e) => setSender(e.target.value)}
                placeholder="Sender ID or number (optional) e.g. VM-SBIINB"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-red-600 focus:outline-none" />
              <Btn disabled={busy || !text.trim()} onClick={() => run(() => analyzeText(text, sender))}>
                Analyze message
              </Btn>
            </div>
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-600">Demo samples</span>
              {SAMPLES.map((s) => (
                <button key={s.label} onClick={() => { setText(s.text); setSender(s.sender || ''); }}
                  className="rounded-md border border-slate-700 px-2 py-1 text-[11px] text-slate-300 hover:border-red-600 hover:text-red-300">
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {mode === 'url' && (
          <div className="space-y-3">
            <input value={url} onChange={(e) => setUrl(e.target.value)}
              placeholder="http://sbi-kyc-update-portal.xyz/login"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-red-600 focus:outline-none" />
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3}
              placeholder="Optional: paste the message the link arrived in, for fuller context…"
              className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-red-600 focus:outline-none" />
            <Btn disabled={busy || !url.trim()} onClick={() => run(() => analyzeUrl(url, text))}>
              Analyze link
            </Btn>
            <p className="text-[11px] text-slate-500">
              RedFlag inspects structure, homoglyphs, brand similarity and redirects. HTTPS alone is
              never treated as proof of legitimacy.
            </p>
          </div>
        )}

        {(mode === 'screenshot' || mode === 'qr') && (
          <div className="space-y-4">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) onFile(f); }}
              onClick={() => fileRef.current?.click()}
              className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-700 bg-slate-950/60 px-6 py-10 text-center hover:border-red-600">
              <Icon name={mode === 'qr' ? 'qr' : 'image'} className="h-8 w-8 text-slate-500" />
              <p className="mt-3 text-sm text-slate-300">
                Drop a {mode === 'qr' ? 'QR code image' : 'screenshot'} here, or click to choose
              </p>
              <p className="mt-1 text-[11px] text-slate-600">PNG, JPEG, WebP or BMP · max 8 MB</p>
              <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp,image/bmp"
                className="hidden"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); }} />
            </div>

            {preview && (
              <img src={preview} alt="Uploaded evidence preview"
                className="max-h-56 rounded-lg border border-slate-700 object-contain" />
            )}

            {mode === 'qr' && (
              <p className="text-[11px] text-slate-500">
                The destination is decoded on the server and shown to you before anything is opened.
                RedFlag never follows a QR target automatically.
              </p>
            )}

            {pendingOcr && (
              <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h4 className="text-sm font-semibold text-slate-100">Extracted text — edit before analyzing</h4>
                  <Chip tone={pendingOcr.conf >= 60 ? 'emerald' : 'amber'}>
                    OCR confidence {pendingOcr.conf}%
                  </Chip>
                </div>
                <textarea value={pendingOcr.text} rows={6}
                  onChange={(e) => setPendingOcr({ ...pendingOcr, text: e.target.value })}
                  className="mt-3 w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-red-600 focus:outline-none" />
                <p className="mt-2 text-[11px] text-amber-300/80">
                  OCR may be wrong. Nothing is invented to fill gaps — correct anything that looks off.
                </p>
                <div className="mt-3">
                  <Btn disabled={busy || !pendingOcr.text.trim()}
                    onClick={() => run(() => analyzeImage(pendingOcr.file, pendingOcr.text))}>
                    Analyze extracted text
                  </Btn>
                </div>
              </div>
            )}
          </div>
        )}

        {busy && <div className="mt-4"><Spinner /></div>}
        {error && <div className="mt-4"><Banner tone="error">{error}</Banner></div>}
      </Panel>
    </div>
  );
}
