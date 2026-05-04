import React, { useState, useRef, useEffect, forwardRef, useImperativeHandle } from 'react';
import { Search, RotateCcw, Globe, Server, Link, Hash, ShieldAlert, ArrowRight } from 'lucide-react';

const EXAMPLES = [
  { label: 'google.com',     icon: Globe,       kind: 'domain' },
  { label: '8.8.8.8',        icon: Server,      kind: 'ipv4'   },
  { label: 'example.com',    icon: Link,        kind: 'domain' },
  { label: 'CVE-2024-3094',  icon: ShieldAlert, kind: 'cve'    },
];

const IPV4_RE   = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_RE   = /^[0-9a-fA-F:]+$/;
const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const HASH_RE   = /^[a-fA-F0-9]+$/;
const CVE_RE    = /^CVE-\d{4}-\d{4,7}$/;

function validateClientSide(raw) {
  const t = raw.trim();
  if (!t) return 'Enter a domain, IP, URL, file hash, or CVE.';
  if (/\s/.test(t)) return 'Target may not contain spaces.';
  if (CVE_RE.test(t)) return null;
  if (t.startsWith('http://') || t.startsWith('https://')) {
    try {
      const u = new URL(t);
      if (!u.hostname) return 'URL is missing a host.';
      return null;
    } catch {
      return 'URL is malformed.';
    }
  }
  if (IPV4_RE.test(t)) return null;
  if (t.includes(':') && IPV6_RE.test(t)) return null;
  if (HASH_RE.test(t)) {
    if ([32, 40, 64].includes(t.length)) return null;
    return `Hex string is ${t.length} chars — expected 32, 40, or 64.`;
  }
  if (/^[\d.]+$/.test(t)) return 'Numeric input is not a valid IP, domain, or hash.';
  if (t.length < 4) return 'Target is too short to be a valid domain or IP.';
  if (!t.includes('.')) return 'Domain must contain at least one dot (e.g. example.com).';
  if (!DOMAIN_RE.test(t)) return 'That does not look like a valid domain, IP, URL, hash, or CVE.';
  return null;
}

const SearchBar = forwardRef(function SearchBar(
  { onScan, loading, hasResults, onNewScan, compact = false },
  externalRef,
) {
  const [value, setValue] = useState('');
  const [clientError, setClientError] = useState(null);
  const inputRef = useRef(null);

  // Expose .focus() to parent — used by hero "Scan a target" CTA + global ⌘K
  useImperativeHandle(externalRef, () => ({
    focus: () => inputRef.current?.focus({ preventScroll: false }),
  }), []);

  useEffect(() => {
    if (!loading && !hasResults && !compact) inputRef.current?.focus();
  }, [loading, hasResults, compact]);

  // Global ⌘K / Ctrl+K to focus the composer — primary entry-point shortcut
  useEffect(() => {
    if (!compact) return;
    const onKey = (e) => {
      const isCmdK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k';
      if (isCmdK) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [compact]);

  const handleChange = (e) => {
    setValue(e.target.value);
    if (clientError) setClientError(null);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (loading) return;
    const err = validateClientSide(value);
    if (err) { setClientError(err); return; }
    onScan(value.trim());
  };

  const handleExample = (target) => {
    setValue(target);
    onScan(target);
  };

  /* ─────────────────────────────────────────────────────────
     Compact (sidebar) variant — restaged as a real "scan composer"
     with eyebrow, ⌘K hint, focus glow, and grouped CTA.
     ───────────────────────────────────────────────────────── */
  if (compact) {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <label className="eyebrow text-sentinel-purple-light/75">Scan composer</label>
          <kbd className="hidden sm:inline-flex items-center gap-0.5 font-mono text-[10px] text-white/55 border border-white/[0.08] rounded px-1.5 py-0.5 bg-white/[0.02]">
            <span className="text-[11px] leading-none">⌘</span>K
          </kbd>
        </div>

        <form onSubmit={handleSubmit} className="space-y-2.5">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-sentinel-text-dim/70 pointer-events-none" strokeWidth={1.75} />
            <input
              ref={inputRef}
              type="text"
              value={value}
              onChange={handleChange}
              placeholder="domain, IP, URL, hash, CVE…"
              disabled={loading}
              spellCheck="false"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              className="composer-input w-full h-11 bg-black/40 border border-white/[0.08] rounded-lg text-white pl-9 pr-3 text-[13px] font-mono placeholder:text-white/30 focus:outline-none disabled:opacity-50 transition-shadow"
            />
          </div>

          <div className="flex gap-2">
            <button
              type="submit"
              disabled={!value.trim() || loading}
              className="btn-primary focus-ring flex-1 h-10 rounded-lg text-white text-[12px] font-display font-semibold tracking-tight2 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-1.5"
            >
              {loading ? (
                <>
                  <span className="w-1 h-1 rounded-full bg-white/80 animate-pulse" />
                  Scanning…
                </>
              ) : (
                <>
                  Scan
                  <ArrowRight className="w-3 h-3" />
                </>
              )}
            </button>
            {hasResults && (
              <button
                type="button"
                onClick={() => { onNewScan(); setValue(''); }}
                className="btn-ghost focus-ring h-10 px-3 rounded-lg text-white/65 hover:text-white cursor-pointer"
                title="New scan"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </form>

        {clientError && (
          <p className="text-red-300 font-mono text-[11px] leading-relaxed">{clientError}</p>
        )}

        {!hasResults && !loading && (
          <div className="space-y-2 pt-1">
            <span className="eyebrow !text-[10px] text-white/35">Try</span>
            <div className="flex flex-wrap gap-1.5">
              {EXAMPLES.map(({ label, icon: Icon }) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => handleExample(label)}
                  className="group flex items-center gap-1.5 px-2 py-1 bg-white/[0.02] border border-white/[0.06] rounded-md text-white/65 text-[10.5px] font-mono hover:border-sentinel-purple/40 hover:text-white hover:-translate-y-px transition-all cursor-pointer"
                >
                  <Icon className="w-2.5 h-2.5 text-sentinel-purple-light/80" strokeWidth={2} />
                  {label}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  /* ─────────────────────────────────────────────────────────
     Full-size variant — preserved (kept available for any
     future "centered hero composer" route).
     ───────────────────────────────────────────────────────── */
  return (
    <div className="w-full flex flex-col items-center">
      <form onSubmit={handleSubmit} className="w-full max-w-2xl">
        <div className="relative flex items-center justify-center group glow-search">
          <div className="glow-layer glow-layer-outer" aria-hidden />
          <div className="glow-layer glow-layer-mid" aria-hidden />
          <div className="glow-layer glow-layer-inner" aria-hidden />

          <div className="relative h-[60px] w-full flex items-center bg-[#050308] rounded-xl overflow-hidden">
            <Search className="w-5 h-5 text-sentinel-purple-light ml-5 flex-shrink-0" strokeWidth={1.75} />
            <input
              ref={inputRef}
              type="text"
              value={value}
              onChange={handleChange}
              placeholder="Enter domain, IP, or URL…"
              disabled={loading}
              className="flex-1 h-full bg-transparent border-none text-white px-4 text-base font-mono focus:outline-none placeholder:text-gray-500 disabled:opacity-50 min-w-0"
            />
            {hasResults && (
              <button
                type="button"
                onClick={() => { onNewScan(); setValue(''); }}
                className="p-2 text-sentinel-text-dim hover:text-sentinel-purple-light transition-colors cursor-pointer flex-shrink-0"
                title="New scan"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
            <button
              type="submit"
              disabled={!value.trim() || loading}
              className="btn-primary mr-2 px-5 h-[44px] rounded-lg text-white text-sm font-display font-semibold tracking-tight2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex-shrink-0"
            >
              {loading ? 'Scanning…' : 'Scan'}
            </button>
          </div>
        </div>
      </form>

      {clientError && (
        <div className="mt-3 text-center">
          <p className="text-red-300 font-mono text-xs">{clientError}</p>
        </div>
      )}

      {!hasResults && !loading && (
        <div className="flex items-center justify-center gap-3 mt-5 flex-wrap">
          <span className="eyebrow !text-[10px]">Try</span>
          {EXAMPLES.map(({ label, icon: Icon }) => (
            <button
              key={label}
              type="button"
              onClick={() => handleExample(label)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-white/[0.02] border border-white/[0.06] rounded-lg text-sentinel-text-dim text-xs font-mono hover:border-sentinel-purple/45 hover:text-sentinel-purple-light hover:-translate-y-px transition-all duration-200 cursor-pointer"
            >
              <Icon className="w-3 h-3" />{label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
});

export default SearchBar;
