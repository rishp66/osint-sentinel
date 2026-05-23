import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { useScan } from '../hooks/useScan';
import SearchBar from '../components/SearchBar';
import ScanLoader from '../components/ScanLoader';
import ThreatBrief from '../components/ThreatBrief';
import SourceCard, { SOURCE_CATEGORIES, categorize } from '../components/SourceCard';
import ScanHistory from '../components/ScanHistory';
import AgentReport from '../components/AgentReport';

const SOURCE_ORDER = [
  'virustotal', 'abuseipdb', 'greynoise', 'threatfox', 'hybrid_analysis',
  'pulsedive', 'shodan', 'alienvault_otx', 'urlscan', 'malwarebazaar',
  'urlhaus', 'whois', 'dns_resolution', 'ipinfo', 'rdap', 'circl_cve',
];

function orderSources(sources) {
  const rank = new Map(SOURCE_ORDER.map((name, i) => [name, i]));
  return [...sources].sort((a, b) => {
    const ra = rank.has(a.source) ? rank.get(a.source) : SOURCE_ORDER.length;
    const rb = rank.has(b.source) ? rank.get(b.source) : SOURCE_ORDER.length;
    return ra - rb;
  });
}

const grid = {
  hidden: { opacity: 0 },
  show:   { opacity: 1, transition: { staggerChildren: 0.04, delayChildren: 0.05 } },
};

// Corner bracket decoration — hero-ascii-one aesthetic
function CornerBracket({ position }) {
  const classes = {
    'top-left':     'top-0 left-0 border-t-2 border-l-2',
    'top-right':    'top-0 right-0 border-t-2 border-r-2',
    'bottom-left':  'bottom-0 left-0 border-b-2 border-l-2',
    'bottom-right': 'bottom-0 right-0 border-b-2 border-r-2',
  }[position];

  return (
    <div
      className={`absolute w-6 h-6 sm:w-8 sm:h-8 border-sentinel-purple/25 pointer-events-none ${classes}`}
      aria-hidden="true"
    />
  );
}

// Minimal dot-bar decoration above headline
function DotRow() {
  return (
    <div className="flex items-center gap-1 mb-5 opacity-40" aria-hidden="true">
      <div className="w-6 h-px bg-white" />
      <span className="font-mono text-white text-[10px]">∞</span>
      <div className="flex-1 h-px bg-white max-w-[180px]" />
    </div>
  );
}

export default function Console({ health }) {
  const { data, loading, error, scan, reset, scanHistory, clearHistory } = useScan();
  const resultRef = useRef(null);
  const loaderRef = useRef(null);
  const searchRef = useRef(null);

  // Auto-focus the search bar when the console page loads
  useEffect(() => {
    const t = setTimeout(() => searchRef.current?.focus(), 100);
    return () => clearTimeout(t);
  }, []);

  // Scroll to the loader as soon as a scan starts
  useEffect(() => {
    if (loading && loaderRef.current) {
      requestAnimationFrame(() =>
        loaderRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
      );
    }
  }, [loading]);

  // Scroll to results when a scan finishes
  useEffect(() => {
    if (data && !loading && resultRef.current) {
      requestAnimationFrame(() =>
        resultRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
      );
    }
  }, [data, loading]);

  const buckets = data ? categorize(orderSources(data.sources)) : null;
  const categoryEntries = buckets
    ? Object.entries(SOURCE_CATEGORIES)
        .map(([key, meta]) => ({ key, meta, items: buckets[key] || [] }))
        .filter(g => g.items.length > 0)
    : [];

  const isOnline = health?.status === 'ok';
  const hasHealth = health !== null && health !== undefined;

  return (
    <div className="relative min-h-screen">
      {/* Corner brackets */}
      <CornerBracket position="top-left" />
      <CornerBracket position="top-right" />

      {/* Technical top bar */}
      <div className="border-b border-white/[0.05] bg-black/20 backdrop-blur-sm">
        <div className="flex items-center justify-between px-4 sm:px-6 lg:px-10 py-2">
          <div className="flex items-center gap-3 sm:gap-5 font-mono text-[9px] sm:text-[10px] uppercase tracking-[0.18em] text-white/35">
            <span className="text-sentinel-purple-light/60">// SCAN.COMPOSER</span>
            <span className="hidden sm:inline text-white/15">·</span>
            <span className="hidden sm:inline">NODE.ACTIVE</span>
            <span className="hidden sm:inline text-white/15">·</span>
            <span className="hidden md:inline">MULTI-AGENT</span>
          </div>
          <div className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-[0.18em]">
            {hasHealth && (
              <span className={`flex items-center gap-1.5 ${isOnline ? 'text-emerald-400/70' : 'text-red-400/70'}`}>
                <span className={`w-1 h-1 rounded-full ${isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
                {isOnline ? 'API.OK' : 'API.OFFLINE'}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Composer region ────────────────────────────── */}
      <section className="px-4 sm:px-6 lg:px-10 pt-14 sm:pt-20 pb-10 relative">
        {/* Purple ambient glow behind the composer */}
        <div
          className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[400px] pointer-events-none"
          style={{
            background: 'radial-gradient(ellipse at 50% 0%, rgba(139,92,246,0.14) 0%, transparent 70%)',
          }}
          aria-hidden="true"
        />

        <div className="relative max-w-3xl mx-auto">
          <DotRow />

          <div className="eyebrow text-sentinel-purple-light/80 mb-4">
            Scan composer
          </div>

          <h1
            className="display-tight font-bold text-white mb-4"
            style={{ fontSize: 'clamp(36px, 5.5vw, 72px)', letterSpacing: '-0.03em', lineHeight: 1.02 }}
          >
            Run a{' '}
            <span
              className="serif-italic font-normal text-white/90"
              style={{ textShadow: '0 0 32px rgba(139,92,246,0.3)' }}
            >
              scan.
            </span>
          </h1>

          <p className="text-sentinel-text-dim font-body text-base sm:text-[17px] leading-relaxed mb-8 max-w-xl">
            Drop a domain, IP, URL, file hash, or CVE — Sentinel fans out across 14 OSINT sources
            in parallel and returns a synthesized verdict in under{' '}
            <span className="font-mono text-white">~6s</span>.
          </p>

          {/* Large non-compact SearchBar — this is the main CTA */}
          <div className="w-full">
            <SearchBar
              ref={searchRef}
              onScan={scan}
              loading={loading}
              hasResults={!!data}
              onNewScan={reset}
            />
          </div>

          {/* Scan history as horizontal pill row */}
          {scanHistory?.length > 0 && (
            <div className="mt-5 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[10px] text-white/35 uppercase tracking-[0.15em]">
                Recent ▸
              </span>
              {scanHistory.slice(0, 6).map((item) => (
                <button
                  key={item.target}
                  onClick={() => scan(item.target)}
                  className="px-2.5 py-1 rounded-full border border-white/[0.08] bg-white/[0.02] font-mono text-[11px] text-white/55 hover:text-white hover:border-sentinel-purple/40 hover:bg-sentinel-purple/[0.06] transition-all duration-150 cursor-pointer"
                >
                  {item.target}
                </button>
              ))}
              <button
                onClick={clearHistory}
                className="font-mono text-[10px] text-white/25 hover:text-white/50 transition-colors ml-1 cursor-pointer"
              >
                clear
              </button>
            </div>
          )}
        </div>
      </section>

      {/* ── Error banner ───────────────────────────────── */}
      {error && !loading && !data && (
        <div className="px-4 sm:px-6 lg:px-10 pb-6">
          <div className="max-w-3xl mx-auto bg-red-950/40 border border-red-800/40 rounded-xl p-4 backdrop-blur-sm">
            <p className="text-red-300 font-mono text-sm">{error}</p>
          </div>
        </div>
      )}

      {/* ── Scan loader ────────────────────────────────── */}
      {loading && (
        <div ref={loaderRef} className="px-4 sm:px-6 lg:px-10 pb-8">
          <ScanLoader />
        </div>
      )}

      {/* ── Results ────────────────────────────────────── */}
      {data && !loading && (
        <motion.div
          ref={resultRef}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          className="px-4 sm:px-6 lg:px-10 py-10 border-t border-white/[0.05]"
        >
          {/* Results header */}
          <div className="flex items-center gap-3 mb-7 flex-wrap">
            <div className="eyebrow text-sentinel-purple-light/80">Scan complete</div>
            <span className="text-white/15 text-xs">/</span>
            <span className="font-mono text-sentinel-text-dim text-sm">target</span>
            <code
              className="font-mono text-sentinel-purple-light text-sm px-2.5 py-0.5 rounded-md border border-sentinel-purple/30"
              style={{ background: 'rgba(139,92,246,0.06)' }}
            >
              {data.target}
            </code>
            <span className="font-mono text-sentinel-text-dim text-xs ml-auto">
              {(data.scan_duration_ms / 1000).toFixed(1)}s
            </span>
          </div>

          {error && (
            <div className="w-full bg-red-950/40 border border-red-800/40 rounded-xl p-4 backdrop-blur-sm mb-6">
              <p className="text-red-300 font-mono text-sm">{error}</p>
            </div>
          )}

          {data.threat_brief && (
            <ThreatBrief brief={{
              risk_level: data.risk_level?.toLowerCase(),
              risk_score: data.risk_score,
              summary: data.threat_brief,
            }} />
          )}

          <section className="mt-12 space-y-12">
            <div className="flex items-baseline gap-3 flex-wrap">
              <h2
                className="display-tight text-white font-bold"
                style={{ fontSize: 'clamp(26px, 3vw, 34px)', letterSpacing: '-0.03em' }}
              >
                Source intelligence
              </h2>
              <span className="font-mono text-[11px] text-white/40 uppercase tracking-[0.18em]">
                {data.sources?.length ?? 0} returned · {(data.scan_duration_ms / 1000).toFixed(1)}s
              </span>
            </div>

            {categoryEntries.map(group => (
              <div key={group.key}>
                <div className="flex items-baseline gap-3 mb-5 pb-3 border-b border-white/[0.05] flex-wrap">
                  <span className="eyebrow text-sentinel-purple-light/70">{group.meta.label}</span>
                  <span className="font-mono text-[11px] text-white/35 tabular-nums">{group.items.length}</span>
                  <span className="text-white/15 text-xs">/</span>
                  <span className="font-mono text-[11px] text-white/45">{group.meta.hint}</span>
                </div>
                <motion.div
                  variants={grid}
                  initial="hidden"
                  animate="show"
                  className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"
                >
                  {group.items.map(source => (
                    <SourceCard key={source.source} source={source} />
                  ))}
                </motion.div>
              </div>
            ))}

            {buckets?.other?.length > 0 && (
              <div>
                <div className="flex items-baseline gap-3 mb-5 pb-3 border-b border-white/[0.05] flex-wrap">
                  <span className="eyebrow text-sentinel-purple-light/70">Other sources</span>
                  <span className="font-mono text-[11px] text-white/35 tabular-nums">{buckets.other.length}</span>
                </div>
                <motion.div
                  variants={grid}
                  initial="hidden"
                  animate="show"
                  className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"
                >
                  {buckets.other.map(source => (
                    <SourceCard key={source.source} source={source} />
                  ))}
                </motion.div>
              </div>
            )}
          </section>

          {data.agent_report && <AgentReport report={data.agent_report} />}
        </motion.div>
      )}

      {/* ── Technical footer bar ───────────────────────── */}
      <div className="border-t border-white/[0.05] bg-black/20 mt-8">
        <div className="flex items-center justify-between px-4 sm:px-6 lg:px-10 py-2.5">
          <div className="flex items-center gap-3 sm:gap-5 font-mono text-[9px] uppercase tracking-[0.18em] text-white/25">
            <span>// SYS.READY</span>
            <span className="hidden sm:inline text-white/10">·</span>
            <div className="hidden sm:flex gap-0.5 items-end">
              {[4, 8, 5, 10, 7, 12, 6, 9].map((h, i) => (
                <div key={i} className="w-0.5 bg-white/20 rounded-sm" style={{ height: `${h}px` }} />
              ))}
            </div>
            <span className="hidden sm:inline">V1.0</span>
          </div>
          <div className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-[0.18em] text-white/25">
            <span className="hidden sm:inline">FRAME: ∞</span>
            <div className="flex gap-1">
              <div className="w-1 h-1 bg-white/40 rounded-full animate-pulse" />
              <div className="w-1 h-1 bg-white/25 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }} />
              <div className="w-1 h-1 bg-white/15 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Bottom corner brackets */}
      <CornerBracket position="bottom-left" />
      <CornerBracket position="bottom-right" />
    </div>
  );
}
