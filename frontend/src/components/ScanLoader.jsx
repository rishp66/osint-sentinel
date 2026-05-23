import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { ScanEye } from 'lucide-react';
import MatrixRain from './ui/MatrixRain';

const SCAN_STEPS = [
  { label: 'VirusTotal',         delay: 0,    kind: 'source' },
  { label: 'AbuseIPDB',          delay: 100,  kind: 'source' },
  { label: 'AlienVault OTX',     delay: 200,  kind: 'source' },
  { label: 'Shodan',             delay: 300,  kind: 'source' },
  { label: 'GreyNoise',          delay: 400,  kind: 'source' },
  { label: 'WHOIS',              delay: 500,  kind: 'source' },
  { label: 'RDAP',               delay: 600,  kind: 'source' },
  { label: 'urlscan.io',         delay: 700,  kind: 'source' },
  { label: 'IPinfo',             delay: 800,  kind: 'source' },
  { label: 'ThreatFox',          delay: 900,  kind: 'source' },
  { label: 'Pulsedive',          delay: 1000, kind: 'source' },
  { label: 'DNS resolution',     delay: 1100, kind: 'source' },
  { label: 'Hybrid Analysis',    delay: 1200, kind: 'source' },
  { label: 'MalwareBazaar',      delay: 1300, kind: 'source' },
  { label: 'Synthesize brief',   delay: 1400, kind: 'synthesis' },
];

// Asymptotic curve: fast start, decelerates towards 95%, never overshoots.
function _calcProgress(elapsedMs) {
  return 95 * (1 - Math.exp(-elapsedMs / 10000));
}

export default function ScanLoader() {
  const [activeSteps, setActiveSteps] = useState(new Set());
  const [progress, setProgress] = useState(0);
  const startRef = useRef(Date.now());

  useEffect(() => {
    const timers = SCAN_STEPS.map(({ delay }, i) =>
      setTimeout(() => setActiveSteps(prev => new Set([...prev, i])), delay)
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      setProgress(_calcProgress(Date.now() - startRef.current));
    }, 150);
    return () => clearInterval(id);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="relative min-h-[78vh] w-full flex items-center justify-center overflow-hidden hairline rounded-2xl"
      style={{
        background: 'linear-gradient(180deg, rgba(255,255,255,0.012), rgba(255,255,255,0.002))',
        boxShadow: '0 0 60px rgba(139,92,246,0.10) inset',
      }}
    >
      {/* Matrix-rain background — softer fade so the foreground reads cleanly */}
      <MatrixRain color="#8b5cf6" fontSize={18} fadeOpacity={0.08} speed={1.1} />

      {/* Vignette */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: 'radial-gradient(ellipse at center, rgba(0,0,0,0.45) 0%, rgba(0,0,0,0.92) 75%)' }}
      />

      {/* Foreground content — editorial column, ~580px max */}
      <div className="relative z-10 max-w-xl w-full mx-auto px-6 sm:px-8 py-10">
        {/* Radar icon with three concentric pings */}
        <div className="relative w-24 h-24 mx-auto mb-7">
          <div className="absolute inset-0 rounded-full border border-sentinel-purple/40 animate-ping" style={{ animationDuration: '1.5s' }} />
          <div className="absolute inset-3 rounded-full border border-sentinel-purple-light/25 animate-ping" style={{ animationDuration: '1.5s', animationDelay: '0.3s' }} />
          <div className="absolute inset-6 rounded-full border border-sentinel-purple/20 animate-ping" style={{ animationDuration: '1.5s', animationDelay: '0.6s' }} />
          <div className="absolute inset-0 flex items-center justify-center">
            <div
              className="p-3 rounded-full border border-sentinel-purple/50"
              style={{
                background: 'rgba(8,8,11,0.85)',
                boxShadow: '0 0 36px rgba(139,92,246,0.5)',
              }}
            >
              <ScanEye className="w-7 h-7 text-sentinel-purple-light" strokeWidth={1.75} />
            </div>
          </div>
        </div>

        {/* Headline — same display lockup as the rest of the app */}
        <h2
          className="display-tight text-center text-white font-bold leading-tight matrix-title-glow"
          style={{ fontSize: 'clamp(28px, 4vw, 40px)', letterSpacing: '-0.03em' }}
        >
          Querying the field<span className="serif-italic font-normal text-white/85 matrix-caret"> in parallel</span>
        </h2>
        <p className="text-center text-white/55 font-body text-sm mt-3 max-w-md mx-auto">
          Fanning out to {SCAN_STEPS.length - 1} OSINT sources, then synthesizing the findings into a single brief.
        </p>

        {/* Progress bar — minimal, monoscale label above */}
        <div className="max-w-sm mx-auto mt-8">
          <div className="flex justify-between items-center mb-2">
            <span className="eyebrow !text-[10px]">Progress</span>
            <span className="font-mono text-[11px] text-sentinel-purple-light tabular-nums">{Math.round(progress)}%</span>
          </div>
          <div className="h-1 bg-black/60 rounded-full overflow-hidden border border-white/[0.06]">
            <div
              className="h-full rounded-full transition-none"
              style={{
                width: `${progress}%`,
                background: 'linear-gradient(90deg, #8b5cf6, #a78bfa)',
                boxShadow: '0 0 12px rgba(139,92,246,0.7)',
              }}
            />
          </div>
        </div>

        {/* Source list — two columns, mono labels, pulse only on active */}
        <div className="grid grid-cols-2 gap-x-6 gap-y-2 mt-8 max-w-md mx-auto">
          {SCAN_STEPS.map(({ label, kind }, i) => {
            const active = activeSteps.has(i);
            const isSynth = kind === 'synthesis';
            return (
              <div
                key={label}
                className={`flex items-center gap-2 text-[11px] font-mono transition-all duration-300 ${
                  active
                    ? isSynth
                      ? 'text-sentinel-cyan'
                      : 'text-white/85'
                    : 'text-white/25'
                }`}
              >
                <div
                  className={`w-1.5 h-1.5 rounded-full flex-shrink-0 transition-all duration-300 ${
                    active
                      ? isSynth
                        ? 'bg-sentinel-cyan cyan-pulse'
                        : 'bg-sentinel-purple animate-pulse'
                      : 'bg-white/10'
                  }`}
                />
                {label}
              </div>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
}
