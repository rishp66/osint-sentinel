import { useRef } from 'react';
import Hero from '../components/Hero';
import LandingSections from '../components/LandingSections';

// Corner bracket — hero-ascii-one aesthetic
function CornerBracket({ position }) {
  const classes = {
    'top-left':     'top-0 left-0 border-t-2 border-l-2',
    'top-right':    'top-0 right-0 border-t-2 border-r-2',
    'bottom-left':  'bottom-0 left-0 border-b-2 border-l-2',
    'bottom-right': 'bottom-0 right-0 border-b-2 border-r-2',
  }[position];

  return (
    <div
      className={`absolute w-6 h-6 sm:w-8 sm:h-8 border-sentinel-purple/25 z-20 pointer-events-none ${classes}`}
      aria-hidden="true"
    />
  );
}

export default function Landing({ health }) {
  const exampleRef = useRef(null);

  const handleExampleCta = () => {
    exampleRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="relative">
      {/* Corner frames around the whole landing */}
      <CornerBracket position="top-left" />
      <CornerBracket position="top-right" />

      {/* First viewport: top bar + hero fill exactly one screen below the fixed navbar */}
      <div className="flex flex-col min-h-[calc(100svh-5rem)]">
        {/* Technical top bar */}
        <div className="border-b border-white/[0.05] bg-black/20 backdrop-blur-sm">
          <div className="flex items-center justify-between px-4 sm:px-6 lg:px-10 py-2">
            <div className="flex items-center gap-3 sm:gap-5 font-mono text-[9px] sm:text-[10px] uppercase tracking-[0.18em] text-white/35">
              <span className="text-sentinel-purple-light/60">// SENTINEL.NODE</span>
              <span className="hidden sm:inline text-white/15">·</span>
              <span className="hidden sm:inline">14 SOURCES</span>
              <span className="hidden sm:inline text-white/15">·</span>
              <span className="hidden md:inline">PARALLEL SCAN</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-[0.18em]">
              <span
                className={`flex items-center gap-1.5 ${health?.status === 'ok' ? 'text-emerald-400/70' : 'text-white/30'}`}
              >
                <span
                  className={`w-1 h-1 rounded-full ${health?.status === 'ok' ? 'bg-emerald-400 animate-pulse' : 'bg-white/30'}`}
                />
                {health?.status === 'ok' ? 'API.OK' : health ? 'API.OFFLINE' : 'CONNECTING'}
              </span>
            </div>
          </div>
        </div>

        <Hero onExampleCta={handleExampleCta} health={health} />
      </div>

      <LandingSections ref={exampleRef} />
    </div>
  );
}
