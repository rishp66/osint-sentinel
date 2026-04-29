import { motion } from 'framer-motion';

const PINGS = [
  { x: '22%', y: '34%', delay: '0.0s',  tone: 'purple', label: 'IPv4' },
  { x: '70%', y: '24%', delay: '1.4s',  tone: 'amber',  label: 'CVE'  },
  { x: '78%', y: '60%', delay: '0.7s',  tone: 'cyan',   label: 'DNS'  },
  { x: '32%', y: '74%', delay: '2.1s',  tone: 'purple', label: 'URL'  },
  { x: '58%', y: '46%', delay: '1.8s',  tone: 'cyan',   label: 'IOC'  },
  { x: '46%', y: '18%', delay: '0.4s',  tone: 'purple', label: 'ASN'  },
];

const TONE = {
  purple: 'text-sentinel-purple-light',
  amber:  'text-sentinel-amber',
  cyan:   'text-sentinel-cyan',
};

// Full-circle radar: 8 concentric purple rings + thin rotating sweep line + IOC pings.
export default function RadarVisual() {
  const rings = Array.from({ length: 8 });

  return (
    <div
      className="relative aspect-square w-full max-w-[520px] mx-auto select-none"
      aria-hidden="true"
    >
      {/* Decorative outer frame */}
      <div className="absolute -inset-3 rounded-full border border-white/[0.04]" />

      {/* 8 concentric rings — outermost faintest, innermost brightest */}
      {rings.map((_, i) => {
        const size = ((i + 1) / 8) * 100;
        return (
          <motion.div
            key={i}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: i * 0.08, duration: 0.3 }}
            className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full"
            style={{
              width:  `${size}%`,
              height: `${size}%`,
              border: `1px solid rgba(139, 92, 246, ${0.06 + (8 - i) * 0.028})`,
            }}
          />
        );
      })}

      {/* Crosshair axes */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="absolute h-px w-full bg-gradient-to-r from-transparent via-white/[0.06] to-transparent" />
        <div className="absolute w-px h-full bg-gradient-to-b from-transparent via-white/[0.06] to-transparent" />
      </div>

      {/* Rotating sweep line — pivots from the radar center outward */}
      <div
        className="absolute right-1/2 top-1/2 h-[3px] w-1/2 z-30 flex items-center overflow-hidden bg-transparent"
        style={{
          transformOrigin: 'right center',
          animation: 'radarSpin 6s linear infinite',
        }}
      >
        <div
          className="h-[1.5px] w-full"
          style={{
            background: 'linear-gradient(to right, transparent 0%, rgba(167,139,250,0) 8%, rgba(167,139,250,0.7) 88%, rgba(216,180,254,1) 100%)',
            boxShadow: '0 0 10px rgba(167,139,250,0.55)',
          }}
        />
      </div>

      {/* Ambient glow behind the sweep — gives the rotating line a lit-cone feel */}
      <div
        className="absolute right-1/2 top-1/2 h-[40px] w-1/2 z-20 pointer-events-none"
        style={{
          transformOrigin: 'right center',
          animation: 'radarSpin 6s linear infinite',
          background: 'linear-gradient(to right, transparent 0%, rgba(139,92,246,0) 30%, rgba(139,92,246,0.12) 100%)',
          filter: 'blur(6px)',
        }}
      />

      {/* Center dot — soft pulse */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-40">
        <div
          className="w-3 h-3 rounded-full bg-sentinel-purple animate-[softPulse_2.6s_ease-in-out_infinite]"
          style={{ boxShadow: '0 0 22px rgba(139,92,246,0.9)' }}
        />
      </div>

      {/* IOC ping markers */}
      {PINGS.map((p, i) => (
        <div key={i} className="absolute z-50" style={{ left: p.x, top: p.y }}>
          <div
            className={`radar-ping ${TONE[p.tone]}`}
            style={{ background: 'currentColor', animationDelay: p.delay }}
          />
          {/* Sonar ring */}
          <div
            className={`absolute rounded-full animate-ping ${TONE[p.tone]}`}
            style={{
              width: 20, height: 20,
              top: -7, left: -7,
              border: '1.5px solid currentColor',
              background: 'transparent',
              animationDuration: `${1.8 + i * 0.25}s`,
              animationDelay: p.delay,
              opacity: 0.5,
            }}
          />
          <span className="absolute left-3.5 -top-1 font-mono text-[9px] uppercase tracking-[0.2em] text-white/45 whitespace-nowrap">
            {p.label}
          </span>
        </div>
      ))}

      {/* Cardinal labels */}
      <span className="absolute left-1/2 -translate-x-1/2 top-1 text-[10px] font-mono text-white/30 tracking-[0.3em]">N</span>
      <span className="absolute left-1/2 -translate-x-1/2 bottom-1 text-[10px] font-mono text-white/30 tracking-[0.3em]">S</span>
      <span className="absolute top-1/2 -translate-y-1/2 left-1 text-[10px] font-mono text-white/30 tracking-[0.3em]">W</span>
      <span className="absolute top-1/2 -translate-y-1/2 right-1 text-[10px] font-mono text-white/30 tracking-[0.3em]">E</span>

      {/* Corner readouts — typographic SOC flourish */}
      <div className="absolute bottom-3 left-3 font-mono text-[10px] text-white/35 leading-tight">
        <div>LAT  37.7749° N</div>
        <div>LON 122.4194° W</div>
      </div>
      <div className="absolute bottom-3 right-3 font-mono text-[10px] text-white/35 leading-tight text-right">
        <div>SCAN  ACTIVE</div>
        <div>RANGE  GLOBAL</div>
      </div>
    </div>
  );
}
