import { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowRight, Terminal, Sparkles } from 'lucide-react';
import RadarVisual from './RadarVisual';
import LiveTicker from './LiveTicker';

function ParticleCanvas() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H, particles = [];
    let rafId;

    function resize() {
      W = canvas.width = canvas.offsetWidth;
      H = canvas.height = canvas.offsetHeight;
    }

    class Particle {
      constructor() { this.reset(); }
      reset() {
        this.x = Math.random() * W;
        this.y = Math.random() * H;
        this.vx = (Math.random() - 0.5) * 0.3;
        this.vy = (Math.random() - 0.5) * 0.3;
        this.r = Math.random() * 1.5 + 0.5;
        this.alpha = Math.random() * 0.5 + 0.1;
      }
      update() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > W || this.y < 0 || this.y > H) this.reset();
      }
    }

    function init() {
      particles = [];
      const count = Math.floor((W * H) / 14000);
      for (let i = 0; i < count; i++) particles.push(new Particle());
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(124,58,237,${0.12 * (1 - dist / 120)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      particles.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(168,85,247,${p.alpha})`;
        ctx.fill();
        p.update();
      });
      rafId = requestAnimationFrame(draw);
    }

    resize();
    init();
    draw();

    const handleResize = () => { resize(); init(); };
    window.addEventListener('resize', handleResize);
    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none"
      style={{ zIndex: 0 }}
      aria-hidden="true"
    />
  );
}

// Stagger choreography — each child fades up 80ms after the previous.
// Ease-out + 18px translate is the Linear/Vercel signature.
const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08, delayChildren: 0.05 },
  },
};
const item = {
  hidden: { opacity: 0, y: 18 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.38, ease: [0.22, 1, 0.36, 1] },
  },
};

export default function Hero({ onExampleCta, error, health }) {
  // health prop is `null` while loading, `{ status: 'ok' }` online, anything else = offline
  const apiOnline = health?.status === 'ok';
  const apiKnown  = health !== null && health !== undefined;

  return (
    <section className="relative flex-1 flex flex-col justify-center pt-12 sm:pt-16 pb-16 lg:pb-20 px-4 sm:px-6 lg:px-10 overflow-hidden">
      {/* Particle network background */}
      <ParticleCanvas />

      {/* Soft radial behind the hero — sparse use of gradient, on background only */}
      <div
        className="absolute -top-32 right-[-10%] w-[680px] h-[680px] pointer-events-none opacity-70"
        style={{ background: 'radial-gradient(closest-side, rgba(139,92,246,0.12), transparent 70%)', zIndex: 1 }}
        aria-hidden="true"
      />
      <div
        className="absolute top-40 -left-40 w-[520px] h-[520px] pointer-events-none opacity-70"
        style={{ background: 'radial-gradient(closest-side, rgba(103,232,249,0.06), transparent 70%)', zIndex: 1 }}
        aria-hidden="true"
      />

      <div className="relative grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-center max-w-[1280px] mx-auto w-full" style={{ zIndex: 2 }}>
        {/* ── Text column (6/12) ─────────────────────────── */}
        <motion.div
          className="lg:col-span-6 max-w-[640px]"
          variants={container}
          initial="hidden"
          animate="show"
        >
          {/* Eyebrow row — adapts to API health for honest messaging.
              When the API is offline, we dim the source-online chip and warn instead. */}
          <motion.div variants={item} className="flex items-center gap-2 sm:gap-3 mb-6 sm:mb-8 flex-wrap">
            <span className="eyebrow text-sentinel-purple-light/80">Threat Intelligence</span>
            <span className="text-white/15 text-xs">/</span>
            <span className="eyebrow">v1.0</span>
            <span className="text-white/15 text-xs">/</span>
            {apiKnown && !apiOnline ? (
              <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-red-500/25 bg-red-500/[0.06]">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-red-300">API offline</span>
              </span>
            ) : (
              <span className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border bg-white/[0.02] transition-opacity ${
                apiOnline ? 'border-white/8 opacity-100' : 'border-white/5 opacity-60'
              }`}>
                <span className={apiOnline ? 'status-dot' : 'w-1.5 h-1.5 rounded-full bg-white/40'} />
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-white/65">
                  {apiOnline ? '14 sources online' : 'connecting…'}
                </span>
              </span>
            )}
          </motion.div>

          {/* Display lockup — sans + serif italic contrast.
              Each line is its own motion item so they stagger in. */}
          <h1
            className="display-tight font-bold text-white"
            style={{ fontSize: 'clamp(56px, 8.6vw, 124px)' }}
          >
            <motion.span variants={item} className="block">OSINT</motion.span>
            <motion.span
              variants={item}
              className="serif-italic block"
              style={{ marginLeft: '0.06em' }}
            >
              <span
                style={{
                  background: 'linear-gradient(135deg, #ffffff 20%, #c4b5fd 55%, #a78bfa 80%, #7c3aed 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                  filter: 'drop-shadow(0 0 32px rgba(139,92,246,0.35))',
                }}
              >
                Sentinel
              </span>
              <span className="text-sentinel-purple" style={{ WebkitTextFillColor: 'initial' }}>.</span>
            </motion.span>
          </h1>

          {/* Supporting paragraph — copy adapts to health state */}
          <motion.p
            variants={item}
            className="mt-7 sm:mt-8 text-sentinel-text-dim font-body max-w-[58ch]"
            style={{ fontSize: 'clamp(15px, 1.05vw, 17px)', lineHeight: 1.6 }}
          >
            {apiKnown && !apiOnline ? (
              <>
                Multi-agent threat intelligence for SOC analysts. The backend is currently
                <span className="text-red-300"> unreachable</span>: start the API on{' '}
                <span className="font-mono text-white">:8000</span> and refresh to begin scanning.
              </>
            ) : (
              <>
                Multi-agent threat intelligence for SOC analysts. Query{' '}
                <span className="text-white">14 OSINT sources</span> in parallel, then synthesize
                the findings into a single, actionable brief: verdict, severity, and recommended
                response, in under <span className="font-mono text-white">~6 seconds</span>.
              </>
            )}
          </motion.p>

          {error && (
            <motion.div
              variants={item}
              className="mt-5 max-w-[58ch] bg-red-950/40 border border-red-800/40 rounded-xl px-4 py-3 backdrop-blur-sm"
            >
              <p className="text-red-300 font-mono text-xs">{error}</p>
            </motion.div>
          )}

          {/* CTA pair */}
          <motion.div variants={item} className="mt-9 sm:mt-10 flex flex-wrap items-center gap-3 sm:gap-4">
            <div className="relative group/cta">
              {/* Outer glow halo */}
              <div
                className="absolute inset-0 -m-2 rounded-2xl pointer-events-none opacity-60 blur-xl transition-all duration-300 group-hover/cta:opacity-90 group-hover/cta:blur-2xl"
                style={{ background: 'radial-gradient(ellipse, rgba(167,139,250,0.7), rgba(139,92,246,0.4) 60%, transparent 80%)' }}
                aria-hidden="true"
              />
              <Link
                to="/console"
                className="relative z-10 focus-ring group inline-flex items-center gap-2.5 px-6 sm:px-7 h-[54px] rounded-xl text-white text-sm font-display font-bold tracking-[-0.01em] no-underline transition-all duration-200 hover:-translate-y-0.5"
                style={{
                  background: 'linear-gradient(135deg, #a78bfa 0%, #8b5cf6 40%, #7c3aed 100%)',
                  boxShadow: '0 0 0 1px rgba(167,139,250,0.5), 0 6px 28px -4px rgba(139,92,246,0.75), 0 2px 8px rgba(139,92,246,0.4)',
                }}
              >
                <Terminal className="w-4 h-4 text-white/90" strokeWidth={2.25} />
                Launch Sentinel
                <ArrowRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-0.5" />
              </Link>
            </div>

            <button
              type="button"
              onClick={onExampleCta}
              className="btn-ghost focus-ring group inline-flex items-center gap-2 px-5 h-[52px] rounded-xl text-white/85 hover:text-white text-sm font-display font-medium cursor-pointer"
            >
              <Sparkles className="w-4 h-4 text-sentinel-cyan" strokeWidth={2} />
              View example report
              <ArrowRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-0.5" />
            </button>
          </motion.div>

          {/* Stat row */}
          <motion.dl
            variants={item}
            className="mt-10 grid grid-cols-2 sm:grid-cols-4 gap-6 max-w-xl border-t border-white/[0.06] pt-6"
          >
            <div>
              <dt className="eyebrow">Sources</dt>
              <dd className="display-tight text-white text-2xl font-medium mt-1">14</dd>
            </div>
            <div>
              <dt className="eyebrow">Avg latency</dt>
              <dd className="display-tight text-white text-2xl font-medium mt-1">~6.2<span className="text-white/40 text-base font-normal">s</span></dd>
            </div>
            <div>
              <dt className="eyebrow">Synthesis</dt>
              <dd className="display-tight text-white text-2xl font-medium mt-1">LLM</dd>
            </div>
            <div>
              <dt className="eyebrow">Uptime</dt>
              <dd className="display-tight text-sentinel-green text-2xl font-medium mt-1">99.9<span className="text-sentinel-green/50 text-base font-normal">%</span></dd>
            </div>
          </motion.dl>
        </motion.div>

        {/* ── Visual column (6/12): radar + live ticker stacked ──── */}
        <motion.div
          className="hidden lg:flex lg:col-span-6 flex-col gap-6 items-center justify-center"
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6, delay: 0.25, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className="relative w-full">
            <RadarVisual />
          </div>

          {/* Live intel ticker — gives the radar a data companion */}
          <div className="w-full max-w-[520px]">
            <LiveTicker />
          </div>
        </motion.div>
      </div>

    </section>
  );
}
