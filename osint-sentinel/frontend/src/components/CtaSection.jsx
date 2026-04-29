import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Terminal, ArrowRight } from 'lucide-react';

const viewport = { once: true, margin: '-80px' };

export default function CtaSection() {
  return (
    <section className="relative px-4 sm:px-6 lg:px-10 py-24 sm:py-32 border-t border-white/[0.05] overflow-hidden text-center"
      style={{ background: 'linear-gradient(180deg, #0d0d12 0%, #08080b 100%)' }}
    >
      {/* Centered radial purple glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse 60% 50% at 50% 50%, rgba(139,92,246,0.14) 0%, transparent 70%)',
        }}
        aria-hidden="true"
      />

      <motion.div
        className="relative z-10 max-w-2xl mx-auto"
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={viewport}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      >
        <p className="font-mono text-[10px] tracking-[0.14em] text-sentinel-purple-light/70 uppercase mb-5">
          Get started today
        </p>

        <h2
          className="display-tight font-bold text-white mb-5"
          style={{ fontSize: 'clamp(30px, 4.5vw, 52px)', letterSpacing: '-0.03em', lineHeight: 1.06 }}
        >
          Your SOC team deserves{' '}
          <br className="hidden sm:block" />
          <span className="serif-italic font-normal text-white/90">better threat intel.</span>
        </h2>

        <p className="text-sentinel-text-dim font-body text-base sm:text-[17px] leading-relaxed max-w-md mx-auto mb-10">
          Stop toggling between 14 dashboards. Let Sentinel do it in parallel — and explain what it found.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            to="/console"
            className="btn-primary focus-ring inline-flex items-center gap-2.5 px-7 h-[54px] rounded-xl text-white text-sm font-display font-semibold tracking-[-0.01em] no-underline"
          >
            <Terminal className="w-4 h-4 text-sentinel-purple-light" strokeWidth={2.25} />
            Launch Intelligence Console
          </Link>

          <a
            href="https://github.com/rishp66/osint-sentinel#readme"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-ghost focus-ring inline-flex items-center gap-2 px-6 h-[54px] rounded-xl text-white/80 hover:text-white text-sm font-display font-medium cursor-pointer no-underline transition-colors duration-200"
          >
            Read the docs
            <ArrowRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-0.5" />
          </a>
        </div>

        <p className="mt-7 font-mono text-[11px] text-white/30 tracking-wide">
          Free tier available · No credit card required · API access included
        </p>
      </motion.div>
    </section>
  );
}
