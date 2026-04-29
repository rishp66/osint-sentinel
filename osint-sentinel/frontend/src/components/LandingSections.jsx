import React, { forwardRef } from 'react';
import { motion } from 'framer-motion';
import {
  Network, Zap, Brain, ShieldAlert, History, Globe2,
  ArrowRight, Send, Workflow, FileText, AlertTriangle, Lightbulb, XCircle,
} from 'lucide-react';
import VendorLogos from './VendorLogos';
import CtaSection from './CtaSection';
import Footer from './Footer';

/* ─────────────────────────────────────────────────────────
   Motion presets — reuse across sections so the cadence is
   consistent. once:true means each section fires only on
   first scroll-into-view, never on the way back up.
   ───────────────────────────────────────────────────────── */
const fadeUp = {
  hidden: { opacity: 0, y: 22 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] } },
};
const stagger = {
  hidden: { opacity: 0 },
  show:   { opacity: 1, transition: { staggerChildren: 0.06, delayChildren: 0.05 } },
};
const viewport = { once: true, margin: '-80px' };

/* Editorial section header — eyebrow + serif-italic accent */
function SectionHeader({ eyebrow, title, italic, sub }) {
  return (
    <motion.div
      className="mb-10 sm:mb-14 max-w-3xl"
      variants={stagger}
      initial="hidden"
      whileInView="show"
      viewport={viewport}
    >
      <motion.div variants={fadeUp} className="eyebrow text-sentinel-purple-light/80 mb-4">
        {eyebrow}
      </motion.div>
      <motion.h2
        variants={fadeUp}
        className="display-tight text-white font-bold"
        style={{ fontSize: 'clamp(32px, 4.4vw, 56px)', letterSpacing: '-0.03em', lineHeight: 1.02 }}
      >
        {title}
        {italic && (
          <>
            {' '}
            <span className="serif-italic font-normal text-white/90">{italic}</span>
          </>
        )}
      </motion.h2>
      {sub && (
        <motion.p
          variants={fadeUp}
          className="mt-4 text-sentinel-text-dim font-body text-base sm:text-[17px] leading-relaxed max-w-2xl"
        >
          {sub}
        </motion.p>
      )}
    </motion.div>
  );
}

function CapabilityCard({ icon: Icon, title, body, accent = 'purple', span = '', children }) {
  const accentTone = {
    purple: 'text-sentinel-purple-light',
    cyan:   'text-sentinel-cyan',
    amber:  'text-sentinel-amber',
  }[accent];

  return (
    <motion.div
      variants={fadeUp}
      className={`gradient-border card-hover hairline rounded-2xl p-6 sm:p-7 relative overflow-hidden ${span}`}
      style={{ background: 'linear-gradient(180deg, rgba(255,255,255,0.018), rgba(255,255,255,0.005))' }}
    >
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 rounded-lg border border-white/[0.07] bg-white/[0.02]">
          <Icon className={`w-4 h-4 ${accentTone}`} strokeWidth={1.75} />
        </div>
        <h3 className="font-display font-semibold text-white text-sm tracking-tight2">
          {title}
        </h3>
      </div>
      <p className="text-sentinel-text-dim text-[14px] font-body leading-relaxed">
        {body}
      </p>
      {children}
    </motion.div>
  );
}

function CapabilityBento() {
  return (
    <section className="px-4 sm:px-6 lg:px-10 py-16 sm:py-24">
      <SectionHeader
        eyebrow="What it does"
        title="Operational intel,"
        italic="without the swivel-chair."
        sub="Stop tab-juggling between a dozen vendor portals. Sentinel runs every lookup in parallel, normalizes the noise, and hands you a verdict instead of a stack of raw JSON."
      />

      <motion.div
        variants={stagger}
        initial="hidden"
        whileInView="show"
        viewport={viewport}
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4 sm:gap-5"
      >
        <CapabilityCard
          icon={Network}
          title="Parallel multi-source"
          body="14 OSINT integrations queried simultaneously — VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, ThreatFox, URLScan, and more — fanned out per scan."
          span="lg:col-span-3"
        >
          <div className="mt-5 flex flex-wrap gap-1.5">
            {['VirusTotal', 'Shodan', 'AbuseIPDB', 'OTX', 'GreyNoise', 'ThreatFox', 'URLScan', '+7'].map(s => (
              <span key={s} className="px-2 py-0.5 rounded-md text-[10px] font-mono text-white/65 border border-white/[0.08] bg-white/[0.02]">
                {s}
              </span>
            ))}
          </div>
        </CapabilityCard>

        <CapabilityCard
          icon={Brain}
          title="LLM synthesis"
          body="Raw signals get summarized into a verdict, key findings, and concrete next steps. Built for tickets and Slack threads, not dashboards."
          accent="cyan"
          span="lg:col-span-3"
        />

        <CapabilityCard
          icon={Zap}
          title="Sub-7s scans"
          body="Async fan-out under the hood. Every lookup finishes in the time it takes to copy/paste an IP."
          span="lg:col-span-2"
        />

        <CapabilityCard
          icon={ShieldAlert}
          title="Severity vocabulary"
          body="CRITICAL · HIGH · MEDIUM · LOW · CLEAN — calibrated for triage, mapped consistently across every source."
          accent="amber"
          span="lg:col-span-2"
        >
          <div className="mt-5 flex items-center gap-1">
            {[
              { c: 'bg-red-500',     l: 'CRIT' },
              { c: 'bg-orange-500',  l: 'HIGH' },
              { c: 'bg-yellow-500',  l: 'MED'  },
              { c: 'bg-blue-500',    l: 'LOW'  },
              { c: 'bg-emerald-500', l: 'OK'   },
            ].map(({ c, l }) => (
              <div key={l} className="flex-1 flex flex-col gap-1">
                <div className={`h-1.5 ${c} rounded-sm`} />
                <span className="font-mono text-[9px] text-white/45 tracking-wider">{l}</span>
              </div>
            ))}
          </div>
        </CapabilityCard>

        <CapabilityCard
          icon={Globe2}
          title="IOC coverage"
          body="Domains · IPs · URLs · file hashes (MD5/SHA-1/SHA-256) · CVEs. One composer, every observable."
          span="lg:col-span-2"
        />

        <CapabilityCard
          icon={History}
          title="Local scan history"
          body="The last 10 targets stay one click away in the console. No accounts, no telemetry."
          accent="cyan"
          span="lg:col-span-3"
        />
      </motion.div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    {
      icon: Send, n: '01',
      title: 'Submit a target',
      body: 'Drop a domain, IP, URL, file hash, or CVE into the console. Client-side validation catches typos before the round-trip.',
    },
    {
      icon: Workflow, n: '02',
      title: 'Parallel intelligence fan-out',
      body: 'A multi-agent backend hits every relevant OSINT source concurrently — partial failures degrade gracefully, never block the scan.',
    },
    {
      icon: FileText, n: '03',
      title: 'Synthesized brief',
      body: 'An LLM layer reconciles findings into a single threat assessment: verdict, severity, key findings, recommended response.',
    },
  ];

  return (
    <section className="px-4 sm:px-6 lg:px-10 py-16 sm:py-24 border-t border-white/[0.05]">
      <SectionHeader
        eyebrow="How it works"
        title="Three steps,"
        italic="one verdict."
      />

      <motion.ol
        variants={stagger}
        initial="hidden"
        whileInView="show"
        viewport={viewport}
        className="grid grid-cols-1 md:grid-cols-3 gap-px bg-white/[0.05] rounded-2xl overflow-hidden hairline"
      >
        {steps.map((s, i) => (
          <motion.li
            key={s.n}
            variants={fadeUp}
            className="bg-sentinel-ink p-7 sm:p-8 relative group"
          >
            <div className="display-tight text-white/[0.06] font-bold leading-none mb-6 select-none"
                 style={{ fontSize: '88px', letterSpacing: '-0.06em' }}>
              {s.n}
            </div>
            <div className="flex items-center gap-3 mb-3">
              <div className="p-1.5 rounded-md border border-white/[0.07] bg-white/[0.02]">
                <s.icon className="w-3.5 h-3.5 text-sentinel-purple-light" strokeWidth={1.75} />
              </div>
              <h3 className="font-display font-semibold text-white text-base">{s.title}</h3>
            </div>
            <p className="text-sentinel-text-dim text-[14px] font-body leading-relaxed">
              {s.body}
            </p>
            {i < steps.length - 1 && (
              <ArrowRight
                className="hidden md:block absolute top-1/2 -right-3 -translate-y-1/2 w-5 h-5 text-white/20 z-10"
                strokeWidth={1.5}
                aria-hidden="true"
              />
            )}
          </motion.li>
        ))}
      </motion.ol>
    </section>
  );
}

const ExampleReport = forwardRef(function ExampleReport(props, ref) {
  return (
    <section ref={ref} className="px-4 sm:px-6 lg:px-10 py-16 sm:py-24 border-t border-white/[0.05]">
      <SectionHeader
        eyebrow="Sample output"
        title="What lands in your"
        italic="terminal."
        sub="A real synthesized brief for a sample target. This is what every scan returns — verdict on top, source intelligence below, full agent report at the bottom."
      />

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={viewport}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        className="hairline rounded-2xl overflow-hidden"
        style={{ background: 'linear-gradient(180deg, rgba(255,255,255,0.015), rgba(255,255,255,0.002))' }}
      >
        {/* Toolbar */}
        <div className="flex items-center gap-3 px-4 sm:px-5 py-3 border-b border-white/[0.06] bg-black/30">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
          </div>
          <div className="flex-1 text-center">
            <span className="font-mono text-[11px] text-white/40 tracking-wider">
              osint-sentinel · scan output · target: 185.220.101.42
            </span>
          </div>
          <span className="font-mono text-[10px] text-white/35">5.84s</span>
        </div>

        <div className="p-5 sm:p-7 grid grid-cols-1 lg:grid-cols-3 gap-5 lg:gap-6">
          {/* Verdict block */}
          <div
            className="lg:col-span-2 rounded-xl p-5 sm:p-6 border border-red-500/25"
            style={{
              background: 'linear-gradient(180deg, rgba(239,68,68,0.06), rgba(239,68,68,0.015))',
              boxShadow: '0 0 28px -10px rgba(239,68,68,0.35)',
            }}
          >
            <div className="flex items-start gap-4 flex-wrap">
              <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 flex-shrink-0">
                <XCircle className="w-6 h-6 text-red-400" />
              </div>
              <div className="flex-1 min-w-[200px]">
                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                  <h3 className="font-display text-lg font-bold text-white">Threat Assessment</h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-wider text-red-300 bg-red-500/12 border border-red-500/30">
                    HIGH
                  </span>
                  <code className="ml-auto font-mono text-xs text-sentinel-purple-light/90 px-2 py-0.5 rounded border border-sentinel-purple/25 bg-sentinel-purple/[0.06]">
                    185.220.101.42
                  </code>
                </div>
                <p className="text-sentinel-text-dim text-sm leading-relaxed">
                  Known Tor exit node with multiple recent abuse reports. Active scanner across HTTP/SSH;
                  associated with credential-stuffing and wordpress-xmlrpc bursts in the last 14 days.
                </p>
              </div>
            </div>

            <div className="mt-5 h-1 bg-black/40 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-orange-500 to-red-500 rounded-full" style={{ width: '78%' }} />
            </div>

            <div className="mt-5 grid sm:grid-cols-2 gap-5">
              <div>
                <h4 className="font-display font-semibold text-xs text-white/85 mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-sentinel-amber" /> Key findings
                </h4>
                <ul className="space-y-1.5">
                  {[
                    '11 of 88 AV engines flag IPs in this /24',
                    'Tor exit-node consensus, last seen 2h ago',
                    '47 abuse reports — abuseipdb confidence 100%',
                  ].map((f, i) => (
                    <li key={i} className="flex gap-2 text-[13px] text-sentinel-text-dim leading-relaxed">
                      <span className="text-sentinel-amber mt-0.5">›</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="font-display font-semibold text-xs text-white/85 mb-2 flex items-center gap-1.5">
                  <Lightbulb className="w-3.5 h-3.5 text-sentinel-cyan" /> Recommended response
                </h4>
                <ul className="space-y-1.5">
                  {[
                    'Block at perimeter; add to threat-intel feed',
                    'Audit auth logs for the last 14 days',
                    'Enforce MFA on any account that hit this IP',
                  ].map((r, i) => (
                    <li key={i} className="flex gap-2 text-[13px] text-sentinel-text-dim leading-relaxed">
                      <span className="text-sentinel-cyan mt-0.5">›</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Risk gauge / metadata stack */}
          <div className="space-y-4">
            <div className="hairline rounded-xl p-5 flex items-center gap-4">
              <div className="relative w-20 h-20 rounded-full border-4 border-red-500/30 flex items-center justify-center"
                   style={{ boxShadow: '0 0 22px rgba(239,68,68,0.2)' }}>
                <span className="display-tight text-2xl font-bold text-red-300">78</span>
              </div>
              <div>
                <div className="eyebrow">Risk score</div>
                <div className="font-display text-white text-sm mt-1">Moderate-to-high</div>
                <div className="font-mono text-[11px] text-white/45 mt-0.5">scaled 0–100</div>
              </div>
            </div>

            <div className="hairline rounded-xl p-5 space-y-2.5">
              <div className="eyebrow mb-1">Sources reporting</div>
              {[
                { s: 'abuseipdb',   v: '47 reports',   tone: 'text-red-300' },
                { s: 'virustotal',  v: '11 / 88 flag', tone: 'text-orange-300' },
                { s: 'greynoise',   v: 'malicious',    tone: 'text-red-300' },
                { s: 'shodan',      v: '6 ports open', tone: 'text-amber-300' },
                { s: 'otx',         v: '3 pulses',     tone: 'text-amber-300' },
                { s: 'ipinfo',      v: 'NL · AS197540', tone: 'text-white/70' },
              ].map(r => (
                <div key={r.s} className="flex items-center justify-between font-mono text-xs">
                  <span className="text-white/55">{r.s}</span>
                  <span className={r.tone}>{r.v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </motion.div>
    </section>
  );
});

export default forwardRef(function LandingSections(props, exampleRef) {
  return (
    <>
      <VendorLogos />
      <CapabilityBento />
      <HowItWorks />
      <ExampleReport ref={exampleRef} />
      <CtaSection />
      <Footer />
    </>
  );
});
