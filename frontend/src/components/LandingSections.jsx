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

function CapabilityCard({ icon: Icon, title, body, accent = 'purple', children }) {
  const accentTone = {
    purple: 'text-sentinel-purple-light',
    cyan:   'text-sentinel-cyan',
    amber:  'text-sentinel-amber',
  }[accent];

  const iconBg = {
    purple: 'border-sentinel-purple/20 bg-sentinel-purple/[0.06]',
    cyan:   'border-sentinel-cyan/20 bg-sentinel-cyan/[0.06]',
    amber:  'border-sentinel-amber/20 bg-sentinel-amber/[0.06]',
  }[accent];

  return (
    <motion.div
      variants={fadeUp}
      className="gradient-border card-hover hairline rounded-2xl p-7 sm:p-8 relative overflow-hidden flex flex-col"
      style={{ background: 'linear-gradient(180deg, rgba(255,255,255,0.022), rgba(255,255,255,0.005))' }}
    >
      <div className="flex items-center gap-3 mb-4">
        <div className={`p-2.5 rounded-xl border ${iconBg}`}>
          <Icon className={`w-5 h-5 ${accentTone}`} strokeWidth={1.75} />
        </div>
        <h3 className="font-display font-semibold text-white text-base tracking-tight">
          {title}
        </h3>
      </div>
      <p className="text-sentinel-text-dim text-[15px] font-body leading-relaxed flex-1">
        {body}
      </p>
      {children}
    </motion.div>
  );
}

function CapabilityBento() {
  return (
    <section id="capabilities" className="px-4 sm:px-6 lg:px-10 py-16 sm:py-24 scroll-mt-28">
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
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5"
      >
        {/* Row 1 */}
        <CapabilityCard
          icon={Network}
          title="Parallel multi-source"
          body="14 OSINT integrations queried simultaneously: VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, ThreatFox, URLScan, and more...."
        >
          <div className="mt-5 flex flex-wrap gap-1.5">
            {['VirusTotal', 'Shodan', 'AbuseIPDB', 'OTX', 'GreyNoise', 'ThreatFox', 'URLScan', '+7'].map(s => (
              <span key={s} className="px-2 py-0.5 rounded-md text-[11px] font-mono text-white/60 border border-white/[0.08] bg-white/[0.02]">
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
        />

        <CapabilityCard
          icon={Zap}
          title="Sub-7s scans"
          body="Async fan-out under the hood. Every lookup finishes in the time it takes to copy/paste an IP."
        />

        {/* Row 2 */}
        <CapabilityCard
          icon={ShieldAlert}
          title="Severity vocabulary"
          body="Five tiers calibrated for triage: mapped consistently across every source so you always speak the same language."
          accent="amber"
        >
          <div className="mt-5 space-y-2">
            {[
              { c: 'bg-red-500',     dot: 'bg-red-500',     l: 'CRITICAL', desc: 'Immediate action required' },
              { c: 'bg-orange-500',  dot: 'bg-orange-500',  l: 'HIGH',     desc: 'Investigate within hours'  },
              { c: 'bg-yellow-400',  dot: 'bg-yellow-400',  l: 'MEDIUM',   desc: 'Schedule for review'       },
              { c: 'bg-blue-400',    dot: 'bg-blue-400',    l: 'LOW',      desc: 'Monitor passively'         },
              { c: 'bg-emerald-400', dot: 'bg-emerald-400', l: 'CLEAN',    desc: 'No action needed'          },
            ].map(({ dot, l, desc }) => (
              <div key={l} className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dot}`} />
                <span className="font-mono text-[11px] text-white/90 w-16 tracking-wide">{l}</span>
                <span className="font-body text-[12px] text-white/45 leading-tight">{desc}</span>
              </div>
            ))}
          </div>
        </CapabilityCard>

        <CapabilityCard
          icon={Globe2}
          title="IOC coverage"
          body="One composer handles every observable type: no separate tools, no format guessing."
        >
          <div className="mt-5 grid grid-cols-2 gap-2">
            {[
              { label: 'IP addresses',   eg: '8.8.8.8, 2001:db8::1' },
              { label: 'Domains',        eg: 'evil.example.com'     },
              { label: 'URLs',           eg: 'https://…/payload'    },
              { label: 'File hashes',    eg: 'MD5 · SHA-1 · SHA-256'},
              { label: 'CVEs',           eg: 'CVE-2024-XXXXX'       },
              { label: 'Email headers',  eg: 'sender / reply-to'    },
            ].map(({ label, eg }) => (
              <div key={label} className="rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2.5">
                <div className="font-display text-[12px] text-white/80 font-medium leading-tight">{label}</div>
                <div className="font-mono text-[10px] text-white/35 mt-0.5 truncate">{eg}</div>
              </div>
            ))}
          </div>
        </CapabilityCard>

        <CapabilityCard
          icon={History}
          title="Local scan history"
          body="The last 10 targets stay one click away in the console. No accounts, no telemetry."
          accent="cyan"
        >
          <div className="mt-5 space-y-1.5">
            {[
              { target: '185.220.101.47',       verdict: 'CRITICAL', tone: 'text-red-400'     },
              { target: 'malware.example.com',  verdict: 'HIGH',     tone: 'text-orange-400'  },
              { target: 'd41d8cd98f00b204…',    verdict: 'CLEAN',    tone: 'text-emerald-400' },
              { target: 'CVE-2024-21413',       verdict: 'HIGH',     tone: 'text-orange-400'  },
              { target: '1.1.1.1',              verdict: 'CLEAN',    tone: 'text-emerald-400' },
            ].map(({ target, verdict, tone }) => (
              <div key={target} className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-white/[0.015] px-3 py-2">
                <span className="font-mono text-[11px] text-white/60 truncate max-w-[60%]">{target}</span>
                <span className={`font-mono text-[10px] font-semibold tracking-wider ${tone}`}>{verdict}</span>
              </div>
            ))}
          </div>
        </CapabilityCard>
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
      body: 'A multi-agent backend hits every relevant OSINT source concurrently: partial failures degrade gracefully, never block the scan.',
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
            <div className="display-tight text-white font-bold leading-none mb-6 select-none"
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
    <section ref={ref} id="sample-report" className="px-4 sm:px-6 lg:px-10 py-16 sm:py-24 border-t border-white/[0.05] scroll-mt-28 min-h-[100svh]">
      <SectionHeader
        eyebrow="Sample output"
        title="What lands in your"
        italic="briefing."
        sub={<>A real synthesized brief for a sample target.<br /><span className="whitespace-nowrap">This is what every scan returns: verdict on top, source intelligence below, full agent report at the bottom.</span></>}
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
                    '47 abuse reports: abuseipdb confidence 100%',
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
                <div key={r.s} className="flex items-center justify-between text-xs">
                  <span className="font-display text-white/60 tracking-tight">{r.s}</span>
                  <span className={`font-mono ${r.tone}`}>{r.v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Agent synthesis block */}
        <div className="border-t border-white/[0.06] px-5 sm:px-7 py-5 sm:py-6">
          <div className="flex items-center gap-2 mb-3">
            <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-sentinel-purple-light/70">Agent synthesis</span>
            <span className="h-px flex-1 bg-white/[0.06]" />
            <span className="font-mono text-[10px] text-white/30">gpt-4o · 312 tokens</span>
          </div>
          <p className="font-body text-[13px] sm:text-sm text-sentinel-text-dim leading-relaxed">
            <span className="text-white/80 font-medium">185.220.101.42</span> is a well-documented Tor exit node operated under AS197540 (Netcup GmbH, Netherlands). Cross-referencing AbuseIPDB, GreyNoise, and OTX confirms active participation in credential-stuffing campaigns and automated WordPress xmlrpc brute-force bursts over the last 14 days. Shodan reveals ports 80, 443, 9001, and 9030 open: consistent with a Tor relay/exit configuration. VirusTotal flags 11 of 88 engines on associated infrastructure. <span className="text-sentinel-amber/90">Recommend immediate perimeter block</span>, retroactive auth-log review for the past two weeks, and MFA enforcement on any account that authenticated from this address.
          </p>
        </div>

        {/* Metadata strip */}
        <div className="border-t border-white/[0.06] px-5 sm:px-7 py-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <div className="eyebrow mb-2">Open ports</div>
            <div className="flex flex-wrap gap-1.5">
              {['80/http', '443/https', '9001/tor', '9030/tor-dir'].map(p => (
                <span key={p} className="font-mono text-[11px] text-amber-300/80 border border-amber-500/20 bg-amber-500/[0.04] rounded px-2 py-0.5">{p}</span>
              ))}
            </div>
          </div>
          <div>
            <div className="eyebrow mb-2">Geolocation</div>
            <div className="space-y-1">
              {[
                { k: 'Country', v: 'Netherlands 🇳🇱' },
                { k: 'ASN',     v: 'AS197540 · Netcup' },
                { k: 'City',    v: 'Düsseldorf' },
              ].map(({ k, v }) => (
                <div key={k} className="flex justify-between text-xs">
                  <span className="font-mono text-white/35">{k}</span>
                  <span className="font-mono text-white/70">{v}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <div className="eyebrow mb-2">Threat context</div>
            <div className="space-y-1">
              {[
                { k: 'Classification', v: 'Tor exit node' },
                { k: 'Last seen',      v: '2 hours ago' },
                { k: 'OTX pulses',     v: '3 active' },
              ].map(({ k, v }) => (
                <div key={k} className="flex justify-between text-xs">
                  <span className="font-mono text-white/35">{k}</span>
                  <span className="font-mono text-white/70">{v}</span>
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
