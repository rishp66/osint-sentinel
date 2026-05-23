import { motion } from 'framer-motion';

const SOURCES = [
  { id: 'shodan', label: 'Shodan', href: 'https://www.shodan.io', logo: '/logos/shodan.png' },
  { id: 'virustotal', label: 'VirusTotal', href: 'https://www.virustotal.com', logo: '/logos/virustotal.svg' },
  { id: 'abuseipdb', label: 'AbuseIPDB', href: 'https://www.abuseipdb.com', logo: '/logos/abuseipdb.svg' },
  { id: 'greynoise', label: 'GreyNoise', href: 'https://www.greynoise.io', logo: '/logos/greynoise.svg' },
  { id: 'google', label: 'Google', href: 'https://www.google.com', logo: '/logos/google.svg' },
  { id: 'censys', label: 'Censys', href: 'https://censys.com', logo: '/logos/censys.svg' },
  { id: 'urlscan', label: 'urlscan.io', href: 'https://urlscan.io', logo: '/logos/urlscan.svg' },
  { id: 'urlhaus', label: 'URLhaus', href: 'https://urlhaus.abuse.ch', logo: '/logos/urlhaus.svg' },
  { id: 'threatfox', label: 'ThreatFox', href: 'https://threatfox.abuse.ch', logo: '/logos/threatfox.svg' },
  { id: 'malwarebazaar', label: 'MalwareBazaar', href: 'https://bazaar.abuse.ch', logo: '/logos/malwarebazaar.svg' },
  { id: 'otx', label: 'OTX AlienVault', href: 'https://otx.alienvault.com', logo: '/logos/otx-alienvault.svg' },
  { id: 'ipinfo', label: 'IPinfo', href: 'https://ipinfo.io', logo: '/logos/ipinfo.svg' },
  { id: 'vulnerabilitylookup', label: 'Vulnerability Lookup', href: 'https://www.vulnerability-lookup.org', logo: '/logos/vulnerability-lookup.svg' },
];

function Tile({ source, index }) {
  return (
    <motion.a
      href={source.href}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={source.label}
      className="ti-tile no-underline"
      initial={{ opacity: 0 }}
      whileInView={{ opacity: 1 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.45, delay: Math.min(index * 0.02, 0.28), ease: [0.22, 1, 0.36, 1] }}
    >
      <img
        src={source.logo}
        alt={source.label}
        width="80"
        height="80"
        decoding="async"
        className="h-[72%] w-[72%] object-contain"
      />
    </motion.a>
  );
}

export default function VendorLogos() {
  return (
    <section id="integrations" className="overflow-hidden scroll-mt-28">
      <div className="relative w-full py-16 sm:py-20">
        {/* Centered radial glow — mirrors the CtaSection treatment */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(ellipse 80% 70% at 50% 50%, rgba(139,92,246,0.13) 0%, transparent 70%)',
          }}
        />
        {/* Top fade so the section bleeds in rather than starting abruptly */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-24"
          style={{ background: 'linear-gradient(180deg, rgba(8,8,11,1) 0%, transparent 100%)' }}
          aria-hidden="true"
        />

        <div className="relative text-center px-4 sm:px-6 lg:px-10 mb-10 sm:mb-12">
          <h2
            className="display-tight font-bold text-white leading-none"
            style={{ fontSize: 'clamp(32px, 5vw, 72px)' }}
          >
            <span className="block">THREAT INTELLIGENCE</span>
            <span
              className="serif-italic block font-normal text-white/90"
              style={{ textShadow: '0 0 40px rgba(139,92,246,0.35)' }}
            >
              Sources.
            </span>
          </h2>
          <p className="mt-3 font-mono text-[11px] sm:text-xs uppercase tracking-[0.18em] text-sentinel-purple-light/70">
            Real-time enrichment layer
          </p>
        </div>

        <div className="ti-marquee relative">
          <div className="ti-track">
            <div className="ti-segment">
              {SOURCES.map((source, index) => (
                <Tile key={source.id} source={source} index={index} />
              ))}
            </div>
            <div className="ti-segment" aria-hidden="true">
              {SOURCES.map((source, index) => (
                <Tile key={`${source.id}-dup`} source={source} index={index} />
              ))}
            </div>
          </div>
        </div>
      </div>

      <style>{`
        .ti-marquee {
          overflow: hidden;
          -webkit-mask-image: linear-gradient(to right, transparent 0%, black 8%, black 92%, transparent 100%);
          mask-image: linear-gradient(to right, transparent 0%, black 8%, black 92%, transparent 100%);
        }

        .ti-track {
          display: flex;
          align-items: center;
          width: max-content;
          will-change: transform;
          transform: translate3d(0, 0, 0);
          animation: ti-marquee 45s linear infinite;
        }

        .ti-segment {
          display: flex;
          align-items: center;
          gap: 32px;
          padding-right: 32px;
        }

        .ti-marquee:hover .ti-track {
          animation-play-state: paused;
        }

        .ti-tile {
          width: 120px;
          height: 120px;
          min-width: 120px;
          border-radius: 20px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: linear-gradient(145deg, #0a0f1a, #0f1620);
          border: 1px solid rgba(139, 92, 246, 0.15);
          box-shadow: 0 0 24px rgba(139, 92, 246, 0.08);
          transition: transform 250ms ease, border-color 250ms ease, box-shadow 250ms ease;
        }

        .ti-tile:hover {
          transform: scale(1.06);
          border-color: rgba(139, 92, 246, 0.65);
          box-shadow: 0 0 28px rgba(139, 92, 246, 0.35);
        }

        @keyframes ti-marquee {
          from { transform: translate3d(0, 0, 0); }
          to { transform: translate3d(-50%, 0, 0); }
        }

        @media (prefers-reduced-motion: reduce) {
          .ti-track {
            animation: none;
            transform: translate3d(0, 0, 0);
          }
        }
      `}</style>
    </section>
  );
}
