import { motion } from 'framer-motion';
import { Sparkles } from './ui/Sparkles';

const SOURCES = [
  { id: 'shodan', label: 'Shodan', href: 'https://www.shodan.io', logo: '/logos/shodan.png' },
  { id: 'virustotal', label: 'VirusTotal', href: 'https://www.virustotal.com', logo: '/logos/virustotal.svg' },
  { id: 'abuseipdb', label: 'AbuseIPDB', href: 'https://www.abuseipdb.com', logo: '/logos/abuseipdb.svg' },
  { id: 'greynoise', label: 'GreyNoise', href: 'https://www.greynoise.io', logo: '/logos/greynoise.svg' },
  { id: 'google', label: 'Google', href: 'https://www.google.com', logo: '/logos/google.svg' },
  { id: 'censys', label: 'Censys', href: 'https://censys.com', logo: '/logos/censys.svg' },
  { id: 'foxyproxy', label: 'Foxyproxy', href: 'https://getfoxyproxy.org', logo: '/logos/foxyproxy.svg' },
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
        width="64"
        height="64"
        decoding="async"
        className="h-[66%] w-[66%] object-contain"
      />
    </motion.a>
  );
}

export default function VendorLogos() {
  return (
    <section className="border-t border-white/[0.05] overflow-hidden">
      <div className="relative w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-10 py-16 sm:py-20">
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              'radial-gradient(ellipse 70% 45% at 18% 8%, rgba(34,211,238,0.11), transparent 60%), radial-gradient(ellipse 65% 45% at 82% 0%, rgba(56,189,248,0.08), transparent 60%)',
          }}
        />

        <div className="relative text-center mb-10 sm:mb-12">
          <h2 className="display-tight text-2xl sm:text-3xl lg:text-4xl font-bold text-white leading-none sm:leading-tight tracking-tight whitespace-nowrap">
            THREAT INTELLIGENCE SOURCES
          </h2>
          <p className="mt-3 font-mono text-[11px] sm:text-xs uppercase tracking-[0.18em] text-cyan-200/70">
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

      <div className="relative h-72 w-full overflow-hidden [mask-image:radial-gradient(50%_50%,white,transparent)]">
        <div
          className="absolute inset-0"
          style={{
            background: 'radial-gradient(ellipse 80% 60% at 50% 100%, rgba(139,92,246,0.28), transparent 70%)',
          }}
        />
        <div
          className="absolute -left-1/2 top-1/2 z-10 w-[200%] rounded-[100%] border-t border-white/[0.12]"
          style={{
            aspectRatio: '1/0.7',
            background: '#08080b',
          }}
        />
        <Sparkles
          density={1200}
          speed={0.8}
          color="#ffffff"
          opacity={0.6}
          className="absolute inset-x-0 bottom-0 h-full w-full [mask-image:radial-gradient(50%_50%,white,transparent_85%)]"
        />
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
          gap: 28px;
          padding-right: 28px;
        }

        .ti-marquee:hover .ti-track {
          animation-play-state: paused;
        }

        .ti-tile {
          width: 98px;
          height: 98px;
          min-width: 98px;
          border-radius: 18px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: linear-gradient(145deg, #0a0f1a, #0f1620);
          border: 1px solid rgba(34, 211, 238, 0.12);
          box-shadow: 0 0 24px rgba(34, 211, 238, 0.08);
          transition: transform 250ms ease, border-color 250ms ease, box-shadow 250ms ease;
        }

        .ti-tile:hover {
          transform: scale(1.06);
          border-color: rgba(34, 211, 238, 0.65);
          box-shadow: 0 0 28px rgba(34, 211, 238, 0.35);
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
