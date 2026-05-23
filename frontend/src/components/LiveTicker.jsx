import React from 'react';

// Mocked recent intel feed — purely decorative, communicates the "live" idea
// without claiming to be real data. The list duplicates so the linear ticker
// loops seamlessly via the -50% transform in the `ticker` keyframe.
const FEED = [
  { tag: 'IOC',  source: 'threatfox',  payload: '185.220.101.42',          tone: 'amber'  },
  { tag: 'CVE',  source: 'circl',      payload: 'CVE-2024-3094 · CVSS 10', tone: 'crimson' },
  { tag: 'DNS',  source: 'resolver',   payload: 'malware.evil → 91.92.x.x', tone: 'cyan'   },
  { tag: 'AS',   source: 'rdap',       payload: 'AS197540 · M247 Europe',  tone: 'purple' },
  { tag: 'URL',  source: 'urlscan',    payload: 'login-update[.]secure-portal[.]biz', tone: 'amber' },
  { tag: 'HASH', source: 'mb',         payload: '7f4c2…ab12 · Emotet.E',   tone: 'crimson' },
  { tag: 'SCAN', source: 'shodan',     payload: ':22 :80 :443 :3306',      tone: 'cyan'   },
  { tag: 'TOR',  source: 'greynoise',  payload: 'exit node — last seen 2h', tone: 'purple' },
];

const TONE = {
  purple:  'text-sentinel-purple-light',
  cyan:    'text-sentinel-cyan',
  amber:   'text-sentinel-amber',
  crimson: 'text-red-400',
};

function Row({ item }) {
  return (
    <div className="flex items-center gap-3 py-2">
      <span className={`font-mono text-[9px] uppercase tracking-[0.2em] w-9 ${TONE[item.tone]}`}>
        {item.tag}
      </span>
      <span className="font-mono text-[10px] text-white/35 w-[68px] truncate">
        {item.source}
      </span>
      <span className="font-mono text-[11px] text-white/80 truncate flex-1">
        {item.payload}
      </span>
    </div>
  );
}

export default function LiveTicker() {
  // Two copies + 50% translate keyframe = seamless infinite loop without JS.
  return (
    <div className="hairline rounded-xl px-4 py-3 relative overflow-hidden bg-black/20" aria-hidden="true">
      <div className="flex items-center justify-between mb-2 pb-2 border-b border-white/[0.05]">
        <div className="flex items-center gap-2">
          <span className="status-dot" />
          <span className="eyebrow !text-[10px] text-white/65">Live intel</span>
        </div>
        <span className="font-mono text-[10px] text-white/35 tabular-nums">tail -f</span>
      </div>

      <div className="ticker-mask h-[136px] overflow-hidden">
        <div className="animate-ticker will-change-transform">
          {FEED.map((item, i) => <Row key={`a-${i}`} item={item} />)}
          {FEED.map((item, i) => <Row key={`b-${i}`} item={item} />)}
        </div>
      </div>
    </div>
  );
}
