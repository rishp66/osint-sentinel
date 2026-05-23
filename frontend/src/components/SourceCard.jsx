import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Database, Bug, Shield, Radar, Globe, MapPin, AlertCircle,
  ChevronDown, ChevronUp, Clock, CheckCircle, XCircle,
  Radio, Search, FlaskConical, Network, AlertTriangle, Target,
  FileWarning, Activity, Globe2, Copy, Check,
} from 'lucide-react';

/* ─────────────────────────────────────────────────────────
   Source registry: icon, accent, and category. The category
   key powers the new grouped layout in App.jsx.
   ───────────────────────────────────────────────────────── */
const FAV = (domain) => `https://www.google.com/s2/favicons?domain=${domain}&sz=128`;

const SOURCE_META = {
  whois:           { label: 'WHOIS',           icon: Database,     accent: '#a78bfa', category: 'metadata',       logo: null },
  virustotal:      { label: 'VirusTotal',      icon: Bug,          accent: '#f97316', category: 'threat',         logo: FAV('virustotal.com') },
  abuseipdb:       { label: 'AbuseIPDB',       icon: Shield,       accent: '#ef4444', category: 'threat',         logo: '/logos/abuseipdb.svg' },
  shodan:          { label: 'Shodan',          icon: Radar,        accent: '#06b6d4', category: 'infrastructure',  logo: FAV('shodan.io') },
  alienvault_otx:  { label: 'AlienVault OTX',  icon: Globe,        accent: '#22c55e', category: 'threat',         logo: '/logos/otx-alienvault.svg' },
  ipinfo:          { label: 'IPinfo',          icon: MapPin,       accent: '#eab308', category: 'metadata',       logo: '/logos/ipinfo.svg' },
  greynoise:       { label: 'GreyNoise',       icon: Radio,        accent: '#06b6d4', category: 'threat',         logo: '/logos/greynoise.svg' },
  urlscan:         { label: 'urlscan.io',      icon: Search,       accent: '#3b82f6', category: 'threat',         logo: '/logos/urlscan.svg' },
  hybrid_analysis: { label: 'Hybrid Analysis', icon: FlaskConical, accent: '#8b5cf6', category: 'threat',         logo: FAV('hybrid-analysis.com') },
  rdap:            { label: 'RDAP',            icon: Network,      accent: '#64748b', category: 'metadata',       logo: null },
  circl_cve:       { label: 'CIRCL CVE',       icon: AlertTriangle, accent: '#f59e0b', category: 'threat',        logo: FAV('circl.lu') },
  threatfox:       { label: 'ThreatFox',       icon: Target,       accent: '#f43f5e', category: 'threat',         logo: '/logos/threatfox.svg' },
  malwarebazaar:   { label: 'MalwareBazaar',   icon: FileWarning,  accent: '#ea580c', category: 'threat',         logo: '/logos/malwarebazaar.svg' },
  pulsedive:       { label: 'Pulsedive',       icon: Activity,     accent: '#ec4899', category: 'threat',         logo: FAV('pulsedive.com') },
  dns_resolution:  { label: 'DNS Resolution',  icon: Globe2,       accent: '#94a3b8', category: 'infrastructure',  logo: null },
  urlhaus:         { label: 'URLhaus',         icon: FileWarning,  accent: '#f97316', category: 'threat',         logo: '/logos/urlhaus.svg' },
};

export const SOURCE_CATEGORIES = {
  threat:         { label: 'Threat feeds',     hint: 'Reputation, IOCs, sandbox verdicts' },
  infrastructure: { label: 'Infrastructure',   hint: 'Network exposure, hosting, ports' },
  metadata:       { label: 'Metadata',         hint: 'Registration, ownership, geo' },
};

export function categorize(sources) {
  const buckets = { threat: [], infrastructure: [], metadata: [], other: [] };
  for (const s of sources) {
    const cat = SOURCE_META[s.source]?.category;
    if (cat && buckets[cat]) buckets[cat].push(s);
    else buckets.other.push(s);
  }
  return buckets;
}

/* ── Status derivation ─────────────────────────────────── */
function deriveStatus(source) {
  if (source.error) return 'unknown';
  const name = source.source;

  if (name === 'virustotal') {
    if ((source.malicious || 0) > 0) return 'malicious';
    if ((source.suspicious || 0) > 0) return 'suspicious';
    return 'clean';
  }
  if (name === 'abuseipdb') {
    const score = source.abuse_confidence_score || 0;
    if (score > 50) return 'malicious';
    if (score > 25) return 'suspicious';
    return 'clean';
  }
  if (name === 'greynoise') {
    const cls = (source.classification || '').toLowerCase();
    if (cls === 'malicious') return 'malicious';
    if (cls === 'benign') return 'clean';
    return 'unknown';
  }
  if (name === 'threatfox') {
    if ((source.match_count || 0) > 0) return 'malicious';
    return 'clean';
  }
  if (name === 'hybrid_analysis') {
    const first = source.results?.[0];
    if (first?.threat_score > 50) return 'malicious';
    if (first?.threat_score > 20) return 'suspicious';
    if (first) return 'clean';
    return 'unknown';
  }
  if (name === 'pulsedive') {
    const risk = (source.risk_recommended || source.risk || '').toLowerCase();
    if (risk === 'critical' || risk === 'high') return 'malicious';
    if (risk === 'medium') return 'suspicious';
    if (risk === 'low' || risk === 'none') return 'clean';
    return 'unknown';
  }
  if (name === 'shodan') {
    if (source.vulns?.length > 0) return 'suspicious';
    return 'clean';
  }
  return 'clean';
}

const STATUS_BADGE = {
  malicious:  { label: 'MALICIOUS',  bg: 'bg-red-500/10',     text: 'text-red-300',     border: 'border-red-500/30'     },
  suspicious: { label: 'SUSPICIOUS', bg: 'bg-orange-500/10',  text: 'text-orange-300',  border: 'border-orange-500/30'  },
  clean:      { label: 'CLEAN',      bg: 'bg-emerald-500/10', text: 'text-emerald-300', border: 'border-emerald-500/30' },
  unknown:    { label: 'UNKNOWN',    bg: 'bg-white/[0.04]',   text: 'text-white/55',    border: 'border-white/10'       },
};

/* ── Copy button ───────────────────────────────────────── */
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  };

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center ml-1.5 opacity-0 group-hover/row:opacity-60 hover:!opacity-100 transition-opacity cursor-pointer"
      title="Copy to clipboard"
      aria-label="Copy to clipboard"
    >
      {copied
        ? <Check className="w-3 h-3 text-emerald-400" />
        : <Copy className="w-3 h-3 text-white/55" />}
    </button>
  );
}

/* ── DataRow ───────────────────────────────────────────── */
function DataRow({ label, value, mono = false, copyable = false }) {
  if (value === null || value === undefined || value === '' || value === 'N/A') return null;
  const display = Array.isArray(value) ? value.join(', ') : String(value);
  if (!display) return null;
  return (
    <div className="group/row flex justify-between items-start gap-2 py-1.5 border-b border-white/[0.04] last:border-0">
      <span className="text-white/45 text-[11px] font-mono uppercase tracking-wider flex-shrink-0">{label}</span>
      <span className={`text-white/90 text-xs text-right ${mono ? 'font-mono' : 'font-body'} max-w-[60%] break-all flex items-center`}>
        {display}
        {copyable && display && <CopyButton text={display} />}
      </span>
    </div>
  );
}

function _hasDisplayableValue(v) {
  if (v === null || v === undefined || v === '' || v === 'N/A') return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v).length > 0;
  return true;
}

const _IGNORED_KEYS = new Set([
  'source', '_query_time_ms', 'error', 'note',
  'status', 'domain_name', 'updated_date', 'emails', 'registrant_state',
]);

function _hasContent(source) {
  return Object.entries(source).some(
    ([k, v]) => !_IGNORED_KEYS.has(k) && _hasDisplayableValue(v)
  );
}

/* ── Source-specific content components ────────────────── */
function WhoisContent({ data }) {
  return (
    <>
      <DataRow label="Registrar" value={data.registrar} />
      <DataRow label="Organization" value={data.registrant_org} />
      <DataRow label="Country" value={data.registrant_country} />
      <DataRow label="Created" value={data.creation_date} mono />
      <DataRow label="Expires" value={data.expiration_date} mono />
      <DataRow label="DNSSEC" value={data.dnssec} />
      <DataRow label="Name Servers" value={data.name_servers} mono copyable />
    </>
  );
}

function VirusTotalContent({ data }) {
  const total = (data.malicious || 0) + (data.suspicious || 0) + (data.harmless || 0) + (data.undetected || 0);
  const malPct = total > 0 ? ((data.malicious || 0) / total) * 100 : 0;
  return (
    <>
      <div className="mb-3">
        <div className="flex justify-between text-[11px] mb-1.5">
          <span className="text-white/45 font-mono uppercase tracking-wider">Detection rate</span>
          <span className="font-mono text-white tabular-nums">{data.malicious || 0}<span className="text-white/35">/{total}</span></span>
        </div>
        <div className="h-1.5 bg-black/50 rounded-full overflow-hidden">
          <div className="h-full bg-gradient-to-r from-orange-500 to-red-500 rounded-full transition-all"
            style={{ width: `${malPct}%` }} />
        </div>
      </div>
      <DataRow label="Malicious" value={data.malicious} mono />
      <DataRow label="Suspicious" value={data.suspicious} mono />
      <DataRow label="Harmless" value={data.harmless} mono />
      <DataRow label="Reputation" value={data.reputation} mono />
      <DataRow label="Tags" value={data.tags} />
      {data.categories && Object.keys(data.categories).length > 0 && (
        <DataRow label="Categories" value={Object.values(data.categories).slice(0, 3)} />
      )}
    </>
  );
}

function AbuseIPDBContent({ data }) {
  const score = data.abuse_confidence_score || 0;
  const tone = score > 50 ? 'text-red-300' : score > 20 ? 'text-yellow-300' : 'text-emerald-300';
  const fill = score > 50 ? 'bg-red-500'   : score > 20 ? 'bg-yellow-500'   : 'bg-emerald-500';
  return (
    <>
      <div className="mb-3">
        <div className="flex justify-between text-[11px] mb-1.5">
          <span className="text-white/45 font-mono uppercase tracking-wider">Abuse confidence</span>
          <span className={`font-mono font-semibold ${tone} tabular-nums`}>{score}%</span>
        </div>
        <div className="h-1.5 bg-black/50 rounded-full overflow-hidden">
          <div className={`h-full ${fill} rounded-full transition-all`} style={{ width: `${score}%` }} />
        </div>
      </div>
      <DataRow label="IP" value={data.ip_address} mono copyable />
      <DataRow label="Total reports" value={data.total_reports} mono />
      <DataRow label="Reporters" value={data.num_distinct_users} mono />
      <DataRow label="ISP" value={data.isp} />
      <DataRow label="Country" value={data.country_code} />
      <DataRow label="Usage type" value={data.usage_type} />
      <DataRow label="Tor node" value={data.is_tor ? 'Yes' : 'No'} />
      <DataRow label="Last reported" value={data.last_reported_at} mono />
    </>
  );
}

function ShodanContent({ data }) {
  return (
    <>
      <DataRow label="IP" value={data.ip} mono copyable />
      <DataRow label="Hostnames" value={data.hostnames} copyable />
      <DataRow label="OS" value={data.os} />
      <DataRow label="Org" value={data.org} />
      <DataRow label="ISP" value={data.isp} />
      <DataRow label="ASN" value={data.asn} mono copyable />
      <DataRow label="Open ports" value={data.ports} mono />
      <DataRow label="Location" value={[data.city, data.country_name].filter(Boolean).join(', ')} />
      {data.vulns?.length > 0 && (
        <div className="mt-3 p-2.5 rounded-lg border border-red-500/25 bg-red-950/20">
          <span className="text-red-300 text-[10px] font-mono uppercase tracking-wider">CVEs · </span>
          <span className="text-red-200 text-xs font-mono">{data.vulns.slice(0, 5).join(', ')}</span>
          {data.vulns.length > 5 && <span className="text-red-400/60 text-xs"> +{data.vulns.length - 5} more</span>}
        </div>
      )}
      {data.services?.length > 0 && (
        <div className="mt-3 space-y-1">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Services</span>
          {data.services.slice(0, 4).map((s, i) => (
            <div key={i} className="text-xs font-mono text-white/85 bg-black/30 border border-white/[0.05] rounded px-2 py-1">
              :{s.port}/{s.transport} — {s.product} {s.version || ''}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function OTXContent({ data }) {
  return (
    <>
      <DataRow label="Pulse count" value={data.pulse_count} mono />
      <DataRow label="Malware samples" value={data.malware_samples} mono />
      <DataRow label="Passive DNS" value={data.passive_dns_count} mono />
      <DataRow label="Reputation" value={data.reputation} mono />
      {data.pulses?.length > 0 && (
        <div className="mt-3 space-y-1.5">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Threat pulses</span>
          {data.pulses.slice(0, 3).map((p, i) => (
            <div key={i} className="bg-black/30 border border-white/[0.05] rounded-lg p-2">
              <div className="text-xs font-body text-white/90 font-medium">{p.name}</div>
              {p.tags?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {p.tags.slice(0, 4).map((t, j) => (
                    <span key={j} className="px-1.5 py-0.5 bg-sentinel-purple/15 text-sentinel-purple-light text-[10px] font-mono rounded">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function IPInfoContent({ data }) {
  return (
    <>
      <DataRow label="IP" value={data.ip} mono copyable />
      <DataRow label="Hostname" value={data.hostname} mono copyable />
      <DataRow label="City" value={data.city} />
      <DataRow label="Region" value={data.region} />
      <DataRow label="Country" value={data.country} />
      <DataRow label="Coordinates" value={data.loc} mono />
      <DataRow label="Organization" value={data.org} />
      <DataRow label="Timezone" value={data.timezone} />
      <DataRow label="Postal" value={data.postal} mono />
    </>
  );
}

function GreyNoiseContent({ data }) {
  const cls = (data.classification || '').toLowerCase();
  const clsColor = cls === 'malicious' ? 'text-red-300'
    : cls === 'benign' ? 'text-emerald-300'
    : cls === 'unknown' ? 'text-white/55' : 'text-yellow-300';
  return (
    <>
      <DataRow label="IP" value={data.ip} mono copyable />
      <div className="flex justify-between items-center py-1.5 border-b border-white/[0.04]">
        <span className="text-white/45 text-[11px] font-mono uppercase tracking-wider">Classification</span>
        <span className={`text-xs font-mono font-semibold ${clsColor}`}>{data.classification || 'unknown'}</span>
      </div>
      <DataRow label="Actor" value={data.name} />
      <DataRow label="Noise" value={data.noise === true ? 'Yes' : data.noise === false ? 'No' : null} />
      <DataRow label="RIOT (known good)" value={data.riot === true ? 'Yes' : data.riot === false ? 'No' : null} />
      <DataRow label="Last seen" value={data.last_seen} mono />
      {data.message && <DataRow label="Message" value={data.message} />}
    </>
  );
}

function URLscanContent({ data }) {
  return (
    <>
      <DataRow label="Total results" value={data.total_results} mono />
      {data.results?.length > 0 && (
        <div className="mt-3 space-y-1.5">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Recent scans</span>
          {data.results.slice(0, 3).map((r, i) => (
            <div key={i} className="bg-black/30 border border-white/[0.05] rounded-lg p-2">
              <div className="text-xs font-mono text-white/90 break-all">{r.task_url || r.domain}</div>
              <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-white/55">
                {r.malicious != null && (
                  <span className={r.malicious ? 'text-red-300' : 'text-emerald-300'}>
                    {r.malicious ? 'malicious' : 'clean'}
                  </span>
                )}
                {r.score != null && <span>score: {r.score}</span>}
                {r.time && <span>{r.time.slice(0, 10)}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function HybridAnalysisContent({ data }) {
  const first = data.results?.[0];
  if (!first) return <DataRow label="Result count" value={data.result_count} mono />;
  const score = first.threat_score || 0;
  const tone = score > 50 ? 'text-red-300' : score > 20 ? 'text-yellow-300' : 'text-emerald-300';
  const fill = score > 50 ? 'bg-red-500'   : score > 20 ? 'bg-yellow-500'   : 'bg-emerald-500';
  return (
    <>
      <DataRow label="Verdict" value={first.verdict} />
      <div className="my-2">
        <div className="flex justify-between text-[11px] mb-1.5">
          <span className="text-white/45 font-mono uppercase tracking-wider">Threat score</span>
          <span className={`font-mono font-semibold ${tone}`}>{score}/100</span>
        </div>
        <div className="h-1.5 bg-black/50 rounded-full overflow-hidden">
          <div className={`h-full ${fill} rounded-full`} style={{ width: `${score}%` }} />
        </div>
      </div>
      <DataRow label="Malware family" value={first.vx_family} />
      <DataRow label="File type" value={first.type_short} mono />
      <DataRow label="AV detections" value={first.av_detect} mono />
      <DataRow label="Analyzed" value={first.analysis_start_time} mono />
      <DataRow label="Result count" value={data.result_count} mono />
    </>
  );
}

function RDAPContent({ data }) {
  return (
    <>
      <DataRow label="ASN" value={data.asn} mono copyable />
      <DataRow label="AS description" value={data.asn_description} />
      <DataRow label="CIDR" value={data.asn_cidr} mono copyable />
      <DataRow label="Registry" value={data.asn_registry} />
      <DataRow label="Country" value={data.asn_country_code} />
      <DataRow label="Network name" value={data.network_name} />
      <DataRow label="Network CIDR" value={data.network_cidr} mono copyable />
      {data.entities?.length > 0 && (
        <div className="mt-3 space-y-1">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Entities</span>
          {data.entities.slice(0, 3).map((e, i) => (
            <div key={i} className="text-xs font-mono text-white/85 bg-black/30 border border-white/[0.05] rounded px-2 py-1">
              {e.handle}{e.name ? ` — ${e.name}` : ''}
              {e.roles?.length > 0 && <span className="text-white/45"> ({e.roles.join(', ')})</span>}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function CirclCveContent({ data }) {
  const cvss = data.cvss;
  const cvssColor = cvss >= 9 ? 'text-red-300' : cvss >= 7 ? 'text-orange-300' : cvss >= 4 ? 'text-yellow-300' : 'text-emerald-300';
  return (
    <>
      <DataRow label="CVE" value={data.id} mono copyable />
      {cvss != null && (
        <div className="flex justify-between py-1.5 border-b border-white/[0.04]">
          <span className="text-white/45 text-[11px] font-mono uppercase tracking-wider">CVSS</span>
          <span className={`font-mono font-semibold text-xs ${cvssColor}`}>{cvss}</span>
        </div>
      )}
      <DataRow label="Vector" value={data.cvss_vector} mono />
      <DataRow label="Published" value={data.published} mono />
      <DataRow label="Modified" value={data.modified} mono />
      {data.summary && (
        <div className="mt-3 text-xs text-white/85 font-body leading-relaxed">
          {data.summary}
        </div>
      )}
      {data.references?.length > 0 && (
        <div className="mt-3">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">References</span>
          <div className="mt-1 space-y-0.5">
            {data.references.slice(0, 3).map((r, i) => (
              <div key={i} className="text-[10px] font-mono text-sentinel-purple-light break-all">{r}</div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function ThreatFoxContent({ data }) {
  return (
    <>
      <DataRow label="Status" value={data.query_status} mono />
      <DataRow label="Match count" value={data.match_count} mono />
      {data.matches?.length > 0 && (
        <div className="mt-3 space-y-1.5">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">IOC matches</span>
          {data.matches.slice(0, 3).map((m, i) => (
            <div key={i} className="bg-black/30 border border-white/[0.05] rounded-lg p-2">
              <div className="text-xs font-mono text-red-300">{m.malware || 'unknown'}</div>
              <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-white/55">
                {m.threat_type && <span>{m.threat_type}</span>}
                {m.confidence_level != null && <span>conf: {m.confidence_level}%</span>}
                {m.first_seen && <span>{m.first_seen.slice(0, 10)}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function MalwareBazaarContent({ data }) {
  const first = data.samples?.[0];
  if (!first) return <DataRow label="Status" value={data.query_status} mono />;
  return (
    <>
      <DataRow label="Signature" value={first.signature} />
      <DataRow label="File type" value={first.file_type} mono />
      <DataRow label="File size" value={first.file_size ? `${first.file_size} bytes` : null} mono />
      <DataRow label="SHA256" value={first.sha256_hash} mono copyable />
      <DataRow label="First seen" value={first.first_seen} mono />
      <DataRow label="Delivery" value={first.delivery_method} />
      <DataRow label="Origin" value={first.origin_country} />
      <DataRow label="Tags" value={first.tags} />
    </>
  );
}

function PulsediveContent({ data }) {
  const risk = data.risk_recommended || data.risk;
  const riskColor = risk === 'critical' ? 'text-red-400' : risk === 'high' ? 'text-red-300'
    : risk === 'medium' ? 'text-yellow-300' : risk === 'low' ? 'text-emerald-300' : 'text-white/55';
  return (
    <>
      <DataRow label="Indicator" value={data.indicator} mono copyable />
      <DataRow label="Type" value={data.type} mono />
      <div className="flex justify-between py-1.5 border-b border-white/[0.04]">
        <span className="text-white/45 text-[11px] font-mono uppercase tracking-wider">Risk</span>
        <span className={`text-xs font-mono font-semibold uppercase ${riskColor}`}>{risk || 'none'}</span>
      </div>
      {data.threats?.length > 0 && (
        <div className="mt-3 space-y-1">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Threats</span>
          {data.threats.slice(0, 4).map((t, i) => (
            <div key={i} className="text-xs font-mono text-white/85 bg-black/30 border border-white/[0.05] rounded px-2 py-1">
              {t.name} {t.category && <span className="text-white/45">({t.category})</span>}
            </div>
          ))}
        </div>
      )}
      {data.feeds?.length > 0 && (
        <DataRow label="Feeds" value={data.feeds.map(f => f.name).filter(Boolean)} />
      )}
      {data.ports?.length > 0 && <DataRow label="Ports" value={data.ports} mono />}
    </>
  );
}

function URLhausContent({ data }) {
  const urls = data.urls || [];
  return (
    <>
      <DataRow label="Query status" value={data.query_status} mono />
      <DataRow label="URL count" value={data.url_count != null ? String(data.url_count) : null} mono />
      {urls.length > 0 && (
        <div className="mt-3 space-y-1">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Recent URLs</span>
          {urls.slice(0, 4).map((u, i) => (
            <div key={i} className="bg-black/30 border border-white/[0.05] rounded-lg p-2">
              <div className="text-[11px] font-mono text-orange-300 truncate">{u.url}</div>
              <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-white/55">
                {u.threat && <span>{u.threat}</span>}
                {u.url_status && <span className={u.url_status === 'online' ? 'text-red-400' : 'text-white/40'}>{u.url_status}</span>}
                {u.date_added && <span>{u.date_added.slice(0, 10)}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function DnsResolutionContent({ data }) {
  const ips = data.ip_addresses || data.ips || [];
  return (
    <>
      <DataRow label="Hostname" value={data.hostname || data.target} mono copyable />
      {ips.length > 0 && (
        <div className="mt-3 space-y-1">
          <span className="text-white/45 text-[10px] font-mono uppercase tracking-wider">Resolved IPs</span>
          {ips.map((ip, i) => (
            <div key={i} className="group/row text-xs font-mono text-white/85 bg-black/30 border border-white/[0.05] rounded px-2 py-1 flex items-center justify-between">
              {ip}
              <CopyButton text={ip} />
            </div>
          ))}
        </div>
      )}
    </>
  );
}

const CONTENT_MAP = {
  whois: WhoisContent,
  virustotal: VirusTotalContent,
  abuseipdb: AbuseIPDBContent,
  shodan: ShodanContent,
  alienvault_otx: OTXContent,
  ipinfo: IPInfoContent,
  greynoise: GreyNoiseContent,
  urlscan: URLscanContent,
  hybrid_analysis: HybridAnalysisContent,
  rdap: RDAPContent,
  circl_cve: CirclCveContent,
  threatfox: ThreatFoxContent,
  malwarebazaar: MalwareBazaarContent,
  pulsedive: PulsediveContent,
  dns_resolution: DnsResolutionContent,
  urlhaus: URLhausContent,
};

/* ─────────────────────────────────────────────────────────
   Main card — fully editorial:
   - hairline border at rest, gradient-border on hover
   - eyebrow-style label (mono caps, accent-tinted)
   - status badge sits inline with the source name
   - metadata row uses mono caps for labels
   ───────────────────────────────────────────────────────── */
export default function SourceCard({ source }) {
  const [expanded, setExpanded] = useState(true);
  const [logoFailed, setLogoFailed] = useState(false);
  const meta = SOURCE_META[source.source] || { label: source.source, icon: Database, accent: '#a78bfa', logo: null };
  const Icon = meta.icon;
  const isError = !!source.error;
  const ContentComponent = CONTENT_MAP[source.source];
  const status = deriveStatus(source);
  const badge = STATUS_BADGE[status];
  const showLogo = meta.logo && !logoFailed;

  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 12 },
        show:   { opacity: 1, y: 0, transition: { duration: 0.35, ease: [0.22, 1, 0.36, 1] } },
      }}
      className="gradient-border hairline rounded-xl overflow-hidden card-hover"
      style={{ background: 'linear-gradient(180deg, rgba(255,255,255,0.018), rgba(255,255,255,0.003))' }}
    >
      {/* Header — single row, accent on icon + label, status badge inline */}
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        className="w-full flex items-center gap-3 p-4 text-left transition-colors hover:bg-white/[0.025] cursor-pointer"
      >
        <div
          className="p-1.5 rounded-lg flex-shrink-0 border bg-white/[0.06]"
          style={{
            backgroundColor: showLogo ? 'rgba(255,255,255,0.06)' : `${meta.accent}14`,
            borderColor: `${meta.accent}33`,
            boxShadow: `0 0 14px ${meta.accent}22`,
          }}
        >
          {showLogo ? (
            <img
              src={meta.logo}
              alt={meta.label}
              className="w-5 h-5 object-contain rounded"
              onError={() => setLogoFailed(true)}
            />
          ) : (
            <Icon className="w-3.5 h-3.5" style={{ color: meta.accent }} strokeWidth={1.75} />
          )}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="font-display font-semibold text-[13px] tracking-tight2"
              style={{ color: meta.accent }}
            >
              {meta.label}
            </span>
            {!isError && badge && (
              <span className={`px-1.5 py-0.5 rounded-md text-[9px] font-mono font-semibold tracking-wider border ${badge.bg} ${badge.text} ${badge.border}`}>
                {badge.label}
              </span>
            )}
            {isError && (
              <span className="px-1.5 py-0.5 rounded-md text-[9px] font-mono font-semibold tracking-wider bg-white/[0.04] text-white/45 border border-white/10">
                UNAVAILABLE
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-1 text-[10px] font-mono text-white/40">
            {isError ? (
              <span className="flex items-center gap-1 text-red-400/80">
                <XCircle className="w-3 h-3" /> error
              </span>
            ) : (
              <span className="flex items-center gap-1 text-emerald-400/80">
                <CheckCircle className="w-3 h-3" /> retrieved
              </span>
            )}
            {source._query_time_ms != null && (
              <span className="flex items-center gap-1 tabular-nums">
                <Clock className="w-3 h-3" /> {source._query_time_ms}ms
              </span>
            )}
          </div>
        </div>

        {expanded
          ? <ChevronUp className="w-4 h-4 text-white/40 flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-white/40 flex-shrink-0" />}
      </button>

      {/* Body */}
      {expanded && !isError && ContentComponent && (
        <div className="px-4 pb-4 border-t border-white/[0.05]">
          <div className="pt-3">
            {_hasContent(source) ? (
              <ContentComponent data={source} />
            ) : (
              <div className="text-center py-3">
                <AlertCircle className="w-7 h-7 text-white/20 mx-auto mb-2" />
                <p className="text-white/45 text-xs font-mono">No information available for this source.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {expanded && isError && (
        <div className="px-4 pb-4 border-t border-white/[0.05]">
          <div className="pt-3 text-center py-3">
            <AlertCircle className="w-7 h-7 text-red-400/40 mx-auto mb-2" />
            <p className="text-white/45 text-xs font-mono">Data is not available from this source at this time.</p>
          </div>
        </div>
      )}
    </motion.div>
  );
}
