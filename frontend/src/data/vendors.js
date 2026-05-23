const FAV = (domain) => `https://www.google.com/s2/favicons?domain=${domain}&sz=128`;

export const VENDORS = [
  { id: 'virustotal',     name: 'VirusTotal',      logo: FAV('virustotal.com'),        href: 'https://www.virustotal.com' },
  { id: 'abuseipdb',      name: 'AbuseIPDB',       logo: FAV('abuseipdb.com'),         href: 'https://www.abuseipdb.com' },
  { id: 'shodan',         name: 'Shodan',          logo: FAV('shodan.io'),             href: 'https://www.shodan.io' },
  { id: 'alienvault',     name: 'AlienVault OTX',  logo: FAV('otx.alienvault.com'),    href: 'https://otx.alienvault.com' },
  { id: 'greynoise',      name: 'GreyNoise',       logo: FAV('greynoise.io'),          href: 'https://www.greynoise.io' },
  { id: 'threatfox',      name: 'ThreatFox',       logo: FAV('threatfox.abuse.ch'),    href: 'https://threatfox.abuse.ch' },
  { id: 'hybridanalysis', name: 'Hybrid Analysis', logo: FAV('hybrid-analysis.com'),   href: 'https://www.hybrid-analysis.com' },
  { id: 'pulsedive',      name: 'Pulsedive',       logo: FAV('pulsedive.com'),         href: 'https://pulsedive.com' },
  { id: 'urlscan',        name: 'URLScan',         logo: FAV('urlscan.io'),            href: 'https://urlscan.io' },
  { id: 'malwarebazaar',  name: 'MalwareBazaar',   logo: FAV('bazaar.abuse.ch'),       href: 'https://bazaar.abuse.ch' },
  { id: 'urlhaus',        name: 'URLHaus',         logo: FAV('urlhaus.abuse.ch'),      href: 'https://urlhaus.abuse.ch' },
  { id: 'circl',          name: 'CIRCL CVE',       logo: FAV('cve.circl.lu'),          href: 'https://cve.circl.lu' },
  { id: 'whois',          name: 'WHOIS',           logo: FAV('iana.org'),              href: 'https://www.iana.org/whois' },
  { id: 'ipinfo',         name: 'IPInfo',          logo: FAV('ipinfo.io'),             href: 'https://ipinfo.io' },
];
