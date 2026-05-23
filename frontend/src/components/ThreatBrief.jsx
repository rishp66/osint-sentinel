import React from 'react';
import { ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle, CheckCircle, XCircle, Lightbulb } from 'lucide-react';

const RISK_CONFIG = {
  critical: {
    color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30',
    glow: '0 0 30px rgba(239,68,68,0.3)', icon: XCircle, barColor: 'bg-red-500',
  },
  high: {
    color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30',
    glow: '0 0 30px rgba(249,115,22,0.3)', icon: ShieldAlert, barColor: 'bg-orange-500',
  },
  medium: {
    color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30',
    glow: '0 0 30px rgba(234,179,8,0.25)', icon: AlertTriangle, barColor: 'bg-yellow-500',
  },
  low: {
    color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30',
    glow: '0 0 30px rgba(59,130,246,0.25)', icon: ShieldCheck, barColor: 'bg-blue-500',
  },
  clean: {
    color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30',
    glow: '0 0 30px rgba(16,185,129,0.25)', icon: CheckCircle, barColor: 'bg-emerald-500',
  },
  unknown: {
    color: 'text-sentinel-text-dim', bg: 'bg-sentinel-card', border: 'border-sentinel-border',
    glow: 'none', icon: ShieldQuestion, barColor: 'bg-sentinel-muted',
  },
};

export default function ThreatBrief({ brief }) {
  const level = brief.risk_level || 'unknown';
  const config = RISK_CONFIG[level] || RISK_CONFIG.unknown;
  const Icon = config.icon;

  return (
    <div className={`${config.bg} ${config.border} border rounded-2xl p-6`}
      style={{ boxShadow: config.glow }}>
      {/* Header row */}
      <div className="flex items-start gap-4 mb-5">
        <div className={`p-3 rounded-xl ${config.bg} border ${config.border} flex-shrink-0`}>
          <Icon className={`w-7 h-7 ${config.color}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2 flex-wrap">
            <h2 className="font-display text-xl font-bold text-white">Threat Assessment</h2>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono uppercase ${config.color} ${config.bg} border ${config.border}`}>
              {level}
            </span>
          </div>
          <p className="text-sentinel-text-dim text-sm font-body leading-relaxed">{brief.summary}</p>
        </div>
        {/* Risk score gauge */}
        <div className="flex-shrink-0 text-center">
          <div className={`w-20 h-20 rounded-full border-4 ${config.border} flex items-center justify-center`}
            style={{ boxShadow: config.glow }}>
            <span className={`font-display text-2xl font-extrabold ${config.color}`}>{brief.risk_score}</span>
          </div>
          <span className="text-sentinel-text-dim text-[10px] font-mono mt-1.5 block tracking-widest uppercase">Risk Score</span>
        </div>
      </div>

      {/* Risk bar */}
      <div className="h-1.5 bg-black/40 rounded-full overflow-hidden mb-6">
        <div className={`h-full ${config.barColor} rounded-full transition-all duration-1000`}
          style={{ width: `${brief.risk_score}%` }} />
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {brief.key_findings?.length > 0 && (
          <div>
            <h3 className="font-display font-semibold text-sm text-white mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-sentinel-purple" /> Key Findings
            </h3>
            <ul className="space-y-2">
              {brief.key_findings.map((f, i) => (
                <li key={i} className="flex gap-2 text-sm text-sentinel-text-dim">
                  <span className="text-sentinel-purple mt-1 flex-shrink-0">›</span>
                  <span className="font-body leading-relaxed">{f}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {brief.recommendations?.length > 0 && (
          <div>
            <h3 className="font-display font-semibold text-sm text-white mb-3 flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-sentinel-cyan" /> Recommendations
            </h3>
            <ul className="space-y-2">
              {brief.recommendations.map((r, i) => (
                <li key={i} className="flex gap-2 text-sm text-sentinel-text-dim">
                  <span className="text-sentinel-cyan mt-1 flex-shrink-0">›</span>
                  <span className="font-body leading-relaxed">{r}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
