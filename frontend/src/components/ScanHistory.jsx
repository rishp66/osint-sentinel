import React from 'react';
import { Clock, Trash2 } from 'lucide-react';

const RISK_DOT = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-yellow-500',
  low:      'bg-blue-500',
  clean:    'bg-emerald-500',
  unknown:  'bg-gray-500',
};

export default function ScanHistory({ history, onSelect, onClear }) {
  if (!history || history.length === 0) {
    return (
      <div className="space-y-2.5">
        <div className="eyebrow flex items-center gap-1.5 text-sentinel-purple-light/70">
          <Clock className="w-3 h-3" strokeWidth={2} />
          History
        </div>
        <p className="text-[11px] font-mono text-white/35 leading-relaxed">
          No recent scans. Run a target above and it&apos;ll show up here.
        </p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="eyebrow flex items-center gap-1.5 text-sentinel-purple-light/70">
          <Clock className="w-3 h-3" strokeWidth={2} />
          History
          <span className="text-white/35 ml-1">{history.length}</span>
        </h3>
        {onClear && history.length > 0 && (
          <button
            onClick={onClear}
            className="text-white/40 hover:text-red-400 transition-colors cursor-pointer"
            title="Clear history"
            aria-label="Clear history"
          >
            <Trash2 className="w-3 h-3" />
          </button>
        )}
      </div>

      <div className="space-y-1">
        {history.map((item, i) => {
          const level = item.risk_level?.toLowerCase() || 'unknown';
          const dotClass = RISK_DOT[level] || RISK_DOT.unknown;
          return (
            <button
              key={`${item.target}-${i}`}
              onClick={() => onSelect(item.target)}
              className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-left hover:bg-white/[0.03] transition-all duration-200 group cursor-pointer"
            >
              <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dotClass}`} />
              <span className="font-mono text-[12px] text-white/85 truncate flex-1">{item.target}</span>
              <span className="text-[10px] font-mono text-white/35 opacity-0 group-hover:opacity-100 transition-opacity uppercase tracking-wider">
                {level}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
