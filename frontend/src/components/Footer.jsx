import React from 'react';

export default function Footer() {
  return (
    <footer className="border-t border-white/[0.05] px-4 sm:px-10 lg:px-16 py-7 flex flex-col sm:flex-row items-center justify-between gap-4">
      {/* Logo lockup */}
      <div className="flex items-center gap-2.5">
        <div
          className="w-7 h-7 rounded-md flex items-center justify-center font-mono font-bold text-[11px] text-white"
          style={{ background: '#8b5cf6' }}
        >
          OS
        </div>
        <span className="font-mono text-[13px] font-bold tracking-tight text-white/90">
          OSINT<span className="font-normal text-white/50 ml-0.5">Sentinel</span>
        </span>
      </div>

      {/* Copyright */}
      <p className="font-mono text-[11px] text-white/30 text-center">
        © 2026 OSINT Sentinel · All rights reserved
      </p>

      {/* Version */}
      <p className="font-mono text-[11px] text-white/25">
        v1.0 · Built for SOC analysts
      </p>
    </footer>
  );
}
