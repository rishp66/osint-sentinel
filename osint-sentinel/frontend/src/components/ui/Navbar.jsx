import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Globe, Eye } from 'lucide-react';

// Animated label that slides upward on hover (mini-navbar mechanic).
// The wrapper clips to exactly one line-height (h-5 = 20px); the inner
// flex-col holds two identical labels stacked vertically. On hover the
// whole column shifts up by 100% (one label height), revealing the
// bright-white label underneath.
function AnimatedNavLink({ href, to, children, onClick }) {
  const base = 'group relative inline-flex overflow-hidden h-5 cursor-pointer';

  const inner = (
    <div className="flex flex-col transition-transform duration-300 ease-out group-hover:-translate-y-full">
      <span className="shrink-0 h-5 flex items-center text-sm text-white/55">{children}</span>
      <span className="shrink-0 h-5 flex items-center text-sm text-white">{children}</span>
    </div>
  );

  if (to) {
    return (
      <Link to={to} className={base} onClick={onClick}>
        {inner}
      </Link>
    );
  }

  const handleClick = (e) => {
    e.preventDefault();
    onClick?.();
  };

  return (
    <a href={href} className={base} onClick={handleClick}>
      {inner}
    </a>
  );
}

const NAV_LINKS = [
  { label: 'Integrations', anchor: '#integrations' },
  { label: 'Capabilities', anchor: '#capabilities' },
  { label: 'Sample report', anchor: '#sample-report' },
];

export function Navbar({ health }) {
  const [isOpen, setIsOpen] = useState(false);
  const [shapeClass, setShapeClass] = useState('rounded-full');
  const shapeTimer = useRef(null);
  const location = useLocation();
  const navigate = useNavigate();
  const isOnConsole = location.pathname === '/console';
  const isOnline = health?.status === 'ok';
  const hasHealth = health !== null && health !== undefined;

  useEffect(() => {
    if (shapeTimer.current) clearTimeout(shapeTimer.current);
    if (isOpen) {
      setShapeClass('rounded-2xl');
    } else {
      shapeTimer.current = setTimeout(() => setShapeClass('rounded-full'), 300);
    }
    return () => { if (shapeTimer.current) clearTimeout(shapeTimer.current); };
  }, [isOpen]);

  // Close mobile menu on route change
  useEffect(() => { setIsOpen(false); }, [location.pathname]);

  const handleAnchorClick = (anchor) => {
    setIsOpen(false);
    if (location.pathname === '/') {
      const el = document.querySelector(anchor);
      el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
      navigate({ pathname: '/', hash: anchor });
      setTimeout(() => {
        const el = document.querySelector(anchor);
        el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 120);
    }
  };

  const logoMark = (
    <Link to="/" className="flex items-center gap-2.5 no-underline group" aria-label="OSINT Sentinel home">
      <div
        className="relative w-7 h-7 rounded-md bg-sentinel-purple/[0.1] border border-sentinel-purple/30 flex items-center justify-center flex-shrink-0 transition-all duration-200 group-hover:border-sentinel-purple/60"
        style={{ boxShadow: '0 0 12px rgba(139,92,246,0.2)' }}
      >
        <Globe className="w-3.5 h-3.5 text-sentinel-purple" strokeWidth={1.75} />
        <Eye
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-2 h-2 text-sentinel-purple-light"
          strokeWidth={2.5}
          style={{ filter: 'drop-shadow(0 0 3px rgba(167,139,250,0.9))' }}
        />
      </div>
      <span className="font-display text-[14px] font-bold tracking-[-0.02em] text-white leading-none whitespace-nowrap">
        OSINT<span className="serif-italic font-normal ml-1">Sentinel</span>
      </span>
    </Link>
  );


  return (
    <header
      className={`fixed top-5 left-1/2 -translate-x-1/2 z-50 flex flex-col items-center
        pl-4 pr-4 py-2.5 backdrop-blur-md
        border bg-[rgba(8,8,11,0.82)]
        w-[calc(100%-2rem)] sm:w-auto
        transition-[border-radius] duration-300
        ${shapeClass}
        ${isOpen ? 'border-sentinel-purple/20' : 'border-sentinel-purple/15'}`}
      style={{ boxShadow: '0 0 24px rgba(139,92,246,0.08), 0 1px 0 rgba(255,255,255,0.04) inset' }}
    >
      {/* ── Main row ────────────────────────────────────── */}
      <div className="flex items-center justify-between w-full gap-x-5 sm:gap-x-7">
        {logoMark}

        {/* Desktop nav links */}
        <nav className="hidden sm:flex items-center gap-5 text-sm">
          {NAV_LINKS.map((link) => (
            <AnimatedNavLink
              key={link.anchor}
              href={location.pathname === '/' ? link.anchor : undefined}
              onClick={() => handleAnchorClick(link.anchor)}
            >
              {link.label}
            </AnimatedNavLink>
          ))}
        </nav>

        {/* Desktop action buttons */}
        <div className="hidden sm:flex items-center gap-2.5">
          {/* Health status pill */}
          {hasHealth && (
            <div
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono uppercase tracking-[0.15em] border transition-all
                ${isOnline
                  ? 'border-emerald-500/25 bg-emerald-500/[0.05] text-emerald-300/80'
                  : 'border-red-500/25 bg-red-500/[0.06] text-red-300/80'}`}
            >
              {isOnline
                ? <span className="status-dot" />
                : <span className="w-1.5 h-1.5 rounded-full bg-red-400" />}
              <span>{isOnline ? 'online' : 'offline'}</span>
            </div>
          )}
        </div>

        {/* Mobile hamburger */}
        <button
          className="sm:hidden flex items-center justify-center w-8 h-8 text-white/60 hover:text-white transition-colors focus:outline-none"
          onClick={() => setIsOpen(!isOpen)}
          aria-label={isOpen ? 'Close menu' : 'Open menu'}
        >
          {isOpen ? (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {/* ── Mobile dropdown ─────────────────────────────── */}
      <div
        className={`sm:hidden flex flex-col items-center w-full transition-all duration-300 ease-in-out overflow-hidden
          ${isOpen ? 'max-h-96 opacity-100 pt-4 pb-1' : 'max-h-0 opacity-0 pt-0 pointer-events-none'}`}
      >
        <nav className="flex flex-col items-center gap-4 w-full mb-4">
          {NAV_LINKS.map((link) => (
            <button
              key={link.anchor}
              className="text-white/60 hover:text-white font-mono text-sm transition-colors w-full text-center py-1"
              onClick={() => handleAnchorClick(link.anchor)}
            >
              {link.label}
            </button>
          ))}
        </nav>
        <div className="flex flex-col items-center gap-3 w-full pb-2">
          {hasHealth && (
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[10px] font-mono uppercase tracking-[0.15em] border ${isOnline ? 'border-emerald-500/25 text-emerald-300' : 'border-red-500/25 text-red-300'}`}>
              {isOnline ? <span className="status-dot" /> : <span className="w-1.5 h-1.5 rounded-full bg-red-400" />}
              {isOnline ? 'API online' : 'API offline'}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
