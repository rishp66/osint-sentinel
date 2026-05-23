/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        sentinel: {
          black: '#000000',
          // graded surfaces let us layer cards without harsh #000 stair-stepping
          ink: '#08080b',
          dark: '#0d0d12',
          card: '#0f1018',
          surface: '#15161f',
          border: '#1f2030',
          muted: '#374151',
          purple: '#8b5cf6',
          'purple-light': '#a78bfa',
          'purple-glow': '#8b5cf633',
          'purple-dim': '#4c1d95',
          cyan: '#67e8f9',
          accent: '#67e8f9',
          // amber + crimson give us a real alert vocabulary for IOC results
          amber: '#f59e0b',
          crimson: '#ef4444',
          green: '#10b981',
          text: '#ffffff',
          'text-dim': '#9ca3af',
          'text-mute': '#6b7280',
        }
      },
      fontFamily: {
        // Space Grotesk for the modern sans display work — distinctive but restrained
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        // Instrument Serif italic carries the editorial brand-mark accent on "Sentinel"
        serif: ['"Instrument Serif"', 'Georgia', 'serif'],
        // Inter Variable resolves first via @fontsource-variable/inter; falls back to static Inter
        body: ['"Inter Variable"', '"Inter"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
      },
      letterSpacing: {
        tightest: '-0.04em',
        tighter: '-0.02em',
        tight2: '-0.01em',
        wider2: '0.15em',
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'scan-line': 'scanLine 1.5s ease-in-out infinite',
        'fade-up': 'fadeUp 0.5s ease-out',
        'grid-scroll': 'gridScroll 20s linear infinite',
        'float': 'float 6s ease-in-out infinite',
        'radar-spin': 'radarSpin 4s linear infinite',
        'soft-pulse': 'softPulse 2.6s ease-in-out infinite',
        'ping-radar': 'pingRadar 2.8s cubic-bezier(0,0,0.2,1) infinite',
        'ticker': 'ticker 22s linear infinite',
        'caret-blink': 'caretBlink 1.1s steps(2, start) infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 20px rgba(139,92,246,0.4)' },
          '50%': { boxShadow: '0 0 60px rgba(139,92,246,0.8)' },
        },
        scanLine: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        gridScroll: {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '0 40px' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        radarSpin: {
          to: { transform: 'rotate(360deg)' },
        },
        softPulse: {
          '0%, 100%': { opacity: '0.55', transform: 'scale(1)' },
          '50%':      { opacity: '1',    transform: 'scale(1.08)' },
        },
        pingRadar: {
          '0%':   { transform: 'scale(0.4)', opacity: '0.9' },
          '80%':  { transform: 'scale(2.6)', opacity: '0' },
          '100%': { transform: 'scale(2.6)', opacity: '0' },
        },
        ticker: {
          '0%':   { transform: 'translateY(0%)' },
          '100%': { transform: 'translateY(-50%)' },
        },
        caretBlink: {
          to: { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
}
