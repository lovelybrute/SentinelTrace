/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        /* ---- Structural surfaces: deep navy, near-black ---- */
        base: '#02070D', // Updated to exact request
        surface: {
          DEFAULT: '#06111C', // Updated panel color
          raised: '#0A1726',
          overlay: '#0F1E33',
          inset: '#010408',
        },
        edge: {
          DEFAULT: '#162842',
          strong: '#223C60',
          bright: '#335682',
        },
        /* ---- Text ---- */
        ink: {
          DEFAULT: '#E8EDF6',
          dim: '#98A4BA',
          faint: '#66718A',
          ghost: '#434D62',
        },
        /* ---- Intelligence (cyan/blue/violet) ---- */
        intel: {
          DEFAULT: '#00D9FF', // Primary cyan
          soft: '#67E8F9',
          deep: '#0E7490',
          ink: '#083344',
        },
        forensic: {
          DEFAULT: '#8B5CF6', // Forensic violet
          soft: '#C4B5FD',
          deep: '#5B21B6',
        },
        azure: {
          DEFAULT: '#3B82F6',
          soft: '#93C5FD',
          deep: '#1D4ED8',
        },
        /* ---- Severity scale ---- */
        critical: {
          DEFAULT: '#FF334F', // Critical crimson
          soft: '#FF8496',
          deep: '#8E0C1E',
        },
        high: {
          DEFAULT: '#F59E0B', // Warning amber (used as high here)
          soft: '#FCD34D',
          deep: '#B45309',
        },
        medium: {
          DEFAULT: '#FBBF24',
          soft: '#FDE68A',
          deep: '#D97706',
        },
        low: {
          DEFAULT: '#38BDF8',
          soft: '#93D9FB',
          deep: '#075985',
        },
        safe: {
          DEFAULT: '#22C55E', // Safe green
          soft: '#86EFAC',
          deep: '#14532D',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          'Segoe UI Variable Display',
          'Segoe UI',
          'system-ui',
          '-apple-system',
          'Roboto',
          'Helvetica Neue',
          'sans-serif',
        ],
        mono: [
          'Cascadia Mono',
          'Cascadia Code',
          'JetBrains Mono',
          'Consolas',
          'SFMono-Regular',
          'Menlo',
          'ui-monospace',
          'monospace',
        ],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.02em' }],
      },
      borderRadius: {
        panel: '0.625rem',
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.8)',
        lift: '0 12px 40px -16px rgba(0,0,0,0.9)',
        'glow-critical': '0 0 0 1px rgba(255,59,82,0.35), 0 0 28px -6px rgba(255,59,82,0.35)',
        'glow-intel': '0 0 0 1px rgba(34,211,238,0.30), 0 0 24px -8px rgba(34,211,238,0.30)',
      },
      backgroundImage: {
        grid: 'linear-gradient(to right, rgba(148,163,184,0.055) 1px, transparent 1px), linear-gradient(to bottom, rgba(148,163,184,0.055) 1px, transparent 1px)',
        'fade-b': 'linear-gradient(to bottom, transparent, #05070C)',
      },
      backgroundSize: {
        grid: '44px 44px',
      },
      keyframes: {
        'fade-up': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        pulseDot: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
        sweep: {
          from: { transform: 'translateX(-100%)' },
          to: { transform: 'translateX(300%)' },
        },
        dash: {
          to: { strokeDashoffset: '-24' },
        },
        spinSlow: {
          to: { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        'fade-up': 'fade-up 0.28s cubic-bezier(0.22,1,0.36,1) both',
        'fade-in': 'fade-in 0.2s ease-out both',
        'pulse-dot': 'pulseDot 2s ease-in-out infinite',
        sweep: 'sweep 1.9s ease-in-out infinite',
        dash: 'dash 0.9s linear infinite',
        'spin-slow': 'spinSlow 9s linear infinite',
      },
    },
  },
  plugins: [],
};
