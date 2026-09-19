/** @type {import('tailwindcss').Config} */
// "Graphite Glass" theme: frosted glass and soft neumorphic metal over brushed
// graphite. The `cyber-*` token names are kept so every component picks up the
// palette without being rewritten; only the values changed.
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#22252B',         // inset well
          panel: '#2A2E35',      // raised slate
          border: '#8E97A3',     // steel hairline (used at /20-/60)
          primary: '#A9C3DE',    // steel
          danger: '#E58585',     // garnet
          success: '#7FD1A8',    // jade
          warning: '#E2B36B',    // amber
          purple: '#D9C7A6',     // champagne
          muted: '#A4ACB8',
          peach: '#D9C7A6',
        },
        slate: {
          50: '#F7F8FA', 100: '#ECEFF3', 200: '#DDE1E7', 300: '#C4CAD3',
          400: '#A4ACB8', 500: '#8A93A0', 600: '#7C8592', 700: '#5A626D',
          800: '#3A3F48', 900: '#2A2E35', 950: '#22252B',
        },
      },
      fontFamily: {
        mono: ['"Geist Mono"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
        sans: ['Manrope', 'system-ui', 'sans-serif'],
        display: ['Sora', 'Manrope', 'system-ui', 'sans-serif'],
        serif: ['Sora', 'Manrope', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'glow-primary': '0 0 18px rgba(169, 195, 222, 0.22)',
        'glow-danger': '0 0 18px rgba(229, 133, 133, 0.22)',
        'glow-success': '0 0 18px rgba(127, 209, 168, 0.22)',
        'glow-warning': '0 0 18px rgba(226, 179, 107, 0.22)',
        'cyber-panel': '0 22px 56px -12px rgba(0, 0, 0, 0.4)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'none',
        'scan': 'none',
        'drift': 'drift 16s ease-in-out infinite',
        'drift-slow': 'drift 24s ease-in-out infinite',
      },
      keyframes: {
        drift: {
          '0%, 100%': { transform: 'translate3d(0, 0, 0)' },
          '50%': { transform: 'translate3d(0, -14px, 0)' },
        },
      },
    },
  },
  plugins: [],
}
