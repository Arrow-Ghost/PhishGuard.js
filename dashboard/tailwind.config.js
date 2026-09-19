/** @type {import('tailwindcss').Config} */
// Apple dark-mode system look: flat grouped surfaces, system accent colours and
// SF-style type. The `cyber-*` token names are kept so every component picks up
// the palette without being rewritten; only the values changed.
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#1C1C1E',
          panel: '#2C2C2E',
          border: '#EBEBF5',
          primary: '#0A84FF',
          danger: '#FF453A',
          success: '#30D158',
          warning: '#FF9F0A',
          purple: '#BF5AF2',
          muted: '#8E8E93',
          peach: '#64D2FF',
        },
        slate: {
          50: '#F9F9FB', 100: '#F2F2F7', 200: '#E5E5EA', 300: '#D1D1D6',
          400: '#AEAEB2', 500: '#8E8E93', 600: '#636366', 700: '#48484A',
          800: '#2C2C2E', 900: '#1C1C1E', 950: '#121214',
        },
      },
      fontFamily: {
        mono: ['"Geist Mono"', '"SF Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', 'Inter', 'system-ui', 'sans-serif'],
        display: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Display"', 'Inter', 'system-ui', 'sans-serif'],
        serif: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Display"', 'Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'glow-primary': 'none',
        'glow-danger': 'none',
        'glow-success': 'none',
        'glow-warning': 'none',
        'cyber-panel': 'none',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'none',
        'scan': 'none',
        'drift': 'none',
        'drift-slow': 'none',
      },
    },
  },
  plugins: [],
}
