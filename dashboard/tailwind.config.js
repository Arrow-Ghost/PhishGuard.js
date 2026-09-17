/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0e17',         // Clean slate-950 obsidian base
          panel: '#161b26',      // Professional deep grey/blue panel
          border: '#242b3d',     // Crisp, minimalist slate outline
          primary: '#4f46e5',    // Indigo-600 (Corporate blue-purple)
          danger: '#f43f5e',     // Rose-500 (Clean red alert)
          success: '#10b981',    // Emerald-500 (Clean green status)
          warning: '#f59e0b',    // Amber-500 (Amber warning indicator)
          purple: '#8b5cf6',     // Violet-500 (Accent)
          muted: '#6b7280'       // Cool neutral slate text
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Inter', 'sans-serif'] // Remove sci-fi Orbitron display font
      },
      boxShadow: {
        'glow-primary': '0 2px 8px rgba(79, 70, 229, 0.08)',
        'glow-danger': '0 2px 8px rgba(244, 63, 94, 0.08)',
        'glow-success': '0 2px 8px rgba(16, 185, 129, 0.08)',
        'glow-warning': '0 2px 8px rgba(245, 158, 11, 0.08)',
        'cyber-panel': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'none',
        'scan': 'none',
      },
      keyframes: {
        glowPulse: {
          '0%': { boxShadow: 'none' },
          '100%': { boxShadow: 'none' }
        },
        scanLine: {
          '0%': { transform: 'none' },
          '100%': { transform: 'none' }
        }
      }
    },
  },
  plugins: [],
}
