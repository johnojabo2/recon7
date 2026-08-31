/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        void: 'rgb(var(--bg-void-rgb) / <alpha-value>)',
        panel: {
          DEFAULT: 'rgb(var(--bg-panel-rgb) / <alpha-value>)',
          elevated: 'rgb(var(--bg-panel-elevated-rgb) / <alpha-value>)',
          subtle: 'rgb(var(--bg-panel-subtle-rgb) / <alpha-value>)',
        },
        border: {
          dim: 'rgb(var(--border-dim-rgb) / <alpha-value>)',
          bright: 'rgb(var(--border-bright-rgb) / <alpha-value>)',
          glow: 'rgba(0, 240, 255, 0.3)',
        },
        cyan: {
          signal: 'rgb(var(--cyan-signal-rgb) / <alpha-value>)',
          glow: 'rgba(0, 240, 255, 0.15)',
        },
        magenta: {
          alert: 'rgb(var(--magenta-alert-rgb) / <alpha-value>)',
          glow: 'rgba(255, 46, 136, 0.15)',
        },
        success: {
          green: 'rgb(var(--success-green-rgb) / <alpha-value>)',
          glow: 'rgba(0, 255, 156, 0.15)',
        },
        text: {
          primary: 'rgb(var(--text-primary-rgb) / <alpha-value>)',
          dim: 'rgb(var(--text-dim-rgb) / <alpha-value>)',
          muted: 'rgb(var(--text-muted-rgb) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['Space Grotesk', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(0, 240, 255, 0.25)',
        'glow-cyan-sm': '0 0 10px rgba(0, 240, 255, 0.2)',
        'glow-magenta': '0 0 20px rgba(255, 46, 136, 0.25)',
        'glow-magenta-sm': '0 0 10px rgba(255, 46, 136, 0.2)',
        'glow-green': '0 0 15px rgba(0, 255, 156, 0.2)',
        'panel': '0 4px 20px rgba(0, 0, 0, 0.5)',
      },
      animation: {
        'pulse-cyan': 'pulse-cyan 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'flash-magenta': 'flash-magenta 1.5s ease-out forwards',
        'subtle-pulse': 'subtle-pulse 3s infinite',
      },
      keyframes: {
        'pulse-cyan': {
          '0%, 100%': {
            boxShadow: '0 0 15px rgba(0, 240, 255, 0.4), inset 0 0 10px rgba(0, 240, 255, 0.2)',
            borderColor: '#00F0FF',
          },
          '50%': {
            boxShadow: '0 0 5px rgba(0, 240, 255, 0.1), inset 0 0 2px rgba(0, 240, 255, 0.05)',
            borderColor: 'rgba(0, 240, 255, 0.5)',
          },
        },
        'flash-magenta': {
          '0%': {
            boxShadow: '0 0 25px rgba(255, 46, 136, 0.8)',
            borderColor: '#FF2E88',
            backgroundColor: 'rgba(255, 46, 136, 0.2)',
          },
          '100%': {
            boxShadow: 'none',
            borderColor: '#232330',
            backgroundColor: 'transparent',
          },
        },
        'subtle-pulse': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
      },
    },
  },
  plugins: [],
}
