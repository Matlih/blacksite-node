/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        // Strict monospace stack — all data, inputs, and tables render in mono.
        // Prevents character-width ambiguity attacks in password display.
        mono: ['"JetBrains Mono"', '"Cascadia Code"', '"Fira Code"', 'Consolas', 'monospace'],
        sans: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        // Tactical palette — no neon, no consumer gradients.
        // Gunmetal surface layer (deepest background)
        gunmetal: {
          900: '#0d0f12',
          800: '#13161b',
          700: '#1a1e25',
          600: '#22272f',
        },
        // Slate operational layer (panels, cards)
        ops: {
          900: '#161a20',
          800: '#1e232b',
          700: '#252b35',
          600: '#2e3540',
          500: '#3a4250',
        },
        // Muted amber — warnings, caution states, failed attempts
        amber: {
          dim: '#7a5c00',
          muted: '#b88a00',
          warn: '#d4a017',
          alert: '#e6b422',
        },
        // Slate blue — active states, confirmations, primary actions
        blue: {
          dim: '#1a2a3a',
          muted: '#2a4a6a',
          ops: '#3a6a9a',
          active: '#4a8ab8',
        },
        // Tactical red — critical failures, lockout states
        red: {
          dim: '#3a0a0a',
          muted: '#6a1a1a',
          alert: '#c0392b',
          critical: '#e74c3c',
        },
        // Off-white text — no pure white (reduces eye strain in dark ops environments)
        slate: {
          text: '#c8cdd6',
          dim: '#8892a0',
          label: '#6b7280',
        },
      },
      borderWidth: {
        DEFAULT: '1px',
      },
      animation: {
        'blink': 'blink 1s step-end infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
