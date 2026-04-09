/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Map Tailwind classes to CSS variables so light/dark just works
        bg:             'var(--color-bg)',
        surface:        'var(--color-surface)',
        'surface-hover':'var(--color-surface-hover)',
        'surface-active':'var(--color-surface-active)',
        'surface-offset':'var(--color-surface-offset)',
        border:         'var(--color-border)',
        text:           'var(--color-text)',
        'text-muted':   'var(--color-text-muted)',
        brand:          'var(--color-brand)',
        'brand-light':  'var(--color-brand-light)',
      },
      fontFamily: {
        sans: ['Satoshi', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'slide-in': 'slide-in 0.22s cubic-bezier(0.16,1,0.3,1) both',
        'fade-in':  'fade-in  0.15s ease both',
        'slide-up': 'slide-up 0.2s  ease both',
      },
      keyframes: {
        'slide-in': { from: { transform:'translateX(100%)', opacity:'0' }, to: { transform:'translateX(0)', opacity:'1' } },
        'fade-in':  { from: { opacity:'0' },                                to: { opacity:'1' } },
        'slide-up': { from: { transform:'translateY(8px)', opacity:'0' },  to: { transform:'translateY(0)', opacity:'1' } },
      },
    },
  },
  plugins: [],
}
