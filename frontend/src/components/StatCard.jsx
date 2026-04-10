import { useEffect, useRef, useState } from 'react'

function useCountUp(target, duration = 600) {
  const [display, setDisplay] = useState(target ?? 0)
  const prev = useRef(target ?? 0)
  const raf  = useRef(null)

  useEffect(() => {
    if (target == null) return
    const from = prev.current
    const to   = Number(target)
    if (from === to) return
    const start = performance.now()
    const tick = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      // cubic ease-out
      const ease = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(from + (to - from) * ease))
      if (progress < 1) raf.current = requestAnimationFrame(tick)
      else prev.current = to
    }
    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [target, duration])

  return display
}

const COLOR_MAP = {
  brand:   { gradient: 'from-[color:var(--color-brand)]/10 to-transparent', icon: 'text-[color:var(--color-brand)]', blob: 'bg-[color:var(--color-brand)]/8' },
  emerald: { gradient: 'from-emerald-500/10 to-transparent', icon: 'text-emerald-400', blob: 'bg-emerald-500/8' },
  red:     { gradient: 'from-red-500/10 to-transparent',     icon: 'text-red-400',     blob: 'bg-red-500/8'     },
  amber:   { gradient: 'from-amber-500/10 to-transparent',   icon: 'text-amber-400',   blob: 'bg-amber-500/8'   },
}

export function StatCard({ label, value, icon: Icon, color = 'brand', sub }) {
  const counted = useCountUp(value)
  const c = COLOR_MAP[color] || COLOR_MAP.brand

  return (
    <div
      className={`card bg-gradient-to-br ${c.gradient} p-5 flex flex-col gap-3 relative overflow-hidden`}
      style={{
        '--stat-blob': c.blob,
      }}
    >
      {/* Glow blob */}
      <span
        className="pointer-events-none absolute bottom-0 right-0 w-24 h-24 rounded-full blur-2xl translate-x-6 translate-y-6"
        style={{ background: `color-mix(in srgb, var(--color-brand) 10%, transparent)` }}
        aria-hidden
      />

      <div className="flex items-center justify-between relative">
        <span className="text-xs font-medium text-[color:var(--color-text-muted)] uppercase tracking-wider">
          {label}
        </span>
        {Icon && (
          <span
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: `color-mix(in srgb, var(--color-brand) 12%, transparent)` }}
          >
            <Icon size={16} className={c.icon} />
          </span>
        )}
      </div>

      <div className="flex items-end gap-2 relative">
        <span
          className="text-3xl font-bold tabular-nums leading-none"
          style={{ color: 'var(--color-text)' }}
        >
          {value != null ? counted : '—'}
        </span>
        {sub && <span className="text-xs mb-1" style={{ color: 'var(--color-text-faint)' }}>{sub}</span>}
      </div>
    </div>
  )
}
