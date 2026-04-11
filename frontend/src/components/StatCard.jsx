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
  brand:   { gradient: 'from-[color:var(--color-brand)]/10 to-transparent', icon: 'text-[color:var(--color-brand)]', ring: 'var(--color-brand)'   },
  emerald: { gradient: 'from-emerald-500/10 to-transparent',                icon: 'text-emerald-400',               ring: 'rgb(16,185,129)'      },
  red:     { gradient: 'from-red-500/10 to-transparent',                    icon: 'text-red-400',                   ring: 'rgb(239,68,68)'       },
  amber:   { gradient: 'from-amber-500/10 to-transparent',                  icon: 'text-amber-400',                 ring: 'rgb(245,158,11)'      },
}

export function StatCard({ label, value, icon: Icon, color = 'brand', sub, onClick, active }) {
  const counted = useCountUp(value)
  const c = COLOR_MAP[color] || COLOR_MAP.brand
  const isClickable = typeof onClick === 'function'

  return (
    <div
      onClick={onClick}
      role={isClickable ? 'button' : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onKeyDown={isClickable ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick() } } : undefined}
      aria-pressed={isClickable ? active : undefined}
      className={`card bg-gradient-to-br ${c.gradient} p-5 flex flex-col gap-3 relative overflow-hidden transition-all duration-150
        ${isClickable ? 'cursor-pointer select-none hover:brightness-105 active:scale-[0.98]' : ''}
      `}
      style={{
        outline: active ? `2px solid ${c.ring}` : '2px solid transparent',
        outlineOffset: '2px',
        boxShadow: active ? `0 0 0 4px color-mix(in srgb, ${c.ring} 15%, transparent)` : undefined,
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
            style={{ background: `color-mix(in srgb, ${c.ring} 15%, transparent)` }}
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

      {isClickable && (
        <span
          className="absolute bottom-2 right-3 text-[10px] font-medium uppercase tracking-wider opacity-40"
          style={{ color: c.ring }}
        >
          {active ? 'filtering ✕' : 'click to filter'}
        </span>
      )}
    </div>
  )
}
