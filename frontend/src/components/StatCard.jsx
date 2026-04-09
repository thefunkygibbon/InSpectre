export function StatCard({ label, value, icon: Icon, color = 'brand', sub }) {
  const colors = {
    brand:   'from-brand-500/10 to-brand-600/5 border-brand-500/20 text-brand-400',
    emerald: 'from-emerald-500/10 to-emerald-600/5 border-emerald-500/20 text-emerald-400',
    red:     'from-red-500/10 to-red-600/5 border-red-500/20 text-red-400',
    amber:   'from-amber-500/10 to-amber-600/5 border-amber-500/20 text-amber-400',
  }
  return (
    <div className={`card bg-gradient-to-br ${colors[color]} p-5 flex flex-col gap-3`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">{label}</span>
        {Icon && <Icon size={18} className={colors[color].split(' ').pop()} />}
      </div>
      <div className="flex items-end gap-2">
        <span className="text-3xl font-bold text-gray-50 tabular-nums leading-none">{value ?? '—'}</span>
        {sub && <span className="text-xs text-gray-500 mb-1">{sub}</span>}
      </div>
    </div>
  )
}
