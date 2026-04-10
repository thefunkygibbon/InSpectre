export function OnlineDot({ online, size = 'md' }) {
  const dim = size === 'sm' ? 'h-2 w-2' : 'h-2.5 w-2.5'
  if (online) {
    return (
      <span className={`relative flex ${dim}`}>
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-50`} />
        <span className={`relative inline-flex rounded-full ${dim} bg-emerald-500`} />
      </span>
    )
  }
  return <span className={`inline-flex rounded-full ${dim} bg-red-500/70`} />
}
