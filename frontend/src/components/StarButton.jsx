import { Star } from 'lucide-react'

/**
 * StarButton — toggle is_important on a device.
 * Calls onToggle(mac, newValue) and optimistically updates UI.
 */
export function StarButton({ device, onToggle, size = 16 }) {
  const active = Boolean(device.is_important)

  function handleClick(e) {
    e.stopPropagation()
    onToggle(device.mac_address, !active)
  }

  return (
    <button
      onClick={handleClick}
      aria-label={active ? 'Unwatch device' : 'Watch device'}
      title={active ? 'Remove from watched devices' : 'Mark as watched device'}
      className="transition-all duration-150 rounded-md p-1 hover:scale-110"
      style={{
        color: active ? 'var(--color-brand)' : 'var(--color-text-faint)',
        background: active ? 'var(--color-brand-subtle, rgba(99,102,241,0.1))' : 'transparent',
      }}
    >
      <Star
        size={size}
        fill={active ? 'currentColor' : 'none'}
        strokeWidth={active ? 0 : 1.5}
      />
    </button>
  )
}
