import { Star } from 'lucide-react'
import { api } from '../api'

/**
 * Star / important toggle button.
 * Calls the metadata PATCH endpoint and fires onToggled(updatedDevice)
 * with the response so the parent can update its state.
 */
export function StarButton({ device, onToggled, size = 16, className = '' }) {
  const important = Boolean(device.is_important)

  async function handleClick(e) {
    e.stopPropagation() // don't bubble to card click
    try {
      const updated = await api.updateMetadata(device.mac_address, {
        is_important: !important,
      })
      onToggled?.(updated)
    } catch (err) {
      console.error('Star toggle failed', err)
    }
  }

  return (
    <button
      onClick={handleClick}
      title={important ? 'Unwatch device' : 'Watch / mark important'}
      className={`transition-all ${className}`}
      style={{ color: important ? '#f59e0b' : 'var(--color-text-faint)', lineHeight: 0 }}
    >
      <Star
        size={size}
        fill={important ? '#f59e0b' : 'none'}
        stroke={important ? '#f59e0b' : 'currentColor'}
      />
    </button>
  )
}
