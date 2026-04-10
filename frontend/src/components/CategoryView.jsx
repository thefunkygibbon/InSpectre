/**
 * CategoryView.jsx
 * Renders devices grouped by their detected/overridden category.
 * Each group is a collapsible section with a coloured header.
 */
import { useState } from 'react'
import {
  Wifi, Server, Monitor, Laptop, Smartphone, Tv, Gamepad2,
  Camera, Printer, Cpu, Phone, HelpCircle, ChevronDown, ChevronRight,
  Router,
} from 'lucide-react'
import { groupDevicesByCategory, getDeviceCategory, CATEGORIES } from '../deviceCategories'
import { DeviceCard } from './DeviceCard'
import { DeviceRow  } from './DeviceRow'

// Map category icon string → Lucide component
const ICON_MAP = {
  router:  Router,
  server:  Server,
  monitor: Monitor,
  laptop:  Laptop,
  phone:   Smartphone,
  tv:      Tv,
  gamepad: Gamepad2,
  camera:  Camera,
  printer: Printer,
  cpu:     Cpu,
  help:    HelpCircle,
}

function getCatIcon(iconKey) {
  return ICON_MAP[iconKey] || HelpCircle
}

// Find the CATEGORIES entry for a group label
function catMetaForLabel(label) {
  return Object.values(CATEGORIES).find(c => c.label === label)
    || { color: '#6b7280', bgColor: 'rgba(107,114,128,0.12)', icon: 'help' }
}

function GroupHeader({ label, count, color, bgColor, iconKey, open, onToggle }) {
  const Icon = getCatIcon(iconKey)
  return (
    <button
      onClick={onToggle}
      className="w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors duration-150 hover:brightness-110"
      style={{ background: bgColor, border: `1px solid ${color}33` }}
    >
      <span
        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: `${color}22` }}
      >
        <Icon size={16} style={{ color }} />
      </span>
      <span className="flex-1 text-left font-semibold text-sm" style={{ color: 'var(--color-text)' }}>
        {label}
      </span>
      <span
        className="text-xs font-bold px-2 py-0.5 rounded-full"
        style={{ background: `${color}22`, color }}
      >
        {count}
      </span>
      {open
        ? <ChevronDown  size={14} style={{ color: 'var(--color-text-muted)', flexShrink: 0 }} />
        : <ChevronRight size={14} style={{ color: 'var(--color-text-muted)', flexShrink: 0 }} />
      }
    </button>
  )
}

function CategoryGroup({ label, devices, layout, onDeviceClick, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const meta = catMetaForLabel(label)

  return (
    <div className="space-y-3">
      <GroupHeader
        label={label}
        count={devices.length}
        color={meta.color}
        bgColor={meta.bgColor}
        iconKey={meta.icon}
        open={open}
        onToggle={() => setOpen(o => !o)}
      />

      {open && (
        layout === 'grid' ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 pl-2">
            {devices.map(d => (
              <DeviceCard key={d.mac_address} device={d} onClick={() => onDeviceClick(d)} />
            ))}
          </div>
        ) : (
          <div className="card overflow-hidden ml-2">
            <div
              className="grid grid-cols-[1.5rem_2fr_1fr_1fr_1fr_6rem] gap-4 px-4 py-2.5 border-b
                         text-xs font-semibold uppercase tracking-wider"
              style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}
            >
              <span />
              <span>Name / IP</span>
              <span>MAC</span>
              <span>Vendor</span>
              <span>Last Seen</span>
              <span>Status</span>
            </div>
            {devices.map((d, i) => (
              <DeviceRow
                key={d.mac_address}
                device={d}
                onClick={() => onDeviceClick(d)}
                striped={i % 2 === 1}
              />
            ))}
          </div>
        )
      )}
    </div>
  )
}

export function CategoryView({ devices, layout, onDeviceClick }) {
  const groups = groupDevicesByCategory(devices)

  if (!groups.size) {
    return (
      <div className="flex flex-col items-center text-center py-24 gap-4">
        <HelpCircle size={32} style={{ color: 'var(--color-text-muted)' }} />
        <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>No devices to categorise</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {[...groups.entries()].map(([label, devs]) => (
        <CategoryGroup
          key={label}
          label={label}
          devices={devs}
          layout={layout}
          onDeviceClick={onDeviceClick}
          defaultOpen={label !== 'Unknown'}
        />
      ))}
    </div>
  )
}
