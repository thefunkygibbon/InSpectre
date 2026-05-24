import { useState, useEffect } from 'react'

// Custom event used to sync multiple useTheme() instances within the same tab
const SYNC_EVENT = 'inspectre:theme-sync'

export function useTheme() {
  const [theme, setTheme] = useState(() => {
    try {
      const stored = localStorage.getItem('inspectre-theme')
      if (stored) return stored
    } catch (_) {}
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  const [skin, setSkinState] = useState(() => {
    try { return localStorage.getItem('inspectre-skin') || 'spectre' } catch (_) {}
    return 'spectre'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem('inspectre-theme', theme) } catch (_) {}
    window.dispatchEvent(new CustomEvent(SYNC_EVENT, { detail: { key: 'theme', value: theme } }))
  }, [theme])

  useEffect(() => {
    document.documentElement.setAttribute('data-skin', skin)
    try { localStorage.setItem('inspectre-skin', skin) } catch (_) {}
    window.dispatchEvent(new CustomEvent(SYNC_EVENT, { detail: { key: 'skin', value: skin } }))
  }, [skin])

  // Sync state when another useTheme() instance (e.g. SettingsPanel) changes theme or skin
  useEffect(() => {
    function onSync(e) {
      if (e.detail.key === 'theme') setTheme(e.detail.value)
      if (e.detail.key === 'skin') setSkinState(e.detail.value)
    }
    window.addEventListener(SYNC_EVENT, onSync)
    return () => window.removeEventListener(SYNC_EVENT, onSync)
  }, [])

  const toggle  = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  const setSkin = (s) => setSkinState(s)

  return { theme, toggle, isDark: theme === 'dark', skin, setSkin }
}
