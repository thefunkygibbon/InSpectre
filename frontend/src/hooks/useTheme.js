import { useState, useEffect } from 'react'

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
    const root = document.documentElement
    root.setAttribute('data-theme', theme)
    try { localStorage.setItem('inspectre-theme', theme) } catch (_) {}
  }, [theme])

  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-skin', skin)
    try { localStorage.setItem('inspectre-skin', skin) } catch (_) {}
  }, [skin])

  const toggle  = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  const setSkin = (s) => setSkinState(s)

  return { theme, toggle, isDark: theme === 'dark', skin, setSkin }
}
