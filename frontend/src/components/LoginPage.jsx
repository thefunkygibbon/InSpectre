import { useState } from 'react'
import { Lock, User, Eye, EyeOff } from 'lucide-react'
import { Logo } from './Logo'
import { api, setToken } from '../api'

export function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!username.trim() || !password) return
    setError('')
    setLoading(true)
    try {
      const data = await api.login(username.trim().toLowerCase(), password)
      setToken(data.token)
      onLogin(data.must_change_password ?? false)
    } catch (err) {
      setError('Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4"
         style={{ background: 'var(--color-bg)' }}>
      <div className="noise-overlay" />
      <div className="header-glow" />

      <div className="relative z-10 w-full max-w-sm">
        <div className="flex flex-col items-center gap-3 mb-8">
          <Logo size={48} />
          <div className="text-center">
            <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text)' }}>InSpectre</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>Network Security Suite</p>
          </div>
        </div>

        <div className="card p-6 space-y-4">
          <h2 className="text-base font-semibold" style={{ color: 'var(--color-text)' }}>Sign in</h2>

          <form onSubmit={handleSubmit} className="space-y-3">
            <div className="relative">
              <User size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                style={{ color: 'var(--color-text-muted)' }} />
              <input
                className="input pl-9 w-full"
                placeholder="Username"
                autoComplete="username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="relative">
              <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                style={{ color: 'var(--color-text-muted)' }} />
              <input
                className="input pl-9 pr-10 w-full"
                placeholder="Password"
                type={showPw ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPw(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 opacity-50 hover:opacity-100 transition-opacity"
                tabIndex={-1}
              >
                {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>

            {error && (
              <p className="text-xs px-1" style={{ color: '#ef4444' }}>{error}</p>
            )}

            <button
              type="submit"
              disabled={loading || !username.trim() || !password}
              className="w-full py-2.5 px-4 rounded-xl font-semibold text-sm transition-all"
              style={{
                background: 'var(--color-brand)',
                color: 'white',
                opacity: loading || !username.trim() || !password ? 0.6 : 1,
              }}
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>

        <p className="text-center text-xs mt-6" style={{ color: 'var(--color-text-faint)' }}>
          InSpectre &copy; {new Date().getFullYear()}
        </p>
      </div>
    </div>
  )
}
