import { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { api, getToken } from '../api'

export default function ContainerConsole({ container }) {
  const terminalRef = useRef(null)
  const terminalInstanceRef = useRef(null)
  const [shell, setShell] = useState('/bin/sh')
  const [status, setStatus] = useState('disconnected')

  useEffect(() => {
    if (!terminalRef.current) return undefined
    const terminal = new XTerm({
      cursorBlink: true,
      convertEol: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 12,
      theme: {
        background: '#0b1020',
        foreground: '#e2e8f0',
        cursor: '#e2e8f0',
      },
    })
    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)
    terminal.open(terminalRef.current)
    terminalInstanceRef.current = terminal
    fitAddon.fit()
    terminal.writeln(`Connecting to ${container.name}…`)

    const socket = new WebSocket(api.dockerConsoleUrl(container.id, container.host_id, shell))
    socket.binaryType = 'arraybuffer'
    socket.onopen = () => {
      socket.send(JSON.stringify({ token: getToken() }))
      setStatus('connecting')
      fitAddon.fit()
      socket.send(`\u0000inspectre-resize:${JSON.stringify({ cols: terminal.cols, rows: terminal.rows })}`)
    }
    socket.onmessage = event => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data))
        setStatus('connected')
      } else {
        terminal.write(event.data)
        setStatus('error')
      }
    }
    socket.onerror = () => setStatus('error')
    socket.onclose = event => {
      setStatus(event.code === 1000 ? 'disconnected' : 'error')
      if (event.code === 4401) terminal.writeln('\r\nAuthentication failed. Sign in again to reconnect.')
      else if (event.code === 4404) terminal.writeln('\r\nDocker host or container not found.')
      else if (event.code !== 1000) terminal.writeln('\r\nConsole disconnected.')
    }
    const inputDisposable = terminal.onData(data => {
      if (socket.readyState === WebSocket.OPEN) socket.send(data)
    })
    const resizeDisposable = terminal.onResize(({ cols, rows }) => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(`\u0000inspectre-resize:${JSON.stringify({ cols, rows })}`)
      }
    })
    const resizeObserver = new ResizeObserver(() => fitAddon.fit())
    resizeObserver.observe(terminalRef.current)

    function resizeForViewport() {
      const viewport = window.visualViewport
      const terminalElement = terminalRef.current
      if (!viewport || !terminalElement) return

      const keyboardOpen = viewport.height < window.innerHeight * 0.8
      if (keyboardOpen) {
        const scrollContainer = terminalElement.closest('.overflow-y-auto')
        const visibleTop = viewport.offsetTop + 8
        const terminalTop = terminalElement.getBoundingClientRect().top
        if (terminalTop < visibleTop || terminalTop > viewport.offsetTop + viewport.height - 80) {
          if (scrollContainer) scrollContainer.scrollTop += terminalTop - visibleTop
          else terminalElement.scrollIntoView({ block: 'start' })
        }
        terminalElement.style.maxHeight = `calc(${Math.floor(viewport.height)}px - 180px)`
      } else {
        terminalElement.style.maxHeight = ''
      }
    }

    const viewport = window.visualViewport
    viewport?.addEventListener('resize', resizeForViewport)
    viewport?.addEventListener('scroll', resizeForViewport)
    resizeForViewport()
    terminal.focus()

    return () => {
      viewport?.removeEventListener('resize', resizeForViewport)
      viewport?.removeEventListener('scroll', resizeForViewport)
      resizeObserver.disconnect()
      inputDisposable.dispose()
      resizeDisposable.dispose()
      terminalInstanceRef.current = null
      socket.close()
      terminal.dispose()
    }
  }, [container.id, container.name, container.host_id, shell])

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 flex-wrap">
        <label className="text-xs text-text-muted flex items-center gap-2">
          Shell
          <select className="input text-xs py-1" value={shell} onChange={event => setShell(event.target.value)}>
            <option value="/bin/sh">/bin/sh</option>
            <option value="/bin/bash">/bin/bash</option>
            <option value="/bin/ash">/bin/ash</option>
          </select>
        </label>
        <span className={`text-xs ${status === 'connected' ? 'text-green-400' : status === 'error' ? 'text-red-400' : 'text-text-faint'}`}>
          {status}
        </span>
      </div>
      <p className="text-[11px] text-text-faint">
        Commands run as the container's configured user. Treat this as direct shell access. Traffic is proxied through Inspectre; the container must be running and include the selected shell.
      </p>
      <div
        ref={terminalRef}
        className="rounded-lg overflow-hidden p-2"
        style={{
          height: 'min(58vh, 560px)',
          minHeight: 120,
          maxHeight: 'calc(100dvh - 220px)',
          background: '#0b1020',
          border: '1px solid var(--color-border)',
          scrollMarginTop: 8,
        }}
        onClick={() => terminalInstanceRef.current?.focus()}
      />
    </div>
  )
}
