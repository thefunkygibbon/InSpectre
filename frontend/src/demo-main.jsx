// Demo entry point — must import interceptor FIRST before anything uses fetch
import './demo-interceptor.js'
import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Banner to indicate demo mode
const banner = document.createElement('div')
banner.id = 'demo-mode-banner'
banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;z-index:9999;background:rgba(0,255,65,0.08);border-top:1px solid rgba(0,255,65,0.2);padding:4px 16px;font-size:11px;font-family:monospace;color:#00ff41;text-align:center;pointer-events:none;letter-spacing:0.08em;'
banner.textContent = '⚡ DEMO MODE — sample data only · buttons visible but actions disabled'
document.body.appendChild(banner)

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
