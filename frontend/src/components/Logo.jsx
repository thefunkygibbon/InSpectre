export function Logo({ size = 32 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="InSpectre">
      <rect width="32" height="32" rx="8" fill="url(#grad)"/>
      <circle cx="16" cy="16" r="5" stroke="white" strokeWidth="2"/>
      <circle cx="16" cy="16" r="10" stroke="white" strokeWidth="1.5" strokeDasharray="3 2" opacity="0.6"/>
      <circle cx="16" cy="16" r="2" fill="white"/>
      <defs>
        <linearGradient id="grad" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
          <stop stopColor="#0d9488"/>
          <stop offset="1" stopColor="#0f766e"/>
        </linearGradient>
      </defs>
    </svg>
  )
}
