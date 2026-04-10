export function Logo({ size = 32 }) {
  const r = size / 2
  const cx = r
  const cy = r
  const outer = r * 0.875
  const inner = r * 0.5
  const dot   = r * 0.175
  const tick  = r * 0.12

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="InSpectre"
    >
      {/* Outer ring */}
      <circle cx={cx} cy={cy} r={outer} stroke="#4fa8b0" strokeWidth={size * 0.047} />

      {/* Sweep arc (teal, top-right quadrant) */}
      <path
        d={`M ${cx} ${cy - outer}
            A ${outer} ${outer} 0 0 1 ${cx + outer} ${cy}`}
        stroke="#0d9488"
        strokeWidth={size * 0.09}
        strokeLinecap="round"
        opacity="0.9"
      />

      {/* Dashed inner reticle ring */}
      <circle
        cx={cx} cy={cy} r={inner}
        stroke="#4fa8b0"
        strokeWidth={size * 0.031}
        strokeDasharray={`${size * 0.09} ${size * 0.06}`}
        opacity="0.55"
      />

      {/* Compass tick marks (N/S/E/W) */}
      {[[cx, cy - outer - 1, cx, cy - outer + tick],
        [cx, cy + outer - tick, cx, cy + outer + 1],
        [cx - outer - 1, cy, cx - outer + tick, cy],
        [cx + outer - tick, cy, cx + outer + 1, cy]
      ].map(([x1, y1, x2, y2], i) => (
        <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
          stroke="#4fa8b0" strokeWidth={size * 0.047} strokeLinecap="round" />
      ))}

      {/* Crosshair lines */}
      <line x1={cx} y1={cy - inner * 0.55} x2={cx} y2={cy + inner * 0.55}
        stroke="#4fa8b0" strokeWidth={size * 0.031} opacity="0.4" />
      <line x1={cx - inner * 0.55} y1={cy} x2={cx + inner * 0.55} y2={cy}
        stroke="#4fa8b0" strokeWidth={size * 0.031} opacity="0.4" />

      {/* Centre dot */}
      <circle cx={cx} cy={cy} r={dot} fill="#0d9488" />
    </svg>
  )
}
