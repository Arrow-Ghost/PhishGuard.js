import React, { useMemo } from 'react';

/**
 * The brushed-graphite scene behind every glass panel: a mid-dark metal
 * ground with fine horizontal grain, soft steel and champagne light pools for
 * the glass to refract, and a few chrome spheres and rings. Decorative only.
 * (File name kept so App.jsx keeps importing it unchanged.)
 */

function seeded(seed) {
  let s = seed;
  return () => { s = (s * 16807) % 2147483647; return s / 2147483647; };
}

const chrome = (size) => ({
  width: size,
  height: size,
  background: 'radial-gradient(circle at 34% 30%, #F4F7FA 0%, #B9C4D0 28%, #5A626D 62%, #2B2F36 100%)',
  boxShadow: `0 ${Math.round(size * 0.16)}px ${Math.round(size * 0.4)}px rgba(0,0,0,0.5)`,
});

const SPHERES = [
  { left: '74%', top: '97%', size: 130, slow: true },
  { left: '13%', top: '78%', size: 96, slow: true },
  { left: '46%', top: '1%', size: 36 },
  { left: '95%', top: '72%', size: 60 },
];

const RINGS = [
  { left: '28%', top: '88%', size: 210, stroke: 13 },
  { left: '90%', top: '44%', size: 170, stroke: 9 },
];

export default function DreamBackdrop() {
  const grain = useMemo(() => {
    const r = seeded(7);
    return Array.from({ length: 200 }, () => ({
      y: r() * 900, dy: r() * 2 - 1, o: 0.012 + r() * 0.03, w: 0.5 + r() * 1.2,
    }));
  }, []);

  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
      style={{ background: 'linear-gradient(135deg, #2C3037 0%, #262A31 50%, #22252B 100%)' }}>
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <filter id="gb-blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="90" /></filter>
          <radialGradient id="gb-vig" cx="0.5" cy="0.5" r="0.75">
            <stop offset="0" stopColor="#1C1E23" stopOpacity="0" />
            <stop offset="1" stopColor="#16181C" stopOpacity="0.5" />
          </radialGradient>
        </defs>

        {grain.map((g, i) => (
          <line key={i} x1="0" y1={g.y} x2="1440" y2={g.y + g.dy} stroke="#FFFFFF" strokeOpacity={g.o} strokeWidth={g.w} />
        ))}

        <g filter="url(#gb-blur)">
          <circle cx="120" cy="80" r="340" fill="#6F8FB0" fillOpacity="0.32" />
          <circle cx="1180" cy="200" r="260" fill="#B79B6A" fillOpacity="0.18" />
          <circle cx="1240" cy="820" r="320" fill="#5E7FA6" fillOpacity="0.24" />
          <circle cx="260" cy="880" r="250" fill="#8A7550" fillOpacity="0.15" />
        </g>

        <rect width="1440" height="900" fill="url(#gb-vig)" />
      </svg>

      {RINGS.map((r, i) => (
        <span key={i} className="absolute rounded-full"
          style={{
            left: r.left, top: r.top, width: r.size, height: r.size,
            transform: 'translate(-50%, -50%)',
            border: `${r.stroke}px solid transparent`,
            background: 'linear-gradient(#2A2E35,#2A2E35) padding-box, linear-gradient(135deg,#E8EDF2,#6C7580 50%,#2F343B) border-box',
            boxShadow: '0 14px 26px rgba(0,0,0,0.45)',
            opacity: 0.85,
          }} />
      ))}

      {SPHERES.map((s, i) => (
        <span key={i} className={`absolute rounded-full ${s.slow ? 'animate-drift-slow' : 'animate-drift'}`}
          style={{ left: s.left, top: s.top, ...chrome(s.size), transform: 'translate(-50%, -50%)' }} />
      ))}
    </div>
  );
}
