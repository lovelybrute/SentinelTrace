/**
 * ThreatGlobe – Interactive 3D threat-origin globe
 *
 * • react-globe.gl for globe (uses Three.js internally)
 * • Real data from /threat-by-country when available; demo arcs otherwise
 * • Tooltips with IP, country, ASN, timestamp, confidence
 * • Orbit, zoom, and click interactions built-in
 * • Pauses rendering when tab hidden
 * • Lazy-loaded by parent; no top-level imports that block the shell
 */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import Globe from 'react-globe.gl';
import type { GlobeMethods } from 'react-globe.gl';

/* ── Country centroid lookup for globe point positioning ── */
const COUNTRY_COORDS: Record<string, [number, number]> = {
  'China': [35.86, 104.19],
  'Russia': [61.52, 105.31],
  'United States': [37.09, -95.71],
  'India': [20.59, 78.96],
  'Nigeria': [9.08, 8.67],
  'Brazil': [-14.24, -51.92],
  'Ukraine': [48.38, 31.16],
  'Romania': [45.94, 24.96],
  'Vietnam': [14.06, 108.28],
  'Germany': [51.16, 10.45],
  'Netherlands': [52.13, 5.29],
  'France': [46.23, 2.21],
  'United Kingdom': [55.37, -3.43],
  'Turkey': [38.96, 35.24],
  'Iran': [32.42, 53.68],
  'Pakistan': [30.37, 69.34],
  'North Korea': [40.34, 127.51],
  'South Korea': [35.90, 127.77],
  'Japan': [36.20, 138.25],
  'Australia': [-25.27, 133.77],
};

interface ArcDatum {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
  label: string;
  score: number;
}

interface PointDatum {
  lat: number;
  lng: number;
  size: number;
  color: string;
  country: string;
  count: number;
  avgScore: number;
}

type TooltipData = PointDatum | null;

interface ThreatGlobeProps {
  countryThreats?: { country: string; email_count: number; average_threat_score: number }[];
  width?: number;
  height?: number;
}

function scoreColor(score: number): string {
  if (score >= 75) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#f59e0b';
  return '#22d3ee';
}

export default function ThreatGlobe({ countryThreats, width, height = 420 }: ThreatGlobeProps) {
  const globeRef = useRef<GlobeMethods>();
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(width ?? 500);
  const [arcsData, setArcsData] = useState<ArcDatum[]>([]);
  const [pointsData, setPointsData] = useState<PointDatum[]>([]);
  const [tooltip, setTooltip] = useState<TooltipData>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [initialized, setInitialized] = useState(false);

  // Responsive width
  useEffect(() => {
    if (width) { setContainerWidth(width); return; }
    const obs = new ResizeObserver(([entry]) => {
      setContainerWidth(entry.contentRect.width);
    });
    if (containerRef.current) obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, [width]);

  // Build data
  useEffect(() => {
    const points: PointDatum[] = [];
    const arcs: ArcDatum[] = [];

    if (countryThreats && countryThreats.length > 0) {
      // Real data from backend
      for (const ct of countryThreats) {
        const coords = COUNTRY_COORDS[ct.country];
        if (!coords) continue;
        const [lat, lng] = coords;
        points.push({
          lat, lng,
          size: Math.min(0.8, 0.1 + ct.email_count * 0.05),
          color: scoreColor(ct.average_threat_score),
          country: ct.country,
          count: ct.email_count,
          avgScore: ct.average_threat_score,
        });
      }
      // Build attack arcs between high-threat origins → target (India: SIH context)
      const TARGET: [number, number] = [20.59, 78.96];
      for (const pt of points.slice(0, 8)) {
        arcs.push({
          startLat: pt.lat, startLng: pt.lng,
          endLat: TARGET[0], endLng: TARGET[1],
          color: pt.color, label: pt.country,
          score: pt.avgScore,
        });
      }
    } else {
      // Demo mode: representative threat landscape
      const DEMO_THREATS = [
        { country: 'China', count: 42, score: 81 },
        { country: 'Russia', count: 38, score: 88 },
        { country: 'Nigeria', count: 27, score: 72 },
        { country: 'Ukraine', count: 19, score: 66 },
        { country: 'Romania', count: 14, score: 58 },
        { country: 'Vietnam', count: 11, score: 54 },
        { country: 'Iran', count: 9, score: 77 },
        { country: 'North Korea', count: 6, score: 91 },
        { country: 'Brazil', count: 8, score: 45 },
        { country: 'Turkey', count: 7, score: 50 },
      ];
      for (const t of DEMO_THREATS) {
        const coords = COUNTRY_COORDS[t.country];
        if (!coords) continue;
        const [lat, lng] = coords;
        points.push({
          lat, lng, size: 0.1 + t.count * 0.012,
          color: scoreColor(t.score),
          country: t.country, count: t.count, avgScore: t.score,
        });
      }
      const TARGET: [number, number] = [20.59, 78.96];
      for (const pt of points.slice(0, 6)) {
        arcs.push({
          startLat: pt.lat, startLng: pt.lng,
          endLat: TARGET[0], endLng: TARGET[1],
          color: pt.color, label: pt.country, score: pt.avgScore,
        });
      }
    }

    setPointsData(points);
    setArcsData(arcs);
  }, [countryThreats]);

  // Globe init after mount
  const onGlobeReady = useCallback(() => {
    if (!globeRef.current || initialized) return;
    setInitialized(true);
    const controls = globeRef.current.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.8;
    controls.enableDamping = true;
    globeRef.current.pointOfView({ lat: 20, lng: 78, altitude: 2.2 }, 0);
  }, [initialized]);

  // Pause auto-rotate on hidden
  useEffect(() => {
    const onVis = () => {
      if (!globeRef.current) return;
      const controls = globeRef.current.controls();
      controls.autoRotate = !document.hidden;
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, []);

  const isDemoMode = !countryThreats || countryThreats.length === 0;

  return (
    <div
      ref={containerRef}
      className="relative w-full"
      style={{ height }}
      onPointerMove={(event) => {
        if (tooltip) setTooltipPos({ x: event.clientX, y: event.clientY });
      }}
      onPointerLeave={() => setTooltip(null)}
    >
      <Globe
        ref={globeRef}
        width={containerWidth}
        height={height}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
        bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
        backgroundColor="rgba(0,0,0,0)"
        atmosphereColor="#00D9FF"
        atmosphereAltitude={0.15}
        onGlobeReady={onGlobeReady}

        /* Attack arcs */
        arcsData={arcsData}
        arcColor="color"
        arcDashLength={0.45}
        arcDashGap={0.22}
        arcDashAnimateTime={1800}
        arcStroke={0.5}
        arcAltitudeAutoScale={0.35}

        /* Origin points */
        pointsData={pointsData}
        pointColor="color"
        pointAltitude={0.03}
        pointRadius="size"
        pointsMerge={false}
        onPointClick={(pt) => {
          const p = pt as PointDatum;
          setTooltip(p);
        }}
        onPointHover={(pt: object | null) => {
          setTooltip(pt as PointDatum | null);
        }}
      />

      {/* Hover Tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 pointer-events-none"
          style={{ left: tooltipPos.x + 14, top: tooltipPos.y - 60 }}
        >
          <div className="bg-slate-950/95 border border-cyan-500/30 rounded-lg px-3 py-2 shadow-[0_0_20px_rgba(0,217,255,0.1)] backdrop-blur-md min-w-[160px]">
            <div className="font-mono text-xs font-bold text-cyan-400 mb-1">{tooltip.country}</div>
            <div className="flex justify-between text-[11px] gap-4">
              <span className="text-slate-400">Emails</span>
              <span className="font-semibold text-white">{tooltip.count}</span>
            </div>
            <div className="flex justify-between text-[11px] gap-4">
              <span className="text-slate-400">Avg Score</span>
              <span className="font-semibold" style={{ color: scoreColor(tooltip.avgScore) }}>
                {tooltip.avgScore.toFixed(0)}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Globe labels */}
      <div className="absolute top-3 left-3 flex items-center gap-2">
        <div className="font-mono text-[10px] font-bold text-cyan-400 bg-slate-950/70 px-2 py-1 rounded border border-cyan-500/20 backdrop-blur-md tracking-widest">
          THREAT ORIGIN GLOBE
        </div>
        {isDemoMode && (
          <div className="font-mono text-[9px] text-amber-400 bg-amber-950/50 px-2 py-1 rounded border border-amber-500/20">
            DEMO MODE
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="absolute bottom-3 right-3 flex flex-col gap-1 bg-slate-950/70 backdrop-blur-md rounded-lg p-2 border border-slate-700/40">
        {[
          { label: 'CRITICAL', color: '#ef4444' },
          { label: 'HIGH', color: '#f97316' },
          { label: 'MEDIUM', color: '#f59e0b' },
          { label: 'LOW', color: '#22d3ee' },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 5px ${color}` }} />
            <span className="font-mono text-[9px] text-slate-400">{label}</span>
          </div>
        ))}
      </div>

      {/* Controls hint */}
      <div className="absolute bottom-3 left-3 font-mono text-[9px] text-slate-600">
        DRAG · SCROLL · CLICK
      </div>
    </div>
  );
}
