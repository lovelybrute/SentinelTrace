import React, { useEffect, useRef, useState } from 'react';
import { Sparkles, Shield, ChevronRight, Zap } from 'lucide-react';

interface TeamBruteIntroProps {
  onComplete: () => void;
  forcePlay?: boolean;
}

export function TeamBruteIntro({ onComplete, forcePlay = false }: TeamBruteIntroProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [stage, setStage] = useState<number>(0);
  const [skipped, setSkipped] = useState(false);
  const animFrameRef = useRef<number | null>(null);

  useEffect(() => {
    // Check user preferences
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const introDisabled = localStorage.getItem('sentineltrace_intro_enabled') === 'false';
    const introSeen = localStorage.getItem('sentineltrace_intro_seen') === 'true';

    if (!forcePlay && (prefersReducedMotion || introDisabled || introSeen)) {
      onComplete();
      return;
    }

    // Mark as seen for subsequent regular visits
    localStorage.setItem('sentineltrace_intro_seen', 'true');

    // If reduced motion is requested, transition immediately
    if (prefersReducedMotion) {
      onComplete();
      return;
    }

    // Animation timing milestones (0s to 3.0s)
    const timers = [
      setTimeout(() => setStage(1), 200),  // 0.2s: Crimson Particle
      setTimeout(() => setStage(2), 500),  // 0.5s: Flowing Crimson Digital Fluid
      setTimeout(() => setStage(3), 1000), // 1.0s: TEAM BRUTE
      setTimeout(() => setStage(4), 1500), // 1.5s: Digital Scan
      setTimeout(() => setStage(5), 1800), // 1.8s: SENTINELTRACE
      setTimeout(() => setStage(6), 2200), // 2.2s: AI EMAIL FORENSICS
      setTimeout(() => setStage(7), 2500), // 2.5s: 3D Cyber Network Grid
      setTimeout(() => {
        setStage(8);
        setTimeout(onComplete, 350);       // 3.0s: Finish & Open App
      }, 3000),
    ];

    return () => {
      timers.forEach(clearTimeout);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [forcePlay, onComplete]);

  // Abstract crimson fluid & cyber particle canvas simulation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // Particle nodes representing digital fluid / cyber ink filaments
    interface Particle {
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      alpha: number;
      baseAlpha: number;
      pulseSpeed: number;
      hue: number;
    }

    const particles: Particle[] = [];
    const numParticles = Math.min(width < 768 ? 60 : 140, 160);

    for (let i = 0; i < numParticles; i++) {
      particles.push({
        x: width / 2 + (Math.random() - 0.5) * 400,
        y: height / 2 + (Math.random() - 0.5) * 300,
        vx: (Math.random() - 0.5) * 2.2,
        vy: (Math.random() - 0.5) * 2.2,
        size: Math.random() * 3 + 1,
        alpha: Math.random() * 0.7 + 0.3,
        baseAlpha: Math.random() * 0.7 + 0.3,
        pulseSpeed: Math.random() * 0.03 + 0.01,
        hue: Math.random() > 0.3 ? 355 : 340, // Crimson / Deep Red palette
      });
    }

    let time = 0;

    const render = () => {
      time += 0.03;
      ctx.fillStyle = 'rgba(2, 6, 23, 0.25)'; // slight trail
      ctx.fillRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;

      // Draw flowing fluid filaments between close particles
      for (let i = 0; i < particles.length; i++) {
        const p1 = particles[i];
        p1.x += p1.vx;
        p1.y += p1.vy;

        // Subtle vortex suction towards center
        const dx = centerX - p1.x;
        const dy = centerY - p1.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > 30) {
          p1.vx += (dx / dist) * 0.04;
          p1.vy += (dy / dist) * 0.04;
        }

        // Damping
        p1.vx *= 0.985;
        p1.vy *= 0.985;

        // Pulsing glow
        const currentAlpha = p1.baseAlpha * (0.6 + 0.4 * Math.sin(time + i));

        ctx.beginPath();
        ctx.arc(p1.x, p1.y, p1.size, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${p1.hue}, 95%, 55%, ${currentAlpha})`;
        ctx.shadowColor = 'rgba(239, 68, 68, 0.9)';
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Connect fluid lines
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const distNodes = Math.hypot(p1.x - p2.x, p1.y - p2.y);
          if (distNodes < 90) {
            const lineAlpha = (1 - distNodes / 90) * 0.35;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(239, 68, 68, ${lineAlpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, []);

  const handleSkip = () => {
    setSkipped(true);
    if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    onComplete();
  };

  if (skipped) return null;

  return (
    <div className={`fixed inset-0 z-50 bg-[#020617] flex flex-col items-center justify-center overflow-hidden select-none transition-opacity duration-500 ${stage >= 8 ? 'opacity-0 pointer-events-none' : 'opacity-100'}`}>
      {/* Background Canvas for Flowing Crimson Digital Fluid */}
      <canvas ref={canvasRef} className="absolute inset-0 z-0 pointer-events-none" />

      {/* Cyber Grid Overlay */}
      <div
        className="absolute inset-0 z-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(239, 68, 68, 0.15) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(239, 68, 68, 0.15) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />

      {/* Radial Ambient Glow */}
      <div className="absolute w-[600px] h-[600px] rounded-full bg-gradient-to-r from-red-600/20 via-crimson-600/15 to-transparent blur-[120px] pointer-events-none" />

      {/* Main Content Progression Container */}
      <div className="relative z-10 flex flex-col items-center text-center px-6 max-w-2xl">
        
        {/* Stage 1-2: Crimson Pulse Particle */}
        {stage >= 1 && stage < 3 && (
          <div className="animate-ping w-4 h-4 rounded-full bg-red-500 shadow-[0_0_25px_rgba(239,68,68,1)] mb-4" />
        )}

        {/* Stage 3+: TEAM BRUTE Identifier */}
        {stage >= 3 && (
          <div className="space-y-3 animate-fade-in">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/80 border border-red-500/40 text-red-400 font-mono text-[11px] tracking-widest uppercase shadow-[0_0_20px_rgba(239,68,68,0.3)]">
              <Zap size={12} className="text-red-400 animate-pulse" />
              <span>SIH 26106 CYBERSECURITY ARCHITECTURE</span>
            </div>

            <div className="text-4xl sm:text-6xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-white via-red-200 to-red-500 uppercase font-mono drop-shadow-[0_0_30px_rgba(239,68,68,0.6)]">
              TEAM BRUTE
            </div>
          </div>
        )}

        {/* Stage 4+: Scanline Beam Effect */}
        {stage >= 4 && (
          <div className="w-64 sm:w-96 h-[2px] bg-gradient-to-r from-transparent via-red-500 to-transparent my-4 shadow-[0_0_15px_rgba(239,68,68,0.8)] animate-pulse" />
        )}

        {/* Stage 5+: SENTINELTRACE Platform Brand */}
        {stage >= 5 && (
          <div className="space-y-1 animate-fade-in">
            <div className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white flex items-center justify-center gap-2">
              <Shield size={28} className="text-red-500 drop-shadow-[0_0_12px_rgba(239,68,68,0.8)]" />
              <span className="font-mono tracking-wider">SENTINELTRACE</span>
            </div>
          </div>
        )}

        {/* Stage 6+: AI EMAIL FORENSICS */}
        {stage >= 6 && (
          <div className="mt-2 text-xs sm:text-sm font-mono font-semibold tracking-widest text-red-400 uppercase animate-fade-in flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
            <span>AI-POWERED EMAIL FORENSIC INTELLIGENCE PLATFORM</span>
          </div>
        )}

        {/* Stage 7+: 3D Cyber Network Grid Initializing */}
        {stage >= 7 && (
          <div className="mt-5 flex items-center gap-2 text-[10px] font-mono text-slate-400 tracking-wider animate-pulse">
            <span>INITIALIZING 3D GRAPH ENGINE & MTA RELAY TRACE...</span>
          </div>
        )}
      </div>

      {/* Skip Button */}
      <button
        onClick={handleSkip}
        className="absolute bottom-8 right-8 z-20 flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900/80 hover:bg-red-950/80 border border-slate-700/60 hover:border-red-500/50 text-slate-300 hover:text-red-300 font-mono text-xs tracking-wider uppercase transition-all backdrop-blur-md shadow-lg"
      >
        <span>SKIP INTRO</span>
        <ChevronRight size={13} />
      </button>

      {/* Bottom Subtle Status */}
      <div className="absolute bottom-8 left-8 z-20 hidden sm:flex items-center gap-2 text-[10px] font-mono text-slate-500">
        <span className="w-2 h-2 rounded-full bg-emerald-500/80" />
        <span>SECURE BOOT // SMART INDIA HACKATHON 2026</span>
      </div>
    </div>
  );
}
