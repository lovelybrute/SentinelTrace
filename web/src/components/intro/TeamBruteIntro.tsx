/**
 * TeamBruteIntro – SentinelTrace AI Cinematic Intro
 *
 * • 8–12 second sequence with Three.js / R3F + Framer Motion
 * • Session-storage gate (once per browser session)
 * • Skip button, reduced-motion bypass, mobile low-perf fallback
 * • All Three.js resources disposed on unmount
 * • No copyrighted assets – procedural geometry only
 */

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  Suspense,
} from 'react';
import { Shield, ChevronRight, Zap, Radio, Volume2, VolumeX, Play } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Stars, Sphere } from '@react-three/drei';
import * as THREE from 'three';

/* ─────────────────────────────────────────────────────────── */
/* Helpers                                                      */
/* ─────────────────────────────────────────────────────────── */

function useStableCallback<T extends (...args: unknown[]) => unknown>(fn: T): T {
  const ref = useRef(fn);
  useEffect(() => { ref.current = fn; });
  return useCallback((...args: unknown[]) => ref.current(...args), []) as T;
}

/** Replace NodeJS.Timeout with the correct DOM type */
type TimerId = ReturnType<typeof setTimeout>;

type VoiceProfileId = 'command';

const VOICE_PROFILES: Array<{
  id: VoiceProfileId;
  name: string;
  description: string;
  rate: number;
  pitch: number;
  preferredNames: string[];
}> = [
  {
    id: 'command',
    name: 'Deep Command',
    description: 'Low, powerful male SOC command voice',
    rate: 0.8,
    pitch: 0.55,
    preferredNames: [
      'Microsoft David',
      'Microsoft Mark',
      'Microsoft Guy',
      'Microsoft George',
      'Microsoft Ravi',
      'Microsoft Hemant',
      'Microsoft Prabhat',
      'Google UK English Male',
      'Daniel',
      'Alex',
      'Fred',
      'Rishi',
      'Arthur',
      'Aaron',
      'Brian',
      'Matthew',
      'Christopher',
      'Eric',
      'Ryan',
    ],
  },
];

const WELCOME_MESSAGE =
  'Welcome to SentinelTrace. Initializing forensic intelligence systems. Developed by Team Brute.';

function findMaleVoice(profileId: VoiceProfileId) {
  if (!('speechSynthesis' in window)) return null;
  const profile = VOICE_PROFILES.find((item) => item.id === profileId) ?? VOICE_PROFILES[0];
  const voices = window.speechSynthesis.getVoices();
  const englishVoices = voices.filter((voice) => voice.lang.toLowerCase().startsWith('en'));
  return profile.preferredNames
    .map((name) => englishVoices.find((voice) => voice.name.toLowerCase().includes(name.toLowerCase())))
    .find(Boolean) ?? null;
}

function waitForMaleVoice(profileId: VoiceProfileId, timeout = 3000) {
  const immediate = findMaleVoice(profileId);
  if (immediate || !('speechSynthesis' in window)) return Promise.resolve(immediate);

  return new Promise<SpeechSynthesisVoice | null>((resolve) => {
    let settled = false;
    const finish = (voice: SpeechSynthesisVoice | null) => {
      if (settled) return;
      settled = true;
      window.speechSynthesis.removeEventListener('voiceschanged', check);
      window.clearInterval(pollId);
      window.clearTimeout(timeoutId);
      resolve(voice);
    };
    const check = () => {
      const voice = findMaleVoice(profileId);
      if (voice) finish(voice);
    };
    const pollId = window.setInterval(check, 120);
    const timeoutId = window.setTimeout(() => finish(findMaleVoice(profileId)), timeout);
    window.speechSynthesis.addEventListener('voiceschanged', check);
    window.speechSynthesis.getVoices();
  });
}

function createVoiceUtterance(profileId: VoiceProfileId, text: string, voice: SpeechSynthesisVoice) {
  const profile = VOICE_PROFILES.find((item) => item.id === profileId) ?? VOICE_PROFILES[0];

  const utterance = new SpeechSynthesisUtterance(text);
  utterance.voice = voice;
  utterance.lang = voice.lang || 'en-US';
  utterance.rate = profile.rate;
  utterance.pitch = profile.pitch;
  utterance.volume = 0.92;
  return utterance;
}

/* ─────────────────────────────────────────────────────────── */
/* Animated counter (no NodeJS types)                           */
/* ─────────────────────────────────────────────────────────── */

function AnimatedNumber({ target, duration = 1500 }: { target: number; duration?: number }) {
  const [current, setCurrent] = useState(0);
  useEffect(() => {
    let rafId: number;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 4);
      setCurrent(Math.round(target * eased));
      if (t < 1) rafId = requestAnimationFrame(tick);
    };
    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [target, duration]);
  return <>{current}</>;
}

/* ─────────────────────────────────────────────────────────── */
/* 3-D Scene                                                    */
/* ─────────────────────────────────────────────────────────── */

interface SceneProps {
  stage: number;
  isMobile: boolean;
}

function DisposalHelper() {
  const { gl, scene } = useThree();
  useEffect(
    () => () => {
      scene.traverse((obj) => {
        if ((obj as THREE.Mesh).geometry) (obj as THREE.Mesh).geometry.dispose();
        const mat = (obj as THREE.Mesh).material;
        if (mat) {
          if (Array.isArray(mat)) mat.forEach((m) => m.dispose());
          else mat.dispose();
        }
      });
      gl.dispose();
    },
    [gl, scene],
  );
  return null;
}

// Encrypted packet – cyan icosahedron wireframe
function Packet({ visible, hostile }: { visible: boolean; hostile: boolean }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const mat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: hostile ? '#FF334F' : '#00D9FF',
        emissive: hostile ? '#FF334F' : '#00D9FF',
        emissiveIntensity: 0.35,
        wireframe: true,
      }),
    [hostile],
  );
  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    const t = clock.getElapsedTime();
    meshRef.current.rotation.x = t * 0.6;
    meshRef.current.rotation.y = t * 0.9;
    const s = 1 + Math.sin(t * 5) * 0.04;
    meshRef.current.scale.setScalar(s);
  });
  if (!visible) return null;
  return (
    <mesh ref={meshRef} material={mat}>
      <icosahedronGeometry args={[2, 1]} />
    </mesh>
  );
}

// Hostile red dots orbiting the packet
function HostileSignals({ active }: { active: boolean }) {
  const positions = useMemo<[number, number, number][]>(() => {
    const pts: [number, number, number][] = [];
    const n = 14;
    for (let i = 0; i < n; i++) {
      const phi = Math.acos(-1 + (2 * i) / n);
      const theta = Math.sqrt(n * Math.PI) * phi;
      const r = 3.2;
      pts.push([
        r * Math.cos(theta) * Math.sin(phi),
        r * Math.sin(theta) * Math.sin(phi),
        r * Math.cos(phi),
      ]);
    }
    return pts;
  }, []);
  const gRef = useRef<THREE.Group>(null);
  useFrame(({ clock }) => {
    if (gRef.current) gRef.current.rotation.y = clock.getElapsedTime() * 0.4;
  });
  if (!active) return null;
  return (
    <group ref={gRef}>
      {positions.map((pos, i) => (
        <mesh key={i} position={pos}>
          <sphereGeometry args={[0.09, 6, 6]} />
          <meshBasicMaterial color="#FF334F" />
        </mesh>
      ))}
    </group>
  );
}

// Wireframe globe + attack arcs (tori)
function GlobeScene({ visible }: { visible: boolean }) {
  const globeRef = useRef<THREE.Mesh>(null);
  useFrame(({ clock }) => {
    if (globeRef.current) globeRef.current.rotation.y = clock.getElapsedTime() * 0.18;
  });
  const arcRotations = useMemo<[number, number, number][]>(
    () => [
      [0.4, 0, 0],
      [0, 0.7, 0.3],
      [1.1, 0.5, 0],
      [0.2, 1.3, 0.8],
      [0.9, 0.2, 1.1],
    ],
    [],
  );
  if (!visible) return null;
  return (
    <group>
      <mesh ref={globeRef}>
        <sphereGeometry args={[2.4, 32, 32]} />
        <meshStandardMaterial
          color="#06111C"
          emissive="#00D9FF"
          emissiveIntensity={0.12}
          wireframe
          transparent
          opacity={0.55}
        />
      </mesh>
      {arcRotations.map((rot, i) => (
        <mesh key={i} rotation={rot as [number, number, number]}>
          <torusGeometry args={[2.9, 0.018, 12, 80, Math.PI * 0.55]} />
          <meshBasicMaterial color={i % 2 === 0 ? '#FF334F' : '#00D9FF'} transparent opacity={0.55} />
        </mesh>
      ))}
    </group>
  );
}

// Shield materialisation
function ShieldMesh({ visible }: { visible: boolean }) {
  const ref = useRef<THREE.Mesh>(null);
  useFrame(({ clock }) => {
    if (ref.current) {
      ref.current.rotation.y = Math.sin(clock.getElapsedTime() * 0.6) * 0.25;
    }
  });
  if (!visible) return null;
  return (
    <mesh ref={ref} position={[0, 0.3, 0]}>
      {/* Dodecahedron approximates a shield silhouette */}
      <dodecahedronGeometry args={[1.6, 0]} />
      <meshStandardMaterial
        color="#001A24"
        emissive="#00D9FF"
        emissiveIntensity={0.5}
        wireframe={false}
        transparent
        opacity={0.85}
      />
    </mesh>
  );
}

function Scene({ stage, isMobile }: SceneProps) {
  const starCount = isMobile ? 800 : 2500;
  return (
    <>
      <DisposalHelper />
      <ambientLight intensity={0.15} />
      <pointLight position={[8, 8, 8]} intensity={2} color="#00D9FF" />
      <pointLight position={[-8, -8, -6]} intensity={2} color="#FF334F" />
      <Stars radius={100} depth={60} count={starCount} factor={4} saturation={0} fade speed={0.8} />

      <Packet visible={stage >= 1 && stage <= 4} hostile={stage === 3} />
      <HostileSignals active={stage === 3} />
      <GlobeScene visible={stage >= 5 && stage <= 6} />
      <ShieldMesh visible={stage >= 7} />
    </>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Scanning row component                                       */
/* ─────────────────────────────────────────────────────────── */

const SCAN_STEPS = ['SPF', 'DKIM', 'DMARC', 'IP ADDRESS', 'URLS', 'ATTACHMENTS'];

function ScanningPanel() {
  return (
    <motion.div
      key="scan"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="flex flex-col gap-2 text-left font-mono text-sm w-72 bg-slate-950/85 p-5 rounded-xl border border-cyan-500/20 backdrop-blur-md shadow-[0_0_40px_rgba(0,217,255,0.07)]"
    >
      <div className="text-cyan-400 mb-3 font-bold tracking-widest text-[10px] flex items-center gap-2">
        <Radio size={11} className="animate-pulse" />
        FORENSIC DEEP-SCAN
      </div>
      {SCAN_STEPS.map((item, i) => (
        <motion.div
          key={item}
          initial={{ opacity: 0, x: -8 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.32, ease: 'easeOut' }}
          className="flex justify-between items-center text-slate-300"
        >
          <span className="text-[11px] tracking-wider">{item}</span>
          <motion.span
            initial={{ opacity: 0, color: '#ffffff' }}
            animate={{ opacity: 1, color: '#00D9FF' }}
            transition={{ delay: i * 0.32 + 0.22 }}
            className="text-[11px] font-bold"
          >
            ✓ PASS
          </motion.span>
        </motion.div>
      ))}
    </motion.div>
  );
}

/* ─────────────────────────────────────────────────────────── */
/* Simple 2-D canvas fallback for low-perf / mobile           */
/* ─────────────────────────────────────────────────────────── */

function Canvas2DFallback() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let w = (canvas.width = window.innerWidth);
    let h = (canvas.height = window.innerHeight);
    const onResize = () => {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', onResize);

    // Light particle field
    const pts = Array.from({ length: 80 }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      r: Math.random() * 1.5 + 0.5,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      hue: Math.random() > 0.5 ? 190 : 355,
    }));

    let t = 0;
    const draw = () => {
      t += 0.02;
      ctx.fillStyle = 'rgba(2,7,13,0.22)';
      ctx.fillRect(0, 0, w, h);
      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        const a = 0.5 + 0.5 * Math.sin(t + p.x);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${p.hue},95%,60%,${a})`;
        ctx.fill();
      }
      rafRef.current = requestAnimationFrame(draw);
    };
    rafRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />;
}

/* ─────────────────────────────────────────────────────────── */
/* Main export                                                  */
/* ─────────────────────────────────────────────────────────── */

interface TeamBruteIntroProps {
  onComplete: () => void;
  forcePlay?: boolean;
}

export function TeamBruteIntro({ onComplete, forcePlay = false }: TeamBruteIntroProps) {
  const [stage, setStage] = useState(0);
  const [started, setStarted] = useState(false);
  const [isAnnouncing, setIsAnnouncing] = useState(false);
  const [voiceError, setVoiceError] = useState('');
  const [selectedVoice, setSelectedVoice] = useState<VoiceProfileId>(() => {
    const saved = localStorage.getItem('sentineltrace_intro_voice');
    return VOICE_PROFILES.some((profile) => profile.id === saved)
      ? (saved as VoiceProfileId)
      : 'command';
  });

  // Detect mobile / low-perf: skip WebGL canvas on small screens
  const isMobile = window.innerWidth < 768;
  const prefersReducedMotion = useMemo(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    [],
  );

  const complete = useStableCallback(onComplete);

  const handleSkip = useStableCallback(() => {
    window.speechSynthesis?.cancel();
    onComplete();
  });

  const beginSequence = useCallback(() => {
    sessionStorage.setItem('sentineltrace_intro_seen', 'true');
    setIsAnnouncing(false);
    setStarted(true);
  }, []);

  const previewVoice = useCallback(async (profileId: VoiceProfileId) => {
    setVoiceError('');
    const voice = await waitForMaleVoice(profileId);
    if (!voice) {
      setVoiceError('No compatible male system voice was found on this browser.');
      return;
    }
    const utterance = createVoiceUtterance(profileId, `SentinelTrace ${VOICE_PROFILES.find((item) => item.id === profileId)?.name} voice ready.`, voice);
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
  }, []);

  const startWithSound = useCallback(async () => {
    localStorage.setItem('sentineltrace_intro_voice', selectedVoice);
    setVoiceError('');
    setIsAnnouncing(true);
    const voice = await waitForMaleVoice(selectedVoice);
    if (!voice) {
      setIsAnnouncing(false);
      setVoiceError('Male voice unavailable. Install or enable an English male system voice, then try again.');
      return;
    }
    const utterance = createVoiceUtterance(selectedVoice, WELCOME_MESSAGE, voice);

    window.speechSynthesis.cancel();
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      beginSequence();
    };
    utterance.onend = finish;
    utterance.onerror = finish;
    window.speechSynthesis.speak(utterance);
    window.setTimeout(finish, 6500);
  }, [beginSequence, selectedVoice]);

  const startSilently = useCallback(() => {
    window.speechSynthesis?.cancel();
    beginSequence();
  }, [beginSequence]);

  // ── Decide whether to show at all ──
  useEffect(() => {
    const introDisabled = localStorage.getItem('sentineltrace_intro_enabled') === 'false';
    const introSeen = sessionStorage.getItem('sentineltrace_intro_seen') === 'true';

    if (!forcePlay && (prefersReducedMotion || introDisabled || introSeen)) {
      onComplete();
      return;
    }
  }, [forcePlay, prefersReducedMotion, onComplete]);

  // ── Begin the cinematic only after the visitor chooses sound ──
  useEffect(() => {
    if (!started) return;

    // Sequence timings (total ~12 s)
    const timers: TimerId[] = [
      setTimeout(() => setStage(1), 300),    // packet appears
      setTimeout(() => setStage(2), 1400),   // network glow
      setTimeout(() => setStage(3), 2600),   // hostile intercept
      setTimeout(() => setStage(4), 3800),   // scanning panel
      setTimeout(() => setStage(5), 6500),   // holographic earth
      setTimeout(() => setStage(6), 7600),   // threat score
      setTimeout(() => setStage(7), 8900),   // shield materialise
      setTimeout(() => setStage(8), 9700),   // logo text
      setTimeout(() => setStage(9), 10400),  // tagline
      setTimeout(() => setStage(10), 11200), // fade → dashboard
      setTimeout(() => complete(), 11900),   // unmount after fade
    ];

    return () => timers.forEach(clearTimeout);
  }, [started, complete]);

  // Pause RAF when tab is hidden
  useEffect(() => {
    const onVis = () => {
      // Three.js canvas handles this internally via its own RAF loop
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, []);

  if (!started) {
    return (
      <div className="intro-voice-gate fixed inset-0 z-[9999] flex items-center justify-center overflow-hidden px-5">
        <div className="intro-voice-orb intro-voice-orb-cyan" />
        <div className="intro-voice-orb intro-voice-orb-violet" />
        <section className="intro-voice-panel" aria-labelledby="intro-voice-title">
          <div className="intro-voice-icon"><Volume2 size={25} /></div>
          <p className="intro-voice-eyebrow">SECURE AUDIO HANDSHAKE</p>
          <h1 id="intro-voice-title">Deep Command Voice</h1>
          <p className="intro-voice-copy">
            Preview the low male command voice, then enter the SentinelTrace cinematic experience.
          </p>

          <div className="intro-voice-options" role="radiogroup" aria-label="Welcome voice">
            {VOICE_PROFILES.map((profile) => {
              const active = selectedVoice === profile.id;
              return (
                <button
                  type="button"
                  key={profile.id}
                  role="radio"
                  aria-checked={active}
                  className={`intro-voice-option${active ? ' active' : ''}`}
                  onClick={() => setSelectedVoice(profile.id)}
                >
                  <span>
                    <strong>{profile.name}</strong>
                    <small>{profile.description}</small>
                  </span>
                  <span
                    className="intro-voice-preview"
                    role="button"
                    tabIndex={0}
                    aria-label={`Preview ${profile.name}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      setSelectedVoice(profile.id);
                      previewVoice(profile.id);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        event.stopPropagation();
                        setSelectedVoice(profile.id);
                        previewVoice(profile.id);
                      }
                    }}
                  >
                    <Play size={12} fill="currentColor" />
                  </span>
                </button>
              );
            })}
          </div>

          <button
            type="button"
            className="intro-enter-sound"
            onClick={startWithSound}
            disabled={isAnnouncing}
          >
            <Volume2 size={17} />
            {isAnnouncing ? 'VOICE HANDSHAKE ACTIVE…' : 'ENTER WITH SOUND'}
          </button>
          <button type="button" className="intro-enter-silent" onClick={startSilently}>
            <VolumeX size={14} /> ENTER SILENTLY
          </button>
          <p className="intro-voice-note">
            {voiceError || 'Male voice only. Voice loading may take a moment on first use.'}
          </p>
        </section>
      </div>
    );
  }

  return (
    <motion.div
      className="fixed inset-0 z-[9999] bg-[#02070D] flex flex-col items-center justify-center overflow-hidden select-none"
      animate={{ opacity: stage >= 10 ? 0 : 1 }}
      transition={{ duration: 0.8 }}
    >
      {/* ── Background ── */}
      {isMobile || prefersReducedMotion ? (
        <Canvas2DFallback />
      ) : (
        <div className="absolute inset-0 z-0">
          <Suspense fallback={<Canvas2DFallback />}>
            <Canvas
              camera={{ position: [0, 0, 9], fov: 42 }}
              gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
              dpr={[1, 1.5]}
            >
              <Scene stage={stage} isMobile={isMobile} />
            </Canvas>
          </Suspense>
        </div>
      )}

      {/* Subtle scan-line grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.025]"
        style={{
          backgroundImage:
            'linear-gradient(to right,#00D9FF 1px,transparent 1px),linear-gradient(to bottom,#00D9FF 1px,transparent 1px)',
          backgroundSize: '44px 44px',
        }}
      />

      {/* ── Overlay content ── */}
      <div className="relative z-10 flex flex-col items-center text-center px-6 max-w-xl w-full">
        <AnimatePresence mode="wait">

          {/* Stage 1–2: boot message */}
          {stage >= 1 && stage < 3 && (
            <motion.p
              key="boot"
              initial={{ opacity: 0, letterSpacing: '0.2em' }}
              animate={{ opacity: 1, letterSpacing: '0.35em' }}
              exit={{ opacity: 0 }}
              className="text-cyan-400 font-mono text-xs tracking-[0.35em] uppercase"
            >
              <Zap className="inline-block mr-2 mb-0.5 animate-pulse" size={13} />
              INITIALIZING SECURE EMAIL RELAY ANALYSIS
            </motion.p>
          )}

          {/* Stage 3: hostile alert */}
          {stage === 3 && (
            <motion.div
              key="hostile"
              initial={{ opacity: 0, scale: 0.88 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ type: 'spring', stiffness: 200 }}
              className="flex flex-col items-center gap-3"
            >
              <div className="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_20px_rgba(239,68,68,0.9)] animate-ping" />
              <p className="text-red-400 font-mono font-bold tracking-[0.25em] text-base uppercase">
                HOSTILE INTERCEPTION DETECTED
              </p>
              <p className="text-slate-500 font-mono text-xs">COUNTERMEASURES ACTIVE</p>
            </motion.div>
          )}

          {/* Stage 4: scanning panel */}
          {stage === 4 && <ScanningPanel />}

          {/* Stage 5: earth unlock */}
          {stage === 5 && (
            <motion.p
              key="earth"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="text-cyan-300 font-mono text-xs tracking-widest uppercase"
            >
              GEOLOCATING RELAY ORIGINS · THREAT GLOBE ACTIVE
            </motion.p>
          )}

          {/* Stage 6: threat score */}
          {stage === 6 && (
            <motion.div
              key="score"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              className="flex flex-col items-center gap-2"
            >
              <span className="font-mono text-[10px] tracking-[0.3em] text-slate-400 uppercase">
                Calculated Threat Score
              </span>
              <span
                className="text-[84px] font-black font-mono leading-none text-transparent bg-clip-text"
                style={{ backgroundImage: 'linear-gradient(135deg,#FF334F,#ff7a7a)' }}
              >
                <AnimatedNumber target={92} duration={1400} />
              </span>
              <span className="font-mono text-xs text-slate-500">/ 100 · CRITICAL</span>
            </motion.div>
          )}

          {/* Stage 7–9: logo materialise */}
          {stage >= 7 && (
            <motion.div
              key="logo"
              initial={{ opacity: 0, scale: 0.92, filter: 'blur(12px)' }}
              animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
              transition={{ duration: 1.1, ease: 'easeOut' }}
              className="flex flex-col items-center gap-4"
            >
              <Shield
                size={68}
                strokeWidth={1.5}
                className="text-cyan-400 drop-shadow-[0_0_28px_rgba(0,217,255,0.7)]"
              />

              {stage >= 8 && (
                <motion.h1
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.7 }}
                  className="text-4xl sm:text-5xl font-black tracking-[0.18em] uppercase font-mono text-transparent bg-clip-text"
                  style={{
                    backgroundImage: 'linear-gradient(135deg,#ffffff 0%,#a5f3fc 50%,#00D9FF 100%)',
                  }}
                >
                  SENTINELTRACE AI
                </motion.h1>
              )}

              {stage >= 9 && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.3, duration: 0.8 }}
                  className="font-mono text-sm sm:text-base tracking-[0.22em] text-cyan-400/90"
                >
                  Trace the Signal. Expose the Threat.
                </motion.p>
              )}
            </motion.div>
          )}

        </AnimatePresence>
      </div>

      {/* ── UI Controls ── */}
      {/* Skip button */}
      <button
        onClick={handleSkip}
        id="intro-skip-btn"
        className="absolute bottom-8 right-8 z-20 flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900/80 hover:bg-cyan-950/80 border border-slate-700/50 hover:border-cyan-500/50 text-slate-400 hover:text-cyan-300 font-mono text-xs tracking-wider uppercase transition-all backdrop-blur-md shadow-lg"
        aria-label="Skip intro"
      >
        SKIP INTRO
        <ChevronRight size={13} />
      </button>

      {/* Bottom-left status */}
      <div className="absolute bottom-8 left-8 z-20 hidden sm:flex items-center gap-2 font-mono text-[10px] text-slate-600">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500/80" />
        SECURE BOOT · TEAM BRUTE · SIH 26106
      </div>

      {/* Stage progress dots */}
      <div className="absolute top-6 left-1/2 -translate-x-1/2 flex gap-1.5 z-20">
        {Array.from({ length: 9 }).map((_, i) => (
          <div
            key={i}
            className="rounded-full transition-all duration-500"
            style={{
              width: 5,
              height: 5,
              background: i < stage ? '#00D9FF' : 'rgba(255,255,255,0.12)',
              boxShadow: i < stage ? '0 0 6px #00D9FF' : 'none',
            }}
          />
        ))}
      </div>
    </motion.div>
  );
}
