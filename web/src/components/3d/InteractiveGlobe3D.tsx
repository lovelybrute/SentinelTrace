import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Globe, Shield, AlertTriangle, ExternalLink, X, Info } from 'lucide-react';

export interface LocationPoint {
  ip: string;
  country: string;
  city?: string;
  lat: number;
  lng: number;
  isp?: string;
  asn?: string;
  domain?: string;
  campaign?: string;
  threatScore?: number;
  isThreat?: boolean;
}

interface InteractiveGlobe3DProps {
  locations?: LocationPoint[];
  highlightIp?: string;
  onSelectCountry?: (countryData: { country: string; points: LocationPoint[] }) => void;
}

export function InteractiveGlobe3D({
  locations = [],
  highlightIp,
  onSelectCountry,
}: InteractiveGlobe3DProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [selectedCountry, setSelectedCountry] = useState<{
    country: string;
    points: LocationPoint[];
  } | null>(null);

  // Fallback realistic threat locations if none provided
  const activeLocations: LocationPoint[] = locations.length > 0 ? locations : [
    { ip: '185.220.101.5', country: 'Germany', city: 'Frankfurt', lat: 50.1109, lng: 8.6821, isp: 'Offshore VPS Cloud', asn: 'AS60729', domain: 'paypa1-security.com', campaign: 'ST-CAMP-0042', threatScore: 96, isThreat: true },
    { ip: '194.26.29.112', country: 'Russia', city: 'Moscow', lat: 55.7558, lng: 37.6173, isp: 'Bulletproof Host Network', asn: 'AS44050', domain: 'microsoft-auth-verify.net', campaign: 'ST-CAMP-0017', threatScore: 92, isThreat: true },
    { ip: '45.154.255.89', country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lng: 4.9041, isp: 'Cloud Transit Provider', asn: 'AS200019', domain: 'executive-urgent-desk.com', campaign: 'ST-CAMP-0031', threatScore: 88, isThreat: true },
    { ip: '209.85.128.41', country: 'United States', city: 'Mountain View', lat: 37.3861, lng: -122.0839, isp: 'Google LLC Mail Relay', asn: 'AS15169', domain: 'google.com', threatScore: 15, isThreat: false },
    { ip: '140.82.112.4', country: 'United States', city: 'San Francisco', lat: 37.7749, lng: -122.4194, isp: 'GitHub SMTP Relay', asn: 'AS36459', domain: 'github.com', threatScore: 10, isThreat: false },
    { ip: '103.21.244.0', country: 'Singapore', city: 'Singapore', lat: 1.3521, lng: 103.8198, isp: 'Asia Cloud Gateway', asn: 'AS13335', domain: 'cdn-proxy-node.net', threatScore: 74, isThreat: true },
  ];

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 450;

    // Check reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0, 220);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Track resources for clean disposal
    const disposables: { geometries: THREE.BufferGeometry[]; materials: THREE.Material[] } = {
      geometries: [],
      materials: [],
    };

    // 2. Globe Sphere & Wireframe
    const globeRadius = 70;
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Base Sphere
    const sphereGeo = new THREE.SphereGeometry(globeRadius, 48, 48);
    disposables.geometries.push(sphereGeo);
    const sphereMat = new THREE.MeshStandardMaterial({
      color: 0x050a18,
      emissive: 0x030712,
      roughness: 0.8,
      metalness: 0.2,
      wireframe: false,
    });
    disposables.materials.push(sphereMat);
    const globeMesh = new THREE.Mesh(sphereGeo, sphereMat);
    globeGroup.add(globeMesh);

    // Cyber Latitude/Longitude Grid Wireframe
    const gridMat = new THREE.MeshBasicMaterial({
      color: 0x0e7490,
      wireframe: true,
      transparent: true,
      opacity: 0.18,
    });
    disposables.materials.push(gridMat);
    const gridMesh = new THREE.Mesh(sphereGeo, gridMat);
    gridMesh.scale.setScalar(1.002);
    globeGroup.add(gridMesh);

    // Outer Atmospheric Glow
    const atmosGeo = new THREE.SphereGeometry(globeRadius * 1.15, 32, 32);
    disposables.geometries.push(atmosGeo);
    const atmosMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.08,
      side: THREE.BackSide,
    });
    disposables.materials.push(atmosMat);
    const atmosMesh = new THREE.Mesh(atmosGeo, atmosMat);
    scene.add(atmosMesh);

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x22d3ee, 2);
    dirLight.position.set(100, 50, 150);
    scene.add(dirLight);

    // Helper: Convert Lat/Lng to Vector3 on sphere surface
    const latLngToVector3 = (lat: number, lng: number, radius: number): THREE.Vector3 => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (lng + 180) * (Math.PI / 180);
      return new THREE.Vector3(
        -(radius * Math.sin(phi) * Math.cos(theta)),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta)
      );
    };

    // Plot Location Pins & Beacons
    const markers: THREE.Mesh[] = [];
    activeLocations.forEach((loc) => {
      const pos = latLngToVector3(loc.lat, loc.lng, globeRadius);
      const isThreat = loc.isThreat !== false && (loc.threatScore ? loc.threatScore > 50 : true);
      const markerColor = isThreat ? 0xef4444 : 0x22c55e;

      // Pin
      const pinGeo = new THREE.SphereGeometry(2.2, 16, 16);
      disposables.geometries.push(pinGeo);
      const pinMat = new THREE.MeshBasicMaterial({ color: markerColor });
      disposables.materials.push(pinMat);
      const pinMesh = new THREE.Mesh(pinGeo, pinMat);
      pinMesh.position.copy(pos);
      pinMesh.userData = loc;
      markers.push(pinMesh);
      globeGroup.add(pinMesh);

      // Pulse Ring
      const ringGeo = new THREE.RingGeometry(2.4, 4.2, 24);
      disposables.geometries.push(ringGeo);
      const ringMat = new THREE.MeshBasicMaterial({
        color: markerColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.6,
      });
      disposables.materials.push(ringMat);
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.position.copy(pos);
      ringMesh.lookAt(0, 0, 0);
      globeGroup.add(ringMesh);
    });

    // Raycasting & Interaction
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleClick = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(markers);

      if (intersects.length > 0) {
        const clickedData = intersects[0].object.userData as LocationPoint;
        const matchingPoints = activeLocations.filter(p => p.country === clickedData.country);
        const countryPayload = {
          country: clickedData.country,
          points: matchingPoints,
        };
        setSelectedCountry(countryPayload);
        if (onSelectCountry) onSelectCountry(countryPayload);
      }
    };

    renderer.domElement.addEventListener('click', handleClick);

    // Mouse Drag Rotation
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };

    const onMouseDown = (e: MouseEvent) => {
      isDragging = true;
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const deltaX = e.clientX - previousMousePosition.x;
      const deltaY = e.clientY - previousMousePosition.y;

      globeGroup.rotation.y += deltaX * 0.006;
      globeGroup.rotation.x += deltaY * 0.006;

      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    renderer.domElement.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Animation Loop
    let animId: number;
    const animate = () => {
      if (!prefersReducedMotion && !isDragging && !document.hidden) {
        globeGroup.rotation.y += 0.0025;
      }
      renderer.render(scene, camera);
      animId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight || 450;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      renderer.domElement.removeEventListener('click', handleClick);
      renderer.domElement.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);

      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }

      // Dispose Three.js resources
      disposables.geometries.forEach(g => g.dispose());
      disposables.materials.forEach(m => m.dispose());
      renderer.dispose();
    };
  }, [activeLocations, highlightIp, onSelectCountry]);

  return (
    <div className="relative w-full h-[500px] rounded-2xl bg-[#020617] border border-cyan-500/20 overflow-hidden shadow-[0_0_40px_rgba(0,0,0,0.8)]">
      {/* 3D WebGL Canvas Container */}
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Mandatory Top Overlay Disclaimer */}
      <div className="absolute top-4 left-4 right-4 z-20 flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-xl bg-[#080e21]/90 border border-cyan-500/20 backdrop-blur-md">
        <div className="flex items-center gap-2">
          <Globe size={16} className="text-cyan-400" />
          <span className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
            OBSERVED NETWORK INFRASTRUCTURE (GEOLOCATION MAP)
          </span>
        </div>
        <div className="text-[10px] font-mono text-slate-400">
          Click country markers to inspect observed relay clusters
        </div>
      </div>

      {/* Mandatory Bottom Legal Disclaimer */}
      <div className="absolute bottom-4 left-4 right-4 z-20 p-2.5 rounded-lg bg-[#050a18]/90 border border-amber-500/20 backdrop-blur-md text-[10px] font-mono text-amber-300 flex items-center gap-2">
        <AlertTriangle size={13} className="text-amber-400 flex-shrink-0" />
        <span>
          <strong>LEGAL FORENSIC NOTICE:</strong> Geolocation represents observed network infrastructure / relay hops and does NOT establish the attacker's physical location.
        </span>
      </div>

      {/* Selected Country Inspection Drawer */}
      {selectedCountry && (
        <div className="absolute top-16 right-4 bottom-16 z-30 w-80 p-4 rounded-xl bg-[#080e21]/95 border border-cyan-500/30 backdrop-blur-xl shadow-2xl overflow-y-auto space-y-3 animate-fade-in">
          <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2">
            <div>
              <div className="text-[10px] font-mono font-bold text-cyan-400 uppercase">
                OBSERVED INFRASTRUCTURE REGION
              </div>
              <div className="text-base font-bold text-white mt-0.5">
                {selectedCountry.country}
              </div>
            </div>
            <button
              onClick={() => setSelectedCountry(null)}
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
            >
              <X size={15} />
            </button>
          </div>

          <div className="text-[11px] font-mono text-slate-300">
            {selectedCountry.points.length} observed relay endpoints in this region:
          </div>

          <div className="space-y-2">
            {selectedCountry.points.map((pt, i) => (
              <div key={i} className="p-2.5 rounded bg-[#050a18] border border-slate-800 text-xs font-mono space-y-1">
                <div className="flex justify-between items-center">
                  <span className="text-cyan-300 font-bold">{pt.ip}</span>
                  <span className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${pt.isThreat ? 'bg-red-950 text-red-300 border border-red-500/30' : 'text-emerald-400'}`}>
                    {pt.threatScore ? `Score ${pt.threatScore}` : 'OBSERVED'}
                  </span>
                </div>
                <div className="text-[10px] text-slate-400">{pt.isp || 'Hosting Provider'} ({pt.asn || 'ASN'})</div>
                {pt.domain && (
                  <div className="text-[10px] text-amber-300">Domain: {pt.domain}</div>
                )}
                {pt.campaign && (
                  <div className="text-[10px] text-purple-300">Campaign: #{pt.campaign}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
