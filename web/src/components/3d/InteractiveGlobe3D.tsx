import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

interface LocationPoint {
  ip: string;
  country: string;
  city?: string;
  lat: number;
  lng: number;
  isp?: string;
  isThreat?: boolean;
}

export function InteractiveGlobe3D({
  locations = [],
  highlightIp,
}: {
  locations?: LocationPoint[];
  highlightIp?: string;
}) {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 450;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0, 220);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 2. Globe Sphere & Wireframe
    const globeRadius = 70;
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Base Sphere
    const sphereGeo = new THREE.SphereGeometry(globeRadius, 48, 48);
    const sphereMat = new THREE.MeshStandardMaterial({
      color: 0x050a18,
      emissive: 0x030712,
      roughness: 0.8,
      metalness: 0.2,
      wireframe: false,
    });
    const globeMesh = new THREE.Mesh(sphereGeo, sphereMat);
    globeGroup.add(globeMesh);

    // Cyber Latitude/Longitude Grid Wireframe
    const gridMat = new THREE.MeshBasicMaterial({
      color: 0x0e7490,
      wireframe: true,
      transparent: true,
      opacity: 0.18,
    });
    const gridMesh = new THREE.Mesh(sphereGeo, gridMat);
    gridMesh.scale.setScalar(1.002);
    globeGroup.add(gridMesh);

    // Outer Atmospheric Glow
    const atmosGeo = new THREE.SphereGeometry(globeRadius * 1.15, 32, 32);
    const atmosMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.08,
      side: THREE.BackSide,
    });
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

    // Default reference coordinates if no points passed
    const activeLocations: LocationPoint[] = locations.length > 0
      ? locations
      : [
          { ip: '185.220.101.5', country: 'Germany', city: 'Brandenburg', lat: 52.41, lng: 12.55, isThreat: true },
          { ip: '209.85.128.41', country: 'United States', city: 'Mountain View', lat: 37.42, lng: -122.08, isThreat: false },
          { ip: '103.21.244.0', country: 'India', city: 'Mumbai', lat: 19.07, lng: 72.87, isThreat: false },
        ];

    // Plot Location Pins & Pulse Rings
    const pinGroup = new THREE.Group();
    globeGroup.add(pinGroup);

    activeLocations.forEach((loc) => {
      const pos = latLngToVector3(loc.lat, loc.lng, globeRadius);
      const isHigh = loc.isThreat || loc.ip === highlightIp;
      const pinColor = isHigh ? 0xef4444 : 0x22d3ee;

      // Glowing marker pin
      const markerGeo = new THREE.SphereGeometry(2.5, 16, 16);
      const markerMat = new THREE.MeshStandardMaterial({
        color: pinColor,
        emissive: pinColor,
        emissiveIntensity: 0.9,
      });
      const marker = new THREE.Mesh(markerGeo, markerMat);
      marker.position.copy(pos);
      pinGroup.add(marker);

      // Pulse Ring
      const ringGeo = new THREE.RingGeometry(2.8, 4.2, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color: pinColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.6,
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.position.copy(pos);
      ring.lookAt(new THREE.Vector3(0, 0, 0));
      pinGroup.add(ring);
    });

    // Draw Great-Circle Arcs Between Points
    if (activeLocations.length >= 2) {
      for (let i = 0; i < activeLocations.length - 1; i++) {
        const v1 = latLngToVector3(activeLocations[i].lat, activeLocations[i].lng, globeRadius);
        const v2 = latLngToVector3(activeLocations[i + 1].lat, activeLocations[i + 1].lng, globeRadius);

        // Compute midpoint arched outward
        const mid = v1.clone().add(v2).multiplyScalar(0.5);
        mid.normalize().multiplyScalar(globeRadius * 1.35);

        const curve = new THREE.QuadraticBezierCurve3(v1, mid, v2);
        const points = curve.getPoints(50);
        const arcGeo = new THREE.BufferGeometry().setFromPoints(points);
        const arcMat = new THREE.LineBasicMaterial({
          color: 0x38bdf8,
          transparent: true,
          opacity: 0.6,
        });
        const arcLine = new THREE.Line(arcGeo, arcMat);
        globeGroup.add(arcLine);
      }
    }

    // Interactive Drag to Rotate
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

      globeGroup.rotation.y += deltaX * 0.005;
      globeGroup.rotation.x += deltaY * 0.005;

      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Animation loop
    let animId: number;
    const animate = () => {
      animId = requestAnimationFrame(animate);
      if (!isDragging) {
        globeGroup.rotation.y += 0.0025;
      }
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(animId);
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [locations, highlightIp]);

  return (
    <div className="relative w-full h-full min-h-[380px] rounded-xl overflow-hidden bg-gradient-to-b from-[#050a18]/60 to-[#020617]/90 border border-cyan-500/10">
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
      
      {/* Honest Infrastructure Attribution Badge */}
      <div className="absolute bottom-3 left-3 px-3 py-1.5 rounded-lg bg-[#080e21]/85 border border-cyan-500/20 backdrop-blur-md">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span className="text-[11px] font-mono text-cyan-300">
            Observed MTA Infrastructure Location
          </span>
        </div>
        <div className="text-[9px] text-slate-400 mt-0.5 max-w-[280px]">
          Represents ISP datacenter routing. Does not establish physical human attribution.
        </div>
      </div>
    </div>
  );
}
