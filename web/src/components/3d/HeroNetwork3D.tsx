import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';

interface NetworkNode {
  id: string;
  label: string;
  type: 'IP' | 'DOMAIN' | 'EMAIL' | 'IOC' | 'CAMPAIGN' | 'MTA';
  pos: THREE.Vector3;
  color: string;
  size: number;
}

interface NetworkEdge {
  source: number;
  target: number;
  flowOffset: number;
  color: string;
}

export function HeroNetwork3D({ onSelectNode }: { onSelectNode?: (label: string) => void }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || 500;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x020617, 0.0018);

    const camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
    camera.position.set(0, 30, 160);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 2. Ambient & Point Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);

    const cyanLight = new THREE.PointLight(0x22d3ee, 3, 300);
    cyanLight.position.set(50, 50, 50);
    scene.add(cyanLight);

    const redLight = new THREE.PointLight(0xef4444, 2, 250);
    redLight.position.set(-60, -30, 40);
    scene.add(redLight);

    // 3. Cyber Grid Ring at Base
    const ringGeo = new THREE.RingGeometry(80, 140, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x0e7490,
      side: THREE.DoubleSide,
      wireframe: true,
      transparent: true,
      opacity: 0.12,
    });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.rotation.x = Math.PI / 2;
    ring.position.y = -45;
    scene.add(ring);

    // 4. Generate Structured Forensic Network Nodes
    const rawNodes: Array<{ label: string; type: NetworkNode['type']; color: string; size: number }> = [
      { label: 'ATTACKER RELAY (185.220.101.5)', type: 'IP', color: '#ef4444', size: 3.5 },
      { label: 'paypa1-security.com (TYPOSQUAT)', type: 'DOMAIN', color: '#f97316', size: 3.2 },
      { label: 'executive.dmiller719@gmail.com', type: 'EMAIL', color: '#f59e0b', size: 2.8 },
      { label: 'TARGET: victimcorp.com', type: 'DOMAIN', color: '#38bdf8', size: 3.0 },
      { label: 'SHA-256: 3776da176934...', type: 'IOC', color: '#ec4899', size: 2.2 },
      { label: 'CAMPAIGN: #ST-FIN-FRAUD', type: 'CAMPAIGN', color: '#a855f7', size: 3.8 },
      { label: 'EXTERNAL GATEWAY (209.85.128.41)', type: 'MTA', color: '#22c55e', size: 2.5 },
      { label: 'CREDENTIAL HARVEST: /billing/pay', type: 'IOC', color: '#ef4444', size: 2.4 },
      { label: 'ASN: AS60729 (HOSTING INFRA)', type: 'IP', color: '#06b6d4', size: 2.6 },
      { label: 'SPF: FAIL (UNAUTHORIZED MTA)', type: 'IOC', color: '#f87171', size: 2.3 },
      { label: 'DKIM: SIGNATURE ABSENT', type: 'IOC', color: '#fbbf24', size: 2.1 },
      { label: 'DMARC: POLICY REJECT TRIGGERED', type: 'IOC', color: '#f43f5e', size: 2.5 },
    ];

    const nodes: NetworkNode[] = rawNodes.map((n, idx) => {
      const angle = (idx / rawNodes.length) * Math.PI * 2;
      const radius = 55 + (idx % 3) * 20;
      const heightVar = ((idx % 4) - 1.5) * 22;
      return {
        id: `node-${idx}`,
        label: n.label,
        type: n.type,
        pos: new THREE.Vector3(
          Math.cos(angle) * radius,
          heightVar,
          Math.sin(angle) * radius
        ),
        color: n.color,
        size: n.size,
      };
    });

    // Mesh group for nodes
    const nodeMeshes: THREE.Mesh[] = [];
    const sphereGeo = new THREE.SphereGeometry(1, 24, 24);

    nodes.forEach(n => {
      const mat = new THREE.MeshStandardMaterial({
        color: new THREE.Color(n.color),
        emissive: new THREE.Color(n.color),
        emissiveIntensity: 0.6,
        roughness: 0.2,
        metalness: 0.8,
      });
      const mesh = new THREE.Mesh(sphereGeo, mat);
      mesh.position.copy(n.pos);
      mesh.scale.setScalar(n.size);
      mesh.userData = { id: n.id, label: n.label, color: n.color };
      scene.add(mesh);
      nodeMeshes.push(mesh);

      // Glowing outer ring per node
      const haloGeo = new THREE.RingGeometry(1.4, 1.8, 16);
      const haloMat = new THREE.MeshBasicMaterial({
        color: new THREE.Color(n.color),
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.4,
      });
      const halo = new THREE.Mesh(haloGeo, haloMat);
      halo.position.copy(n.pos);
      halo.lookAt(camera.position);
      scene.add(halo);
    });

    // 5. Connect Edges & Data Flow Packets
    const edges: NetworkEdge[] = [
      { source: 0, target: 1, flowOffset: 0, color: '#ef4444' },
      { source: 1, target: 2, flowOffset: 0.2, color: '#f97316' },
      { source: 2, target: 3, flowOffset: 0.4, color: '#38bdf8' },
      { source: 0, target: 4, flowOffset: 0.6, color: '#ec4899' },
      { source: 0, target: 5, flowOffset: 0.8, color: '#a855f7' },
      { source: 1, target: 7, flowOffset: 0.3, color: '#ef4444' },
      { source: 6, target: 3, flowOffset: 0.5, color: '#22c55e' },
      { source: 0, target: 8, flowOffset: 0.7, color: '#06b6d4' },
      { source: 1, target: 9, flowOffset: 0.1, color: '#f87171' },
      { source: 2, target: 10, flowOffset: 0.9, color: '#fbbf24' },
      { source: 3, target: 11, flowOffset: 0.45, color: '#f43f5e' },
      { source: 5, target: 8, flowOffset: 0.15, color: '#a855f7' },
    ];

    const edgeLines: THREE.Line[] = [];
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x22d3ee,
      transparent: true,
      opacity: 0.25,
    });

    edges.forEach(e => {
      const geo = new THREE.BufferGeometry().setFromPoints([
        nodes[e.source].pos,
        nodes[e.target].pos,
      ]);
      const line = new THREE.Line(geo, lineMat);
      scene.add(line);
      edgeLines.push(line);
    });

    // 6. Traveling Data Packets (Glowing points along edges)
    const packetGeo = new THREE.BufferGeometry();
    const packetCount = edges.length * 3;
    const packetPositions = new Float32Array(packetCount * 3);
    const packetColors = new Float32Array(packetCount * 3);

    for (let i = 0; i < packetCount; i++) {
      const color = new THREE.Color(i % 2 === 0 ? 0x22d3ee : 0xef4444);
      packetColors[i * 3] = color.r;
      packetColors[i * 3 + 1] = color.g;
      packetColors[i * 3 + 2] = color.b;
    }

    packetGeo.setAttribute('position', new THREE.BufferAttribute(packetPositions, 3));
    packetGeo.setAttribute('color', new THREE.BufferAttribute(packetColors, 3));

    const packetMat = new THREE.PointsMaterial({
      size: 3.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    const packetPoints = new THREE.Points(packetGeo, packetMat);
    scene.add(packetPoints);

    // 7. Raycasting for Interaction
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    const handleMouseMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);
      if (intersects.length > 0) {
        const hit = intersects[0].object;
        setHoveredNode(hit.userData.label);
      } else {
        setHoveredNode(null);
      }
    };

    const handleClick = () => {
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes);
      if (intersects.length > 0) {
        const hit = intersects[0].object;
        if (onSelectNode) onSelectNode(hit.userData.label);
      }
    };

    container.addEventListener('mousemove', handleMouseMove);
    container.addEventListener('click', handleClick);

    // 8. Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Subtle slow rotation of the network
      scene.rotation.y = elapsedTime * 0.08;
      scene.rotation.x = Math.sin(elapsedTime * 0.05) * 0.05;

      // Animate floating packet points along edges
      const positions = packetGeo.attributes.position.array as Float32Array;
      let packetIdx = 0;

      edges.forEach((edge) => {
        const src = nodes[edge.source].pos;
        const tgt = nodes[edge.target].pos;

        for (let p = 0; p < 3; p++) {
          const t = ((elapsedTime * 0.4 + edge.flowOffset + p * 0.33) % 1);
          positions[packetIdx * 3] = src.x + (tgt.x - src.x) * t;
          positions[packetIdx * 3 + 1] = src.y + (tgt.y - src.y) * t + Math.sin(elapsedTime * 2 + packetIdx) * 1.5;
          positions[packetIdx * 3 + 2] = src.z + (tgt.z - src.z) * t;
          packetIdx++;
        }
      });

      packetGeo.attributes.position.needsUpdate = true;
      renderer.render(scene, camera);
    };

    animate();

    // 9. Resize Listener
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth;
      const newHeight = container.clientHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      container.removeEventListener('mousemove', handleMouseMove);
      container.removeEventListener('click', handleClick);
      cancelAnimationFrame(animationFrameId);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [onSelectNode]);

  return (
    <div className="relative w-full h-full min-h-[480px] overflow-hidden rounded-2xl bg-gradient-to-b from-transparent via-[#080e21]/40 to-transparent">
      <div ref={mountRef} className="w-full h-full cursor-crosshair" />

      {/* Floating HUD Node Overlay */}
      {hoveredNode && (
        <div className="absolute bottom-6 left-1/2 transform -translate-x-1/2 px-4 py-2 rounded-lg bg-[#080e21]/90 border border-cyan-500/40 backdrop-blur-md shadow-[0_0_20px_rgba(34,211,238,0.25)] pointer-events-none transition-all duration-200">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="font-mono text-xs font-semibold text-cyan-300 tracking-wider">
              {hoveredNode}
            </span>
          </div>
        </div>
      )}

      {/* Ambient Grid Label */}
      <div className="absolute top-4 left-4 font-mono text-[10px] text-cyan-500/50 tracking-widest uppercase pointer-events-none">
        LIVE FORENSIC GRAPH // SIMULATION STREAM
      </div>
    </div>
  );
}
