import React, { useRef, useEffect } from 'react';

// Global Intelligence Hub Coordinates (lat, lon, label, type)
const HUBS = [
  { id: 'dc', lat: 38.9, lon: -77.0, label: 'Washington DC // NSA HQ', color: '#06b6d4' },
  { id: 'london', lat: 51.5, lon: -0.1, label: 'London // GCHQ', color: '#06b6d4' },
  { id: 'frankfurt', lat: 50.1, lon: 8.6, label: 'Frankfurt // DE-CIX', color: '#10b981' },
  { id: 'tokyo', lat: 35.6, lon: 139.6, label: 'Tokyo // AP-EAST', color: '#06b6d4' },
  { id: 'singapore', lat: 1.35, lon: 103.8, label: 'Singapore // SEA Hub', color: '#10b981' },
  { id: 'sydney', lat: -33.8, lon: 151.2, label: 'Sydney // ASD Ops', color: '#06b6d4' },
  { id: 'lagos', lat: 6.5, lon: 3.3, label: 'Lagos // MainOne Gateway', color: '#10b981' },
  { id: 'sf', lat: 37.7, lon: -122.4, label: 'San Francisco // Cyber Hub', color: '#06b6d4' },
  { id: 'saopaulo', lat: -23.5, lon: -46.6, label: 'Sao Paulo // IX.br', color: '#f59e0b' },
  { id: 'dubai', lat: 25.2, lon: 55.2, label: 'Dubai // Gulf Gateway', color: '#06b6d4' },
  { id: 'geneva', lat: 46.2, lon: 6.1, label: 'Geneva // Secure Vault', color: '#f43f5e' },
];

// Active Cyber Reconnaissance Arcs (source -> target)
const ARCS = [
  { from: 'dc', to: 'london', speed: 0.008, color: '#06b6d4' },
  { from: 'london', to: 'frankfurt', speed: 0.012, color: '#10b981' },
  { from: 'frankfurt', to: 'dubai', speed: 0.007, color: '#06b6d4' },
  { from: 'dubai', to: 'singapore', speed: 0.009, color: '#10b981' },
  { from: 'singapore', to: 'tokyo', speed: 0.011, color: '#06b6d4' },
  { from: 'tokyo', to: 'sf', speed: 0.006, color: '#06b6d4' },
  { from: 'sf', to: 'dc', speed: 0.010, color: '#10b981' },
  { from: 'london', to: 'lagos', speed: 0.008, color: '#10b981' },
  { from: 'lagos', to: 'saopaulo', speed: 0.007, color: '#f59e0b' },
  { from: 'singapore', to: 'sydney', speed: 0.009, color: '#06b6d4' },
  { from: 'frankfurt', to: 'geneva', speed: 0.015, color: '#f43f5e' },
];

export default function DarkGlobe({ className = '' }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;

    let width = (canvas.width = canvas.parentElement.clientWidth);
    let height = (canvas.height = canvas.parentElement.clientHeight);

    // Dynamic sizing based on viewport
    let radius = Math.min(width, height) * 0.38;

    const handleResize = () => {
      if (!canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
      radius = Math.min(width, height) * 0.38;
    };
    window.addEventListener('resize', handleResize);

    // Generate Globe Dot Matrix Grid (Latitude & Longitude points)
    const dots = [];
    const latStep = 8;
    const lonStep = 9;

    for (let lat = -80; lat <= 80; lat += latStep) {
      const phi = (90 - lat) * (Math.PI / 180);
      const circumferenceAtLat = 2 * Math.PI * Math.sin(phi);
      const numPoints = Math.max(8, Math.floor(circumferenceAtLat * 22));

      for (let i = 0; i < numPoints; i++) {
        const theta = (i / numPoints) * 2 * Math.PI - Math.PI;
        dots.push({
          lat,
          lon: (theta * 180) / Math.PI,
          baseColor: Math.random() > 0.85 ? '#06b6d4' : '#334155',
          isSignal: Math.random() > 0.94,
        });
      }
    }

    // Convert lat/lon to 3D Cartesian coordinates on sphere
    const toCartesian = (lat, lon, r) => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (lon + 180) * (Math.PI / 180);
      return {
        x: -(r * Math.sin(phi) * Math.cos(theta)),
        y: r * Math.cos(phi),
        z: r * Math.sin(phi) * Math.sin(theta),
      };
    };

    // Rotation state
    let rotY = 0.4;
    let rotX = 0.25;
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;
    let velX = 0;
    let velY = 0;

    const onMouseDown = (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const onMouseMove = (e) => {
      if (!isDragging) return;
      const dx = e.clientX - prevMouseX;
      const dy = e.clientY - prevMouseY;
      velX = dx * 0.005;
      velY = dy * 0.005;
      rotY += velX;
      rotX += velY;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    canvas.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Arc pulse progression tracking
    const arcProgress = ARCS.map(() => Math.random());

    // Main 60 FPS Render Loop
    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Apply inertia rotation
      if (!isDragging) {
        velX *= 0.94;
        velY *= 0.94;
        rotY += 0.0028 + velX;
        rotX += velY;
        // Clamp X tilt to prevent globe inversion
        rotX = Math.max(-0.6, Math.min(0.6, rotX));
      }

      const cx = width / 2;
      const cy = height / 2;

      // 1. Render Atmospheric Dark Glow Silhouette
      const aura = ctx.createRadialGradient(cx, cy, radius * 0.7, cx, cy, radius * 1.25);
      aura.addColorStop(0, 'rgba(6, 182, 212, 0.06)');
      aura.addColorStop(0.5, 'rgba(6, 182, 212, 0.02)');
      aura.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = aura;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.25, 0, Math.PI * 2);
      ctx.fill();

      // 2. Render Dark Globe Sphere Backdrop
      const sphereGrad = ctx.createRadialGradient(
        cx - radius * 0.35,
        cy - radius * 0.35,
        radius * 0.1,
        cx,
        cy,
        radius
      );
      sphereGrad.addColorStop(0, '#0a101f');
      sphereGrad.addColorStop(0.6, '#060a12');
      sphereGrad.addColorStop(1, '#020509');

      ctx.fillStyle = sphereGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      // Sphere Outer Rim Ring
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.28)';
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();

      // Transform 3D coordinates using rotation matrices
      const project = (x, y, z) => {
        // Rotate around Y
        const cosY = Math.cos(rotY);
        const sinY = Math.sin(rotY);
        const x1 = x * cosY - z * sinY;
        const z1 = z * cosY + x * sinY;

        // Rotate around X
        const cosX = Math.cos(rotX);
        const sinX = Math.sin(rotX);
        const y2 = y * cosX - z1 * sinX;
        const z2 = z1 * cosX + y * sinX;

        return {
          px: cx + x1,
          py: cy + y2,
          pz: z2,
          visible: z2 > 0, // In front of sphere
        };
      };

      // 3. Render Globe Surface Dot Matrix
      dots.forEach((dot) => {
        const { x, y, z } = toCartesian(dot.lat, dot.lon, radius);
        const proj = project(x, y, z);

        if (proj.visible) {
          const depthRatio = proj.pz / radius; // 0 to 1
          const alpha = 0.15 + depthRatio * 0.75;
          const size = (0.8 + depthRatio * 1.3) * (dot.isSignal ? 1.6 : 1);

          ctx.fillStyle = dot.isSignal
            ? `rgba(6, 182, 212, ${alpha})`
            : `rgba(148, 163, 184, ${alpha * 0.45})`;

          ctx.beginPath();
          ctx.arc(proj.px, proj.py, size, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // 4. Render Hub Anchors
      const hubProjected = {};
      HUBS.forEach((hub) => {
        const { x, y, z } = toCartesian(hub.lat, hub.lon, radius);
        const proj = project(x, y, z);
        hubProjected[hub.id] = proj;

        if (proj.visible) {
          const depthAlpha = 0.3 + (proj.pz / radius) * 0.7;

          // Pulse ring
          ctx.strokeStyle = hub.color;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(proj.px, proj.py, 4, 0, Math.PI * 2);
          ctx.stroke();

          // Center solid dot
          ctx.fillStyle = hub.color;
          ctx.beginPath();
          ctx.arc(proj.px, proj.py, 2, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // 5. Render Curved Geodesic Intelligence Arcs & Moving Pulses
      ARCS.forEach((arc, arcIdx) => {
        const hubA = HUBS.find((h) => h.id === arc.from);
        const hubB = HUBS.find((h) => h.id === arc.to);
        if (!hubA || !hubB) return;

        const posA = toCartesian(hubA.lat, hubA.lon, radius);
        const posB = toCartesian(hubB.lat, hubB.lon, radius);

        // Advance arc pulse progression
        arcProgress[arcIdx] = (arcProgress[arcIdx] + arc.speed) % 1;
        const currentProgress = arcProgress[arcIdx];

        // Draw segmented great circle arc arching above the sphere
        const segments = 28;
        ctx.beginPath();
        let prevVisible = false;

        for (let s = 0; s <= segments; s++) {
          const t = s / segments;
          // Interpolate 3D position
          const ix = posA.x + (posB.x - posA.x) * t;
          const iy = posA.y + (posB.y - posA.y) * t;
          const iz = posA.z + (posB.z - posA.z) * t;

          // Normalize onto sphere and apply altitude arc curve
          const dist = Math.sqrt(ix * ix + iy * iy + iz * iz) || 1;
          const altitude = Math.sin(t * Math.PI) * (radius * 0.22);
          const currentR = radius + altitude;

          const arcX = (ix / dist) * currentR;
          const arcY = (iy / dist) * currentR;
          const arcZ = (iz / dist) * currentR;

          const proj = project(arcX, arcY, arcZ);

          if (proj.visible) {
            if (!prevVisible) {
              ctx.moveTo(proj.px, proj.py);
            } else {
              ctx.lineTo(proj.px, proj.py);
            }
            prevVisible = true;
          } else {
            prevVisible = false;
          }

          // Draw the traveling glowing pulse packet
          if (Math.abs(t - currentProgress) < 1 / segments && proj.visible) {
            ctx.save();
            ctx.shadowColor = arc.color;
            ctx.shadowBlur = 10;
            ctx.fillStyle = '#ffffff';
            ctx.beginPath();
            ctx.arc(proj.px, proj.py, 3.2, 0, Math.PI * 2);
            ctx.fill();

            // Outer pulse halo
            ctx.strokeStyle = arc.color;
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.arc(proj.px, proj.py, 5.5, 0, Math.PI * 2);
            ctx.stroke();
            ctx.restore();
          }
        }

        ctx.strokeStyle = arc.color;
        ctx.lineWidth = 1.1;
        ctx.globalAlpha = 0.35;
        ctx.stroke();
        ctx.globalAlpha = 1.0;
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      canvas.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
  }, []);

  return (
    <div className={`relative overflow-hidden ${className}`}>
      <canvas
        ref={canvasRef}
        className="w-full h-full cursor-grab active:cursor-grabbing block"
        style={{ touchAction: 'none' }}
      />
    </div>
  );
}
