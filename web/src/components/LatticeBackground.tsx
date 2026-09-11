import { useEffect, useRef } from 'react';

/**
 * The product's visual signature: a live module-lattice mesh behind every
 * screen, not a static hero image. PQC Forge exists because ML-KEM/ML-DSA
 * are *lattice* cryptography — this makes that literal instead of leaving
 * it as a word in the README. Points sit on a jittered grid and connect to
 * their fixed lattice neighbors (not nearest-neighbor search), which is
 * both the actual right picture of a lattice and O(n) instead of O(n²) per
 * frame — cheap enough to run continuously behind glass panels. Occasional
 * bright pulses travel along a random edge, standing in for the
 * negotiation/verification traffic the product itself is about.
 *
 * Reads its palette from CSS custom properties every frame, so it follows
 * the light/dark theme toggle with no extra wiring, and goes fully static
 * (one frame, no loop) under prefers-reduced-motion or when the tab is
 * hidden.
 */
export function LatticeBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    let width = 0;
    let height = 0;
    let cols = 0;
    let rows = 0;
    let spacing = 110;
    let points: { bx: number; by: number; phase: number; speed: number }[][] = [];
    // Pulses hold (row, col) indices into `points`. A resize rebuilds that
    // grid at a new (possibly smaller) size, so any pulse already in
    // flight can end up pointing past the new grid's edge — cleared on
    // every rebuild rather than trying to remap indices across a shape
    // change; losing a few mid-flight cosmetic pulses on resize is
    // invisible, an out-of-bounds read into `points` is not.
    type Pulse = { r0: number; c0: number; r1: number; c1: number; start: number; duration: number };
    let pulses: Pulse[] = [];
    let nextPulseAt = 0;

    function readColor(name: string, fallback: string) {
      const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return value || fallback;
    }

    function buildGrid() {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas!.width = width * dpr;
      canvas!.height = height * dpr;
      canvas!.style.width = `${width}px`;
      canvas!.style.height = `${height}px`;
      spacing = width < 700 ? 84 : width < 1200 ? 100 : 128;
      cols = Math.ceil(width / spacing) + 2;
      rows = Math.ceil(height / spacing) + 2;
      points = Array.from({ length: rows }, (_, row) =>
        Array.from({ length: cols }, (_, col) => ({
          bx: col * spacing - spacing,
          by: row * spacing - spacing,
          phase: Math.random() * Math.PI * 2,
          speed: 0.35 + Math.random() * 0.35
        }))
      );
      pulses = [];
    }

    buildGrid();
    const onResize = () => buildGrid();
    window.addEventListener('resize', onResize);

    function position(row: number, col: number, t: number) {
      const p = points[row][col];
      const jitter = spacing * 0.22;
      return {
        x: p.bx + Math.sin(t * 0.0006 * p.speed + p.phase) * jitter,
        y: p.by + Math.cos(t * 0.0007 * p.speed + p.phase * 1.3) * jitter
      };
    }

    function maybeSpawnPulse(t: number) {
      if (t < nextPulseAt || pulses.length >= 7 || rows < 2 || cols < 2) return;
      const r0 = 1 + Math.floor(Math.random() * (rows - 2));
      const c0 = 1 + Math.floor(Math.random() * (cols - 2));
      const horizontal = Math.random() > 0.5;
      const r1 = horizontal ? r0 : r0 + (Math.random() > 0.5 ? 1 : -1);
      const c1 = horizontal ? c0 + (Math.random() > 0.5 ? 1 : -1) : c0;
      if (r1 < 0 || r1 >= rows || c1 < 0 || c1 >= cols) return;
      pulses.push({ r0, c0, r1, c1, start: t, duration: 1100 + Math.random() * 700 });
      nextPulseAt = t + 260 + Math.random() * 500;
    }

    let raf = 0;
    let lastFrame = 0;
    function draw(t: number) {
      raf = requestAnimationFrame(draw);
      if (document.hidden) return;
      if (!reduceMotion && t - lastFrame < 33) return; // ~30fps cap, plenty smooth, kinder to the CPU
      lastFrame = t;

      const nodeColor = readColor('--lattice-node', 'rgba(120,120,140,0.5)');
      const edgeColor = readColor('--lattice-edge', 'rgba(120,120,140,0.12)');
      const pulseColor = readColor('--lattice-pulse', '#33e5ff');

      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx!.clearRect(0, 0, width, height);

      const time = reduceMotion ? 0 : t;

      // Edges to fixed lattice neighbors: right, down, and both diagonals.
      ctx!.lineWidth = 1;
      ctx!.strokeStyle = edgeColor;
      ctx!.beginPath();
      for (let r = 0; r < rows; r += 1) {
        for (let c = 0; c < cols; c += 1) {
          const a = position(r, c, time);
          if (c + 1 < cols) { const b = position(r, c + 1, time); ctx!.moveTo(a.x, a.y); ctx!.lineTo(b.x, b.y); }
          if (r + 1 < rows) { const b = position(r + 1, c, time); ctx!.moveTo(a.x, a.y); ctx!.lineTo(b.x, b.y); }
          if (r + 1 < rows && c + 1 < cols && (r + c) % 2 === 0) { const b = position(r + 1, c + 1, time); ctx!.moveTo(a.x, a.y); ctx!.lineTo(b.x, b.y); }
        }
      }
      ctx!.stroke();

      // Nodes.
      ctx!.fillStyle = nodeColor;
      for (let r = 0; r < rows; r += 1) {
        for (let c = 0; c < cols; c += 1) {
          const p = position(r, c, time);
          ctx!.beginPath();
          ctx!.arc(p.x, p.y, 1.4, 0, Math.PI * 2);
          ctx!.fill();
        }
      }

      if (reduceMotion) { cancelAnimationFrame(raf); return; }

      // Traveling pulses along random edges: the product's "something is
      // negotiating right now" motif.
      maybeSpawnPulse(t);
      for (let i = pulses.length - 1; i >= 0; i -= 1) {
        const pulse = pulses[i];
        const progress = (t - pulse.start) / pulse.duration;
        if (progress >= 1) { pulses.splice(i, 1); continue; }
        const a = position(pulse.r0, pulse.c0, time);
        const b = position(pulse.r1, pulse.c1, time);
        const x = a.x + (b.x - a.x) * progress;
        const y = a.y + (b.y - a.y) * progress;
        const alpha = Math.sin(progress * Math.PI);
        ctx!.beginPath();
        const gradient = ctx!.createRadialGradient(x, y, 0, x, y, 7);
        gradient.addColorStop(0, pulseColor);
        gradient.addColorStop(1, 'transparent');
        ctx!.fillStyle = gradient;
        ctx!.globalAlpha = alpha;
        ctx!.arc(x, y, 7, 0, Math.PI * 2);
        ctx!.fill();
        ctx!.globalAlpha = 1;
      }
    }
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  return <canvas ref={canvasRef} className="lattice-bg" aria-hidden="true" />;
}
