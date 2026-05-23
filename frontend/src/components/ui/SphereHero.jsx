import React from 'react';

// Decorative wireframe-sphere background. Pointer-events off — sits behind hero content.
// Adapted from geometric-sphere template. Mouse parallax removed to keep it light.
const SPHERE_DENSITY = 12;

export default function SphereHero() {
  const rings = Array.from({ length: SPHERE_DENSITY }, (_, i) => {
    const step = 90 / (SPHERE_DENSITY / 2);
    const angle = i * step;
    const transform = i % 2 === 0 ? `rotateY(${angle}deg)` : `rotateX(${angle}deg)`;
    return <div key={i} className="wireframe-line" style={{ transform }} aria-hidden />;
  });

  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Panning grid */}
      <div className="absolute inset-0 panning-grid" />

      {/* Volumetric haze */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            'radial-gradient(circle at 50% 50%, rgba(139,92,246,0.18) 0%, transparent 55%)',
          filter: 'blur(150px)',
          opacity: 0.7,
          mixBlendMode: 'screen',
        }}
      />

      {/* Core light */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
        style={{ width: 420, height: 420 }}>
        <div
          className="core-light absolute inset-0 rounded-full"
          style={{
            backgroundImage:
              'radial-gradient(circle, rgba(59,130,246,0.45) 0%, transparent 70%)',
            filter: 'blur(200px)',
            boxShadow:
              '0 0 100px 30px rgba(59,130,246,0.2), 0 0 200px 50px rgba(139,92,246,0.15)',
          }}
        />
      </div>

      {/* Geometric wireframe sphere */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 sphere-container">
        <div className="sphere-rotation relative" style={{ width: 700, height: 700 }}>
          {rings}
        </div>
      </div>

      {/* Soft radial bloom */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            'radial-gradient(circle at 50% 50%, rgba(139,92,246,0.3) 0%, transparent 55%), radial-gradient(circle at 15% 15%, rgba(59,130,246,0.18) 0%, transparent 35%)',
          mixBlendMode: 'screen',
          filter: 'blur(100px)',
          opacity: 0.9,
        }}
      />

      {/* Vignette */}
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.85) 100%)',
        }}
      />
    </div>
  );
}
