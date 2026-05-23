// Fixed atmospheric backdrop shared by every page.
// Render once at the layout level so there's no z-fighting between routes.
export default function AtmosphereLayers() {
  return (
    <>
      <div className="fixed inset-0 pointer-events-none grid-bg z-0" aria-hidden="true" />
      <div className="fixed inset-0 pointer-events-none grain z-0" aria-hidden="true" />
      <div
        className="fixed inset-0 pointer-events-none z-0"
        style={{ background: 'radial-gradient(ellipse 80% 60% at 50% 30%, transparent 0%, rgba(0,0,0,0.6) 100%)' }}
        aria-hidden="true"
      />
    </>
  );
}
