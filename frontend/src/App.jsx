import { useEffect } from 'react';
import { Routes, Route } from 'react-router-dom';
import { useHealth } from './hooks/useScan';
import AtmosphereLayers from './components/AtmosphereLayers';
import { Navbar } from './components/ui/Navbar';
import Landing from './pages/Landing';
import Console from './pages/Console';

export default function App() {
  const { health, check } = useHealth();

  useEffect(() => { check(); }, [check]);

  return (
    <div className="min-h-screen bg-sentinel-ink text-white relative">
      <AtmosphereLayers />

      <Navbar health={health} />

      <div className="relative z-10 pt-20">
        <Routes>
          <Route path="/" element={<Landing health={health} />} />
          <Route path="/console" element={<Console health={health} />} />
        </Routes>
      </div>
    </div>
  );
}
