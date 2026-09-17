import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  X, 
  ShieldAlert, 
  Activity, 
  ShieldCheck,
  FastForward
} from 'lucide-react';

export default function ReplayPlayer({ log, onClose }) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [speed, setSpeed] = useState(1); // 1x default speed
  const [steps, setSteps] = useState([]);

  useEffect(() => {
    if (!log) return;
    // Generate step sequence from log telemetry
    const generated = [
      { id: 1, title: 'Package Execution', desc: `Script/Package [${log.sourcePackage}] initialized in runtime.` }
    ];

    if (log.action.includes('Network')) {
      generated.push({ id: 2, title: 'Payload Activation', desc: `Data access mechanism triggered.` });
      generated.push({ id: 3, title: 'External Request Initiated', desc: `Attempted network call to ${log.callerUrl || 'external domain'}` });
      generated.push({ id: 4, title: 'Zero Trust Proxy Intercept', desc: 'Fetch API wrapper captured outbound traffic' });
    } else if (log.action.includes('Storage')) {
      generated.push({ id: 2, title: 'Storage Read/Write', desc: `Attempted to access LocalStorage.` });
      generated.push({ id: 3, title: 'Storage Proxy Intercept', desc: 'Analyzing written values for sensitive credentials.' });
    } else {
      generated.push({ id: 2, title: 'DOM Manipulation', desc: `Attempting dynamic script insertion.` });
      generated.push({ id: 3, title: 'DOM Shield Observer', desc: 'MutationObserver caught untrusted element addition.' });
    }

    generated.push({ id: 5, title: `Action ${log.status}`, desc: `Evaluation: ${log.details}` });
    generated.push({ id: 6, title: 'Telemetry Broadcast', desc: `Generated ${log.severity.toUpperCase()} SOC alert via WebSocket.` });

    setSteps(generated);
  }, [log]);

  useEffect(() => {
    let timer;
    if (isPlaying && currentStep < steps.length) {
      timer = setTimeout(() => {
        setCurrentStep(prev => prev + 1);
      }, 1500 / speed);
    } else if (currentStep >= steps.length) {
      setIsPlaying(false);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentStep, steps.length, speed]);

  const togglePlay = () => {
    if (currentStep >= steps.length) {
      setCurrentStep(0);
    }
    setIsPlaying(!isPlaying);
  };

  const handleRestart = () => {
    setCurrentStep(0);
    setIsPlaying(true);
  };

  const cycleSpeed = () => {
    setSpeed(prev => prev === 1 ? 2 : prev === 2 ? 0.5 : 1);
  };

  if (!log) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 select-none">
      <div className="glass-panel w-full max-w-2xl rounded-xl border border-cyber-border/50 shadow-2xl overflow-hidden flex flex-col">
        
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-cyber-border/40 bg-cyber-panel/60">
          <div className="flex items-center gap-3">
            <div className="p-1.5 bg-cyber-primary/20 rounded-md text-cyber-primary">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-display font-bold text-slate-100 uppercase tracking-wide">
                Attack Replay System
              </h3>
              <p className="text-[10px] font-mono text-slate-400">
                Simulating execution timeline for Event ID: {log.id}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-slate-800/60 text-slate-400 hover:text-slate-200 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Replay Viewer */}
        <div className="p-6 bg-[#080a10] min-h-[300px] flex gap-6 relative overflow-hidden">
          {/* Vertical Timeline Track */}
          <div className="w-2 bg-cyber-border/30 rounded-full relative ml-4">
            <div 
              className="absolute top-0 w-full bg-cyber-primary rounded-full transition-all duration-500 shadow-glow-primary"
              style={{ height: `${steps.length > 0 ? (Math.min(currentStep, steps.length - 1) / (steps.length - 1)) * 100 : 0}%` }}
            />
          </div>

          <div className="flex-1 space-y-6">
            {steps.map((step, idx) => {
              const isActive = currentStep === idx;
              const isPast = currentStep > idx;
              
              return (
                <div 
                  key={step.id} 
                  className={`flex items-start gap-4 transition-all duration-500 ${
                    isPast ? 'opacity-50' : isActive ? 'opacity-100 scale-105 transform translate-x-2' : 'opacity-20'
                  }`}
                >
                  <div className={`mt-0.5 shrink-0 rounded-full w-4 h-4 border-2 flex items-center justify-center ${
                    isActive ? 'border-cyber-primary bg-cyber-primary shadow-glow-primary' : isPast ? 'border-cyber-success bg-cyber-success' : 'border-cyber-border'
                  }`}>
                    {isPast && <div className="w-1.5 h-1.5 bg-white rounded-full" />}
                  </div>
                  <div>
                    <h4 className={`font-mono font-bold text-xs uppercase tracking-wider ${
                      isActive ? 'text-cyber-primary glow-text-primary' : 'text-slate-300'
                    }`}>
                      {step.title}
                    </h4>
                    <p className="text-[11px] font-sans text-slate-400 mt-1 leading-relaxed">
                      {step.desc}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Control Bar */}
        <div className="p-4 border-t border-cyber-border/40 bg-cyber-panel/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={togglePlay}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-primary hover:bg-indigo-600 text-white font-mono text-[10px] font-bold uppercase transition-all shadow-glow-primary/20"
            >
              {isPlaying ? <Pause className="w-4 h-4 fill-white" /> : <Play className="w-4 h-4 fill-white" />}
              {isPlaying ? 'Pause' : currentStep >= steps.length ? 'Replay' : 'Play'}
            </button>
            <button
              onClick={handleRestart}
              className="p-2 rounded-lg bg-slate-800 border border-slate-700 hover:border-slate-500 text-slate-300 transition-colors"
              title="Restart Replay"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
          
          <button
            onClick={cycleSpeed}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800/50 border border-slate-700/50 text-slate-400 font-mono text-[10px] font-bold uppercase hover:bg-slate-800 transition-all"
            title="Adjust Playback Speed"
          >
            <FastForward className="w-3.5 h-3.5" />
            {speed}x
          </button>
        </div>
      </div>
    </div>
  );
}
