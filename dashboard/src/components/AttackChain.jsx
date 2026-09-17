import React, { useState, useEffect } from 'react';
import { Network, Database, ShieldAlert, FileCode, Lock, Server } from 'lucide-react';

export default function AttackChain({ triggerType }) {
  const [activeNodes, setActiveNodes] = useState([]);
  const [complete, setComplete] = useState(false);

  // Define static node configurations for layout
  const nodes = [
    { id: 'package', label: 'Compromised Package', icon: FileCode, x: 50, y: 150, color: 'text-slate-400', border: 'border-slate-500' },
    { id: 'storage', label: 'Storage Access', icon: Database, x: 200, y: 50, color: 'text-cyber-warning', border: 'border-cyber-warning' },
    { id: 'token', label: 'Token Extraction', icon: Lock, x: 350, y: 50, color: 'text-cyber-danger', border: 'border-cyber-danger' },
    { id: 'network', label: 'Network Request', icon: Network, x: 200, y: 250, color: 'text-cyber-warning', border: 'border-cyber-warning' },
    { id: 'external', label: 'External Domain', icon: Server, x: 350, y: 250, color: 'text-cyber-danger', border: 'border-cyber-danger' },
    { id: 'blocked', label: 'Zero-Trust Block', icon: ShieldAlert, x: 500, y: 150, color: 'text-cyber-success', border: 'border-cyber-success' },
  ];

  // Define edges with their activation order and trigger requirements
  const edges = [
    { source: 'package', target: 'storage', type: 'storage_harvest' },
    { source: 'storage', target: 'token', type: 'storage_harvest' },
    { source: 'token', target: 'blocked', type: 'storage_harvest' },
    
    { source: 'package', target: 'network', type: 'network_exfil' },
    { source: 'network', target: 'external', type: 'network_exfil' },
    { source: 'external', target: 'blocked', type: 'network_exfil' },

    { source: 'package', target: 'blocked', type: 'dom_inject' },
  ];

  useEffect(() => {
    setActiveNodes([]);
    setComplete(false);
    if (!triggerType) return;

    let path = [];
    if (triggerType === 'storage_harvest') {
      path = ['package', 'storage', 'token', 'blocked'];
    } else if (triggerType === 'network_exfil') {
      path = ['package', 'network', 'external', 'blocked'];
    } else if (triggerType === 'dom_inject') {
      path = ['package', 'blocked'];
    }

    let timer;
    if (path.length > 0) {
      path.forEach((nodeId, idx) => {
        setTimeout(() => {
          setActiveNodes(prev => [...prev, nodeId]);
          if (idx === path.length - 1) setComplete(true);
        }, idx * 800);
      });
    }

    return () => clearTimeout(timer);
  }, [triggerType]);

  const activeEdges = edges.filter(
    edge => activeNodes.includes(edge.source) && activeNodes.includes(edge.target) && edge.type === triggerType
  );

  return (
    <div className="w-full h-full min-h-[350px] relative bg-cyber-bg/40 rounded-lg border border-cyber-border/30 overflow-hidden select-none">
      <div className="absolute top-4 left-4 z-20">
        <h3 className="font-mono text-xs font-bold uppercase tracking-widest text-slate-400">Live Attack Chain</h3>
        <p className="text-[10px] text-slate-500 font-sans mt-0.5">Real-time propagation path tracking</p>
      </div>

      <svg className="w-full h-full absolute inset-0 z-10" viewBox="0 0 600 300" preserveAspectRatio="xMidYMid meet">
        {/* Draw base edges */}
        {edges.map((edge, i) => {
          const src = nodes.find(n => n.id === edge.source);
          const tgt = nodes.find(n => n.id === edge.target);
          return (
            <path
              key={`base-${i}`}
              d={`M ${src.x + 30} ${src.y} C ${src.x + 80} ${src.y}, ${tgt.x - 80} ${tgt.y}, ${tgt.x - 30} ${tgt.y}`}
              fill="none"
              stroke="#242b3d"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
          );
        })}

        {/* Draw active edges with animations */}
        {activeEdges.map((edge, i) => {
          const src = nodes.find(n => n.id === edge.source);
          const tgt = nodes.find(n => n.id === edge.target);
          return (
            <g key={`active-${i}`}>
              <path
                d={`M ${src.x + 30} ${src.y} C ${src.x + 80} ${src.y}, ${tgt.x - 80} ${tgt.y}, ${tgt.x - 30} ${tgt.y}`}
                fill="none"
                stroke={tgt.id === 'blocked' ? '#10b981' : '#f43f5e'}
                strokeWidth="3"
                className="animate-pulse"
              />
              <circle r="4" fill={tgt.id === 'blocked' ? '#10b981' : '#f43f5e'}>
                <animateMotion 
                  path={`M ${src.x + 30} ${src.y} C ${src.x + 80} ${src.y}, ${tgt.x - 80} ${tgt.y}, ${tgt.x - 30} ${tgt.y}`}
                  dur="0.8s" 
                  fill="freeze"
                />
              </circle>
            </g>
          );
        })}
      </svg>

      {/* Draw HTML Nodes over SVG */}
      {nodes.map(node => {
        const isActive = activeNodes.includes(node.id);
        const Icon = node.icon;
        
        return (
          <div
            key={node.id}
            className={`absolute flex flex-col items-center justify-center transform -translate-x-1/2 -translate-y-1/2 transition-all duration-500 ${
              isActive ? 'opacity-100 scale-100' : 'opacity-30 scale-90 grayscale'
            }`}
            style={{ left: `${(node.x / 600) * 100}%`, top: `${(node.y / 300) * 100}%` }}
          >
            <div className={`p-3 rounded-full border-2 bg-cyber-panel shadow-lg ${isActive ? node.border : 'border-cyber-border'}`}>
              <Icon className={`w-5 h-5 ${isActive ? node.color : 'text-slate-500'}`} />
            </div>
            <span className={`mt-2 font-mono text-[9px] font-bold tracking-wider uppercase text-center w-24 ${
              isActive ? 'text-slate-200' : 'text-slate-600'
            }`}>
              {node.label}
            </span>
          </div>
        );
      })}

      {complete && (
        <div className="absolute inset-0 bg-cyber-success/5 pointer-events-none z-30 flex items-center justify-center animate-fadeIn">
          <div className="px-4 py-2 bg-cyber-success/20 border border-cyber-success/40 text-cyber-success font-mono text-xs font-bold uppercase rounded-lg shadow-glow-success/20 backdrop-blur-md translate-y-24">
            Threat Neutralized
          </div>
        </div>
      )}
    </div>
  );
}
