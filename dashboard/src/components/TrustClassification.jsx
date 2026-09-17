import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Package } from 'lucide-react';
import { usePhishGuard } from '../App';

export default function TrustClassification() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const [classifications, setClassifications] = useState({ trusted: [], monitored: [], quarantined: [] });
  const [filter, setFilter] = useState('ALL');

  useEffect(() => {
    fetch('/api/packages/classification')
      .then(res => res.json())
      .then(data => setClassifications(data))
      .catch(console.error);
  }, [nonce]);

  const allPackages = [
    ...classifications.trusted.map(p => ({ ...p, type: 'TRUSTED' })),
    ...classifications.monitored.map(p => ({ ...p, type: 'MONITORED' })),
    ...classifications.quarantined.map(p => ({ ...p, type: 'QUARANTINED' }))
  ];

  const filteredPackages = allPackages.filter(p => filter === 'ALL' || p.type === filter);

  const getStyle = (type) => {
    switch(type) {
      case 'TRUSTED': return { icon: ShieldCheck, color: 'text-cyber-success', bg: 'bg-cyber-success/10 border-cyber-success/30' };
      case 'MONITORED': return { icon: AlertTriangle, color: 'text-cyber-warning', bg: 'bg-cyber-warning/10 border-cyber-warning/30' };
      case 'QUARANTINED': return { icon: ShieldAlert, color: 'text-cyber-danger', bg: 'bg-cyber-danger/10 border-cyber-danger/30' };
      default: return { icon: Package, color: 'text-slate-400', bg: 'bg-slate-800' };
    }
  };

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-full min-h-[350px]">
      <div className="flex justify-between items-center mb-4 border-b border-cyber-border/30 pb-3">
        <div className="flex items-center gap-2">
          <Package className="w-5 h-5 text-cyber-primary" />
          <div>
            <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Package Trust Index</h3>
            <span className="text-[10px] text-slate-400">Categorized ecosystem safety state</span>
          </div>
        </div>
        
        <div className="flex bg-cyber-bg/50 border border-cyber-border/40 rounded p-1">
          {['ALL', 'TRUSTED', 'MONITORED', 'QUARANTINED'].map(f => (
            <button 
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 text-[9px] font-mono font-bold tracking-widest rounded ${filter === f ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2.5 pr-2">
        {filteredPackages.map((pkg, i) => {
          const style = getStyle(pkg.type);
          const Icon = style.icon;
          return (
            <div key={i} className={`flex items-center justify-between p-3 rounded-lg border transition-all hover:bg-cyber-bg/50 ${style.bg}`}>
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${style.color}`} />
                <div>
                  <h4 className="font-mono font-bold text-xs text-slate-100">{pkg.name}</h4>
                  <span className="text-[10px] text-slate-400 font-sans">
                    {pkg.publisher ? `${pkg.publisher} • ` : ''}{pkg.version ? `v${pkg.version}` : ''}
                  </span>
                </div>
              </div>
              <div className="text-right flex items-center gap-4">
                {pkg.reason && (
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border border-dashed ${style.color} border-current opacity-80 max-w-[120px] truncate`}>
                    {pkg.reason}
                  </span>
                )}
                <div className="text-[11px] font-display font-black w-8 text-center" style={{ color: style.color === 'text-cyber-success' ? '#10b981' : style.color === 'text-cyber-danger' ? '#f43f5e' : '#f59e0b'}}>
                  {pkg.score}
                </div>
              </div>
            </div>
          );
        })}
        {filteredPackages.length === 0 && (
          <div className="text-center p-6 text-slate-500 font-mono text-xs uppercase">
            No packages in this category.
          </div>
        )}
      </div>
    </div>
  );
}
