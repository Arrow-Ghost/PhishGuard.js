import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { BrainCircuit, AlertTriangle } from 'lucide-react';
import { usePhishGuard } from '../App';

export default function ThreatPredictionEngine() {
  const pg = usePhishGuard();
  const nonce = pg ? pg.nonce : 0;
  const [data, setData] = useState({ forecast: [], packageRisks: [], basis: null });

  useEffect(() => {
    fetch('/api/threat-prediction')
      .then(res => res.json())
      .then(resData => setData(resData))
      .catch(console.error);
  }, [nonce]);

  return (
    <div className="glass-panel rounded-xl border border-cyber-border/40 p-5 flex flex-col h-[400px]">
      <div className="flex justify-between items-center mb-4 border-b border-cyber-border/30 pb-3 shrink-0">
        <div className="flex items-center gap-2">
          <BrainCircuit className="w-5 h-5 text-cyber-purple" />
          <div>
            <h3 className="font-sans font-bold text-sm tracking-wide text-slate-100">Posture Projection</h3>
            <span className="text-[10px] text-slate-400">
              14-day linear regression over scan history{data.basis === 'insufficient-history' ? ' (needs ≥2 scans)' : ''}
            </span>
          </div>
        </div>
      </div>

      <div className="flex-1 relative flex gap-6 min-h-0">
        
        {/* Chart Area */}
        <div className="flex-1 relative">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data.forecast} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="day" stroke="#475569" fontSize={10} tickMargin={10} axisLine={false} tickLine={false} />
              <YAxis stroke="#475569" fontSize={10} axisLine={false} tickLine={false} domain={[0, 100]} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '12px' }}
                itemStyle={{ color: '#c084fc' }}
                labelStyle={{ color: '#94a3b8', marginBottom: '4px' }}
              />
              <Line
                type="monotone"
                dataKey="riskProbability"
                stroke="#c084fc"
                strokeWidth={2}
                dot={{ fill: '#c084fc', r: 3, strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#fff', stroke: '#c084fc', strokeWidth: 2 }}
                name="Projected risk %"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* High Risk Packages List */}
        <div className="w-48 flex flex-col gap-2 overflow-y-auto pr-1">
          <span className="text-[10px] font-mono uppercase text-slate-500 mb-1">Predicted Exploits</span>
          {data.packageRisks.map((pkg, i) => (
            <div key={i} className="p-2.5 bg-cyber-bg/50 border border-cyber-border/30 rounded-lg">
              <div className="flex justify-between items-start mb-1">
                <span className="font-bold text-xs text-slate-200 truncate pr-2">{pkg.name}</span>
                <span className="text-[10px] font-mono text-cyber-danger">{pkg.score}%</span>
              </div>
              <div className="flex items-center gap-1 mt-1">
                <AlertTriangle className="w-3 h-3 text-cyber-warning" />
                <span className="text-[9px] text-slate-400">{pkg.driver}</span>
              </div>
            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
