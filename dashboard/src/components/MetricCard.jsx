import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

export default function MetricCard({ title, value, subtext, icon: Icon, color = 'primary', trend, sparklineData }) {
  // Styles mapping matching our tailwind SOC palette
  const styles = {
    primary: {
      border: 'hover:border-cyber-primary/60 hover:shadow-glow-primary/20',
      iconBg: 'bg-cyber-primary/10 border-cyber-primary/30 text-cyber-primary',
      badge: 'bg-cyber-primary/10 text-cyber-primary border-cyber-primary/25',
      glow: 'shadow-glow-primary/10'
    },
    success: {
      border: 'hover:border-cyber-success/60 hover:shadow-glow-success/20',
      iconBg: 'bg-cyber-success/10 border-cyber-success/30 text-cyber-success',
      badge: 'bg-cyber-success/10 text-cyber-success border-cyber-success/25',
      glow: 'shadow-glow-success/10'
    },
    danger: {
      border: 'hover:border-cyber-danger/60 hover:shadow-glow-danger/20',
      iconBg: 'bg-cyber-danger/10 border-cyber-danger/30 text-cyber-danger',
      badge: 'bg-cyber-danger/10 text-cyber-danger border-cyber-danger/25',
      glow: 'shadow-glow-danger/10'
    },
    warning: {
      border: 'hover:border-cyber-warning/60 hover:shadow-glow-warning/20',
      iconBg: 'bg-cyber-warning/10 border-cyber-warning/30 text-cyber-warning',
      badge: 'bg-cyber-warning/10 text-cyber-warning border-cyber-warning/25',
      glow: 'shadow-glow-warning/10'
    }
  };

  const currentStyle = styles[color] || styles.primary;

  return (
    <div className={`glass-panel p-5 rounded-xl border border-cyber-border/40 transition-all duration-150 relative group overflow-hidden`}>
      <div className="flex justify-between items-start mb-4 relative z-10">
        <div>
          <span className="text-xs font-mono font-medium tracking-wider text-slate-400 uppercase block">
            {title}
          </span>
          <span className="text-2xl font-sans font-bold text-slate-100 mt-1.5 block tracking-wide">
            {value}
          </span>
        </div>
        <div className={`p-2.5 rounded-lg border ${currentStyle.iconBg}`}>
          <Icon className="w-5.5 h-5.5" />
        </div>
      </div>

      <div className="flex items-center gap-3 relative z-10">
        {/* Trend Indicator Badge */}
        {trend && (
          <div className={`flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
            trend.type === 'up'
              ? 'bg-cyber-success/15 border-cyber-success/35 text-cyber-success'
              : 'bg-cyber-danger/15 border-cyber-danger/35 text-cyber-danger'
          }`}>
            {trend.type === 'up' ? <TrendingUp className="w-3.5 h-3.5" /> : <TrendingDown className="w-3.5 h-3.5" />}
            {trend.value}
          </div>
        )}
        
        <span className="text-xs text-slate-400 tracking-wide select-none">
          {subtext}
        </span>

        {/* Small Real-Time Pulse sparklines */}
        {sparklineData && (
          <div className="ml-auto w-20 h-7 flex items-end gap-[2px]">
            {sparklineData.map((val, idx) => {
              const max = Math.max(...sparklineData);
              const heightPercent = `${(val / max) * 100}%`;
              return (
                <div
                  key={idx}
                  style={{ height: heightPercent }}
                  className={`w-[3px] rounded-t-sm transition-all duration-300 ${
                    color === 'primary' 
                      ? 'bg-cyber-primary/40 group-hover:bg-cyber-primary' 
                      : color === 'success' 
                      ? 'bg-cyber-success/40 group-hover:bg-cyber-success' 
                      : color === 'danger' 
                      ? 'bg-cyber-danger/40 group-hover:bg-cyber-danger' 
                      : 'bg-cyber-warning/40 group-hover:bg-cyber-warning'
                  }`}
                />
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
