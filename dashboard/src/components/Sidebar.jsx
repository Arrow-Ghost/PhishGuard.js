import React from 'react';
import {
  LayoutDashboard,
  Network,
  PackageSearch,
  Terminal,
  Activity,
  Database,
  FileSearch,
  Globe2
} from 'lucide-react';

export default function Sidebar({ activeView, setActiveView, isConnected, project }) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'supplychain', label: 'Supply Chain', icon: PackageSearch },
    { id: 'threatmap', label: 'Threat Map', icon: Network },
    { id: 'globalintel', label: 'Global Intel', icon: Globe2 },
    { id: 'logs', label: 'Telemetry', icon: Activity },
    { id: 'forensics', label: 'Forensics', icon: FileSearch },
    { id: 'dbexplorer', label: 'Database', icon: Database },
    { id: 'sandbox', label: 'Shield Sandbox', icon: Terminal },
  ];

  return (
    <aside className="glass-panel relative z-10 m-5 mr-0 w-64 px-4 py-6 flex flex-col shrink-0 border !rounded-[30px]">

      {/* Brand */}
      <div className="flex items-center gap-3 mb-8 px-2 select-none">
        <span
          aria-hidden="true"
          className="w-10 h-10 rounded-full shrink-0"
          style={{
            background: 'radial-gradient(circle at 34% 30%, #F4F7FA 0%, #B9C4D0 30%, #5A626D 64%, #2B2F36 100%)',
            boxShadow: '0 0 18px rgba(169, 195, 222, 0.6)',
          }}
        />
        <div className="min-w-0">
          <h1 className="font-display font-normal text-[20px] leading-tight text-white">PhishGuard</h1>
          <span className="text-[11px] text-slate-300/80 block truncate max-w-[150px]" title={project?.root}>
            {project ? project.name : 'zero-trust supply-chain guard'}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="space-y-1 flex-1">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id)}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-2xl text-left border transition-all duration-200 ${
                isActive
                  ? 'neo-inset text-white font-semibold'
                  : 'bg-transparent border-transparent text-slate-200/80 hover:text-white hover:bg-white/[0.07]'
              }`}
            >
              <Icon className={`w-[18px] h-[18px] ${isActive ? 'text-white' : 'text-slate-300'}`} />
              <span className="text-sm truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Agent status */}
      <div className="mt-4 rounded-[22px] border border-white/20 bg-white/[0.08] px-4 py-3.5">
        <div className="flex items-center gap-2.5">
          <span
            className={`w-2 h-2 rounded-full ${isConnected ? 'bg-cyber-success' : 'bg-cyber-danger'}`}
            style={{ boxShadow: isConnected ? '0 0 10px #7FD1A8' : '0 0 10px #E58585' }}
          />
          <span className="text-[13px] font-medium text-white">
            {isConnected ? 'Agent is watching' : 'Agent offline'}
          </span>
        </div>
        <span className="block mt-1 font-mono text-[11px] text-slate-400">ws://localhost:4173</span>
      </div>
    </aside>
  );
}
