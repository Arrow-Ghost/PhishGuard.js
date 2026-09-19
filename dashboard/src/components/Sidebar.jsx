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

// Grouped like System Settings: each destination gets a coloured icon tile.
const GROUPS = [
  {
    title: 'Protect',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, tile: '#0A84FF' },
      { id: 'supplychain', label: 'Supply Chain', icon: PackageSearch, tile: '#FF9F0A' },
      { id: 'threatmap', label: 'Threat Map', icon: Network, tile: '#BF5AF2' },
      { id: 'sandbox', label: 'Shield Sandbox', icon: Terminal, tile: '#30D158' },
    ],
  },
  {
    title: 'Observe',
    items: [
      { id: 'globalintel', label: 'Global Intel', icon: Globe2, tile: '#64D2FF' },
      { id: 'logs', label: 'Telemetry', icon: Activity, tile: '#FF453A' },
      { id: 'forensics', label: 'Forensics', icon: FileSearch, tile: '#5E5CE6' },
      { id: 'dbexplorer', label: 'Database', icon: Database, tile: '#8E8E93' },
    ],
  },
];

export default function Sidebar({ activeView, setActiveView, isConnected, project }) {
  return (
    <aside className="relative z-10 w-[248px] shrink-0 flex flex-col bg-[#242426] border-r border-white/[0.06] px-3 pt-5 pb-4">
      <div className="flex items-center gap-2.5 px-2 mb-6 select-none">
        <span className="w-8 h-8 rounded-[9px] bg-[#0A84FF] flex items-center justify-center text-white text-[15px] font-bold">P</span>
        <div className="min-w-0">
          <h1 className="text-[15px] font-semibold leading-tight text-white">PhishGuard</h1>
          <span className="text-[11px] text-slate-500 block truncate max-w-[170px]" title={project?.root}>
            {project ? project.name : 'supply-chain guard'}
          </span>
        </div>
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto">
        {GROUPS.map((g) => (
          <div key={g.title}>
            <div className="px-2 mb-1.5 text-[11px] font-semibold text-slate-500">{g.title}</div>
            <div className="space-y-0.5">
              {g.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeView === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveView(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2 py-[6px] rounded-lg text-left transition-colors ${
                      isActive ? 'bg-white/[0.16] text-white font-semibold' : 'text-slate-200 hover:bg-white/[0.07]'
                    }`}
                  >
                    <span className="w-[22px] h-[22px] rounded-[6px] flex items-center justify-center shrink-0" style={{ background: item.tile }}>
                      <Icon className="w-3.5 h-3.5 text-white" strokeWidth={2.2} />
                    </span>
                    <span className="text-[14px] truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="mt-4 rounded-xl bg-white/[0.06] px-3 py-2.5">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-cyber-success' : 'bg-cyber-danger'}`} />
          <span className="text-[13px] font-medium text-white">{isConnected ? 'Runtime agent' : 'Agent offline'}</span>
        </div>
        <span className="block mt-0.5 text-[11px] text-slate-500">
          {isConnected ? 'Listening on port 4173' : 'Waiting to reconnect'}
        </span>
      </div>
    </aside>
  );
}
