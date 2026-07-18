import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { useCaptureStore } from '../../store/captureStore';
import { 
  LayoutDashboard, 
  ListTree, 
  Activity,
  Network,
  ShieldAlert,
  Bot,
  Settings,
  ChevronLeft,
  ChevronRight,
  Globe,
  MonitorCheck
} from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

const api = axios.create({ baseURL: '' });

const NavItem = ({ to, icon: Icon, label, collapsed, badgeCount }) => {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => twMerge(
        clsx(
          "flex items-center px-4 py-3 mx-2 my-1 rounded-md transition-colors",
          "hover:bg-slate-100 text-slate-600 font-medium",
          isActive && "bg-blue-50 text-blue-700 font-semibold before:absolute before:left-0 before:w-1 before:h-8 before:bg-blue-600 before:rounded-r-full relative"
        )
      )}
      title={collapsed ? label : undefined}
    >
      <Icon className="w-5 h-5 min-w-[20px]" />
      {!collapsed && (
        <span className="ml-3 truncate flex-1">{label}</span>
      )}
      {!collapsed && badgeCount > 0 && (
        <span className="ml-auto bg-red-100 text-red-700 py-0.5 px-2 rounded-full text-xs font-semibold">
          {badgeCount}
        </span>
      )}
      {collapsed && badgeCount > 0 && (
        <span className="absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full" />
      )}
    </NavLink>
  );
};

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const { sessionId, isCapturing } = useCaptureStore();

  // Live alert count for badge
  const { data: alertsData = [] } = useQuery({
    queryKey: ['alerts-count', sessionId],
    queryFn: () =>
      api.get(`/api/alerts?n=100${sessionId ? `&session_id=${sessionId}` : ''}`).then(r =>
        Array.isArray(r.data) ? r.data : []
      ),
    refetchInterval: isCapturing ? 10000 : false,
    enabled: !!sessionId,
  });
  const alertCount = alertsData.length;

  return (
    <aside 
      className={clsx(
        "flex flex-col bg-white border-r border-slate-200 transition-all duration-300",
        collapsed ? "w-[72px]" : "w-[240px]"
      )}
    >
      <div className="h-14 flex items-center px-4 border-b border-slate-200">
        <div className="w-8 h-8 rounded-md flex items-center justify-center shrink-0">
          <img src="/logo.png" alt="PeliCap Logo" className="w-8 h-8 object-contain" />
        </div>
        {!collapsed && (
          <span className="ml-3 font-semibold text-slate-900 tracking-tight whitespace-nowrap">
            PeliCap
          </span>
        )}
      </div>

      <nav className="flex-1 py-4 overflow-y-auto overflow-x-hidden space-y-1">
        <NavItem to="/sessions" icon={ListTree} label="Sessions" collapsed={collapsed} />
        <NavItem to="/overview" icon={LayoutDashboard} label="Overview" collapsed={collapsed} />
        <NavItem to="/flows" icon={Activity} label="Flow Explorer" collapsed={collapsed} />
        <NavItem to="/packets" icon={ListTree} label="Packet Explorer" collapsed={collapsed} />
        
        {!collapsed && <div className="px-6 py-2 mt-4 text-xs font-semibold text-slate-400 uppercase tracking-wider">Analytics</div>}
        {collapsed && <div className="h-4" />}
        
        <NavItem to="/dns" icon={Globe} label="DNS Analytics" collapsed={collapsed} />
        <NavItem to="/http" icon={MonitorCheck} label="Web Analytics" collapsed={collapsed} />
        <NavItem to="/topology" icon={Network} label="Network Topology" collapsed={collapsed} />
        
        {!collapsed && <div className="px-6 py-2 mt-4 text-xs font-semibold text-slate-400 uppercase tracking-wider">Security</div>}
        {collapsed && <div className="h-4" />}
        
        <NavItem to="/alerts" icon={ShieldAlert} label="Alerts" collapsed={collapsed} badgeCount={alertCount} />
        <NavItem to="/copilot" icon={Bot} label="AI Copilot" collapsed={collapsed} />
      </nav>

      <div className="p-4 border-t border-slate-200">
        <NavItem to="/settings" icon={Settings} label="Settings" collapsed={collapsed} />
        <button 
          onClick={() => setCollapsed(!collapsed)}
          className="mt-2 w-full flex items-center justify-center p-2 rounded hover:bg-slate-100 text-slate-500 transition-colors"
        >
          {collapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
