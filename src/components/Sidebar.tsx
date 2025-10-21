
import React from 'react';
import { Shield, FileText, Settings as SettingsIcon, LogOut, Search, Info, Users, BarChart3 } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { useUserRole } from '@/hooks/useUserRole';

interface SidebarProps {
  activeView: string;
  onViewChange: (view: string) => void;
}

export const Sidebar = ({ activeView, onViewChange }: SidebarProps) => {
  const { signOut, user } = useAuth();
  const { isAdmin, isLoading: roleLoading } = useUserRole();
  
  // Fetch scans this month
  const { data: scansThisMonth } = useQuery({
    queryKey: ['scans-this-month', user?.id],
    queryFn: async () => {
      if (!user) return 0;
      
      const { count } = await supabase
        .from('scans')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', user.id)
        .gte('start_time', new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0]);
      
      return count || 0;
    },
    enabled: !!user
  });
  
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield, path: '/' },
    { id: 'history', label: 'Scan History', icon: FileText, path: '/' },
    { id: 'settings', label: 'Settings', icon: SettingsIcon, path: '/' },
  ];

  const adminMenuItems = [
    { label: 'Users', icon: Users, path: '/admin/users' },
    { label: 'Analytics', icon: BarChart3, path: '/admin/analytics' },
  ];

  const externalMenuItems = [
    { label: 'How It Works', icon: Info, path: '/workflow' },
    { label: 'CVE Lookup', icon: Search, path: '/cve-lookup' },
  ];

  const handleSignOut = async () => {
    await signOut();
  };

  return (
    <div className="w-64 bg-slate-900 text-white flex flex-col">
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center space-x-3">
          <Shield className="h-8 w-8 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">VulnScan AI</h1>
            <p className="text-slate-400 text-sm">Security Scanner</p>
          </div>
        </div>
      </div>
      
      <nav className="flex-1 p-4 space-y-6">
        <div>
          <ul className="space-y-2">
            {menuItems.map((item) => {
              const Icon = item.icon;
              return (
                <li key={item.id}>
                  <button
                    onClick={() => onViewChange(item.id)}
                    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                      activeView === item.id
                        ? 'bg-blue-600 text-white shadow-lg'
                        : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    <Icon className="h-5 w-5" />
                    <span className="font-medium">{item.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>

        {isAdmin && !roleLoading && (
          <div>
            <div className="px-4 mb-2">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Admin
              </p>
            </div>
            <ul className="space-y-2">
              {adminMenuItems.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.path}>
                    <NavLink
                      to={item.path}
                      className={({ isActive }) => 
                        `w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                          isActive
                            ? 'bg-blue-600 text-white shadow-lg'
                            : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                        }`
                      }
                    >
                      <Icon className="h-5 w-5" />
                      <span className="font-medium">{item.label}</span>
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        <div>
          <div className="px-4 mb-2">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Resources
            </p>
          </div>
          <ul className="space-y-2">
            {externalMenuItems.map((item) => {
              const Icon = item.icon;
              return (
                <li key={item.path}>
                  <NavLink
                    to={item.path}
                    className={({ isActive }) => 
                      `w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                        isActive
                          ? 'bg-blue-600 text-white shadow-lg'
                          : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                      }`
                    }
                  >
                    <Icon className="h-5 w-5" />
                    <span className="font-medium">{item.label}</span>
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </div>
      </nav>
      
      <div className="p-4 border-t border-slate-700 space-y-4">
        {user && (
          <div className="text-center">
            <p className="text-slate-400 text-sm mb-2">Logged in as:</p>
            <p className="text-white text-sm font-medium truncate">{user.email}</p>
          </div>
        )}
        
        <div className="bg-slate-800 rounded-lg p-4 text-center">
          <div className="text-slate-400 text-sm mb-2">Scans this month</div>
          <div className="text-2xl font-bold text-green-400">{scansThisMonth || 0}</div>
        </div>
        
        <Button 
          onClick={handleSignOut}
          variant="outline"
          className="w-full bg-transparent border-slate-600 text-slate-300 hover:bg-slate-800 hover:text-white"
        >
          <LogOut className="h-4 w-4 mr-2" />
          Sign Out
        </Button>
      </div>
    </div>
  );
};
