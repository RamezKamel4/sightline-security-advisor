
import React from 'react';
import { Shield, Plus, FileText, Settings as SettingsIcon, LogOut, Search } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';

interface SidebarProps {
  activeView: string;
  onViewChange: (view: string) => void;
}

export const Sidebar = ({ activeView, onViewChange }: SidebarProps) => {
  const { signOut, user } = useAuth();
  
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield },
    { id: 'history', label: 'Scan History', icon: FileText },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
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
      
      <nav className="flex-1 p-4">
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
          <li>
            <Link
              to="/cve-lookup"
              className="w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 text-slate-300 hover:bg-slate-800 hover:text-white"
            >
              <Search className="h-5 w-5" />
              <span className="font-medium">CVE Lookup</span>
            </Link>
          </li>
        </ul>
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
          <div className="text-2xl font-bold text-green-400">47</div>
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
