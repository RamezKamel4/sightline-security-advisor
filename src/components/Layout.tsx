import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Sidebar } from '@/components/Sidebar';

interface LayoutProps {
  children: React.ReactNode;
  activeView?: string;
}

export const Layout = ({ children, activeView = '' }: LayoutProps) => {
  const navigate = useNavigate();

  const handleViewChange = (view: string) => {
    // Navigate to the home page which handles these views internally
    navigate('/');
  };

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <Sidebar activeView={activeView} onViewChange={handleViewChange} />
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
};
