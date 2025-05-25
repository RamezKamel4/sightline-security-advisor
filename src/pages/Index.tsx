
import React, { useState } from 'react';
import { Sidebar } from '@/components/Sidebar';
import { Dashboard } from '@/components/Dashboard';
import { ScanHistory } from '@/components/ScanHistory';
import { Settings } from '@/components/Settings';
import { NewScanModal } from '@/components/NewScanModal';

const Index = () => {
  const [activeView, setActiveView] = useState('dashboard');
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);

  const renderContent = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard onNewScan={() => setIsNewScanOpen(true)} />;
      case 'history':
        return <ScanHistory />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard onNewScan={() => setIsNewScanOpen(true)} />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <Sidebar activeView={activeView} onViewChange={setActiveView} />
      <main className="flex-1 p-6">
        {renderContent()}
      </main>
      <NewScanModal 
        isOpen={isNewScanOpen} 
        onClose={() => setIsNewScanOpen(false)} 
      />
    </div>
  );
};

export default Index;
