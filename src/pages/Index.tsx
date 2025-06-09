
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Sidebar } from '@/components/Sidebar';
import { Dashboard } from '@/components/Dashboard';
import { ScanHistory } from '@/components/ScanHistory';
import { Settings } from '@/components/Settings';
import { NewScanModal } from '@/components/NewScanModal';

const Index = () => {
  const [activeView, setActiveView] = useState('dashboard');
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      navigate('/auth');
    }
  }, [user, navigate]);

  const handleScanCreated = () => {
    setRefreshKey(prev => prev + 1);
  };

  const renderContent = () => {
    switch (activeView) {
      case 'dashboard':
        return <Dashboard onNewScan={() => setIsNewScanOpen(true)} />;
      case 'history':
        return <ScanHistory key={refreshKey} />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard onNewScan={() => setIsNewScanOpen(true)} />;
    }
  };

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <Sidebar activeView={activeView} onViewChange={setActiveView} />
      <main className="flex-1 p-6">
        {renderContent()}
      </main>
      <NewScanModal 
        isOpen={isNewScanOpen} 
        onClose={() => setIsNewScanOpen(false)}
        onScanCreated={handleScanCreated}
      />
    </div>
  );
};

export default Index;
