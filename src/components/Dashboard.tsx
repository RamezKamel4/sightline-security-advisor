
import React from 'react';
import { Plus, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface DashboardProps {
  onNewScan: () => void;
}

export const Dashboard = ({ onNewScan }: DashboardProps) => {
  const stats = [
    { title: 'Total Scans', value: '247', icon: Shield, color: 'text-blue-600' },
    { title: 'Critical Findings', value: '12', icon: AlertTriangle, color: 'text-red-600' },
    { title: 'Resolved Issues', value: '89', icon: CheckCircle, color: 'text-green-600' },
    { title: 'Pending Scans', value: '3', icon: Clock, color: 'text-yellow-600' },
  ];

  const recentScans = [
    { id: 1, target: '192.168.1.0/24', status: 'completed', risk: 'high', date: '2025-05-25 10:30' },
    { id: 2, target: 'api.company.com', status: 'running', risk: 'medium', date: '2025-05-25 09:15' },
    { id: 3, target: '10.0.0.0/16', status: 'completed', risk: 'low', date: '2025-05-24 16:45' },
  ];

  const getStatusBadge = (status: string) => {
    const styles = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
    };
    return `px-2 py-1 rounded-full text-xs font-medium ${styles[status as keyof typeof styles]}`;
  };

  const getRiskBadge = (risk: string) => {
    const styles = {
      high: 'bg-red-100 text-red-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-green-100 text-green-800',
    };
    return `px-2 py-1 rounded-full text-xs font-medium ${styles[risk as keyof typeof styles]}`;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Security Dashboard</h1>
          <p className="text-slate-600 mt-1">Monitor your network security posture</p>
        </div>
        <Button onClick={onNewScan} className="bg-blue-600 hover:bg-blue-700">
          <Plus className="h-4 w-4 mr-2" />
          New Scan
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <Card key={index} className="hover:shadow-lg transition-shadow duration-200">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-slate-600">{stat.title}</p>
                    <p className="text-3xl font-bold text-slate-900 mt-2">{stat.value}</p>
                  </div>
                  <Icon className={`h-8 w-8 ${stat.color}`} />
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Recent Scans</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentScans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
                  <div>
                    <p className="font-medium text-slate-900">{scan.target}</p>
                    <p className="text-sm text-slate-600">{scan.date}</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={getRiskBadge(scan.risk)}>{scan.risk}</span>
                    <span className={getStatusBadge(scan.status)}>{scan.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Risk Overview</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600">Critical</span>
                <div className="flex items-center space-x-2">
                  <div className="w-32 h-2 bg-slate-200 rounded-full">
                    <div className="w-1/4 h-2 bg-red-500 rounded-full"></div>
                  </div>
                  <span className="text-sm font-medium">12</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600">Medium</span>
                <div className="flex items-center space-x-2">
                  <div className="w-32 h-2 bg-slate-200 rounded-full">
                    <div className="w-1/2 h-2 bg-yellow-500 rounded-full"></div>
                  </div>
                  <span className="text-sm font-medium">24</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600">Low</span>
                <div className="flex items-center space-x-2">
                  <div className="w-32 h-2 bg-slate-200 rounded-full">
                    <div className="w-3/4 h-2 bg-green-500 rounded-full"></div>
                  </div>
                  <span className="text-sm font-medium">56</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
