
import React from 'react';
import { Plus, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';

interface DashboardProps {
  onNewScan: () => void;
}

export const Dashboard = ({ onNewScan }: DashboardProps) => {
  // Fetch dashboard statistics
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('Not authenticated');

      // Get total scans
      const { count: totalScans } = await supabase
        .from('scans')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', user.id);

      // Get pending scans
      const { count: pendingScans } = await supabase
        .from('scans')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', user.id)
        .eq('status', 'running');

      // Get completed scans for calculating critical findings
      const { data: completedScans } = await supabase
        .from('scans')
        .select('scan_id')
        .eq('user_id', user.id)
        .eq('status', 'completed');

      let criticalFindings = 0;
      let totalFindings = 0;

      if (completedScans && completedScans.length > 0) {
        const scanIds = completedScans.map(scan => scan.scan_id);
        
        // Get all findings for completed scans
        const { data: findings } = await supabase
          .from('findings')
          .select('cve_id')
          .in('scan_id', scanIds);

        if (findings) {
          totalFindings = findings.length;
          // For now, count findings with CVEs as critical (we could enhance this with actual CVSS scoring)
          criticalFindings = findings.filter(f => f.cve_id).length;
        }
      }

      // For "resolved issues", we'll use a simple calculation (total findings - critical)
      // In a real app, this would track actual resolution status
      const resolvedIssues = Math.max(0, totalFindings - criticalFindings);

      return {
        totalScans: totalScans || 0,
        criticalFindings,
        resolvedIssues,
        pendingScans: pendingScans || 0
      };
    }
  });

  // Fetch recent scans
  const { data: recentScans, isLoading: scansLoading } = useQuery({
    queryKey: ['recent-scans'],
    queryFn: async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('Not authenticated');

      const { data } = await supabase
        .from('scans')
        .select('scan_id, target, status, start_time')
        .eq('user_id', user.id)
        .order('start_time', { ascending: false })
        .limit(3);

      return data || [];
    }
  });

  const statsData = [
    { title: 'Total Scans', value: statsLoading ? '...' : stats?.totalScans.toString() || '0', icon: Shield, color: 'text-blue-600' },
    { title: 'Critical Findings', value: statsLoading ? '...' : stats?.criticalFindings.toString() || '0', icon: AlertTriangle, color: 'text-red-600' },
    { title: 'Resolved Issues', value: statsLoading ? '...' : stats?.resolvedIssues.toString() || '0', icon: CheckCircle, color: 'text-green-600' },
    { title: 'Pending Scans', value: statsLoading ? '...' : stats?.pendingScans.toString() || '0', icon: Clock, color: 'text-yellow-600' },
  ];

  const getStatusBadge = (status: string) => {
    const styles = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
    };
    return `px-2 py-1 rounded-full text-xs font-medium ${styles[status as keyof typeof styles]}`;
  };

  const getRiskBadge = (findingsCount: number) => {
    // Simple risk calculation based on findings count
    if (findingsCount >= 5) return 'bg-red-100 text-red-800';
    if (findingsCount >= 2) return 'bg-yellow-100 text-yellow-800';
    return 'bg-green-100 text-green-800';
  };

  const getRiskLevel = (findingsCount: number) => {
    if (findingsCount >= 5) return 'high';
    if (findingsCount >= 2) return 'medium';
    return 'low';
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Unknown';
    return new Date(dateString).toLocaleString();
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
        {statsData.map((stat, index) => {
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
              {scansLoading ? (
                <div className="text-center py-4 text-slate-600">Loading recent scans...</div>
              ) : recentScans && recentScans.length > 0 ? (
                recentScans.map((scan) => (
                  <div key={scan.scan_id} className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
                    <div>
                      <p className="font-medium text-slate-900">{scan.target}</p>
                      <p className="text-sm text-slate-600">{formatDate(scan.start_time)}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskBadge(0)}`}>
                        {getRiskLevel(0)}
                      </span>
                      <span className={getStatusBadge(scan.status || 'unknown')}>{scan.status}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-slate-600">No scans yet. Create your first scan!</div>
              )}
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
                    <div 
                      className="h-2 bg-red-500 rounded-full" 
                      style={{ width: stats?.criticalFindings ? `${Math.min((stats.criticalFindings / Math.max(stats.criticalFindings + stats.resolvedIssues, 1)) * 100, 100)}%` : '0%' }}
                    ></div>
                  </div>
                  <span className="text-sm font-medium">{stats?.criticalFindings || 0}</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600">Medium</span>
                <div className="flex items-center space-x-2">
                  <div className="w-32 h-2 bg-slate-200 rounded-full">
                    <div className="w-1/2 h-2 bg-yellow-500 rounded-full"></div>
                  </div>
                  <span className="text-sm font-medium">0</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600">Low</span>
                <div className="flex items-center space-x-2">
                  <div className="w-32 h-2 bg-slate-200 rounded-full">
                    <div 
                      className="h-2 bg-green-500 rounded-full" 
                      style={{ width: stats?.resolvedIssues ? `${Math.min((stats.resolvedIssues / Math.max(stats.criticalFindings + stats.resolvedIssues, 1)) * 100, 100)}%` : '0%' }}
                    ></div>
                  </div>
                  <span className="text-sm font-medium">{stats?.resolvedIssues || 0}</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
