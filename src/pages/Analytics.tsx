import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Activity, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { useAuth } from '@/contexts/AuthContext';
import { useUserRole } from '@/hooks/useUserRole';

const Analytics = () => {
  const { user } = useAuth();
  const { isAdmin } = useUserRole();

  // Fetch scan statistics
  const { data: scanStats, isLoading: statsLoading } = useQuery({
    queryKey: ['scan-analytics', user?.id],
    queryFn: async () => {
      if (!user) return null;

      // Always filter by current user's scans
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', user.id);
      
      if (error) throw error;

      const total = data.length;
      const completed = data.filter(s => s.status === 'completed').length;
      const failed = data.filter(s => s.status === 'failed').length;
      const running = data.filter(s => s.status === 'running').length;

      // Group by profile
      const byProfile: Record<string, number> = {};
      data.forEach(scan => {
        const profile = scan.profile || 'quick';
        byProfile[profile] = (byProfile[profile] || 0) + 1;
      });

      // Scans per day (last 7 days)
      const last7Days = [...Array(7)].map((_, i) => {
        const date = new Date();
        date.setDate(date.getDate() - i);
        return date.toISOString().split('T')[0];
      }).reverse();

      const scansByDay = last7Days.map(day => {
        const dayStart = new Date(day);
        const dayEnd = new Date(day);
        dayEnd.setDate(dayEnd.getDate() + 1);
        
        return {
          date: dayStart.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
          scans: data.filter(s => {
            if (!s.start_time) return false;
            const scanDate = new Date(s.start_time);
            return scanDate >= dayStart && scanDate < dayEnd;
          }).length,
        };
      });

      return {
        total,
        completed,
        failed,
        running,
        byProfile: Object.entries(byProfile).map(([name, value]) => ({ name, value })),
        scansByDay,
      };
    },
  });

  // Fetch vulnerability statistics
  const { data: vulnStats, isLoading: vulnLoading } = useQuery({
    queryKey: ['vulnerability-stats', user?.id],
    queryFn: async () => {
      if (!user) return null;

      // Always filter findings by current user's scans
      const { data, error } = await supabase
        .from('findings')
        .select('*, cve(*), scans!inner(user_id)')
        .eq('scans.user_id', user.id);
      
      if (error) throw error;

      const totalFindings = data.length;
      const withCVE = data.filter(f => f.cve_id).length;
      
      // Group by severity (based on CVSS score)
      const critical = data.filter(f => f.cve?.cvss_score && f.cve.cvss_score >= 9.0).length;
      const high = data.filter(f => f.cve?.cvss_score && f.cve.cvss_score >= 7.0 && f.cve.cvss_score < 9.0).length;
      const medium = data.filter(f => f.cve?.cvss_score && f.cve.cvss_score >= 4.0 && f.cve.cvss_score < 7.0).length;
      const low = data.filter(f => f.cve?.cvss_score && f.cve.cvss_score < 4.0).length;

      return {
        totalFindings,
        withCVE,
        bySeverity: [
          { name: 'Critical', value: critical, color: '#ef4444' },
          { name: 'High', value: high, color: '#f97316' },
          { name: 'Medium', value: medium, color: '#eab308' },
          { name: 'Low', value: low, color: '#22c55e' },
        ],
      };
    },
  });

  if (statsLoading || vulnLoading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          My Analytics
        </h1>
        <p className="text-muted-foreground">
          View your scan statistics and vulnerability findings
        </p>
      </div>

      {/* Key Metrics */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scanStats?.total || 0}</div>
            <p className="text-xs text-muted-foreground">All time</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scanStats?.completed || 0}</div>
            <p className="text-xs text-muted-foreground">
              {scanStats?.total ? Math.round((scanStats.completed / scanStats.total) * 100) : 0}% success rate
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scanStats?.failed || 0}</div>
            <p className="text-xs text-muted-foreground">
              {scanStats?.total ? Math.round((scanStats.failed / scanStats.total) * 100) : 0}% failure rate
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities Found</CardTitle>
            <TrendingUp className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{vulnStats?.totalFindings || 0}</div>
            <p className="text-xs text-muted-foreground">{vulnStats?.withCVE || 0} with CVE IDs</p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Scans Over Time (Last 7 Days)</CardTitle>
            <CardDescription>Daily scan activity</CardDescription>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scanStats?.scansByDay}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="scans" fill="hsl(var(--primary))" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Vulnerability Severity Distribution</CardTitle>
            <CardDescription>Breakdown by CVSS score</CardDescription>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={vulnStats?.bySeverity}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {vulnStats?.bySeverity.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scans by Profile</CardTitle>
            <CardDescription>Distribution of scan profiles used</CardDescription>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scanStats?.byProfile} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" />
                <Tooltip />
                <Bar dataKey="value" fill="hsl(var(--chart-2))" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Analytics;
