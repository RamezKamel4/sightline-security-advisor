
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { FileText, Download, Search, Filter } from 'lucide-react';

export const ScanHistory = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');

  const mockScans = [
    {
      id: 1,
      target: '192.168.1.0/24',
      profile: 'Web Applications',
      status: 'completed',
      risk: 'high',
      date: '2025-05-25 10:30',
      duration: '15m 32s',
      findings: 23,
      critical: 3,
    },
    {
      id: 2,
      target: 'api.company.com',
      profile: 'Web Applications',
      status: 'running',
      risk: 'medium',
      date: '2025-05-25 09:15',
      duration: '8m 45s',
      findings: 12,
      critical: 0,
    },
    {
      id: 3,
      target: '10.0.0.0/16',
      profile: 'Comprehensive',
      status: 'completed',
      risk: 'low',
      date: '2025-05-24 16:45',
      duration: '45m 12s',
      findings: 8,
      critical: 0,
    },
    {
      id: 4,
      target: 'db.internal.com',
      profile: 'Databases',
      status: 'failed',
      risk: 'unknown',
      date: '2025-05-24 14:20',
      duration: '2m 10s',
      findings: 0,
      critical: 0,
    },
  ];

  const getStatusBadge = (status: string) => {
    const variants = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
      pending: 'bg-yellow-100 text-yellow-800',
    };
    return variants[status as keyof typeof variants] || 'bg-gray-100 text-gray-800';
  };

  const getRiskBadge = (risk: string) => {
    const variants = {
      high: 'bg-red-100 text-red-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-green-100 text-green-800',
      unknown: 'bg-gray-100 text-gray-800',
    };
    return variants[risk as keyof typeof variants] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Scan History</h1>
          <p className="text-slate-600 mt-1">View and manage your security scans</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-4 sm:space-y-0">
            <CardTitle>Recent Scans</CardTitle>
            <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                <Input
                  placeholder="Search targets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 w-full sm:w-64"
                />
              </div>
              <Select value={filterStatus} onValueChange={setFilterStatus}>
                <SelectTrigger className="w-full sm:w-40">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="running">Running</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Target</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Profile</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Risk</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Date</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Duration</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Findings</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Actions</th>
                </tr>
              </thead>
              <tbody>
                {mockScans.map((scan) => (
                  <tr key={scan.id} className="border-b border-slate-100 hover:bg-slate-50">
                    <td className="py-4 px-4">
                      <div className="font-medium text-slate-900">{scan.target}</div>
                    </td>
                    <td className="py-4 px-4 text-slate-600">{scan.profile}</td>
                    <td className="py-4 px-4">
                      <Badge className={getStatusBadge(scan.status)}>
                        {scan.status}
                      </Badge>
                    </td>
                    <td className="py-4 px-4">
                      <Badge className={getRiskBadge(scan.risk)}>
                        {scan.risk}
                      </Badge>
                    </td>
                    <td className="py-4 px-4 text-slate-600">{scan.date}</td>
                    <td className="py-4 px-4 text-slate-600">{scan.duration}</td>
                    <td className="py-4 px-4">
                      <div className="text-slate-900">
                        {scan.findings} total
                        {scan.critical > 0 && (
                          <div className="text-xs text-red-600">{scan.critical} critical</div>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-4">
                      <div className="flex space-x-2">
                        <Button size="sm" variant="outline">
                          <FileText className="h-4 w-4 mr-1" />
                          Report
                        </Button>
                        <Button size="sm" variant="outline">
                          <Download className="h-4 w-4 mr-1" />
                          PDF
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
