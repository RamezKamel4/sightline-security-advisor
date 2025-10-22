
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { FileText, Download, AlertTriangle, CheckCircle, Monitor, Wifi, HardDrive } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/components/ui/use-toast';
import { generateReport } from '@/services/scanService';
import type { HostInfo } from '@/services/scanApi';

interface ScanResultsProps {
  scanId: string;
}

interface Finding {
  finding_id: string;
  host?: string;
  port: number;
  state?: string;
  service_name: string;
  service_version: string | null;
  cve_id: string | null;
  confidence?: number;
  raw_banner?: string;
  headers?: any;
  tls_info?: any;
  proxy_detection?: any;
  detection_methods?: any;
  cve?: {
    cve_id: string;
    title: string;
    description: string;
    cvss_score: number | null;
  };
}

interface Report {
  report_id: string;
  summary: string | null;
  fix_recommendations: string | null;
  created_at: string;
  pdf_url: string | null;
}

export const ScanResults = ({ scanId }: ScanResultsProps) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    fetchFindings();
    fetchReport();
    fetchHostInfo();
  }, [scanId]);

  const fetchFindings = async () => {
    try {
      const { data, error } = await supabase
        .from('findings')
        .select(`
          *,
          cve:cve_id (
            cve_id,
            title,
            description,
            cvss_score
          )
        `)
        .eq('scan_id', scanId);

      if (error) throw error;
      setFindings(data || []);
    } catch (error) {
      console.error('Error fetching findings:', error);
      toast({
        title: "Error",
        description: "Failed to load scan findings",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchReport = async () => {
    try {
      const { data, error } = await supabase
        .from('reports')
        .select('*')
        .eq('scan_id', scanId)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      setReport(data);
    } catch (error) {
      console.error('Error fetching report:', error);
    }
  };

  const fetchHostInfo = async () => {
    try {
      const { data, error } = await supabase
        .from('scans')
        .select('host_info')
        .eq('scan_id', scanId)
        .single();

      if (error) throw error;
      setHostInfo((data as any)?.host_info || null);
    } catch (error) {
      console.error('Error fetching host info:', error);
    }
  };

  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    try {
      await generateReport(scanId);
      await fetchReport();
      toast({
        title: "Report Generated",
        description: "AI-powered security report has been created successfully.",
      });
    } catch (error) {
      toast({
        title: "Report Generation Failed",
        description: error instanceof Error ? error.message : "Failed to generate report",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const handleDownloadPDF = async () => {
    if (!report?.pdf_url) return;

    try {
      const response = await fetch(report.pdf_url);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast({
        title: "PDF Downloaded",
        description: "Report has been downloaded to your device.",
      });
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "Failed to download the PDF report",
        variant: "destructive"
      });
    }
  };

  const getRiskLevel = () => {
    const criticalCVEs = findings.filter(f => f.cve_id).length;
    const highScoreCVEs = findings.filter(f => f.cve?.cvss_score && f.cve.cvss_score >= 7.0).length;
    
    if (highScoreCVEs > 3 || criticalCVEs > 5) return { level: 'High', color: 'bg-red-100 text-red-800' };
    if (highScoreCVEs > 1 || criticalCVEs > 2) return { level: 'Medium', color: 'bg-yellow-100 text-yellow-800' };
    if (criticalCVEs > 0) return { level: 'Low', color: 'bg-orange-100 text-orange-800' };
    return { level: 'Very Low', color: 'bg-green-100 text-green-800' };
  };

  if (loading) {
    return <div className="p-4">Loading scan results...</div>;
  }

  const risk = getRiskLevel();

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Scan Results</h2>
          <p className="text-slate-600">Findings for scan {scanId}</p>
        </div>
        <div className="flex space-x-2">
          {!report && (
            <Button 
              onClick={handleGenerateReport}
              disabled={isGeneratingReport}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <FileText className="h-4 w-4 mr-2" />
              {isGeneratingReport ? 'Generating...' : 'Generate AI Report'}
            </Button>
          )}
          {report && report.pdf_url && (
            <Button variant="outline" onClick={handleDownloadPDF}>
              <Download className="h-4 w-4 mr-2" />
              Download PDF
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-sm text-slate-600">Open Ports</p>
                <p className="text-2xl font-bold">{findings.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-sm text-slate-600">Vulnerabilities</p>
                <p className="text-2xl font-bold">{findings.filter(f => f.cve_id).length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <CheckCircle className={`h-5 w-5 ${risk.level === 'Very Low' ? 'text-green-500' : 'text-red-500'}`} />
              <div>
                <p className="text-sm text-slate-600">Risk Level</p>
                <Badge className={risk.color}>{risk.level}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {hostInfo && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Monitor className="h-5 w-5" />
              Host Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {hostInfo.os_matches && hostInfo.os_matches.length > 0 && (
                <div>
                  <h4 className="font-semibold text-sm text-slate-600 mb-2 flex items-center gap-2">
                    <HardDrive className="h-4 w-4" />
                    Operating System Detection
                  </h4>
                  <div className="space-y-2">
                    {hostInfo.os_matches.map((os, idx) => (
                      <div key={idx} className="flex justify-between items-center">
                        <span className="text-sm">{os.name}</span>
                        <Badge variant="secondary">{os.accuracy}% match</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(hostInfo.mac_address || hostInfo.hostnames) && (
                <div>
                  <h4 className="font-semibold text-sm text-slate-600 mb-2 flex items-center gap-2">
                    <Wifi className="h-4 w-4" />
                    Network Information
                  </h4>
                  <div className="space-y-2 text-sm">
                    {hostInfo.mac_address && (
                      <div>
                        <span className="text-slate-600">MAC Address:</span>
                        <p className="font-mono">{hostInfo.mac_address}</p>
                        {hostInfo.mac_vendor && (
                          <p className="text-slate-500 text-xs">Vendor: {hostInfo.mac_vendor}</p>
                        )}
                      </div>
                    )}
                    {hostInfo.hostnames && hostInfo.hostnames.length > 0 && (
                      <div>
                        <span className="text-slate-600">Hostname(s):</span>
                        <p>{hostInfo.hostnames.join(', ')}</p>
                      </div>
                    )}
                    {hostInfo.distance !== undefined && (
                      <div>
                        <span className="text-slate-600">Network Distance:</span>
                        <p>{hostInfo.distance} hops</p>
                      </div>
                    )}
                    {hostInfo.state && (
                      <div>
                        <span className="text-slate-600">Host State:</span>
                        <Badge variant={hostInfo.state === 'up' ? 'default' : 'secondary'}>
                          {hostInfo.state}
                        </Badge>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Discovered Services</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
              <TableHead>Host</TableHead>
              <TableHead>Port</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Service</TableHead>
              <TableHead>Version</TableHead>
                <TableHead>CVE</TableHead>
                <TableHead>CVSS Score</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((finding) => (
                <TableRow key={finding.finding_id}>
                  <TableCell className="font-mono text-sm">{finding.host || 'N/A'}</TableCell>
                  <TableCell className="font-medium">{finding.port}</TableCell>
                  <TableCell>
                    <Badge 
                      variant="outline"
                      className={
                        finding.state === 'open' ? 'border-green-500 text-green-700' :
                        finding.state === 'filtered' ? 'border-yellow-500 text-yellow-700' :
                        finding.state === 'closed' ? 'border-gray-500 text-gray-700' :
                        'border-blue-500 text-blue-700'
                      }
                    >
                      {finding.state || 'unknown'}
                    </Badge>
                  </TableCell>
                  <TableCell>{finding.service_name}</TableCell>
                  <TableCell>{finding.service_version || 'Unknown'}</TableCell>
                  <TableCell>
                    {finding.cve_id ? (
                      <Badge variant="destructive">{finding.cve_id}</Badge>
                    ) : (
                      <Badge variant="secondary">None</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {finding.cve?.cvss_score ? (
                      <Badge className={
                        finding.cve.cvss_score >= 9.0 ? 'bg-red-600 text-white' :
                        finding.cve.cvss_score >= 7.0 ? 'bg-orange-500 text-white' :
                        finding.cve.cvss_score >= 4.0 ? 'bg-yellow-500 text-white' :
                        'bg-green-500 text-white'
                      }>
                        {finding.cve.cvss_score.toFixed(1)}
                      </Badge>
                    ) : (
                      <span className="text-slate-400">-</span>
                    )}
                  </TableCell>
                  <TableCell className="max-w-md">
                    {finding.cve?.description ? (
                      <span className="text-sm text-slate-600 line-clamp-2">
                        {finding.cve.description}
                      </span>
                    ) : (
                      <span className="text-slate-400">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge className={finding.cve_id ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}>
                      {finding.cve_id ? 'Vulnerable' : 'Secure'}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {report && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              AI Security Report
            </CardTitle>
            <p className="text-sm text-slate-600 mt-2">
              Generated on {new Date(report.created_at).toLocaleDateString()} at {new Date(report.created_at).toLocaleTimeString()}
            </p>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {report.summary?.split('\n\n').map((section, index) => {
                // Check if section is a header (starts with ** or #)
                const isHeader = section.trim().startsWith('**') || section.trim().startsWith('#');
                const cleanSection = section.replace(/^\*\*|\*\*$/g, '').replace(/^#+\s*/, '');
                
                if (isHeader) {
                  return (
                    <h3 key={index} className="text-lg font-semibold text-slate-900 mt-6 first:mt-0">
                      {cleanSection}
                    </h3>
                  );
                }
                
                // Regular paragraph
                return (
                  <div key={index} className="text-slate-700 leading-relaxed">
                    {section.split('\n').map((line, lineIndex) => {
                      // Handle bullet points
                      if (line.trim().startsWith('-') || line.trim().startsWith('•')) {
                        return (
                          <div key={lineIndex} className="ml-4 mb-2 flex gap-2">
                            <span className="text-blue-600 font-bold">•</span>
                            <span>{line.replace(/^[-•]\s*/, '')}</span>
                          </div>
                        );
                      }
                      // Handle bold text (**text**) safely without dangerouslySetInnerHTML
                      const parts = line.split(/(\*\*.*?\*\*)/g);
                      return (
                        <p key={lineIndex} className="mb-2">
                          {parts.map((part, partIdx) => {
                            if (part.startsWith('**') && part.endsWith('**')) {
                              return <strong key={partIdx} className="font-semibold text-slate-900">{part.slice(2, -2)}</strong>;
                            }
                            return <span key={partIdx}>{part}</span>;
                          })}
                        </p>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
