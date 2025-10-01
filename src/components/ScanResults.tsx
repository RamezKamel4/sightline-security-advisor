
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { FileText, Download, AlertTriangle, CheckCircle } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/components/ui/use-toast';
import { generateReport } from '@/services/scanService';

interface ScanResultsProps {
  scanId: string;
}

interface Finding {
  finding_id: string;
  port: number;
  service_name: string;
  service_version: string | null;
  cve_id: string | null;
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
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    fetchFindings();
    fetchReport();
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
          {report && (
            <Button variant="outline">
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

      <Card>
        <CardHeader>
          <CardTitle>Discovered Services</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Port</TableHead>
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
                  <TableCell className="font-medium">{finding.port}</TableCell>
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
            <CardTitle>AI Security Report</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="prose max-w-none">
              <pre className="whitespace-pre-wrap text-sm">{report.summary}</pre>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
