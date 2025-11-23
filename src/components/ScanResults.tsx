
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { FileText, Download, AlertTriangle, CheckCircle, Monitor, Wifi, HardDrive, ChevronDown, ChevronUp } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/components/ui/use-toast';
import { generateReport } from '@/services/reportService';
import { enrichFindingsWithCVE } from '@/services/cveEnrichmentService';
import type { HostInfo } from '@/services/scanApi';
import { useQuery } from '@tanstack/react-query';

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
  status: 'pending_review' | 'approved' | 'rejected';
  review_notes?: string;
}

export const ScanResults = ({ scanId }: ScanResultsProps) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isEnrichingCVE, setIsEnrichingCVE] = useState(false);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [selectedConsultant, setSelectedConsultant] = useState<string>('');
  const [showConsultantSelect, setShowConsultantSelect] = useState(false);
  const { toast } = useToast();

  // Fetch consultants and admins
  const { data: consultants = [], error: consultantsError } = useQuery({
    queryKey: ['consultants'],
    queryFn: async () => {
      console.log('🔍 Fetching consultants...');
      
      // Get all users and their roles in a single query
      const { data, error } = await supabase
        .from('users')
        .select(`
          user_id,
          email,
          name
        `);

      if (error) {
        console.error('❌ Error fetching users:', error);
        throw error;
      }

      console.log('👥 All users:', data);

      if (!data || data.length === 0) {
        console.log('⚠️ No users found in users table');
        return [];
      }

      // Get roles for these users
      const { data: rolesData, error: rolesError } = await supabase
        .from('user_roles')
        .select('user_id, role')
        .in('role', ['consultant', 'admin']);

      if (rolesError) {
        console.error('❌ Error fetching roles:', rolesError);
        throw rolesError;
      }

      console.log('📋 Roles data:', rolesData);

      // Filter users who have consultant or admin role
      const roleUserIds = new Set(rolesData?.map(r => r.user_id) || []);
      const filteredUsers = data.filter(user => roleUserIds.has(user.user_id));

      console.log('✅ Filtered consultants/admins:', filteredUsers);
      return filteredUsers;
    },
  });

  // Log any errors
  if (consultantsError) {
    console.error('Consultants query error:', consultantsError);
  }

  const toggleRowExpansion = (findingId: string) => {
    setExpandedRows(prev => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  };

  useEffect(() => {
    const initializeScanResults = async () => {
      await fetchFindings();
      await fetchReport();
      await fetchHostInfo();
      
      // Automatically enrich findings with CVE data
      await enrichCVEData();
    };
    
    initializeScanResults();
  }, [scanId]);

  const enrichCVEData = async () => {
    try {
      setIsEnrichingCVE(true);
      console.log('🔍 Checking if CVE enrichment is needed...');
      
      // enrichFindingsWithCVE will check if already enriched and skip if so
      await enrichFindingsWithCVE(scanId);
      console.log('✅ CVE enrichment process completed, refreshing findings...');
      
      // Refresh findings to show enriched data
      await fetchFindings();
      
      // Only show success toast if enrichment actually ran
      const { data: scanData } = await supabase
        .from('scans')
        .select('cve_enriched')
        .eq('scan_id', scanId)
        .single();
      
      if (scanData?.cve_enriched) {
        toast({
          title: "CVE Data Loaded",
          description: "Vulnerability details have been loaded from database.",
        });
      }
    } catch (error) {
      console.error('Error enriching CVE data:', error);
      toast({
        title: "CVE Enrichment Warning",
        description: "Some vulnerability details could not be loaded. Report generation will continue.",
        variant: "destructive"
      });
    } finally {
      setIsEnrichingCVE(false);
    }
  };

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
    if (!selectedConsultant) {
      toast({
        title: "Consultant Required",
        description: "Please select a consultant before generating the report.",
        variant: "destructive"
      });
      return;
    }

    setIsGeneratingReport(true);
    try {
      await generateReport(scanId);
      
      // Update the report with selected consultant
      const { data: reportData } = await supabase
        .from('reports')
        .select('report_id')
        .eq('scan_id', scanId)
        .single();

      if (reportData) {
        await supabase
          .from('reports')
          .update({ consultant_id: selectedConsultant })
          .eq('report_id', reportData.report_id);
      }

      await fetchReport();
      setShowConsultantSelect(false);
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
    const cveFindings = findings.filter(f => f.cve?.cvss_score);
    
    // No CVEs found - Secure
    if (cveFindings.length === 0) {
      return { level: 'Secure', color: 'bg-green-100 text-green-800' };
    }
    
    // Calculate average and max CVSS scores
    const cvssScores = cveFindings.map(f => f.cve?.cvss_score || 0);
    const avgCvss = cvssScores.reduce((sum, score) => sum + score, 0) / cvssScores.length;
    const maxCvss = Math.max(...cvssScores);
    
    // Apply CVSS-based thresholds
    if (maxCvss >= 9.0 || avgCvss >= 9.0) {
      return { level: 'Critical', color: 'bg-purple-100 text-purple-800' };
    }
    if (avgCvss >= 7.0) {
      return { level: 'High', color: 'bg-red-100 text-red-800' };
    }
    if (avgCvss >= 4.0) {
      return { level: 'Medium', color: 'bg-yellow-100 text-yellow-800' };
    }
    if (avgCvss > 0.0) {
      return { level: 'Low', color: 'bg-orange-100 text-orange-800' };
    }
    
    return { level: 'Secure', color: 'bg-green-100 text-green-800' };
  };

  if (loading) {
    return (
      <div className="p-4">
        <div className="flex flex-col items-center justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mb-4"></div>
          <p className="text-slate-600">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (isEnrichingCVE) {
    return (
      <div className="p-4">
        <div className="flex flex-col items-center justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mb-4"></div>
          <p className="text-slate-600 font-medium mb-2">Enriching vulnerability data...</p>
          <p className="text-slate-500 text-sm">Fetching CVE details from NVD database</p>
        </div>
      </div>
    );
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
          {!report && !showConsultantSelect && (
            <Button 
              onClick={() => setShowConsultantSelect(true)}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <FileText className="h-4 w-4 mr-2" />
              Generate AI Report
            </Button>
          )}
          {report && report.status === 'approved' && report.pdf_url && (
            <Button variant="outline" onClick={handleDownloadPDF}>
              <Download className="h-4 w-4 mr-2" />
              Download PDF
            </Button>
          )}
        </div>
      </div>

      {showConsultantSelect && !report && (
        <Card className="border-blue-200 bg-blue-50">
          <CardHeader>
            <CardTitle className="text-blue-900">Select Consultant for Report Review</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="consultant">Assign to Consultant</Label>
              <Select value={selectedConsultant} onValueChange={setSelectedConsultant}>
                <SelectTrigger id="consultant" className="bg-white">
                  <SelectValue placeholder="Select a consultant" />
                </SelectTrigger>
                <SelectContent className="bg-white z-50">
                  {consultants.map((consultant: any) => (
                    <SelectItem key={consultant.user_id} value={consultant.user_id}>
                      {consultant.name} ({consultant.email})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2">
              <Button 
                onClick={handleGenerateReport}
                disabled={isGeneratingReport || !selectedConsultant}
                className="bg-blue-600 hover:bg-blue-700"
              >
                <FileText className="h-4 w-4 mr-2" />
                {isGeneratingReport ? 'Generating...' : 'Generate Report'}
              </Button>
              <Button 
                variant="outline" 
                onClick={() => setShowConsultantSelect(false)}
                disabled={isGeneratingReport}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

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
              <CheckCircle className={`h-5 w-5 ${risk.level === 'Secure' || risk.level === 'Low' ? 'text-green-500' : 'text-red-500'}`} />
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
                      <div className="flex gap-2 items-start">
                        <span className={`text-sm text-slate-600 ${!expandedRows.has(finding.finding_id) ? 'line-clamp-2' : ''}`}>
                          {finding.cve.description}
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 w-6 p-0 flex-shrink-0"
                          onClick={() => toggleRowExpansion(finding.finding_id)}
                        >
                          {expandedRows.has(finding.finding_id) ? (
                            <ChevronUp className="h-4 w-4" />
                          ) : (
                            <ChevronDown className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
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

      {report && report.status === 'approved' && (
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

      {report && report.status === 'pending_review' && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-yellow-800">
              <FileText className="h-5 w-5" />
              Report Pending Review
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-center py-8">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-yellow-100 mb-4">
                <svg className="w-8 h-8 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-yellow-900 mb-2">
                AI Report Under Review
              </h3>
              <p className="text-yellow-700 max-w-md mx-auto">
                Your security report has been generated by our AI and is currently being reviewed by our security consultants 
                to ensure accuracy. You'll receive an email notification once the report is approved and ready for viewing.
              </p>
              <p className="text-sm text-yellow-600 mt-4">
                Generated on {new Date(report.created_at).toLocaleDateString()} at {new Date(report.created_at).toLocaleTimeString()}
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {report && report.status === 'rejected' && (
        <Card className="border-red-200 bg-red-50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-800">
              <FileText className="h-5 w-5" />
              Report Rejected
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-center py-8">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 mb-4">
                <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-red-900 mb-2">
                Report Requires Revision
              </h3>
              <p className="text-red-700 max-w-md mx-auto mb-4">
                The AI-generated report has been reviewed and requires revision. Our team is working on generating an improved version.
              </p>
              {report.review_notes && (
                <div className="bg-white border border-red-200 rounded-lg p-4 max-w-md mx-auto text-left">
                  <p className="text-sm font-semibold text-red-900 mb-2">Consultant Feedback:</p>
                  <p className="text-sm text-red-700">{report.review_notes}</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
