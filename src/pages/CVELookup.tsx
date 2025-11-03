import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Search, Sparkles } from 'lucide-react';
import { searchByServiceName, searchByCveId, NVDResponse } from '@/services/nvdService';
import { useToast } from '@/hooks/use-toast';
import { analyzeCVE } from '@/services/geminiService';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const CVELookup = () => {
  const [searchParams] = useSearchParams();
  const [searchMode, setSearchMode] = useState<'service' | 'cveId'>('service');
  const [serviceName, setServiceName] = useState('');
  const [version, setVersion] = useState('');
  const [cveId, setCveId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NVDResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analyzingCve, setAnalyzingCve] = useState<string | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<{ [key: string]: string }>({});
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(5);
  const { toast } = useToast();

  // Check for CVE ID in URL query parameters on mount
  useEffect(() => {
    const cveIdParam = searchParams.get('cveId');
    if (cveIdParam) {
      setSearchMode('cveId');
      setCveId(cveIdParam);
      // Trigger search automatically after a short delay
      setTimeout(() => {
        handleLookupWithCveId(cveIdParam);
      }, 100);
    }
  }, []);

  // Reset to page 1 when results change
  useEffect(() => {
    setCurrentPage(1);
  }, [result]);

  const handleLookupWithCveId = async (cveIdToSearch: string) => {
    if (!cveIdToSearch.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await searchByCveId(cveIdToSearch);
      setResult(data);
      toast({
        title: "Success",
        description: `Found ${data.totalResults || 0} vulnerabilities`,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleLookup = async () => {
    if (searchMode === 'service' && !serviceName.trim()) {
      toast({
        title: "Input Required",
        description: "Please enter a service name",
        variant: "destructive",
      });
      return;
    }

    if (searchMode === 'cveId' && !cveId.trim()) {
      toast({
        title: "Input Required",
        description: "Please enter a CVE ID",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let data;
      if (searchMode === 'service') {
        data = await searchByServiceName(serviceName, version || undefined);
      } else {
        data = await searchByCveId(cveId);
      }
      
      setResult(data);
      toast({
        title: "Success",
        description: `Found ${data.totalResults || 0} vulnerabilities`,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleLookup();
    }
  };

  const handleAiAnalysis = async (cveId: string, description: string, cvssScore?: number) => {
    setAnalyzingCve(cveId);
    
    try {
      const response = await analyzeCVE(cveId, description, cvssScore);
      
      if (response.success && response.response) {
        setAiAnalysis(prev => ({ ...prev, [cveId]: response.response }));
        toast({
          title: "AI Analysis Complete",
          description: "Vulnerability analyzed successfully",
        });
      } else {
        throw new Error(response.error || 'Failed to get AI analysis');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to analyze vulnerability';
      toast({
        title: "Analysis Failed",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setAnalyzingCve(null);
    }
  };

  return (
    <div className="p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-2xl">Vulnerability Search</CardTitle>
            <CardDescription>
              Search for vulnerabilities by service name or CVE ID
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={searchMode} onValueChange={(value) => setSearchMode(value as 'service' | 'cveId')}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="service">Service Name</TabsTrigger>
                <TabsTrigger value="cveId">CVE ID</TabsTrigger>
              </TabsList>
              
              <TabsContent value="service" className="space-y-2 mt-4">
                <Input
                  placeholder="Service name (e.g., OpenSSH, Apache, nginx)"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  onKeyPress={handleKeyPress}
                  disabled={loading}
                />
                <Input
                  placeholder="Version (optional, e.g., 7.2, 2.4.41)"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                  onKeyPress={handleKeyPress}
                  disabled={loading}
                />
              </TabsContent>
              
              <TabsContent value="cveId" className="space-y-2 mt-4">
                <Input
                  placeholder="CVE ID (e.g., CVE-2021-44228)"
                  value={cveId}
                  onChange={(e) => setCveId(e.target.value)}
                  onKeyPress={handleKeyPress}
                  disabled={loading}
                />
              </TabsContent>
            </Tabs>
            
            <Button onClick={handleLookup} disabled={loading} className="w-full">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Search className="h-4 w-4" />
              )}
              <span className="ml-2">Search Vulnerabilities</span>
            </Button>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {result && (
              <Card className="bg-muted">
                <CardHeader>
                  <div className="flex justify-between items-center">
                    <div>
                      <CardTitle className="text-lg">Results</CardTitle>
                      <CardDescription>
                        Total Results: {result.totalResults || 0}
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground">Show:</span>
                      <Select
                        value={itemsPerPage.toString()}
                        onValueChange={(value) => {
                          setItemsPerPage(Number(value));
                          setCurrentPage(1);
                        }}
                      >
                        <SelectTrigger className="w-[100px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="5">5</SelectItem>
                          <SelectItem value="10">10</SelectItem>
                          <SelectItem value="25">25</SelectItem>
                          <SelectItem value="50">50</SelectItem>
                        </SelectContent>
                      </Select>
                      <span className="text-sm text-muted-foreground">per page</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {result.vulnerabilities && result.vulnerabilities.length > 0 ? (
                    <>
                      {(() => {
                        const totalPages = Math.ceil(result.vulnerabilities.length / itemsPerPage);
                        const startIndex = (currentPage - 1) * itemsPerPage;
                        const endIndex = startIndex + itemsPerPage;
                        const paginatedVulnerabilities = result.vulnerabilities.slice(startIndex, endIndex);

                        return (
                          <>
                            <div className="space-y-4">
                              {paginatedVulnerabilities.map((vuln, index) => {
                        const cveId = vuln.cve.id;
                        const description = vuln.cve.descriptions.find(d => d.lang === 'en')?.value || 'No description available';
                        const cvssScore = vuln.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
                        
                        return (
                          <Card key={index}>
                            <CardHeader>
                              <CardTitle className="text-base">{cveId}</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-4">
                              <div>
                                <strong>Description:</strong>
                                <p className="text-sm text-muted-foreground mt-1">
                                  {description}
                                </p>
                              </div>
                              
                              {vuln.cve.metrics?.cvssMetricV31 && (
                                <div>
                                  <strong>CVSS Score:</strong>
                                  <p className="text-sm text-muted-foreground">
                                    {cvssScore} 
                                    ({vuln.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity})
                                  </p>
                                </div>
                              )}

                              {vuln.cve.published && (
                                <div>
                                  <strong>Published:</strong>
                                  <p className="text-sm text-muted-foreground">
                                    {new Date(vuln.cve.published).toLocaleDateString()}
                                  </p>
                                </div>
                              )}

                              <Button
                                onClick={() => handleAiAnalysis(cveId, description, cvssScore)}
                                disabled={analyzingCve === cveId}
                                variant="outline"
                                className="w-full mt-4"
                              >
                                {analyzingCve === cveId ? (
                                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                                ) : (
                                  <Sparkles className="h-4 w-4 mr-2" />
                                )}
                                {analyzingCve === cveId ? 'Analyzing...' : 'Get AI Analysis & Fixes'}
                              </Button>

                              {aiAnalysis[cveId] && (
                                <Card className="bg-blue-50 border-blue-200 mt-4">
                                  <CardHeader>
                                    <CardTitle className="text-sm flex items-center gap-2">
                                      <Sparkles className="h-4 w-4 text-blue-600" />
                                      AI Analysis by Gemini
                                    </CardTitle>
                                  </CardHeader>
                                  <CardContent>
                                    <div className="space-y-4 text-sm">
                                      {aiAnalysis[cveId].split('\n\n').map((section, idx) => {
                                        const isHeader = section.trim().startsWith('**') || section.trim().startsWith('#');
                                        const cleanSection = section.replace(/^\*\*|\*\*$/g, '').replace(/^#+\s*/, '');
                                        
                                        if (isHeader) {
                                          return (
                                            <h4 key={idx} className="font-semibold text-blue-900 mt-3 first:mt-0">
                                              {cleanSection}
                                            </h4>
                                          );
                                        }
                                        
                                        return (
                                          <div key={idx} className="text-slate-700">
                                            {section.split('\n').map((line, lineIdx) => {
                                              if (line.trim().startsWith('-') || line.trim().startsWith('•')) {
                                                return (
                                                  <div key={lineIdx} className="ml-4 mb-1 flex gap-2">
                                                    <span className="text-blue-600">•</span>
                                                    <span>{line.replace(/^[-•]\s*/, '')}</span>
                                                  </div>
                                                );
                                              }
                                              // Handle bold text (**text**) safely without dangerouslySetInnerHTML
                                              const parts = line.split(/(\*\*.*?\*\*)/g);
                                              return (
                                                <p key={lineIdx} className="mb-1">
                                                  {parts.map((part, partIdx) => {
                                                    if (part.startsWith('**') && part.endsWith('**')) {
                                                      return <strong key={partIdx} className="font-semibold">{part.slice(2, -2)}</strong>;
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
                            </CardContent>
                          </Card>
                        );
                              })}
                            </div>

                            {totalPages > 1 && (
                              <div className="mt-6 space-y-4">
                                <div className="text-sm text-muted-foreground text-center">
                                  Showing {startIndex + 1} to {Math.min(endIndex, result.vulnerabilities.length)} of {result.vulnerabilities.length} vulnerabilities
                                </div>
                                <Pagination>
                                  <PaginationContent>
                                    <PaginationItem>
                                      <PaginationPrevious
                                        onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                                        className={currentPage === 1 ? "pointer-events-none opacity-50" : "cursor-pointer"}
                                      />
                                    </PaginationItem>
                                    
                                    {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => {
                                      if (
                                        page === 1 ||
                                        page === totalPages ||
                                        (page >= currentPage - 1 && page <= currentPage + 1)
                                      ) {
                                        return (
                                          <PaginationItem key={page}>
                                            <PaginationLink
                                              onClick={() => setCurrentPage(page)}
                                              isActive={currentPage === page}
                                              className="cursor-pointer"
                                            >
                                              {page}
                                            </PaginationLink>
                                          </PaginationItem>
                                        );
                                      } else if (
                                        page === currentPage - 2 ||
                                        page === currentPage + 2
                                      ) {
                                        return (
                                          <PaginationItem key={page}>
                                            <PaginationEllipsis />
                                          </PaginationItem>
                                        );
                                      }
                                      return null;
                                    })}
                                    
                                    <PaginationItem>
                                      <PaginationNext
                                        onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                                        className={currentPage === totalPages ? "pointer-events-none opacity-50" : "cursor-pointer"}
                                      />
                                    </PaginationItem>
                                  </PaginationContent>
                                </Pagination>
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </>
                  ) : (
                    <p className="text-muted-foreground">No vulnerabilities found</p>
                  )}

                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm font-medium">
                      View Raw JSON
                    </summary>
                    <pre className="mt-2 p-4 bg-background rounded-md overflow-x-auto text-xs">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </details>
                </CardContent>
              </Card>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default CVELookup;
