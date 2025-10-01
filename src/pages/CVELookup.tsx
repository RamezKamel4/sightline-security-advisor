import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Search, Sparkles } from 'lucide-react';
import { searchByServiceName, NVDResponse } from '@/services/nvdService';
import { useToast } from '@/hooks/use-toast';
import { chatWithGemini } from '@/services/geminiService';

const CVELookup = () => {
  const [serviceName, setServiceName] = useState('');
  const [version, setVersion] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NVDResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analyzingCve, setAnalyzingCve] = useState<string | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<{ [key: string]: string }>({});
  const { toast } = useToast();

  const handleLookup = async () => {
    if (!serviceName.trim()) {
      toast({
        title: "Input Required",
        description: "Please enter a service name",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await searchByServiceName(serviceName, version || undefined);
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
    
    const prompt = `You are a cybersecurity expert. Analyze this vulnerability and provide:

CVE ID: ${cveId}
Description: ${description}
${cvssScore ? `CVSS Score: ${cvssScore}` : ''}

Please provide:
1. **Simple Explanation**: Explain what this vulnerability is in simple terms (2-3 sentences)
2. **Potential Impact**: What could happen if this vulnerability is exploited?
3. **Step-by-Step Fix Recommendations**:
   - Specific actions to take
   - Patch versions or configuration changes needed
   - Priority level (Critical/High/Medium/Low)
   - Testing recommendations after applying fixes

Be concise, practical, and specific.`;

    try {
      const response = await chatWithGemini(prompt);
      
      if (response.success && response.response) {
        setAiAnalysis(prev => ({ ...prev, [cveId]: response.response }));
        toast({
          title: "AI Analysis Complete",
          description: "Gemini has analyzed the vulnerability",
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
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-2xl">Vulnerability Search</CardTitle>
            <CardDescription>
              Search for vulnerabilities by service name and version
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
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
            </div>
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
                  <CardTitle className="text-lg">Results</CardTitle>
                  <CardDescription>
                    Total Results: {result.totalResults || 0}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {result.vulnerabilities && result.vulnerabilities.length > 0 ? (
                    <div className="space-y-4">
                      {result.vulnerabilities.map((vuln, index) => {
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
                                              const boldFormatted = line.replace(/\*\*(.*?)\*\*/g, '<strong class="font-semibold">$1</strong>');
                                              return (
                                                <p key={lineIdx} className="mb-1" dangerouslySetInnerHTML={{ __html: boldFormatted }} />
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
