import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Search } from 'lucide-react';
import { lookupCVE, NVDResponse } from '@/services/nvdService';
import { useToast } from '@/hooks/use-toast';

const CVELookup = () => {
  const [cveId, setCveId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NVDResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const handleLookup = async () => {
    if (!cveId.trim()) {
      toast({
        title: "Input Required",
        description: "Please enter a CVE ID",
        variant: "destructive",
      });
      return;
    }

    // Validate CVE ID format (CVE-YYYY-NNNNN)
    const cvePattern = /^CVE-\d{4}-\d{4,}$/i;
    if (!cvePattern.test(cveId.trim())) {
      toast({
        title: "Invalid Format",
        description: "CVE ID must be in format: CVE-YYYY-NNNNN (e.g., CVE-2014-0160)",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await lookupCVE(cveId);
      setResult(data);
      toast({
        title: "Success",
        description: `Found ${data.totalResults || 0} result(s)`,
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

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-2xl">CVE Lookup</CardTitle>
            <CardDescription>
              Search the National Vulnerability Database for CVE information
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                placeholder="Enter CVE ID (e.g., CVE-2014-0160)"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                onKeyPress={handleKeyPress}
                disabled={loading}
              />
              <Button onClick={handleLookup} disabled={loading}>
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                <span className="ml-2">Lookup CVE</span>
              </Button>
            </div>

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
                      {result.vulnerabilities.map((vuln, index) => (
                        <Card key={index}>
                          <CardHeader>
                            <CardTitle className="text-base">{vuln.cve.id}</CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-2">
                            <div>
                              <strong>Description:</strong>
                              <p className="text-sm text-muted-foreground mt-1">
                                {vuln.cve.descriptions.find(d => d.lang === 'en')?.value || 'No description available'}
                              </p>
                            </div>
                            
                            {vuln.cve.metrics?.cvssMetricV31 && (
                              <div>
                                <strong>CVSS Score:</strong>
                                <p className="text-sm text-muted-foreground">
                                  {vuln.cve.metrics.cvssMetricV31[0].cvssData.baseScore} 
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
                          </CardContent>
                        </Card>
                      ))}
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
