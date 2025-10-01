import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowRight, Search, Database, Shield, FileText } from 'lucide-react';

const WorkflowGuide = () => {
  const steps = [
    {
      number: 1,
      icon: Shield,
      title: 'Create New Scan',
      description: 'Input target IP/domain, select scan profile and depth. The scan identifies open ports, services, and versions.',
      color: 'text-blue-500'
    },
    {
      number: 2,
      icon: Search,
      title: 'Vulnerability Detection',
      description: 'Scan results are analyzed to identify services and their versions running on detected ports.',
      color: 'text-purple-500'
    },
    {
      number: 3,
      icon: Database,
      title: 'NVD CVE Lookup',
      description: 'Each found service/version is queried against the National Vulnerability Database (NVD) to find associated CVEs with CVSS scores.',
      color: 'text-orange-500'
    },
    {
      number: 4,
      icon: FileText,
      title: 'AI Report Generation',
      description: 'Gemini AI generates a comprehensive report including vulnerability explanations, impact analysis, and specific remediation steps.',
      color: 'text-green-500'
    }
  ];

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-5xl mx-auto space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-3xl">How VulnScan AI Works</CardTitle>
            <CardDescription className="text-base">
              Automated vulnerability scanning and intelligent reporting workflow
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-8">
              {steps.map((step, index) => {
                const Icon = step.icon;
                return (
                  <div key={step.number}>
                    <div className="flex items-start gap-4">
                      <div className="flex-shrink-0">
                        <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center">
                          <Icon className={`h-6 w-6 ${step.color}`} />
                        </div>
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className={`text-2xl font-bold ${step.color}`}>
                            {step.number}
                          </span>
                          <h3 className="text-xl font-semibold">{step.title}</h3>
                        </div>
                        <p className="text-muted-foreground">{step.description}</p>
                      </div>
                    </div>
                    {index < steps.length - 1 && (
                      <div className="ml-6 mt-4 mb-4">
                        <ArrowRight className="h-6 w-6 text-muted-foreground" />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Key Features</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <h4 className="font-semibold">🔍 Comprehensive Scanning</h4>
                <p className="text-sm text-muted-foreground">
                  Detects open ports, identifies services, and determines versions
                </p>
              </div>
              <div className="space-y-2">
                <h4 className="font-semibold">🗄️ Real-time CVE Database</h4>
                <p className="text-sm text-muted-foreground">
                  Direct integration with NVD for latest vulnerability data
                </p>
              </div>
              <div className="space-y-2">
                <h4 className="font-semibold">🤖 AI-Powered Analysis</h4>
                <p className="text-sm text-muted-foreground">
                  Gemini AI generates detailed, actionable security reports
                </p>
              </div>
              <div className="space-y-2">
                <h4 className="font-semibold">📊 CVSS Scoring</h4>
                <p className="text-sm text-muted-foreground">
                  Industry-standard risk assessment with CVSS scores
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default WorkflowGuide;
