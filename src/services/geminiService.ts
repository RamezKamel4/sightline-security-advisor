import { supabase } from '@/integrations/supabase/client';

export interface GeminiResponse {
  success: boolean;
  response: string;
  fullResponse?: any;
  error?: string;
  details?: string;
}

export const chatWithGemini = async (message: string): Promise<GeminiResponse> => {
  try {
    console.log('🤖 Sending message to Gemini:', message);
    
    const { data, error } = await supabase.functions.invoke('gemini-chat', {
      body: { message }
    });

    if (error) {
      console.error('❌ Edge function error:', error);
      throw new Error(error.message || 'Failed to communicate with Gemini');
    }

    if (data?.error) {
      console.error('❌ Gemini API error:', data.error);
      throw new Error(data.error);
    }

    console.log('✅ Gemini response received successfully');
    return data;

  } catch (error) {
    console.error('💥 Gemini service error:', error);
    
    const friendlyMessage = error instanceof Error 
      ? error.message 
      : 'An unexpected error occurred while communicating with Gemini';
    
    return {
      success: false,
      response: '',
      error: friendlyMessage
    };
  }
};

export const analyzeCVE = async (cveId: string, description: string, cvssScore?: number): Promise<GeminiResponse> => {
  try {
    console.log('🔍 Analyzing CVE with Lovable AI:', cveId);
    
    const { data, error } = await supabase.functions.invoke('cve-analysis', {
      body: { cveId, description, cvssScore }
    });

    if (error) {
      console.error('❌ Edge function error:', error);
      
      // Handle rate limit errors specifically
      if (error.message?.includes('429') || error.message?.includes('rate limit')) {
        throw new Error('Too many requests. Please wait a moment and try again.');
      }
      
      if (error.message?.includes('402')) {
        throw new Error('AI analysis credits exhausted. Please contact support.');
      }
      
      throw new Error(error.message || 'Failed to analyze CVE');
    }

    if (data?.error) {
      console.error('❌ AI analysis error:', data.error);
      throw new Error(data.error);
    }

    console.log('✅ CVE analysis completed successfully');
    return data;

  } catch (error) {
    console.error('💥 CVE analysis service error:', error);
    
    const friendlyMessage = error instanceof Error 
      ? error.message 
      : 'An unexpected error occurred while analyzing the vulnerability';
    
    return {
      success: false,
      response: '',
      error: friendlyMessage
    };
  }
};