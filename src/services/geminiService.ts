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