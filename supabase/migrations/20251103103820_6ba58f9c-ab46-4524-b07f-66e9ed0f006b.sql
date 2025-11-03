-- Add confidence and published_year columns to cve table
ALTER TABLE public.cve 
ADD COLUMN IF NOT EXISTS confidence TEXT CHECK (confidence IN ('low', 'medium', 'high')),
ADD COLUMN IF NOT EXISTS published_year INTEGER;