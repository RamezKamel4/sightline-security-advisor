-- Add enhanced service detection fields to findings table
ALTER TABLE public.findings
ADD COLUMN IF NOT EXISTS confidence NUMERIC(5,2) DEFAULT 0,
ADD COLUMN IF NOT EXISTS raw_banner TEXT,
ADD COLUMN IF NOT EXISTS headers JSONB,
ADD COLUMN IF NOT EXISTS tls_info JSONB,
ADD COLUMN IF NOT EXISTS proxy_detection JSONB,
ADD COLUMN IF NOT EXISTS detection_methods JSONB;

-- Add comment explaining the new fields
COMMENT ON COLUMN public.findings.confidence IS 'Confidence score (0-100) for service detection accuracy';
COMMENT ON COLUMN public.findings.raw_banner IS 'Raw service banner captured during scan';
COMMENT ON COLUMN public.findings.headers IS 'HTTP/HTTPS headers captured from the service';
COMMENT ON COLUMN public.findings.tls_info IS 'TLS/SSL certificate and connection information';
COMMENT ON COLUMN public.findings.proxy_detection IS 'Detected reverse proxy or CDN information';
COMMENT ON COLUMN public.findings.detection_methods IS 'Methods used to detect the service (nmap, http probe, banner grab, etc.)';