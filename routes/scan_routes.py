
from fastapi import APIRouter, HTTPException
from models.scan_models import ScanRequest
from services.scan_service import perform_network_scan
import traceback

router = APIRouter()

@router.post("/scan")
async def scan_ip(request: ScanRequest):
    """
    Perform network scan on target IP address
    Supports follow-up scans when request.follow_up=True
    Returns: { results: [...], nmap_cmd: "...", nmap_output: "..." }
    """
    try:
        print(f"🔍 Received scan request: {request}")
        scan_data = perform_network_scan(
            ip_address=request.ip_address,
            nmap_args=request.nmap_args,
            scan_profile=request.scan_profile,
            follow_up=getattr(request, "follow_up", False)
        )
        return scan_data

    except Exception as e:
        print(f"❌ Scan error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/scan/test")
async def test_endpoint():
    """Test endpoint to verify the API is working"""
    return {"message": "Scan API is working", "status": "ok"}

# Add an OPTIONS handler for CORS preflight requests
@router.options("/scan")
async def scan_options():
    """Handle CORS preflight requests"""
    return {"message": "OK"}
