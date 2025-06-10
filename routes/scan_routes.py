
from fastapi import APIRouter, HTTPException
from models.scan_models import ScanRequest
from services.scan_service import perform_network_scan
import traceback

router = APIRouter()

@router.post("/scan")
async def scan_ip(request: ScanRequest):
    """
    Perform network scan on target IP address
    """
    try:
        print(f"🔍 Received scan request: {request}")
        print(f"🎯 Target: {request.ip}")
        print(f"⚙️ Args: {request.nmap_args}")
        print(f"📋 Profile: {request.scan_profile}")
        
        result = perform_network_scan(request.ip, request.nmap_args, request.scan_profile)
        
        print(f"✅ Scan completed, returning: {len(result) if isinstance(result, list) else 'message'} results")
        return result
        
    except Exception as e:
        print(f"❌ Scan error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/scan/test")
async def test_endpoint():
    """Test endpoint to verify the API is working"""
    return {"message": "Scan API is working", "status": "ok"}
