
from fastapi import APIRouter, HTTPException
from models.scan_models import ScanRequest
from services.scan_service import perform_network_scan
from services.target_normalizer import normalize_target
import traceback

router = APIRouter()

@router.post("/scan")
async def scan_ip(request: ScanRequest):
    """
    Perform network scan on target IP address
    Supports follow-up scans when request.follow_up=True
    Returns: { results: [...], nmap_cmd: "...", nmap_output: "...", target_info: {...} }
    """
    try:
        print(f"🔍 Received scan request: {request}")
        
        # Normalize and validate target
        target_info = normalize_target(request.ip_address)
        print(f"📍 Target normalized: {target_info['original']} -> {target_info['normalized']}")
        
        if target_info['warnings']:
            for warning in target_info['warnings']:
                print(f"⚠️  {warning}")
        
        # Perform scan using normalized target
        scan_data = perform_network_scan(
            ip_address=target_info['normalized'],
            nmap_args=request.nmap_args,
            scan_profile=request.scan_profile,
            follow_up=getattr(request, "follow_up", False)
        )
        
        # Include target normalization info in response
        scan_data['target_info'] = target_info
        
        return scan_data

    except ValueError as e:
        # Target validation errors
        print(f"❌ Invalid target: {e}")
        raise HTTPException(status_code=400, detail=str(e))
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
