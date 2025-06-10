
from fastapi import APIRouter
from models.scan_models import ScanRequest
from services.scan_service import perform_network_scan

router = APIRouter()

@router.post("/scan")
async def scan_ip(request: ScanRequest):
    """
    Perform network scan on target IP address
    """
    print(f"Received scan request: {request}")
    result = perform_network_scan(request.ip, request.nmap_args, request.scan_profile)
    print(f"Scan completed, returning: {len(result) if isinstance(result, list) else 'message'} results")
    return result
