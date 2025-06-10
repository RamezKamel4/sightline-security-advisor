
from pydantic import BaseModel

class ScanRequest(BaseModel):
    ip: str
    nmap_args: str = "-T4"  # Default nmap arguments
    scan_profile: str = "basic"  # Scan profile for reference
