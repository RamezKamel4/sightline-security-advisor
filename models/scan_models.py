
from pydantic import BaseModel
from typing import Optional

class ScanRequest(BaseModel):
    ip_address: str
    nmap_args: str = "-T4"  # Default nmap arguments
    scan_profile: str = "basic"  # Scan profile for reference
    follow_up: Optional[bool] = False
