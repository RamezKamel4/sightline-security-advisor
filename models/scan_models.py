from pydantic import BaseModel, field_validator
from typing import Optional
import re
import ipaddress

class ScanRequest(BaseModel):
    ip_address: str
    nmap_args: str = "-T4"  # Default nmap arguments
    scan_profile: str = "basic"  # Scan profile for reference
    follow_up: Optional[bool] = False
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        """Validate IP address or CIDR notation"""
        v = v.strip()
        
        # Check for CIDR notation
        if '/' in v:
            try:
                ipaddress.ip_network(v, strict=False)
                return v
            except ValueError:
                raise ValueError(f"Invalid CIDR notation: {v}")
        
        # Check for single IP or IP range
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Check if it's a simple range like 192.168.1.1-10
            if '-' in v:
                parts = v.split('-')
                if len(parts) == 2:
                    base = parts[0].strip()
                    try:
                        ipaddress.ip_address(base)
                        # Basic validation - range should be numeric
                        if parts[1].strip().isdigit():
                            return v
                    except ValueError:
                        pass
            
            raise ValueError(f"Invalid IP address format: {v}. Use single IP (192.168.1.1), CIDR (192.168.1.0/24), or range (192.168.1.1-10)")
    
    @field_validator('nmap_args')
    @classmethod
    def validate_nmap_args(cls, v: str) -> str:
        """Validate nmap arguments - whitelist safe arguments only"""
        # Whitelist of safe nmap arguments
        safe_patterns = [
            r'-T[0-5]',           # Timing template
            r'-p[\d,-]+',         # Port specification
            r'-sV',               # Service version detection
            r'-O',                # OS detection
            r'-A',                # Aggressive scan (OS, version, script, traceroute)
            r'-Pn',               # Skip host discovery
            r'-n',                # No DNS resolution
            r'--top-ports\s+\d+', # Top ports
            r'--min-rate\s+\d+',  # Minimum packet rate
            r'--max-retries\s+\d+', # Maximum retries
            r'-v+',               # Verbosity
            r'--version-intensity\s+[0-9]', # Version detection intensity
        ]
        
        # Dangerous patterns that should never be allowed
        dangerous_patterns = [
            r'--script',          # Custom script execution
            r'-oN',               # Output to file
            r'-oX',               # XML output to file
            r'-oG',               # Grepable output to file
            r'-oA',               # All output formats
            r'--script-args',     # Script arguments
            r'--datadir',         # Data directory manipulation
            r'--system-dns',      # Use system DNS
            r'[\$`;&|]',          # Shell metacharacters
        ]
        
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(f"Unsafe nmap argument detected: matches pattern '{pattern}'")
        
        # Validate each argument against whitelist
        args = v.split()
        for arg in args:
            if not arg:
                continue
            
            # Allow if matches any safe pattern
            if any(re.match(f'^{pattern}$', arg, re.IGNORECASE) for pattern in safe_patterns):
                continue
            
            raise ValueError(f"Nmap argument not allowed: '{arg}'. Only safe scanning arguments are permitted.")
        
        return v
