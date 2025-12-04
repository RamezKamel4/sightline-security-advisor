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
        """Validate IP address, CIDR notation, range, or domain name"""
        v = v.strip()
        
        if not v:
            raise ValueError("Target cannot be empty")
        
        # Check for CIDR notation
        if '/' in v:
            try:
                ipaddress.ip_network(v, strict=False)
                return v
            except ValueError:
                raise ValueError(f"Invalid CIDR notation: {v}")
        
        # Check for single IP
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        
        # Check if it's a simple range like 192.168.1.1-10
        if '-' in v and not v.startswith('-'):
            parts = v.split('-')
            if len(parts) == 2:
                base = parts[0].strip()
                try:
                    ipaddress.ip_address(base)
                    if parts[1].strip().isdigit():
                        return v
                except ValueError:
                    pass
        
        # Check for valid domain name (allow scanme.nmap.org, example.com, etc.)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, v) and '.' in v and len(v) <= 253:
            return v
        
        raise ValueError(f"Invalid target format: {v}. Use IP (192.168.1.1), CIDR (192.168.1.0/24), range (192.168.1.1-10), or domain (example.com)")
    
    @field_validator('nmap_args')
    @classmethod
    def validate_nmap_args(cls, v: str) -> str:
        """Validate nmap arguments - whitelist safe arguments only"""
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
        
        # Safe standalone flags
        safe_flags = {
            '-sV', '-O', '-A', '-Pn', '-n', '-sS', '-sT', '-sU', '-sN', '-sF', '-sX',
            '-v', '-vv', '-vvv', '-F', '--open', '-r',
        }
        
        # Safe arguments that take a value
        safe_value_args = {'-p', '-T', '--top-ports', '--min-rate', '--max-retries', '--version-intensity'}
        
        args = v.split()
        i = 0
        while i < len(args):
            arg = args[i]
            
            if not arg:
                i += 1
                continue
            
            # Check standalone safe flags
            if arg in safe_flags:
                i += 1
                continue
            
            # Check timing flags -T0 through -T5
            if re.match(r'^-T[0-5]$', arg):
                i += 1
                continue
            
            # Check combined port arg like -p80,443
            if arg.startswith('-p') and len(arg) > 2:
                i += 1
                continue
            
            # Check args that take values (like -p 80,443)
            if arg in safe_value_args:
                i += 1  # Move past the flag
                if i < len(args):
                    i += 1  # Skip the value
                continue
            
            # Check if it looks like a port list (could be value after -p)
            if re.match(r'^[\d,\-]+$', arg):
                i += 1
                continue
            
            # Check other safe value args with attached values
            for prefix in ['--top-ports', '--min-rate', '--max-retries', '--version-intensity']:
                if arg.startswith(prefix + '='):
                    i += 1
                    continue
            
            raise ValueError(f"Nmap argument not allowed: '{arg}'. Only safe scanning arguments are permitted.")
        
        return v
