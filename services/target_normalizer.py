"""
Target normalization and validation for network scans.
Handles IPv4/IPv6 addresses, CIDR notation, hostnames, and IP ranges.
"""

import re
import ipaddress
from typing import Dict, Optional, Tuple


def normalize_target(user_input: str) -> Dict[str, any]:
    """
    Normalize and validate a scan target.
    
    Args:
        user_input: Raw target string from user (IP, CIDR, hostname, or range)
        
    Returns:
        Dictionary with:
        - original: Original user input
        - normalized: Normalized target for nmap
        - hosts_count: Estimated number of hosts (None for hostnames)
        - target_type: Type of target (single_ip, cidr, hostname, range)
        - warnings: List of warning messages (e.g., large scan)
        
    Raises:
        ValueError: If target is invalid
    """
    user_input = user_input.strip()
    
    if not user_input:
        raise ValueError("Target cannot be empty")
    
    # Check if it's a CIDR notation
    if '/' in user_input:
        return _normalize_cidr(user_input)
    
    # Check if it's an IP range (e.g., 192.168.1.10-192.168.1.20 or 192.168.1.10-20)
    if '-' in user_input:
        return _normalize_range(user_input)
    
    # Try to parse as IP address
    try:
        ip = ipaddress.ip_address(user_input)
        
        # Special case: IPv4 ending in .0 -> convert to /24
        if isinstance(ip, ipaddress.IPv4Address) and user_input.endswith('.0'):
            octets = user_input.split('.')
            if len(octets) == 4 and octets[3] == '0':
                cidr = f"{user_input}/24"
                return {
                    "original": user_input,
                    "normalized": cidr,
                    "hosts_count": 256,
                    "target_type": "cidr",
                    "warnings": [f"Converted {user_input} to {cidr} (256 hosts)"]
                }
        
        # Regular single IP address
        return {
            "original": user_input,
            "normalized": user_input,
            "hosts_count": 1,
            "target_type": "single_ip",
            "warnings": []
        }
    except ValueError:
        # Not an IP address, might be a hostname
        return _normalize_hostname(user_input)


def _normalize_cidr(cidr_input: str) -> Dict[str, any]:
    """Normalize and validate CIDR notation."""
    try:
        network = ipaddress.ip_network(cidr_input, strict=False)
        hosts_count = network.num_addresses
        
        warnings = []
        if hosts_count > 1024:
            warnings.append(f"Large scan: {hosts_count} hosts. This may take a long time.")
        elif hosts_count > 256:
            warnings.append(f"Medium scan: {hosts_count} hosts.")
        
        return {
            "original": cidr_input,
            "normalized": str(network),
            "hosts_count": hosts_count,
            "target_type": "cidr",
            "warnings": warnings
        }
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation '{cidr_input}': {str(e)}")


def _normalize_range(range_input: str) -> Dict[str, any]:
    """
    Normalize and validate IP range.
    Supports:
    - Full range: 192.168.1.10-192.168.1.20
    - Short range: 192.168.1.10-20
    """
    parts = range_input.split('-')
    if len(parts) != 2:
        raise ValueError(f"Invalid range format '{range_input}'. Use '192.168.1.10-192.168.1.20' or '192.168.1.10-20'")
    
    start_str = parts[0].strip()
    end_str = parts[1].strip()
    
    try:
        start_ip = ipaddress.ip_address(start_str)
        
        # Check if end is just the last octet (short form)
        if end_str.isdigit() and '.' not in end_str:
            # Short form: 192.168.1.10-20
            if isinstance(start_ip, ipaddress.IPv4Address):
                start_octets = start_str.split('.')
                end_octets = start_octets[:3] + [end_str]
                end_str = '.'.join(end_octets)
            else:
                raise ValueError("Short range notation only supported for IPv4")
        
        end_ip = ipaddress.ip_address(end_str)
        
        # Validate same type and order
        if type(start_ip) != type(end_ip):
            raise ValueError("Start and end IPs must be same version")
        
        if start_ip >= end_ip:
            raise ValueError("Start IP must be less than end IP")
        
        # Calculate host count
        hosts_count = int(end_ip) - int(start_ip) + 1
        
        warnings = []
        if hosts_count > 1024:
            warnings.append(f"Large scan: {hosts_count} hosts. This may take a long time.")
        elif hosts_count > 256:
            warnings.append(f"Medium scan: {hosts_count} hosts.")
        
        # Nmap accepts ranges like "192.168.1.10-20"
        normalized = range_input
        
        return {
            "original": range_input,
            "normalized": normalized,
            "hosts_count": hosts_count,
            "target_type": "range",
            "warnings": warnings
        }
        
    except ValueError as e:
        raise ValueError(f"Invalid IP range '{range_input}': {str(e)}")


def _normalize_hostname(hostname: str) -> Dict[str, any]:
    """
    Validate and normalize hostname.
    Basic validation for valid hostname format.
    """
    # Basic hostname validation
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(hostname_pattern, hostname):
        raise ValueError(f"Invalid hostname format '{hostname}'")
    
    if len(hostname) > 253:
        raise ValueError(f"Hostname too long (max 253 characters): '{hostname}'")
    
    return {
        "original": hostname,
        "normalized": hostname,
        "hosts_count": None,  # Unknown for hostnames
        "target_type": "hostname",
        "warnings": []
    }


def validate_target_safety(target_info: Dict[str, any], max_hosts: int = 1024) -> Tuple[bool, Optional[str]]:
    """
    Check if a target is safe to scan without additional confirmation.
    
    Args:
        target_info: Result from normalize_target()
        max_hosts: Maximum hosts allowed without warning
        
    Returns:
        Tuple of (is_safe, warning_message)
    """
    hosts_count = target_info.get('hosts_count')
    
    if hosts_count is None:
        # Hostname - can't estimate, assume safe
        return (True, None)
    
    if hosts_count > max_hosts:
        return (False, f"Large scan ({hosts_count} hosts) requires confirmation")
    
    return (True, None)
