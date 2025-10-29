"""
Unit tests for target normalization logic
"""

import pytest
from services.target_normalizer import normalize_target, validate_target_safety


class TestTargetNormalization:
    """Test target normalization and validation"""
    
    def test_single_ip_regular(self):
        """Test regular single IP address"""
        result = normalize_target("192.168.1.100")
        assert result["normalized"] == "192.168.1.100"
        assert result["hosts_count"] == 1
        assert result["target_type"] == "single_ip"
        assert len(result["warnings"]) == 0
    
    def test_single_ip_ending_in_zero(self):
        """Test IP ending in .0 converts to /24"""
        result = normalize_target("192.168.1.0")
        assert result["normalized"] == "192.168.1.0/24"
        assert result["hosts_count"] == 256
        assert result["target_type"] == "cidr"
        assert len(result["warnings"]) == 1
        assert "192.168.1.0/24" in result["warnings"][0]
    
    def test_cidr_notation(self):
        """Test CIDR notation is preserved"""
        result = normalize_target("192.168.1.0/24")
        assert result["normalized"] == "192.168.1.0/24"
        assert result["hosts_count"] == 256
        assert result["target_type"] == "cidr"
    
    def test_cidr_large_network(self):
        """Test large CIDR generates warning"""
        result = normalize_target("10.0.0.0/16")
        assert result["hosts_count"] == 65536
        assert len(result["warnings"]) > 0
        assert "Large scan" in result["warnings"][0]
    
    def test_cidr_small_network(self):
        """Test small CIDR (no warning)"""
        result = normalize_target("192.168.1.0/28")
        assert result["hosts_count"] == 16
        assert result["target_type"] == "cidr"
    
    def test_hostname_valid(self):
        """Test valid hostname"""
        result = normalize_target("example.com")
        assert result["normalized"] == "example.com"
        assert result["hosts_count"] is None
        assert result["target_type"] == "hostname"
    
    def test_hostname_subdomain(self):
        """Test hostname with subdomain"""
        result = normalize_target("api.example.com")
        assert result["normalized"] == "api.example.com"
        assert result["target_type"] == "hostname"
    
    def test_range_full_form(self):
        """Test full IP range"""
        result = normalize_target("192.168.1.10-192.168.1.20")
        assert result["normalized"] == "192.168.1.10-192.168.1.20"
        assert result["hosts_count"] == 11
        assert result["target_type"] == "range"
    
    def test_range_short_form(self):
        """Test short IP range"""
        result = normalize_target("192.168.1.10-20")
        assert result["normalized"] == "192.168.1.10-20"
        assert result["hosts_count"] == 11
        assert result["target_type"] == "range"
    
    def test_range_large(self):
        """Test large IP range generates warning"""
        result = normalize_target("192.168.1.1-192.168.5.254")
        assert result["hosts_count"] > 1000
        assert len(result["warnings"]) > 0
    
    def test_invalid_ip_out_of_range(self):
        """Test invalid IP with octet > 255"""
        with pytest.raises(ValueError, match="Invalid"):
            normalize_target("999.999.999.999")
    
    def test_invalid_ip_format(self):
        """Test invalid IP format"""
        with pytest.raises(ValueError):
            normalize_target("not.an.ip")
    
    def test_invalid_cidr_mask(self):
        """Test invalid CIDR mask"""
        with pytest.raises(ValueError, match="Invalid CIDR"):
            normalize_target("192.168.1.0/33")
    
    def test_invalid_range_reversed(self):
        """Test range with start > end"""
        with pytest.raises(ValueError, match="Start IP must be less than end"):
            normalize_target("192.168.1.20-192.168.1.10")
    
    def test_empty_target(self):
        """Test empty target"""
        with pytest.raises(ValueError, match="cannot be empty"):
            normalize_target("")
    
    def test_whitespace_trimming(self):
        """Test whitespace is trimmed"""
        result = normalize_target("  192.168.1.100  ")
        assert result["normalized"] == "192.168.1.100"
    
    def test_localhost(self):
        """Test localhost address"""
        result = normalize_target("127.0.0.1")
        assert result["normalized"] == "127.0.0.1"
        assert result["hosts_count"] == 1
    
    def test_network_address_with_mask(self):
        """Test explicit network address with /24 mask"""
        result = normalize_target("10.0.0.0/24")
        assert result["normalized"] == "10.0.0.0/24"
        assert result["hosts_count"] == 256


class TestTargetSafety:
    """Test target safety validation"""
    
    def test_safe_single_ip(self):
        """Test single IP is safe"""
        target_info = normalize_target("192.168.1.100")
        is_safe, warning = validate_target_safety(target_info)
        assert is_safe is True
        assert warning is None
    
    def test_safe_small_network(self):
        """Test small network is safe"""
        target_info = normalize_target("192.168.1.0/24")
        is_safe, warning = validate_target_safety(target_info, max_hosts=1024)
        assert is_safe is True
    
    def test_unsafe_large_network(self):
        """Test large network requires confirmation"""
        target_info = normalize_target("10.0.0.0/16")
        is_safe, warning = validate_target_safety(target_info, max_hosts=1024)
        assert is_safe is False
        assert warning is not None
        assert "requires confirmation" in warning
    
    def test_hostname_is_safe(self):
        """Test hostname is considered safe (can't estimate)"""
        target_info = normalize_target("example.com")
        is_safe, warning = validate_target_safety(target_info)
        assert is_safe is True
        assert warning is None


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_broadcast_address(self):
        """Test broadcast address .255"""
        result = normalize_target("192.168.1.255")
        assert result["normalized"] == "192.168.1.255"
        assert result["hosts_count"] == 1
    
    def test_network_boundary(self):
        """Test network boundary addresses"""
        # .0 should convert to /24
        result = normalize_target("10.0.0.0")
        assert result["normalized"] == "10.0.0.0/24"
        
        # .1 should remain single IP
        result = normalize_target("10.0.0.1")
        assert result["normalized"] == "10.0.0.1"
    
    def test_private_networks(self):
        """Test various private network ranges"""
        # Class A private
        result = normalize_target("10.0.0.0/8")
        assert result["hosts_count"] == 16777216
        
        # Class B private
        result = normalize_target("172.16.0.0/12")
        assert result["hosts_count"] == 1048576
        
        # Class C private
        result = normalize_target("192.168.0.0/16")
        assert result["hosts_count"] == 65536
    
    def test_hostname_max_length(self):
        """Test hostname length validation"""
        # Valid max length
        long_hostname = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
        result = normalize_target(long_hostname)
        assert result["target_type"] == "hostname"
        
        # Too long
        too_long = "a" * 254
        with pytest.raises(ValueError, match="too long"):
            normalize_target(too_long)
    
    def test_hostname_with_hyphens(self):
        """Test hostname with hyphens"""
        result = normalize_target("my-server.example-site.com")
        assert result["normalized"] == "my-server.example-site.com"
        assert result["target_type"] == "hostname"
    
    def test_range_single_host(self):
        """Test range with same start and end (should fail)"""
        with pytest.raises(ValueError, match="Start IP must be less than end"):
            normalize_target("192.168.1.10-192.168.1.10")
    
    def test_ipv6_not_supported(self):
        """Test IPv6 addresses (future consideration)"""
        # Currently our implementation focuses on IPv4
        # IPv6 should either work with ipaddress library or fail gracefully
        try:
            result = normalize_target("2001:0db8::1")
            # If it works, it should be recognized
            assert result["target_type"] in ["single_ip", "hostname"]
        except ValueError:
            # If not supported yet, should fail with clear message
            pass
