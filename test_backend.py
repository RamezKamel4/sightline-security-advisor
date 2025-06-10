
#!/usr/bin/env python3
"""
Test script to verify the VulnScan AI Backend is working
"""
import requests
import json

def test_backend():
    base_url = "http://localhost:8000"
    
    print("🧪 Testing VulnScan AI Backend...")
    
    # Test 1: Health check
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend. Make sure it's running on localhost:8000")
        return False
    
    # Test 2: API test endpoint
    try:
        response = requests.get(f"{base_url}/api/scan/test")
        if response.status_code == 200:
            print("✅ API test endpoint working")
        else:
            print(f"❌ API test endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API test failed: {e}")
        return False
    
    # Test 3: Scan endpoint with localhost
    try:
        scan_data = {
            "ip": "127.0.0.1",
            "nmap_args": "-T4 --top-ports 10",
            "scan_profile": "test"
        }
        
        response = requests.post(
            f"{base_url}/api/scan",
            json=scan_data,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            print("✅ Scan endpoint working")
            result = response.json()
            print(f"📊 Scan found {len(result)} services" if isinstance(result, list) else f"📊 Scan result: {result}")
        else:
            print(f"❌ Scan endpoint failed: {response.status_code}")
            print(f"Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Scan test failed: {e}")
        return False
    
    print("🎉 All tests passed! Backend is working correctly.")
    return True

if __name__ == "__main__":
    test_backend()
