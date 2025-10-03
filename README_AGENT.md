# VulnScan AI - Local Scan Agent

## Overview

The VulnScan AI Local Agent allows you to run network scans from a machine inside your target LAN, providing better accuracy and performance for local network scanning compared to scanning from a remote backend.

## When to Use the Agent

Use the local agent when:
- Your VulnScan backend is not on the same network as your scan targets
- You need to scan multiple isolated network segments
- You want to perform scans from specific network locations
- Network firewalls block scanning from your backend

## Agent Installation

### Prerequisites
- Python 3.8+
- Nmap installed with raw socket capabilities
- Network access to VulnScan AI backend

### Setup

1. **Install Dependencies**
```bash
pip install requests python-dotenv
```

2. **Grant Nmap Capabilities**
```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/nmap
```

3. **Configure Agent**

Create `.env` file:
```bash
VULNSCAN_BACKEND_URL=https://your-backend.example.com
VULNSCAN_API_KEY=your_agent_api_key_here
```

4. **Download Agent Script**

Save `scan_agent.py` (provided below) to your local machine.

## Agent Script

Create `scan_agent.py`:

```python
#!/usr/bin/env python3
"""
VulnScan AI Local Scan Agent
Executes Nmap scans locally and reports results to backend
"""

import os
import sys
import json
import uuid
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

BACKEND_URL = os.getenv('VULNSCAN_BACKEND_URL', 'http://localhost:8000')
API_KEY = os.getenv('VULNSCAN_API_KEY')
SCAN_DIR = Path('/tmp/vulnscan_agent')

def setup():
    """Initialize agent environment"""
    SCAN_DIR.mkdir(exist_ok=True)
    
    if not API_KEY:
        print("❌ VULNSCAN_API_KEY not configured")
        sys.exit(1)
    
    # Verify nmap capabilities
    try:
        result = subprocess.run(['getcap', '/usr/bin/nmap'], 
                              capture_output=True, text=True)
        if 'cap_net_raw' not in result.stdout:
            print("⚠️  Warning: Nmap lacks raw socket capabilities")
            print("Run: sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/nmap")
    except FileNotFoundError:
        print("❌ Nmap not installed")
        sys.exit(1)

def execute_scan(scan_id, target, nmap_args):
    """Execute local Nmap scan"""
    print(f"🔍 Starting scan {scan_id} on {target}")
    print(f"📝 Args: {nmap_args}")
    
    xml_output = SCAN_DIR / f"scan_{scan_id}.xml"
    
    command = ['sudo', 'nmap'] + nmap_args.split() + [target, '-oX', str(xml_output)]
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode != 0:
            raise Exception(f"Nmap failed: {result.stderr}")
        
        # Read XML output
        with open(xml_output, 'r') as f:
            xml_data = f.read()
        
        return {
            'success': True,
            'xml_output': xml_data,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'command': ' '.join(command)
        }
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Scan timeout exceeded',
            'command': ' '.join(command)
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'command': ' '.join(command)
        }

def upload_results(scan_id, results):
    """Upload scan results to backend"""
    print(f"📤 Uploading results for scan {scan_id}")
    
    url = f"{BACKEND_URL}/api/scan/agent-result"
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'scan_id': scan_id,
        'agent_id': os.uname().nodename,
        'timestamp': datetime.utcnow().isoformat(),
        'results': results
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        print("✅ Results uploaded successfully")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Upload failed: {e}")
        return False

def poll_for_jobs():
    """Poll backend for pending scan jobs"""
    url = f"{BACKEND_URL}/api/scan/agent-jobs"
    headers = {'Authorization': f'Bearer {API_KEY}'}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        jobs = response.json()
        return jobs.get('pending_scans', [])
    except requests.exceptions.RequestException as e:
        print(f"⚠️  Job polling failed: {e}")
        return []

def main():
    """Agent main loop"""
    print("🚀 VulnScan AI Local Agent Starting")
    setup()
    
    if len(sys.argv) > 1:
        # Direct scan mode
        if len(sys.argv) < 4:
            print("Usage: scan_agent.py <scan_id> <target> <nmap_args>")
            sys.exit(1)
        
        scan_id = sys.argv[1]
        target = sys.argv[2]
        nmap_args = ' '.join(sys.argv[3:])
        
        results = execute_scan(scan_id, target, nmap_args)
        upload_results(scan_id, results)
    else:
        # Polling mode (not implemented in this version)
        print("❌ Polling mode not yet implemented")
        print("Run with: scan_agent.py <scan_id> <target> <nmap_args>")

if __name__ == '__main__':
    main()
```

## Usage

### Manual Scan Execution

```bash
./scan_agent.py scan_12345 192.168.1.0/24 "-T4 -F -sS -PR -sV"
```

### Systemd Service (Optional)

For automatic polling mode, create `/etc/systemd/system/vulnscan-agent.service`:

```ini
[Unit]
Description=VulnScan AI Local Scan Agent
After=network.target

[Service]
Type=simple
User=vulnscan
WorkingDirectory=/opt/vulnscan-agent
ExecStart=/usr/bin/python3 /opt/vulnscan-agent/scan_agent.py --daemon
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable vulnscan-agent
sudo systemctl start vulnscan-agent
```

## Security Considerations

1. **API Key**: Keep `VULNSCAN_API_KEY` secret and rotate regularly
2. **Sudo Access**: Agent needs sudo for Nmap - consider using sudoers file to restrict commands
3. **Network Segmentation**: Run agent on trusted management networks only
4. **Logging**: All scans are logged locally in `/tmp/vulnscan_agent/`
5. **Firewall**: Ensure agent can reach backend API over HTTPS

## Troubleshooting

**Agent can't connect to backend:**
- Verify `VULNSCAN_BACKEND_URL` is correct
- Check firewall rules allow HTTPS egress
- Confirm API key is valid

**Nmap permission errors:**
- Run `getcap /usr/bin/nmap` to verify capabilities
- Ensure agent is using `sudo` for Nmap execution

**Scans not appearing in UI:**
- Check backend logs for upload errors
- Verify scan_id matches the one in UI
- Confirm network connectivity during upload

## Future Enhancements

- [ ] Automatic job polling from backend
- [ ] Multiple concurrent scan support
- [ ] Encrypted result upload
- [ ] Agent health monitoring dashboard
- [ ] Automatic agent updates
