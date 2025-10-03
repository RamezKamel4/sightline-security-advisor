# VulnScan AI - Deployment & Configuration Guide

## LAN Scanning Requirements

VulnScan AI uses Nmap for network scanning. To achieve parity with tools like Zenmap when scanning local LAN ranges (e.g., 192.168.1.0/24), the backend requires specific privileges.

### Privilege Requirements

For optimal LAN scanning with ARP discovery and SYN scans, Nmap needs raw socket capabilities:

#### Option 1: Grant Nmap Capabilities (Recommended)
```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/nmap
```

#### Option 2: Run Backend as Root (Not Recommended for Production)
```bash
sudo python start_backend.py
```

#### Option 3: Docker with Host Network & Capabilities
```bash
docker run --rm \
  --network=host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --name vulnscan-backend \
  vulnscan:latest
```

Or use privileged mode (less secure):
```bash
docker run --rm \
  --network=host \
  --privileged \
  --name vulnscan-backend \
  vulnscan:latest
```

### LAN Scanning Behavior

The backend automatically detects private IP ranges (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and applies optimal scanning arguments:

**For Local LAN Targets (when backend is on same subnet):**
```bash
nmap -T4 -F -sS -PR -sV <target>
```
- `-T4`: Aggressive timing (fast)
- `-F`: Top 100 ports
- `-sS`: SYN stealth scan (requires raw sockets)
- `-PR`: ARP ping discovery (LAN only, requires privileges)
- `-sV`: Service/version detection

**For Remote or Non-LAN Targets:**
```bash
nmap -T4 -F -sS -Pn -sV <target>
```
- Replaces `-PR` with `-Pn` to skip ICMP host discovery

### Verifying Configuration

Test your setup:
```bash
# Test raw socket capability
getcap /usr/bin/nmap
# Should output: /usr/bin/nmap cap_net_admin,cap_net_raw=ep

# Test LAN scan
sudo nmap -T4 -F -sS -PR -sV 192.168.1.0/24 -oX test_scan.xml

# Check results
cat test_scan.xml
```

### Docker Deployment

#### Build Image
```bash
docker build -t vulnscan:latest .
```

#### Run with Host Network (Required for LAN Scanning)
```bash
docker run -d \
  --name vulnscan-backend \
  --network=host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v /var/lib/vulnscan:/var/lib/vulnscan \
  -e GEMINI_API_KEY=${GEMINI_API_KEY} \
  vulnscan:latest
```

### Security Considerations

1. **Authorization**: Always ensure you have written permission to scan target networks
2. **Privileges**: Only grant minimum required capabilities (NET_RAW, NET_ADMIN)
3. **Network Isolation**: Consider running the backend in a dedicated security network segment
4. **Logging**: All scans are logged with the exact nmap command used
5. **User Warnings**: The UI displays permission warnings before starting aggressive scans

### Troubleshooting

**Issue**: "Operation not permitted" errors
- **Solution**: Verify Nmap has raw socket capabilities: `getcap /usr/bin/nmap`

**Issue**: ARP discovery not working
- **Solution**: Ensure backend host is on the same subnet as target

**Issue**: Docker container can't scan host network
- **Solution**: Use `--network=host` mode, not bridge networking

**Issue**: Missing hosts compared to Zenmap
- **Solution**: Verify privileges and check that `-PR` flag is being applied for LAN scans

### Production Checklist

- [ ] Nmap capabilities configured (`cap_net_raw`, `cap_net_admin`)
- [ ] Backend can access target network (routing/firewall rules)
- [ ] Scan results directory exists with proper permissions
- [ ] Database connection configured
- [ ] Legal authorization documented for all target networks
- [ ] Monitoring and alerting configured for scan activity
- [ ] Rate limiting configured to prevent network overload

### Environment Variables

```bash
# .env file
GEMINI_API_KEY=your_api_key_here
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
```

### Performance Tuning

For large network scans:
- Use `--host-timeout 30s` for slow hosts
- Increase `--max-retries` if packet loss is high
- Consider splitting large CIDR ranges into smaller batches
- Use `comprehensive` profile sparingly (scans all 65535 ports)

### Database Schema

The `scans` table stores:
- `nmap_cmd`: Exact command executed
- `nmap_output`: Raw Nmap output/CSV
- `scan_source`: 'backend' or 'agent'
- `use_arp_discovery`: Boolean flag for ARP usage

This enables audit trails and reproducibility of scan results.
