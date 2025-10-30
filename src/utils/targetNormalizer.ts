/**
 * Client-side target normalization and validation
 * Provides quick feedback before sending to backend
 */

export interface NormalizedTarget {
  original: string;
  normalized: string;
  hostsCount: number | null;
  targetType: 'single_ip' | 'cidr' | 'hostname' | 'range';
  warnings: string[];
  isValid: boolean;
  error?: string;
}

/**
 * Preview what the target will be normalized to
 * This provides instant feedback to users before scanning
 */
export const previewTargetNormalization = (input: string): NormalizedTarget => {
  const trimmed = input.trim();
  
  if (!trimmed) {
    return {
      original: input,
      normalized: input,
      hostsCount: null,
      targetType: 'single_ip',
      warnings: [],
      isValid: false,
      error: 'Target cannot be empty'
    };
  }
  
  // Check for CIDR notation
  if (trimmed.includes('/')) {
    return previewCIDR(trimmed);
  }
  
  // Check for IP range
  if (trimmed.includes('-')) {
    return previewRange(trimmed);
  }
  
  // Check if it's an IPv4 address ending in .0
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = trimmed.match(ipv4Regex);
  
  if (match) {
    const octets = match.slice(1, 5).map(Number);
    
    // Validate octets
    if (octets.some(o => o > 255)) {
      return {
        original: trimmed,
        normalized: trimmed,
        hostsCount: null,
        targetType: 'single_ip',
        warnings: [],
        isValid: false,
        error: 'Invalid IP address: octets must be 0-255'
      };
    }
    
    // Special case: .0 address -> convert to /24
    if (octets[3] === 0) {
      const cidr = `${trimmed}/24`;
      return {
        original: trimmed,
        normalized: cidr,
        hostsCount: 256,
        targetType: 'cidr',
        warnings: [`Will scan entire /24 subnet (256 hosts)`],
        isValid: true
      };
    }
    
    // Regular single IP
    return {
      original: trimmed,
      normalized: trimmed,
      hostsCount: 1,
      targetType: 'single_ip',
      warnings: [],
      isValid: true
    };
  }
  
  // Might be a hostname
  return previewHostname(trimmed);
};

const previewCIDR = (cidr: string): NormalizedTarget => {
  try {
    const [ip, mask] = cidr.split('/');
    const maskNum = parseInt(mask, 10);
    
    if (isNaN(maskNum) || maskNum < 0 || maskNum > 32) {
      return {
        original: cidr,
        normalized: cidr,
        hostsCount: null,
        targetType: 'cidr',
        warnings: [],
        isValid: false,
        error: 'Invalid CIDR mask (must be 0-32)'
      };
    }
    
    // Calculate host count
    const hostsCount = Math.pow(2, 32 - maskNum);
    const warnings: string[] = [];
    
    if (hostsCount > 1024) {
      warnings.push(`⚠️ Large scan: ${hostsCount.toLocaleString()} hosts. This may take a very long time.`);
    } else if (hostsCount > 256) {
      warnings.push(`Medium scan: ${hostsCount.toLocaleString()} hosts.`);
    }
    
    return {
      original: cidr,
      normalized: cidr,
      hostsCount,
      targetType: 'cidr',
      warnings,
      isValid: true
    };
  } catch (e) {
    return {
      original: cidr,
      normalized: cidr,
      hostsCount: null,
      targetType: 'cidr',
      warnings: [],
      isValid: false,
      error: 'Invalid CIDR notation'
    };
  }
};

const previewRange = (range: string): NormalizedTarget => {
  const parts = range.split('-');
  
  if (parts.length !== 2) {
    return {
      original: range,
      normalized: range,
      hostsCount: null,
      targetType: 'range',
      warnings: [],
      isValid: false,
      error: 'Invalid range format. Use "192.168.1.10-192.168.1.20" or "192.168.1.10-20"'
    };
  }
  
  const start = parts[0].trim();
  const end = parts[1].trim();
  
  // Validate start IP
  const startMatch = start.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!startMatch) {
    return {
      original: range,
      normalized: range,
      hostsCount: null,
      targetType: 'range',
      warnings: [],
      isValid: false,
      error: 'Invalid start IP in range'
    };
  }
  
  const startOctets = startMatch.slice(1, 5).map(Number);
  
  // Check if end is just a number (short form)
  let endOctets: number[];
  if (/^\d{1,3}$/.test(end)) {
    // Short form: 192.168.1.10-20
    endOctets = [...startOctets.slice(0, 3), parseInt(end, 10)];
  } else {
    // Full form: 192.168.1.10-192.168.1.20
    const endMatch = end.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!endMatch) {
      return {
        original: range,
        normalized: range,
        hostsCount: null,
        targetType: 'range',
        warnings: [],
        isValid: false,
        error: 'Invalid end IP in range'
      };
    }
    endOctets = endMatch.slice(1, 5).map(Number);
  }
  
  // Validate octets
  if ([...startOctets, ...endOctets].some(o => o > 255)) {
    return {
      original: range,
      normalized: range,
      hostsCount: null,
      targetType: 'range',
      warnings: [],
      isValid: false,
      error: 'Invalid IP address: octets must be 0-255'
    };
  }
  
  // Calculate host count
  const startNum = startOctets[0] * 16777216 + startOctets[1] * 65536 + startOctets[2] * 256 + startOctets[3];
  const endNum = endOctets[0] * 16777216 + endOctets[1] * 65536 + endOctets[2] * 256 + endOctets[3];
  
  if (startNum >= endNum) {
    return {
      original: range,
      normalized: range,
      hostsCount: null,
      targetType: 'range',
      warnings: [],
      isValid: false,
      error: 'Start IP must be less than end IP'
    };
  }
  
  const hostsCount = endNum - startNum + 1;
  const warnings: string[] = [];
  
  if (hostsCount > 1024) {
    warnings.push(`⚠️ Large scan: ${hostsCount.toLocaleString()} hosts. This may take a very long time.`);
  } else if (hostsCount > 256) {
    warnings.push(`Medium scan: ${hostsCount.toLocaleString()} hosts.`);
  }
  
  return {
    original: range,
    normalized: range,
    hostsCount,
    targetType: 'range',
    warnings,
    isValid: true
  };
};

const previewHostname = (hostname: string): NormalizedTarget => {
  // Basic hostname validation
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  
  if (!hostnameRegex.test(hostname)) {
    return {
      original: hostname,
      normalized: hostname,
      hostsCount: null,
      targetType: 'hostname',
      warnings: [],
      isValid: false,
      error: 'Invalid hostname format'
    };
  }
  
  if (hostname.length > 253) {
    return {
      original: hostname,
      normalized: hostname,
      hostsCount: null,
      targetType: 'hostname',
      warnings: [],
      isValid: false,
      error: 'Hostname too long (max 253 characters)'
    };
  }
  
  return {
    original: hostname,
    normalized: hostname,
    hostsCount: null,
    targetType: 'hostname',
    warnings: ['Hostname will be resolved at scan time'],
    isValid: true
  };
};

/**
 * Check if target requires confirmation due to size
 */
export const requiresConfirmation = (normalized: NormalizedTarget, threshold: number = 512): boolean => {
  if (normalized.hostsCount === null) {
    return false; // Hostname, can't estimate
  }
  return normalized.hostsCount > threshold;
};
