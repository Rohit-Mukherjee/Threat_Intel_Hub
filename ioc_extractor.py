"""IOC Extractor - Extract Indicators of Compromise from threat intel."""
import re
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum


class IOCType(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    CVE = "cve"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    FILE_NAME = "file_name"
    MAC_ADDRESS = "mac_address"


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""
    value: str
    ioc_type: str
    source: str
    source_url: str
    confidence: str  # High, Medium, Low
    first_seen: str
    tags: List[str]
    context: str
    related_threat_actors: List[str]
    related_techniques: List[str]
    malware_family: Optional[str] = None
    times_seen: int = 1


class IOCExtractor:
    """Extract IOCs from text content."""
    
    # Regex patterns for IOC extraction
    PATTERNS = {
        IOCType.IP_ADDRESS: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        IOCType.DOMAIN: r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|tk|ml|ga|cf|gq|pw|cc|ws|su|onion|ly|me|co|tv|cc|ms|la|vc|gd|ws|hm|nu|fm|am|as|ac|im|sh|st|to|tk|cf|ga|ml|gq)\b',
        IOCType.URL: r'https?://[^\s<>"{}|\\^`\[\]]+',
        IOCType.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        IOCType.MD5: r'\b[a-fA-F0-9]{32}\b',
        IOCType.SHA1: r'\b[a-fA-F0-9]{40}\b',
        IOCType.SHA256: r'\b[a-fA-F0-9]{64}\b',
        IOCType.SHA512: r'\b[a-fA-F0-9]{128}\b',
        IOCType.CVE: r'\bCVE-\d{4}-\d{4,7}\b',
        IOCType.FILE_PATH: r'(?:[A-Za-z]:\\[^\s<>:"|?*]+|[A-Za-z]:\\[^\s<>:"|?*]+\.[A-Za-z]{2,4}|/[a-zA-Z0-9_\-./]+/\w+\.\w+)',
        IOCType.REGISTRY_KEY: r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[^\s]+)+',
        IOCType.USER_AGENT: r'Mozilla/[0-9]\.[0-9][^\n"]{0,100}',
        IOCType.MAC_ADDRESS: r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})',
    }
    
    # Pattern to extract filename from context near hashes
    FILENAME_PATTERN = r'(?:file[:\s]+|named[:\s]+|filename[:\s]+|malware[:\s]+|trojan[:\s]+)["\']?([a-zA-Z0-9_\-]+\.(?:exe|dll|bat|ps1|vbs|js|scr|bin))["\']?'
    
    # High-confidence domain patterns (more restrictive)
    HIGH_CONFIDENCE_TLDS = {
        'com', 'net', 'org', 'io', 'ru', 'cn', 'xyz', 'top', 'info', 'biz'
    }
    
    # Known benign domains to exclude
    BENIGN_DOMAINS = {
        # Security vendors - should never be flagged as malicious
        'virustotal.com', 'crowdstrike.com', 'mandiant.com', 'microsoft.com',
        'kaspersky.com', 'securelist.com', 'sophos.com', 'bleepingcomputer.com',
        'darkreading.com', 'threatpost.com', 'securityweek.com', 'theregister.com',
        'zdnet.com', 'techcrunch.com', 'arstechnica.com', 'wired.com',
        'paloaltonetworks.com', 'unit42.paloaltonetworks.com',
        'sentinelone.com', 'trendmicro.com', 'eset.com', 'malwarebytes.com',
        'symantec.com', 'mcafee.com', 'f-secure.com', 'bitdefender.com',
        'avast.com', 'avg.com', 'norton.com', 'kasperskycontenthub.com',
        'drweb.com', 'humansecurity.com', 'gdatasoftware.com',
        # Tech companies
        'google.com', 'facebook.com', 'amazon.com', 'apple.com',
        'github.com', 'stackoverflow.com', 'wikipedia.org',
        'youtube.com', 'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
        'cloudflare.com', 'akamai.com', 'amazonaws.com', 'googleapis.com',
        'windows.com', 'office.com', 'outlook.com', 'live.com',
        'azure.com', 'aws.amazon.com', 'digitalocean.com',
        # Security research
        'malpedia.caad.fkie.fraunhofer.de', 'fraunhofer.de',
        'mitre.org', 'attack.mitre.org', 'cisa.gov', 'nvd.nist.gov',
        'sans.org', 'isc.sans.edu', 'owasp.org', 'w3.org',
        # Common benign
        'example.com', 'example.org', 'localhost', 'test.com',
        'mozilla.org', 'apache.org', 'ubuntu.com', 'debian.org',
        # Cloud/CDN providers (often false positives)
        'gstatic.com', 'googleusercontent.com', 'googlevideo.com',
        'ytimg.com', 'fbcdn.net', 'twimg.com', 'licdn.com',
        # More false positive domains
        'android.com', 'gstatic2.com', 'glogstatic.com', 'ytimg2.com',
        'gmsstatic.com', 'tmgstatic.com', 'fbsimg.com', 'fbgraph.com',
        'ufileos.com', 'aliyuncs.com', 'istaticfiles.com',
        # Hardware vendors
        'dell.com', 'hp.com', 'lenovo.com', 'intel.com', 'amd.com',
        'samsung.com', 'sony.com', 'lg.com', 'asus.com', 'acer.com',
        # Software vendors
        'adobe.com', 'oracle.com', 'ibm.com', 'vmware.com', 'salesforce.com',
        # Telecom
        'verizon.com', 'att.com', 'tmobile.com', 'vodafone.com',
    }
    
    # Domain keywords that indicate benign/infrastructure domains
    BENIGN_KEYWORDS = [
        'static', 'cdn', 'content', 'images', 'media', 'assets',
        'analytics', 'tracking', 'telemetry', 'update', 'download',
        'support', 'help', 'docs', 'api', 'cloud', 'storage',
        'report', 'graph', 'img', 'video', 'news', 'blog',
    ]
    
    # Security vendor URL patterns to exclude from IOC extraction
    SECURITY_VENDOR_URLS = [
        r'https?://(?:www\.)?virustotal\.com',
        r'https?://(?:www\.)?crowdstrike\.com',
        r'https?://(?:www\.)?mandiant\.com',
        r'https?://(?:www\.)?microsoft\.com',
        r'https?://securelist\.com',
        r'https?://(?:www\.)?sophos\.com',
        r'https?://(?:www\.)?bleepingcomputer\.com',
        r'https?://(?:www\.)?darkreading\.com',
        r'https?://threatpost\.com',
        r'https?://(?:www\.)?thehackernews\.com',
        r'https?://unit42\.paloaltonetworks\.com',
        r'https?://(?:www\.)?sentinelone\.com',
        r'https?://(?:www\.)?elastic\.co',
        r'https?://malpedia\.caad\.fkie\.fraunhofer\.de',
        r'https?://(?:www\.)?github\.com',
        r'https?://(?:www\.)?youtube\.com/watch',
        r'https?://twitter\.com/',
        r'https?://(?:www\.)?linkedin\.com/',
        r'https?://(?:www\.)?paloaltonetworks\.com',
        r'https?://(?:www\.)?kaspersky\.com',
    ]
    
    # Known benign URLs to exclude
    BENIGN_URL_PATTERNS = [
        r'https?://(?:www\.)?(microsoft|google|github|stackoverflow|wikipedia)\.com',
        r'https?://(?:docs|learn|support)\.microsoft\.com',
        r'https?://(?:www\.)?youtube\.com/watch',
        r'https?://twitter\.com/',
        r'https?://(?:www\.)?linkedin\.com/',
    ]
    
    def __init__(self):
        self.compiled_patterns = {
            ioc_type: re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for ioc_type, pattern in self.PATTERNS.items()
        }
        self.benign_url_regexes = [
            re.compile(p, re.IGNORECASE) for p in self.BENIGN_URL_PATTERNS
        ]
        self.security_vendor_regexes = [
            re.compile(p, re.IGNORECASE) for p in self.SECURITY_VENDOR_URLS
        ]
    
    def extract_all(self, content: str, source: str, source_url: str,
                    threat_actors: List[str] = None,
                    techniques: List[str] = None,
                    tags: List[str] = None) -> List[IOC]:
        """Extract all IOCs from content."""
        iocs = []

        # Extract each IOC type
        for ioc_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(content)
            for match in matches:
                value = match.strip()
                
                # Skip if value matches the source URL (don't extract blog URLs as IOCs)
                if source_url and value == source_url:
                    continue
                
                # Skip URLs from security vendor sites
                if ioc_type == IOCType.URL:
                    if self._is_benign_url(value):
                        continue
                
                ioc = self._create_ioc(
                    value=value,
                    ioc_type=ioc_type,
                    source=source,
                    source_url=source_url,
                    threat_actors=threat_actors or [],
                    techniques=techniques or [],
                    tags=tags or [],
                    content=content
                )
                if ioc and self._is_valid_ioc(ioc):
                    iocs.append(ioc)

        return iocs

    def _is_benign_url(self, url: str) -> bool:
        """Check if URL is from a benign/security vendor source."""
        url_lower = url.lower()
        
        # Check against security vendor regexes
        for regex in self.security_vendor_regexes:
            if regex.match(url):
                return True
        
        # Check against benign URL patterns
        for regex in self.benign_url_regexes:
            if regex.match(url):
                return True
        
        # Check for common benign patterns - BE MORE AGGRESSIVE
        benign_indicators = [
            # Feed/RSS
            '/feed', '/rss', '/rss.xml', '/feed.xml',
            'feedburner', 'feeds.feedburner.com',
            
            # Social media
            'twitter.com/', 'linkedin.com/', 'facebook.com/',
            'youtube.com/', 'google.com/', 'github.com/',
            'reddit.com/', 'medium.com/', 'substack.com',
            
            # Tech companies
            'microsoft.com/', 'windows.com/', 'office.com/',
            'amazon.com/', 'aws.amazon.com/', 'apple.com/',
            
            # CDN/static/assets
            'cdn.', 'static.', 'assets.', 'media.',
            'cloudflare.', 'akamai.', 'fastly.',
            
            # Documentation
            'docs.', 'support.', 'learn.', 'help.',
            'developer.', 'blog.', 'news.', 'article.',
            
            # File types that are typically not IOCs
            '.html', '.php', '.aspx', '.jsp',
            
            # Common benign paths
            '/category/', '/tag/', '/author/', '/page/',
            '/wp-content/', '/wp-includes/',
            
            # Search/analytics
            'googleusercontent', 'googlevideo', 'gstatic',
            'ytimg.com', 'fbcdn.net', 'twimg.com',
            
            # Standards/research
            'w3.org', 'mozilla.org', 'apache.org',
            'wikipedia.org', 'stackoverflow.com',
            
            # Government/education
            '.gov/', '.edu/', '.mil/',
            'cisa.gov', 'fbi.gov', 'nsa.gov',
            
            # Security vendors (should never be IOCs)
            'virustotal.com', 'mandiant.com', 'crowdstrike.com',
            'kaspersky.com', 'securelist.com', 'sophos.com',
            'bleepingcomputer.com', 'darkreading.com',
            'threatpost.com', 'securityweek.com', 'theregister.com',
            'sentinelone.com', 'paloaltonetworks.com', 'unit42',
            'eset.com', 'malwarebytes.com', 'trendmicro.com',
            'bitdefender.com', 'avast.com', 'symantec.com',
            'mcafee.com', 'f-secure.com', 'drweb.com',
            'gdatasoftware.com', 'humansecurity.com', 'elastic.co',
        ]
        
        for indicator in benign_indicators:
            if indicator in url_lower:
                return True
        
        # Check for common TLDs that are usually benign when combined with www
        if 'www.' in url_lower:
            benign_tld_with_www = [
                '.com/', '.org/', '.net/', '.io/',
            ]
            for tld in benign_tld_with_www:
                if tld in url_lower and 'www.' in url_lower:
                    # Additional check: if it has /blog/ or /news/, it's benign
                    if any(x in url_lower for x in ['/blog/', '/news/', '/article/', '/post/']):
                        return True
        
        return False
    
    def _create_ioc(self, value: str, ioc_type: IOCType, source: str,
                    source_url: str, threat_actors: List[str],
                    techniques: List[str], tags: List[str],
                    content: str) -> Optional[IOC]:
        """Create an IOC object with metadata."""
        # Normalize value
        value = value.strip().rstrip('.,;:)]}>')
        
        if not value:
            return None
        
        # Determine confidence level
        confidence = self._assess_confidence(value, ioc_type)
        
        # Extract context (surrounding text)
        context = self._extract_context(value, content)
        
        # Try to identify malware family
        malware_family = self._identify_malware_family(value, content)
        
        # For hash IOCs, try to extract associated filename from context
        malware_name = None
        if ioc_type in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512]:
            malware_name = self._extract_filename_for_hash(value, content)
        
        return IOC(
            value=value,
            ioc_type=ioc_type.value,
            source=source,
            source_url=source_url,
            confidence=confidence,
            first_seen=datetime.now().isoformat(),
            tags=tags[:5] if tags else [],
            context=context,
            related_threat_actors=threat_actors[:3] if threat_actors else [],
            related_techniques=techniques[:5] if techniques else [],
            malware_family=malware_name or malware_family,
            times_seen=1
        )
    
    def _extract_filename_for_hash(self, hash_value: str, content: str) -> Optional[str]:
        """Extract filename associated with a hash from context."""
        # Look for filename patterns near the hash
        hash_idx = content.find(hash_value)
        if hash_idx == -1:
            return None
        
        # Get context window around the hash (200 chars before and after)
        start = max(0, hash_idx - 200)
        end = min(len(content), hash_idx + len(hash_value) + 200)
        context = content[start:end]
        
        # Try to find filename patterns
        match = re.search(self.FILENAME_PATTERN, context, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Also try to find common malware naming patterns
        malware_patterns = [
            r'([a-zA-Z0-9_\-]+Stealer\.exe)',
            r'([a-zA-Z0-9_\-]+Ransom\.exe)',
            r'([a-zA-Z0-9_\-]+Bot\.exe)',
            r'([a-zA-Z0-9_\-]+Loader\.dll)',
            r'([a-zA-Z0-9_\-]+Dropper\.exe)',
        ]
        
        for pattern in malware_patterns:
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _assess_confidence(self, value: str, ioc_type: IOCType) -> str:
        """Assess confidence level of an IOC."""
        value_lower = value.lower()
        
        # Hash types are always high confidence
        if ioc_type in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512]:
            return "High"
        
        # CVEs are high confidence
        if ioc_type == IOCType.CVE:
            return "High"
        
        # Check domain confidence
        if ioc_type == IOCType.DOMAIN:
            # Check if it's a known benign domain
            for benign in self.BENIGN_DOMAINS:
                if benign in value_lower:
                    return "Low"
            
            # Check TLD
            tld = value.split('.')[-1].lower() if '.' in value else ''
            if tld in self.HIGH_CONFIDENCE_TLDS:
                return "Medium"
            return "Low"
        
        # Check URL confidence
        if ioc_type == IOCType.URL:
            for benign_regex in self.benign_url_regexes:
                if benign_regex.match(value):
                    return "Low"
            return "Medium"
        
        # IP addresses - check for private/reserved
        if ioc_type == IOCType.IP_ADDRESS:
            if self._is_private_ip(value):
                return "Low"
            return "Medium"
        
        return "Medium"
    
    def _is_valid_ioc(self, ioc: IOC) -> bool:
        """Validate if an IOC should be kept."""
        value = ioc.value.lower()
        
        # Strip www. prefix for checking
        check_value = value
        if check_value.startswith('www.'):
            check_value = check_value[4:]
        
        # Skip known benign domains
        for benign in self.BENIGN_DOMAINS:
            if benign == check_value or check_value.endswith('.' + benign):
                return False
        
        # Check for benign keywords in domain
        if ioc.ioc_type == IOCType.DOMAIN.value:
            # Skip domains containing benign keywords
            for keyword in self.BENIGN_KEYWORDS:
                if keyword in check_value:
                    return False
            
            # Skip domains that look like vendor subdomains
            vendor_indicators = ['unit42', 'labs', 'research', 'security', 'blog', 
                                'news', 'media', 'press', 'about', 'support',
                                'help', 'docs', 'developer', 'api', 'cdn',
                                'static', 'content', 'assets', 'images']
            for indicator in vendor_indicators:
                if indicator in check_value.split('.')[0]:  # Check subdomain
                    return False
            
            # Require domain to have some "suspicious" characteristics
            # to avoid false positives from legitimate sites
            parts = check_value.split('.')
            if len(parts) >= 2:
                main_domain = parts[-2] if len(parts) >= 2 else parts[0]
                # Skip if main domain is a well-known brand
                known_brands = ['google', 'facebook', 'amazon', 'microsoft', 
                               'apple', 'cloudflare', 'akamai', 'github',
                               'paloalto', 'kaspersky', 'sophos', 'crowdstrike',
                               'mandiant', 'sentinel', 'trendmicro', 'eset',
                               'dell', 'hp', 'lenovo', 'intel', 'amd',
                               'samsung', 'sony', 'adobe', 'oracle', 'ibm',
                               'vmware', 'mozilla', 'apache', 'ubuntu', 'debian']
                if any(brand in main_domain.lower() for brand in known_brands):
                    return False
                
                # Skip domains with only numbers + common TLD (too many false positives)
                subdomain = parts[0] if len(parts) > 1 else ''
                if subdomain.replace('_', '').replace('-', '').isalnum():
                    # Check if it looks like a random generated domain
                    if len(subdomain) < 5 and not any(c.isdigit() for c in subdomain):
                        return False
        
        # Skip security vendor URLs
        if ioc.ioc_type == IOCType.URL.value:
            for vendor_regex in self.security_vendor_regexes:
                if vendor_regex.match(value):
                    return False
        
        # Skip localhost and common test values
        if value in ['localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'test.com']:
            return False
        
        # Skip private IPs for external threat intel
        if ioc.ioc_type == IOCType.IP_ADDRESS.value:
            if self._is_private_ip(ioc.value):
                return False
        
        # Skip very short domains (likely false positives)
        if ioc.ioc_type == IOCType.DOMAIN.value:
            if len(check_value) < 8 or check_value.count('.') < 1:
                return False
        
        # Skip URLs that are just references to security tools
        if ioc.ioc_type == IOCType.URL.value:
            if any(kw in value for kw in ['virustotal', 'crowdstrike', 'mandiant', 
                                           'microsoft.com/security', 'github.com',
                                           'paloaltonetworks.com', 'kaspersky.com']):
                return False
        
        # Skip file names that look like domains or PDFs
        if ioc.ioc_type == IOCType.FILE_NAME.value:
            if '.com' in value or '.org' in value or '.pdf' in value:
                return False
        
        return True
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return True
            
            # 10.x.x.x
            if octets[0] == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            # 192.168.x.x
            if octets[0] == 192 and octets[1] == 168:
                return True
            # 127.x.x.x (loopback)
            if octets[0] == 127:
                return True
            # 0.x.x.x
            if octets[0] == 0:
                return True
            
            return False
        except (ValueError, IndexError):
            return True
    
    def _extract_context(self, value: str, content: str, window: int = 100) -> str:
        """Extract surrounding context for an IOC."""
        try:
            idx = content.find(value)
            if idx == -1:
                return ""
            
            start = max(0, idx - window)
            end = min(len(content), idx + len(value) + window)
            
            context = content[start:end]
            context = ' '.join(context.split())  # Normalize whitespace
            
            return context[:200] + "..." if len(context) > 200 else context
        except Exception:
            return ""
    
    def _identify_malware_family(self, value: str, content: str) -> Optional[str]:
        """Try to identify malware family from context."""
        malware_patterns = [
            (r'(\w+[-_]?ransomware)', 'ransomware'),
            (r'(\w+[-_]?trojan)', 'trojan'),
            (r'(\w+[-_]?backdoor)', 'backdoor'),
            (r'(\w+[-_]?rat)', 'rat'),
            (r'(\w+[-_]?stealer)', 'stealer'),
            (r'(\w+[-_]?loader)', 'loader'),
            (r'(\w+[-_]?dropper)', 'dropper'),
            (r'(?:called|known as|named|dubbed)\s+["\']?(\w+)["\']?', 'malware'),
        ]
        
        for pattern, category in malware_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return matches[0]
        
        return None
    
    def extract_from_html(self, html_content: str, source: str,
                         source_url: str, **kwargs) -> List[IOC]:
        """Extract IOCs from HTML content."""
        # Strip HTML tags
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = re.sub(r'\s+', ' ', text)
        return self.extract_all(text, source, source_url, **kwargs)


def hash_ioc(ioc: IOC) -> str:
    """Generate a unique hash for an IOC (for deduplication)."""
    key = f"{ioc.value}:{ioc.ioc_type}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
