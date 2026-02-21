"""IOC Enrichment - Query external APIs for additional context."""
import requests
import hashlib
from typing import Dict, List, Optional
from datetime import datetime


class IOCEnricher:
    """Enrich IOCs with data from external APIs."""
    
    def __init__(self, vt_api_key: str = None, use_free_apis: bool = True):
        """
        Initialize enricher.
        
        Args:
            vt_api_key: VirusTotal API key (optional, free tier: 4/min, 500/day)
            use_free_apis: Use free APIs (Abuse.ch, Google Safe Browsing, etc.)
        """
        self.vt_api_key = vt_api_key
        self.use_free_apis = use_free_apis
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntel Hub IOC Enricher'
        })
    
    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Enrich a single IOC with all available sources.
        
        Returns dict with enrichment data.
        """
        result = {
            'value': ioc_value,
            'type': ioc_type,
            'enriched_at': datetime.now().isoformat(),
            'virustotal': None,
            'abuse_ch': None,
            'google_safe_browsing': None,
            'urlhaus': None,
            'threatfox': None,
        }
        
        # VirusTotal enrichment
        if self.vt_api_key:
            result['virustotal'] = self._query_virustotal(ioc_value, ioc_type)
        
        # Abuse.ch enrichment (free, no API key needed)
        if self.use_free_apis:
            if ioc_type in ['ip_address', 'domain']:
                result['abuse_ch'] = self._query_abuse_ch(ioc_value, ioc_type)
            
            if ioc_type == 'url':
                result['urlhaus'] = self._query_urlhaus(ioc_value)
            
            if ioc_type in ['md5', 'sha1', 'sha256']:
                result['threatfox'] = self._query_threatfox(ioc_value)
        
        return result
    
    def _query_virustotal(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Query VirusTotal API."""
        if not self.vt_api_key:
            return None
        
        try:
            # Determine endpoint based on type
            if ioc_type in ['md5', 'sha1', 'sha256']:
                endpoint = f"files/{value}"
            elif ioc_type == 'ip_address':
                endpoint = f"ip_addresses/{value}"
            elif ioc_type == 'domain':
                endpoint = f"domains/{value}"
            elif ioc_type == 'url':
                # URL requires POST with encoded URL
                return self._vt_url_scan(value)
            else:
                return None
            
            url = f"https://www.virustotal.com/api/v3/{endpoint}"
            headers = {
                'x-apikey': self.vt_api_key,
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get('data', {}).get('attributes', {})
                
                return {
                    'detection_ratio': self._get_vt_detection_ratio(attrs),
                    'reputation': attrs.get('reputation', 0),
                    'last_analysis_date': attrs.get('last_analysis_date'),
                    'tags': attrs.get('tags', []),
                    'permalink': f"https://www.virustotal.com/gui/{self._vt_type(ioc_type)}/{value}",
                    'total_votes': attrs.get('total_votes', {}),
                    'whois': attrs.get('whois'),
                }
            elif response.status_code == 404:
                return {'not_found': True}
            else:
                return {'error': f"Status {response.status_code}"}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _vt_url_scan(self, url: str) -> Optional[Dict]:
        """Scan URL with VirusTotal (requires POST)."""
        try:
            # First, submit URL for analysis
            submit_url = "https://www.virustotal.com/api/v3/urls"
            headers = {
                'x-apikey': self.vt_api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # URL needs to be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            data = {'url': url}
            response = self.session.post(submit_url, headers=headers, data=data, timeout=30)
            
            if response.status_code in [200, 201]:
                # Get analysis
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
                analysis_response = self.session.get(analysis_url, headers=headers, timeout=30)
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                    
                    return {
                        'detection_ratio': self._get_vt_detection_ratio(stats),
                        'permalink': f"https://www.virustotal.com/gui/url/{url_id}",
                    }
            
            return None
        except Exception as e:
            return {'error': str(e)}
    
    def _get_vt_detection_ratio(self, attrs: Dict) -> str:
        """Get detection ratio from VT attributes."""
        stats = attrs.get('last_analysis_stats', {})
        if not stats:
            stats = attrs  # Fallback for different response formats
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum([
            stats.get('malicious', 0),
            stats.get('suspicious', 0),
            stats.get('undetected', 0),
            stats.get('harmless', 0),
            stats.get('timeout', 0),
        ])
        
        if total > 0:
            return f"{malicious + suspicious}/{total}"
        return "0/0"
    
    def _vt_type(self, ioc_type: str) -> str:
        """Map IOC type to VT URL type."""
        mapping = {
            'ip_address': 'ip',
            'domain': 'domain',
            'url': 'url',
            'md5': 'file',
            'sha1': 'file',
            'sha256': 'file',
        }
        return mapping.get(ioc_type, ioc_type)
    
    def _query_abuse_ch(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Query Abuse.ch blocklists."""
        try:
            if ioc_type == 'ip_address':
                return self._query_abuse_ch_ip(value)
            elif ioc_type == 'domain':
                return self._query_abuse_ch_domain(value)
            return None
        except Exception as e:
            return {'error': str(e)}
    
    def _query_abuse_ch_ip(self, ip: str) -> Optional[Dict]:
        """Query Abuse.ch for IP reputation."""
        try:
            # Check against Feodo Tracker
            response = self.session.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                timeout=30
            )
            
            if response.status_code == 200:
                blocklist = response.text.split('\n')
                if ip in blocklist:
                    return {
                        'listed': True,
                        'source': 'Feodo Tracker',
                        'type': 'C2 Server',
                        'blocklist_url': 'https://feodotracker.abuse.ch/'
                    }
            
            # Check against SSL Blacklist
            response = self.session.get(
                "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
                timeout=30
            )
            
            if response.status_code == 200:
                blocklist = response.text.split('\n')
                if ip in blocklist:
                    return {
                        'listed': True,
                        'source': 'SSL Blacklist',
                        'type': 'Malicious SSL Certificate',
                        'blocklist_url': 'https://sslbl.abuse.ch/'
                    }
            
            return {'listed': False}
        except Exception as e:
            return {'error': str(e)}
    
    def _query_abuse_ch_domain(self, domain: str) -> Optional[Dict]:
        """Query Abuse.ch for domain reputation."""
        try:
            # Check against URLhaus
            response = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={'host': domain},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('urls'):
                    return {
                        'listed': True,
                        'source': 'URLhaus',
                        'url_count': len(data['urls']),
                        'threat_type': data['urls'][0].get('threat'),
                        'blocklist_url': f"https://urlhaus.abuse.ch/host/{domain}/"
                    }
            
            return {'listed': False}
        except Exception as e:
            return {'error': str(e)}
    
    def _query_urlhaus(self, url: str) -> Optional[Dict]:
        """Query URLhaus for URL reputation."""
        try:
            response = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={'url': url},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'listed': True,
                        'id': data.get('id'),
                        'threat': data.get('threat'),
                        'tags': data.get('tags', []),
                        'firstseen': data.get('firstseen'),
                        'blocklist_url': f"https://urlhaus.abuse.ch/url/{data.get('id')}/"
                    }
            
            return {'listed': False}
        except Exception as e:
            return {'error': str(e)}
    
    def _query_threatfox(self, hash_value: str) -> Optional[Dict]:
        """Query ThreatFox for malware hash."""
        try:
            response = self.session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={'query': 'get_info', 'ioc': hash_value},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    result = data.get('data', {})
                    return {
                        'listed': True,
                        'id': result.get('id'),
                        'malware': result.get('malware'),
                        'malware_printable': result.get('malware_printable'),
                        'first_seen': result.get('first_seen'),
                        'tags': result.get('tags', []),
                        'reporter': result.get('reporter'),
                        'blocklist_url': f"https://threatfox.abuse.ch/ioc/{result.get('id')}/"
                    }
            
            return {'listed': False}
        except Exception as e:
            return {'error': str(e)}
    
    def bulk_enrich(self, iocs: List[Dict], delay: float = 0.5) -> List[Dict]:
        """
        Enrich multiple IOCs with rate limiting.
        
        Args:
            iocs: List of IOC dicts with 'value' and 'ioc_type'
            delay: Delay between API calls (seconds)
        
        Returns:
            List of enriched IOC dicts
        """
        import time
        
        enriched = []
        for ioc in iocs:
            result = self.enrich_ioc(ioc['value'], ioc['ioc_type'])
            enriched.append(result)
            time.sleep(delay)  # Rate limiting
        
        return enriched


def enrich_database_iocs(db, limit: int = 100, vt_api_key: str = None):
    """
    Enrich IOCs in database and update with results.
    
    Args:
        db: ThreatIntelDB instance
        limit: Number of IOCs to enrich
        vt_api_key: Optional VirusTotal API key
    """
    enricher = IOCEnricher(vt_api_key=vt_api_key)
    
    # Get IOCs that haven't been enriched yet
    iocs = db.get_iocs(limit=limit)
    
    enriched_count = 0
    for ioc in iocs:
        print(f"Enriching: {ioc['value']} ({ioc['ioc_type']})")
        
        result = enricher.enrich_ioc(ioc['value'], ioc['ioc_type'])
        
        # Update database with enrichment results
        vt_data = result.get('virustotal')
        if vt_data and not vt_data.get('error'):
            db.conn = sqlite3.connect(db.db_path)
            cursor = db.conn.cursor()
            
            cursor.execute('''
                UPDATE iocs SET 
                    vt_permalink = ?,
                    vt_detection = ?
                WHERE value = ? AND ioc_type = ?
            ''', (
                vt_data.get('permalink'),
                vt_data.get('detection_ratio'),
                ioc['value'],
                ioc['ioc_type']
            ))
            
            db.conn.commit()
            db.conn.close()
            enriched_count += 1
        
        abuse_ch_data = result.get('abuse_ch')
        if abuse_ch_data and abuse_ch_data.get('listed'):
            db.conn = sqlite3.connect(db.db_path)
            cursor = db.conn.cursor()
            
            cursor.execute('''
                UPDATE iocs SET 
                    abuse_ch_malware = ?
                WHERE value = ? AND ioc_type = ?
            ''', (
                abuse_ch_data.get('source'),
                ioc['value'],
                ioc['ioc_type']
            ))
            
            db.conn.commit()
            db.conn.close()
    
    print(f"Enriched {enriched_count} IOCs")
    return enriched_count


# Import for database operations
import sqlite3
