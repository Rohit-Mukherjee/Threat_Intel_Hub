"""Threat Intelligence Collectors - Free Sources."""
import feedparser
import requests
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json
import sys
from pathlib import Path

# Import IOC extractor
sys.path.insert(0, str(Path(__file__).parent.parent))
from ioc_extractor import IOCExtractor
from attack_chain_extractor import AttackChainExtractor


class TwitterCollector:
    """Collect threat intel from Twitter/X via Nitter RSS (no API key needed)."""
    
    # Security researchers and orgs to track on Twitter
    # Using Nitter RSS feeds (privacy-focused Twitter frontend)
    TWITTER_ACCOUNTS = {
        'TheDFIRReport': 'https://nitter.privacydev.net/TheDFIRReport/rss',
        'malwrhunterteam': 'https://nitter.privacydev.net/malwrhunterteam/rss',
        'IntelFlock': 'https://nitter.privacydev.net/IntelFlock/rss',
        'mandiant': 'https://nitter.privacydev.net/mandiant/rss',
        'MSFTSecIntel': 'https://nitter.privacydev.net/MSFTSecIntel/rss',
        'CISAgov': 'https://nitter.privacydev.net/CISAgov/rss',
        'FBI': 'https://nitter.privacydev.net/FBI/rss',
        'NCSC': 'https://nitter.privacydev.net/NCSC/rss',
        'Unit42': 'https://nitter.privacydev.net/Unit42/rss',
        'CrowdStrike': 'https://nitter.privacydev.net/CrowdStrike/rss',
        'SecureList': 'https://nitter.privacydev.net/SecureList/rss',
        'Threatpost': 'https://nitter.privacydev.net/Threatpost/rss',
        'hacker_news': 'https://nitter.privacydev.net/hacker_news/rss',
        'bleepincomputer': 'https://nitter.privacydev.net/bleepincomputer/rss',
        'VirusTotal': 'https://nitter.privacydev.net/VirusTotal/rss',
        'Abuse_CH': 'https://nitter.privacydev.net/Abuse_CH/rss',
        'malware_traffic': 'https://nitter.privacydev.net/malware_traffic/rss',
        '1ZRR4H': 'https://nitter.privacydev.net/1ZRR4H/rss',
        'c3rb3ru5d3d53c': 'https://nitter.privacydev.net/c3rb3ru5d3d53c/rss',
        'vxunderground': 'https://nitter.privacydev.net/vxunderground/rss',
    }
    
    # Alternative Nitter instances (fallback)
    NITTER_INSTANCES = [
        'https://nitter.privacydev.net',
        'https://nitter.net',
        'https://nitter.lunar.icu',
        'https://nitter.dark.fail',
    ]
    
    def __init__(self, db):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (ThreatIntel Bot)'
        })
        self.ioc_extractor = IOCExtractor()
    
    def collect_tweets(self, accounts=None, limit_per_account=10):
        """Collect tweets from tracked threat intel accounts."""
        accounts = accounts or self.TWITTER_ACCOUNTS
        total_collected = 0
        
        for account_name, rss_url in accounts.items():
            try:
                count = self._collect_account(account_name, rss_url, limit_per_account)
                if count > 0:
                    total_collected += count
                    print(f"✓ Twitter/{account_name}: {count} tweets")
            except Exception as e:
                # Try fallback instances
                for instance in self.NITTER_INSTANCES[1:3]:
                    try:
                        fallback_url = rss_url.replace('nitter.privacydev.net', instance)
                        count = self._collect_account(account_name, fallback_url, limit_per_account)
                        if count > 0:
                            total_collected += count
                            print(f"✓ Twitter/{account_name} (fallback): {count} tweets")
                        break
                    except:
                        continue
                else:
                    print(f"✗ Twitter/{account_name}: Failed all instances")
        
        return total_collected
    
    def _collect_account(self, account_name, rss_url, limit):
        """Collect from a single Twitter account."""
        response = self.session.get(rss_url, timeout=30)
        response.raise_for_status()
        
        feed = feedparser.parse(response.content)
        count = 0
        
        for entry in feed.entries[:limit]:
            # Parse tweet date
            published = None
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                try:
                    published = datetime(*entry.published_parsed[:6])
                except:
                    pass
            
            # Skip old tweets (older than 7 days)
            if published and published < datetime.now() - timedelta(days=7):
                continue
            
            # Get tweet content
            content = self._get_tweet_content(entry)
            
            # Extract IOCs from tweet
            iocs = self.ioc_extractor.extract_all(
                content=content,
                source=f"Twitter/{account_name}",
                source_url=entry.link,
                threat_actors=[],
                techniques=[],
                tags=['twitter', 'social-media']
            )
            
            # Only store if IOCs found or mentions threat actors
            threat_actors = self._extract_threat_actors(content)
            
            if iocs or threat_actors:
                # Store as intel item
                self.db.add_intel_item(
                    title=entry.title[:200],
                    source=f"Twitter/{account_name}",
                    url=entry.link,
                    summary=content[:500],
                    threat_actors=threat_actors if threat_actors else None,
                    techniques=None,
                    severity='High' if threat_actors else 'Medium',
                    published_at=published.isoformat() if published else None,
                    tags=['twitter', account_name]
                )
                
                # Store IOCs
                for ioc in iocs:
                    self.db.add_ioc(
                        value=ioc.value,
                        ioc_type=ioc.ioc_type,
                        source=ioc.source,
                        source_url=ioc.source_url,
                        confidence=ioc.confidence,
                        first_seen=ioc.first_seen,
                        tags=ioc.tags,
                        context=ioc.context,
                        related_threat_actors=ioc.related_threat_actors,
                        related_techniques=ioc.related_techniques,
                        malware_family=ioc.malware_family
                    )
                
                count += 1
        
        return count
    
    def _get_tweet_content(self, entry) -> str:
        """Extract clean content from tweet entry."""
        content = ""
        if hasattr(entry, 'summary'):
            content = entry.summary
        elif hasattr(entry, 'description'):
            content = entry.description
        
        # Remove HTML tags
        content = re.sub(r'<[^>]+>', ' ', content)
        content = re.sub(r'\s+', ' ', content).strip()
        
        # Remove Twitter-specific artifacts
        content = re.sub(r'pic\.twitter\.com/\w+', '', content)
        content = re.sub(r'https?://t\.co/\w+', '', content)
        
        return content[:1000]  # Tweets are short
    
    def _extract_threat_actors(self, content: str) -> List[str]:
        """Extract threat actor names from tweet content."""
        patterns = [
            r'APT\d+',
            r'Lazarus\s*(Group)?',
            r'Cozy\s*Bear',
            r'Fancy\s*Bear',
            r'Sandworm',
            r'Gamaredon',
            r'GhostWriter',
            r'Sidewinder',
            r'TA\d+',
            r'FIN\d+',
            r'UNC\d+',
            r'Volt\s*Typhoon',
            r'Midnight\s*Blizzard',
            r'Storm-?\d+',
            r'Ransom\s*\w+',
        ]
        
        actors = []
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            actors.extend(matches)
        
        return list(set(actors))


class RSSCollector:
    """Collect threat intel from RSS feeds."""
    
    FEEDS = {
        'The DFIR Report': 'https://thedfirreport.com/feed/',
        'Mandiant': 'https://www.mandiant.com/resources/blog/rss.xml',
        'Microsoft Security': 'https://www.microsoft.com/en-us/security/blog/feed/',
        'CrowdStrike': 'https://www.crowdstrike.com/en-us/blog/feed/',
        'SecureList (Kaspersky)': 'https://securelist.com/feed/',
        'Naked Security': 'https://nakedsecurity.sophos.com/feed/',
        'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
        'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
        'DarkReading': 'https://www.darkreading.com/rss.xml',
        'CISA Alerts': 'https://www.cisa.gov/cybersecurity-advisories.xml',
        'SentinelOne': 'https://www.sentinelone.com/labs/feed/',
        'Unit42 (Palo Alto)': 'https://unit42.paloaltonetworks.com/feed/',
        'Threatpost': 'https://threatpost.com/feed/',
        'SecurityWeek': 'https://www.securityweek.com/feed/',
        'Recorded Future': 'https://www.recordedfuture.com/insights-feed/feed/',
    }
    
    def __init__(self, db):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (ThreatIntel Bot)'
        })
        self.ioc_extractor = IOCExtractor()
        self.chain_extractor = AttackChainExtractor()

    def collect_all(self, days_back: int = 7):
        """Collect from all RSS feeds."""
        cutoff = datetime.now() - timedelta(days=days_back)
        total_collected = 0
        
        for source, url in self.FEEDS.items():
            try:
                count = self._collect_feed(source, url, cutoff)
                total_collected += count
                print(f"✓ {source}: {count} items")
            except Exception as e:
                print(f"✗ {source}: {str(e)}")
        
        return total_collected
    
    def _collect_feed(self, source: str, url: str, cutoff: datetime) -> int:
        """Collect from a single RSS feed."""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise Exception(f"Failed to fetch feed: {e}")
        
        feed = feedparser.parse(response.content)
        count = 0
        
        for entry in feed.entries:
            # Parse published date
            published = None
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                try:
                    published = datetime(*entry.published_parsed[:6])
                except (TypeError, ValueError):
                    pass
            
            # Skip old entries
            if published and published < cutoff:
                continue
            
            # Extract threat actors and techniques from content
            content = self._get_entry_content(entry)
            threat_actors = self._extract_threat_actors(content)
            techniques = self._extract_techniques(content)
            severity = self._assess_severity(entry.title, content)
            tags = self._extract_tags(entry)
            
            self.db.add_intel_item(
                title=entry.title,
                source=source,
                url=entry.link,
                summary=self._clean_summary(entry),
                threat_actors=threat_actors if threat_actors else None,
                techniques=techniques if techniques else None,
                severity=severity,
                published_at=published.isoformat() if published else None,
                tags=tags
            )
            
            # Extract and store IOCs from content
            iocs = self.ioc_extractor.extract_all(
                content=content,
                source=source,
                source_url=entry.link,
                threat_actors=threat_actors,
                techniques=techniques,
                tags=tags
            )
            for ioc in iocs:
                self.db.add_ioc(
                    value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source=ioc.source,
                    source_url=ioc.source_url,
                    confidence=ioc.confidence,
                    first_seen=ioc.first_seen,
                    tags=ioc.tags,
                    context=ioc.context,
                    related_threat_actors=ioc.related_threat_actors,
                    related_techniques=ioc.related_techniques,
                    malware_family=ioc.malware_family
                )
            
            # Extract attack chain using AI
            attack_chain = self.chain_extractor.extract_attack_chain(
                title=entry.title,
                content=content,
                source=source
            )
            
            # Store attack chain if we found meaningful data
            if attack_chain.get('chain_data') or attack_chain.get('mitre_techniques'):
                self.db.add_attack_chain(
                    campaign_name=attack_chain.get('campaign_name', entry.title[:50]),
                    source=source,
                    url=entry.link,
                    chain_data=attack_chain.get('chain_data', {}),
                    mitre_techniques=attack_chain.get('mitre_techniques', []),
                    published_at=published.isoformat() if published else None
                )
            
            count += 1
        
        return count
    
    def _get_entry_content(self, entry) -> str:
        """Get content from entry."""
        content = ""
        if hasattr(entry, 'summary'):
            content += entry.summary + " "
        if hasattr(entry, 'description'):
            content += entry.description + " "
        if hasattr(entry, 'content') and entry.content:
            content += entry.content[0].get('value', '')
        return content
    
    def _extract_threat_actors(self, content: str) -> List[str]:
        """Extract threat actor names from content."""
        # Common threat actor patterns
        patterns = [
            r'APT\d+',
            r'APT-[A-Z]',
            r'Lazarus\s*(Group)?',
            r'Cozy\s*Bear',
            r'Fancy\s*Bear',
            r'Sandworm',
            r'Gamaredon',
            r'GhostWriter',
            r'Sidewinder',
            r'TA\d+',
            r'FIN\d+',
            r'UNC\d+',
            r'DPRK',
            r'Volt\s*Typhoon',
            r'Midnight\s*Blizzard',
            r'Storm-?\d+',
        ]
        
        actors = []
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            actors.extend(matches)
        
        return list(set(actors))
    
    def _extract_techniques(self, content: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs."""
        # Match T-codes like T1059, T1566.001
        pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
        matches = re.findall(pattern, content, re.IGNORECASE)
        return list(set(matches))
    
    def _assess_severity(self, title: str, content: str) -> str:
        """Assess severity based on keywords."""
        title_lower = title.lower()
        content_lower = content.lower()
        
        critical_keywords = ['ransomware', 'zero-day', 'critical', 'apt', 'nation-state',
                           'breach', 'compromise', 'exploit', 'weaponized']
        high_keywords = ['malware', 'trojan', 'backdoor', 'c2', 'c&c', 'exfiltration',
                        'lateral movement', 'persistence', 'credential theft']
        medium_keywords = ['vulnerability', 'CVE', 'patch', 'advisory', 'threat',
                          'campaign', 'phishing']
        
        for kw in critical_keywords:
            if kw in title_lower or kw in content_lower[:500]:
                return 'Critical'
        
        for kw in high_keywords:
            if kw in title_lower or kw in content_lower[:500]:
                return 'High'
        
        for kw in medium_keywords:
            if kw in title_lower or kw in content_lower[:500]:
                return 'Medium'
        
        return 'Low'
    
    def _extract_tags(self, entry) -> List[str]:
        """Extract tags/categories from entry."""
        tags = []
        if hasattr(entry, 'tags'):
            for tag in entry.tags:
                if hasattr(tag, 'term'):
                    tags.append(tag.term)
        return tags[:5]  # Limit to 5 tags
    
    def _clean_summary(self, entry) -> str:
        """Clean and truncate summary."""
        summary = ""
        if hasattr(entry, 'summary'):
            summary = entry.summary
        elif hasattr(entry, 'description'):
            summary = entry.description
        
        # Remove HTML tags
        summary = re.sub(r'<[^>]+>', '', summary)
        summary = re.sub(r'\s+', ' ', summary).strip()
        
        # Truncate if too long
        if len(summary) > 500:
            summary = summary[:497] + "..."
        
        return summary


class GitHubCollector:
    """Collect from GitHub threat intel repositories."""
    
    REPOS = {
        'sigma_rules': 'https://api.github.com/repos/SigmaHQ/sigma/contents/rules',
        'detection_rules': 'https://api.github.com/repos/elastic/detection-rules/contents/rules',
        'threat_intel': 'https://api.github.com/repos/mthcht/awesome-threat-intelligence/contents',
        'malware_iocs': 'https://api.github.com/repos/eset/malware-ioc/contents',
    }
    
    def __init__(self, db):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntel Bot',
            'Accept': 'application/vnd.github.v3+json'
        })
    
    def collect_latest(self) -> int:
        """Collect latest detection rules and intel."""
        count = 0
        
        # Collect from malware IOC repos
        count += self._collect_eset_iocs()
        
        return count
    
    def _collect_eset_iocs(self) -> int:
        """Collect ESET malware IOCs."""
        try:
            response = self.session.get(
                'https://api.github.com/repos/eset/malware-ioc/contents',
                timeout=30
            )
            response.raise_for_status()
            
            files = response.json()
            count = 0
            
            for file in files[:10]:  # Limit to 10 latest
                if file.get('type') == 'file' and file.get('name', '').endswith('.md'):
                    self.db.add_intel_item(
                        title=f"ESET IOC: {file['name'].replace('.md', '')}",
                        source="ESET GitHub",
                        url=file.get('html_url', ''),
                        summary=f"IOC indicators for {file['name'].replace('.md', '')}",
                        tags=['IOC', 'malware', 'ESET'],
                        severity='High'
                    )
                    count += 1
            
            return count
        except Exception as e:
            print(f"ESET IOC collection error: {e}")
            return 0


class CISACollector:
    """Collect CISA alerts and advisories."""
    
    def __init__(self, db):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntel Bot'
        })
    
    def collect_alerts(self, days_back: int = 7) -> int:
        """Collect CISA cybersecurity advisories."""
        try:
            # CISA API for known exploited vulnerabilities
            response = self.session.get(
                'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            cutoff = datetime.now() - timedelta(days=days_back)
            count = 0
            
            for vuln in data.get('vulnerabilities', []):
                try:
                    due_date = datetime.strptime(vuln.get('dueDate', ''), '%Y-%m-%d')
                except ValueError:
                    due_date = datetime.now()
                
                if due_date >= cutoff:
                    self.db.add_intel_item(
                        title=f"CISA KEV: {vuln.get('cveID', 'Unknown')}",
                        source="CISA",
                        url=vuln.get('url', ''),
                        summary=vuln.get('shortDescription', ''),
                        threat_actors=[],
                        severity='Critical' if vuln.get('cwss', 0) > 9 else 'High',
                        published_at=vuln.get('dateAdded', ''),
                        tags=['KEV', 'CVE', vuln.get('cveID', '')]
                    )
                    count += 1
            
            return count
        except Exception as e:
            print(f"CISA collection error: {e}")
            return 0


class ThreatActorCollector:
    """Collect threat actor profiles."""
    
    # Known threat actor data (curated)
    ACTORS = {
        'APT29': {
            'aliases': ['Cozy Bear', 'The Dukes', 'NOBELIUM'],
            'origin': 'Russia',
            'motivation': 'Espionage',
            'targets': ['Government', 'Think Tanks', 'Healthcare', 'Technology'],
            'tools': ['WellMess', 'WellMail', 'SUNBURST', 'TEARDROP'],
            'techniques': ['T1566', 'T1059', 'T1078', 'T1071']
        },
        'APT28': {
            'aliases': ['Fancy Bear', 'Sofacy', 'Pawn Storm'],
            'origin': 'Russia',
            'motivation': 'Espionage',
            'targets': ['Government', 'Military', 'NATO'],
            'tools': ['XAgent', 'X-Tunnel', 'Zebrocy'],
            'techniques': ['T1566', 'T1204', 'T1055', 'T1003']
        },
        'Lazarus Group': {
            'aliases': ['APT38', 'Hidden Cobra', 'Guardians of Peace'],
            'origin': 'North Korea',
            'motivation': 'Financial, Espionage',
            'targets': ['Financial', 'Cryptocurrency', 'Entertainment'],
            'tools': ['BLINDINGCAN', 'COPPERHEDGE', 'FALLCHILL'],
            'techniques': ['T1566', 'T1059', 'T1486', 'T1565']
        },
        'APT41': {
            'aliases': ['Barium', 'Winnti', 'Double Dragon'],
            'origin': 'China',
            'motivation': 'Espionage, Financial',
            'targets': ['Healthcare', 'Telecom', 'Gaming'],
            'tools': ['POISONPLUG', 'HIGHNOON', 'DEADEYE'],
            'techniques': ['T1190', 'T1059', 'T1027', 'T1070']
        },
        'Sandworm': {
            'aliases': ['APT44', 'BlackEnergy', 'Voodoo Bear'],
            'origin': 'Russia',
            'motivation': 'Destruction, Espionage',
            'targets': ['Energy', 'Government', 'Critical Infrastructure'],
            'tools': ['BlackEnergy', 'Industroyer', 'NotPetya', 'GreyEnergy'],
            'techniques': ['T1190', 'T1059', 'T1485', 'T1565']
        },
        'Volt Typhoon': {
            'aliases': ['Vanguard Panda', 'Bronze Silhouette'],
            'origin': 'China',
            'motivation': 'Espionage',
            'targets': ['Critical Infrastructure', 'Telecom', 'Transportation'],
            'tools': ['Living off the Land', 'SOCKS5 Proxy'],
            'techniques': ['T1078', 'T1059', 'T1071', 'T1572']
        },
    }
    
    def __init__(self, db):
        self.db = db
    
    def collect_all(self):
        """Add all known threat actors to database."""
        for name, data in self.ACTORS.items():
            self.db.add_threat_actor(
                name=name,
                **data
            )


class MalpediaCollector:
    """Collect malware family data from Malpedia."""
    
    def __init__(self, db):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntel Bot'
        })
    
    def collect_families(self, limit=50):
        """Collect latest malware families from Malpedia API."""
        try:
            # Malpedia public API
            response = self.session.get(
                'https://malpedia.caad.fkie.fraunhofer.de/api/get/families',
                timeout=30
            )
            
            if response.status_code == 200:
                families = response.json()
                count = 0
                
                for family_id, family_data in list(families.items())[:limit]:
                    # Add as intel item
                    self.db.add_intel_item(
                        title=f"Malware Family: {family_data.get('common_name', family_id)}",
                        source="Malpedia",
                        url=f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_id}",
                        summary=f"Malware family tracked by Malpedia. {family_data.get('description', '')[:200]}",
                        threat_actors=family_data.get('attributions', []),
                        tags=['malware', 'family', family_id],
                        severity='High'
                    )
                    count += 1
                
                return count
        except Exception as e:
            print(f"Malpedia collection error: {e}")
        return 0


def run_collection(db, days_back: int = 7):
    """Run all collectors."""
    print("\n🔍 Starting Threat Intelligence Collection...\n")

    # RSS Collection
    print("📰 Collecting RSS feeds...")
    rss_collector = RSSCollector(db)
    rss_count = rss_collector.collect_all(days_back=days_back)
    print(f"   Total RSS items: {rss_count}")

    # Twitter/X Collection
    print("\n🐦 Collecting Twitter/X threat intel...")
    twitter_collector = TwitterCollector(db)
    twitter_count = twitter_collector.collect_tweets(limit_per_account=5)
    print(f"   Total Twitter items: {twitter_count}")

    # CISA Collection
    print("\n🏛️  Collecting CISA alerts...")
    cisa_collector = CISACollector(db)
    cisa_count = cisa_collector.collect_alerts(days_back=days_back)
    print(f"   Total CISA items: {cisa_count}")

    # Malpedia Collection
    print("\n🦠 Collecting Malpedia malware families...")
    malpedia_collector = MalpediaCollector(db)
    malpedia_count = malpedia_collector.collect_families(limit=50)
    print(f"   Total Malpedia items: {malpedia_count}")

    # GitHub Collection
    print("\n🐙 Collecting GitHub intel...")
    github_collector = GitHubCollector(db)
    github_count = github_collector.collect_latest()
    print(f"   Total GitHub items: {github_count}")

    # Threat Actor Profiles
    print("\n👤 Loading threat actor profiles...")
    actor_collector = ThreatActorCollector(db)
    actor_collector.collect_all()
    print(f"   Loaded {len(ThreatActorCollector.ACTORS)} threat actors")

    total = rss_count + twitter_count + cisa_count + malpedia_count + github_count
    print(f"\n✅ Collection complete! Total new items: {total}")
    
    return total
