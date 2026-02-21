"""AI-Powered Attack Chain Extractor using LLM."""
import re
import json
from typing import Dict, List, Optional
from datetime import datetime


class AttackChainExtractor:
    """Extract attack chains from threat intelligence articles using pattern matching and heuristics."""
    
    # MITRE ATT&CK Kill Chain Phases
    KILL_CHAIN_PHASES = {
        'initial_access': [
            'spearphishing', 'phishing', 'drive-by compromise', 'supply chain',
            'trusted relationship', 'valid accounts', 'external remote services',
            'hardware additions', 'replication through removable media'
        ],
        'execution': [
            'command and script interpreter', 'powershell', 'cmd', 'bash',
            'scheduled task', 'cron', 'system services', 'container',
            'user execution', 'malicious file', 'scripting'
        ],
        'persistence': [
            'registry run keys', 'startup folder', 'scheduled task', 'launchd',
            'login hook', 'network logon script', 'bootkit', 'browser extensions',
            'create account', 'domain policy modification'
        ],
        'privilege_escalation': [
            'access token manipulation', 'bypass user account control', 'sudo',
            'exploit privilege escalation', 'process injection', 'dll side-loading'
        ],
        'defense_evasion': [
            'obfuscated files', 'timestomp', 'indicator removal', 'masquerading',
            'disable security tools', 'impair defenses', 'signed binary proxy execution'
        ],
        'credential_access': [
            'os credential dumping', 'lsass memory', 'keylogging', 'credentials from web browsers',
            'unsecured credentials', 'brute force', 'password spraying'
        ],
        'discovery': [
            'system information discovery', 'network service scanning', 'account discovery',
            'file and directory discovery', 'software discovery', 'cloud infrastructure discovery'
        ],
        'lateral_movement': [
            'remote services', 'rdp', 'ssh', 'smb', 'winrm', 'internal spearphishing',
            'lateral tool transfer', 'exploit remote services'
        ],
        'collection': [
            'data from local system', 'clipboard data', 'input capture', 'screen capture',
            'data from network shared drive', 'email collection', 'archive collected data'
        ],
        'command_control': [
            'application layer protocol', 'web service', 'dns', 'encrypted channel',
            'fallback channels', 'ingress tool transfer', 'proxy'
        ],
        'exfiltration': [
            'exfiltration over c2 channel', 'exfiltration over web service',
            'exfiltration over alternative protocol', 'automated exfiltration',
            'transfer data to cloud account'
        ],
        'impact': [
            'data encrypted', 'data destroyed', 'disk structure wipe', 'endpoint denial of service',
            'defacement', 'resource hijacking', 'ransomware'
        ]
    }
    
    # TTP patterns for extraction
    TTP_PATTERNS = {
        'T1566': ['phishing', 'spearphishing', 'phishing attachment', 'phishing link'],
        'T1059': ['command', 'script', 'powershell', 'cmd', 'bash', 'vbs', 'javascript'],
        'T1053': ['scheduled task', 'cron', 'at', 'systemd timer'],
        'T1547': ['registry run', 'startup folder', 'launch agent', 'login hook'],
        'T1078': ['valid accounts', 'default accounts', 'local accounts', 'cloud accounts'],
        'T1003': ['credential dumping', 'lsass', 'ntds', 'sam', 'keychain'],
        'T1021': ['remote services', 'rdp', 'ssh', 'smb', 'winrm', 'telnet'],
        'T1071': ['application layer protocol', 'web protocols', 'dns', 'smtp'],
        'T1568': ['dynamic resolution', 'fast flux', 'domain generation algorithms'],
        'T1041': ['exfiltration over c2', 'data exfiltration'],
        'T1486': ['data encrypted', 'ransomware', 'encrypt files'],
        'T1485': ['data destroyed', 'disk wipe', 'file deletion'],
        'T1055': ['process injection', 'dll injection', 'code injection'],
        'T1190': ['exploit public-facing application', 'vulnerability exploitation'],
        'T1133': ['external remote services', 'vpn', 'citrix', 'rdp gateway'],
        'T1195': ['supply chain compromise', 'supply chain'],
        'T1090': ['proxy', 'tunnel', 'multihop proxy', 'tor'],
        'T1048': ['exfiltration over alternative protocol'],
        'T1567': ['exfiltration over web service'],
        'T1046': ['network service scanning', 'port scan'],
        'T1082': ['system information discovery'],
        'T1083': ['file and directory discovery'],
        'T1070': ['indicator removal', 'clear logs', 'delete files'],
        'T1027': ['obfuscated files', 'encrypted payload', 'packed'],
        'T1036': ['masquerading', 'fake name', 'impersonation'],
        'T1562': ['disable security tools', 'impair defenses', 'disable antivirus'],
        'T1574': ['dll side-loading', 'dll hijacking'],
        'T1543': ['create service', 'systemd', 'launchd'],
        'T1548': ['bypass uac', 'sudo', 'setuid'],
        'T1110': ['brute force', 'password spraying', 'credential stuffing'],
        'T1114': ['email collection', 'mailbox rules'],
        'T1113': ['screen capture', 'screenshot'],
        'T1119': ['automated collection'],
        'T1560': ['archive collected data', 'zip', 'rar', '7z'],
        'T1572': ['protocol tunneling', 'reverse tunnel'],
        'T1573': ['encrypted channel', 'ssl/tls'],
        'T1583': ['acquire infrastructure', 'domains', 'server'],
        'T1584': ['compromise infrastructure'],
    }
    
    # Malware family patterns
    MALWARE_PATTERNS = [
        r'(\w+[-_]?ransomware)',
        r'(\w+[-_]?trojan)',
        r'(\w+[-_]?backdoor)',
        r'(\w+[-_]?rat)',
        r'(\w+[-_]?stealer)',
        r'(\w+[-_]?loader)',
        r'(\w+[-_]?dropper)',
        r'(\w+[-_]?rootkit)',
        r'(\w+[-_]?botnet)',
        r'(?:malware|tool|payload|implant)[:\s]+["\']?(\w+)["\']?',
    ]
    
    def __init__(self):
        self.compiled_ttp_patterns = {
            ttp_id: [re.compile(p, re.IGNORECASE) for p in patterns]
            for ttp_id, patterns in self.TTP_PATTERNS.items()
        }
    
    def extract_attack_chain(self, title: str, content: str, source: str) -> Dict:
        """Extract complete attack chain from article content."""
        full_text = f"{title} {content}"
        
        # Extract kill chain phases
        chain_data = {}
        for phase, keywords in self.KILL_CHAIN_PHASES.items():
            phase_content = self._extract_phase_content(full_text, phase, keywords)
            if phase_content:
                chain_data[phase] = phase_content
        
        # Extract MITRE ATT&CK techniques
        techniques = self._extract_techniques(full_text)
        
        # Extract malware families
        malware_families = self._extract_malware_families(full_text)
        
        # Extract threat actors
        threat_actors = self._extract_threat_actors(full_text)
        
        # Extract campaign name
        campaign_name = self._extract_campaign_name(title, content)
        
        # Build structured attack chain
        attack_chain = {
            'campaign_name': campaign_name,
            'source': source,
            'chain_data': chain_data,
            'mitre_techniques': techniques,
            'malware_families': malware_families,
            'threat_actors': threat_actors,
            'extracted_at': datetime.now().isoformat()
        }
        
        return attack_chain
    
    def _extract_phase_content(self, text: str, phase: str, keywords: List[str]) -> str:
        """Extract content related to a specific kill chain phase."""
        matches = []
        for keyword in keywords:
            # Find sentences containing the keyword
            pattern = rf'[^.!?]*{keyword}[^.!?]*[.!?]'
            found = re.findall(pattern, text, re.IGNORECASE)
            matches.extend(found)
        
        if matches:
            # Return unique matches, limited to 500 chars
            unique = list(set(matches))[:3]
            content = ' '.join(unique)
            return content[:500] if len(content) > 500 else content
        
        return None
    
    def _extract_techniques(self, text: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from text."""
        techniques = set()
        
        # Direct T-code matching
        t_pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
        direct_matches = re.findall(t_pattern, text, re.IGNORECASE)
        techniques.update(direct_matches)
        
        # Pattern-based technique detection
        for ttp_id, patterns in self.compiled_ttp_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    techniques.add(ttp_id)
                    break
        
        return sorted(list(techniques))
    
    def _extract_malware_families(self, text: str) -> List[str]:
        """Extract malware family names from text."""
        malware = set()
        
        for pattern_str in self.MALWARE_PATTERNS:
            matches = re.findall(pattern_str, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[-1]  # Get last group if multiple
                malware.add(match.strip())
        
        # Filter out common false positives
        false_positives = {'malware', 'tool', 'payload', 'implant', 'the', 'and', 'with'}
        malware = {m for m in malware if m.lower() not in false_positives and len(m) > 2}
        
        return sorted(list(malware))
    
    def _extract_threat_actors(self, text: str) -> List[str]:
        """Extract threat actor names from text."""
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
            r'Bronze\s*\w+',
            r'Vanguard\s*Panda',
            r'Hidden\s*Cobra',
            r'Sofacy',
            r'Pawn\s*Storm',
            r'Barium',
            r'Winnti',
            r'Double\s*Dragon',
            r'BlackEnergy',
            r'Voodoo\s*Bear',
        ]
        
        actors = set()
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] or match[1] if len(match) > 1 else match[0]
                actors.add(match.strip())
        
        return sorted(list(actors))
    
    def _extract_campaign_name(self, title: str, content: str) -> str:
        """Extract or generate campaign name."""
        # Look for operation/campaign names
        patterns = [
            r'[Oo]peration\s+["\']?(\w+(?:\s+\w+)?)["\']?',
            r'[Cc]ampaign\s+["\']?(\w+(?:\s+\w+)?)["\']?',
            r'["\'](\w+[-_]?(?:storm|blizzard|typhoon|bear|panda|cobra))["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, f"{title} {content}")
            if match:
                return match.group(1)
        
        # Generate name from first few words of title
        words = title.split()[:4]
        return ' '.join(words) if words else 'Unknown Campaign'
    
    def generate_mitre_navigator_layer(self, techniques: List[str]) -> Dict:
        """Generate MITRE ATT&CK Navigator layer JSON."""
        layer = {
            "name": "Attack Chain Techniques",
            "versions": {
                "attack": "14",
                "navigator": "4.8.2",
                "layer": "4.4"
            },
            "domain": "mitre-attack",
            "description": "Techniques extracted from threat intelligence",
            "filters": {
                "platforms": ["Windows", "macOS", "Linux", "Azure AD", "Office 365", "SaaS", "IaaS", "Google Workspace", "Containers"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#202020",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }
        
        for technique in techniques:
            technique_id = technique.split('.')[0] if '.' in technique else technique
            layer["techniques"].append({
                "techniqueID": technique_id,
                "tactic": None,
                "color": "#ff6666",
                "comment": f"Detected in campaign",
                "enabled": True
            })
        
        return layer
    
    def generate_summary(self, attack_chain: Dict) -> str:
        """Generate human-readable summary of attack chain."""
        summary_parts = []
        
        # Campaign info
        if attack_chain.get('campaign_name'):
            summary_parts.append(f"**Campaign:** {attack_chain['campaign_name']}")
        
        # Threat actors
        if attack_chain.get('threat_actors'):
            actors = ', '.join(attack_chain['threat_actors'])
            summary_parts.append(f"**Threat Actors:** {actors}")
        
        # Malware
        if attack_chain.get('malware_families'):
            malware = ', '.join(attack_chain['malware_families'])
            summary_parts.append(f"**Malware:** {malware}")
        
        # Kill chain summary
        chain_data = attack_chain.get('chain_data', {})
        if chain_data:
            phases_active = list(chain_data.keys())
            summary_parts.append(f"**Kill Chain Phases:** {len(phases_active)} phases detected")
        
        # Techniques
        techniques = attack_chain.get('mitre_techniques', [])
        if techniques:
            summary_parts.append(f"**MITRE ATT&CK Techniques:** {len(techniques)} techniques identified")
        
        return '\n'.join(summary_parts)
