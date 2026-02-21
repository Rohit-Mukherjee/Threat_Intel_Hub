"""SQLite database for storing threat intelligence."""
import sqlite3
from datetime import datetime
from pathlib import Path
import json
from typing import List, Dict, Optional


class ThreatIntelDB:
    def __init__(self, db_path: str = "data/threat_intel.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """Initialize database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threat intelligence feed items
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intel_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                url TEXT UNIQUE NOT NULL,
                summary TEXT,
                threat_actors TEXT,
                techniques TEXT,
                severity TEXT,
                published_at TIMESTAMP,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT
            )
        ''')
        
        # Attack chain data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT NOT NULL,
                source TEXT NOT NULL,
                url TEXT UNIQUE NOT NULL,
                initial_access TEXT,
                execution TEXT,
                persistence TEXT,
                privilege_escalation TEXT,
                defense_evasion TEXT,
                credential_access TEXT,
                discovery TEXT,
                lateral_movement TEXT,
                collection TEXT,
                command_control TEXT,
                exfiltration TEXT,
                impact TEXT,
                mitre_techniques TEXT,
                published_at TIMESTAMP,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Threat actors
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                aliases TEXT,
                origin TEXT,
                motivation TEXT,
                targets TEXT,
                tools TEXT,
                techniques TEXT,
                last_seen TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IOC storage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                source_url TEXT,
                confidence TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT,
                context TEXT,
                related_threat_actors TEXT,
                related_techniques TEXT,
                malware_family TEXT,
                times_seen INTEGER DEFAULT 1,
                vt_permalink TEXT,
                vt_detection INTEGER,
                abuse_ch_malware TEXT,
                is_active INTEGER DEFAULT 1,
                UNIQUE(value, ioc_type)
            )
        ''')
        
        # Create index for faster IOC lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)
        ''')
        
        conn.commit()
        conn.close()
    
    def add_intel_item(self, title, source, url, summary=None, 
                       threat_actors=None, techniques=None, severity=None,
                       published_at=None, tags=None):
        """Add a new intelligence item."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO intel_items 
                (title, source, url, summary, threat_actors, techniques, 
                 severity, published_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (title, source, url, summary, 
                  json.dumps(threat_actors) if threat_actors else None,
                  json.dumps(techniques) if techniques else None,
                  severity, published_at, json.dumps(tags) if tags else None))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # URL already exists
        finally:
            conn.close()
    
    def add_attack_chain(self, campaign_name, source, url, chain_data, 
                         mitre_techniques=None, published_at=None):
        """Add attack chain data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO attack_chains 
                (campaign_name, source, url, initial_access, execution,
                 persistence, privilege_escalation, defense_evasion,
                 credential_access, discovery, lateral_movement,
                 collection, command_control, exfiltration, impact,
                 mitre_techniques, published_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (campaign_name, source, url,
                  chain_data.get('initial_access'),
                  chain_data.get('execution'),
                  chain_data.get('persistence'),
                  chain_data.get('privilege_escalation'),
                  chain_data.get('defense_evasion'),
                  chain_data.get('credential_access'),
                  chain_data.get('discovery'),
                  chain_data.get('lateral_movement'),
                  chain_data.get('collection'),
                  chain_data.get('command_control'),
                  chain_data.get('exfiltration'),
                  chain_data.get('impact'),
                  json.dumps(mitre_techniques) if mitre_techniques else None,
                  published_at))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
    
    def add_threat_actor(self, name, aliases=None, origin=None,
                         motivation=None, targets=None, tools=None,
                         techniques=None):
        """Add or update threat actor information."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_actors 
            (name, aliases, origin, motivation, targets, tools, techniques, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, json.dumps(aliases) if aliases else None, origin,
              motivation, json.dumps(targets) if targets else None,
              json.dumps(tools) if tools else None,
              json.dumps(techniques) if techniques else None,
              datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_recent_intel(self, limit=50):
        """Get recent intelligence items."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT title, source, url, summary, threat_actors, techniques,
                   severity, published_at, tags
            FROM intel_items
            ORDER BY published_at DESC NULLS LAST, collected_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'title': r[0], 'source': r[1], 'url': r[2], 'summary': r[3],
            'threat_actors': json.loads(r[4]) if r[4] else None,
            'techniques': json.loads(r[5]) if r[5] else None,
            'severity': r[6], 'published_at': r[7], 'tags': json.loads(r[8]) if r[8] else None
        } for r in rows]
    
    def get_attack_chains(self, limit=20):
        """Get attack chain data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT campaign_name, source, url, initial_access, execution,
                   persistence, defense_evasion, lateral_movement,
                   command_control, exfiltration, mitre_techniques, published_at
            FROM attack_chains
            ORDER BY published_at DESC NULLS LAST, collected_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'campaign_name': r[0], 'source': r[1], 'url': r[2],
            'initial_access': r[3], 'execution': r[4], 'persistence': r[5],
            'defense_evasion': r[6], 'lateral_movement': r[7],
            'command_control': r[8], 'exfiltration': r[9],
            'mitre_techniques': json.loads(r[10]) if r[10] else None,
            'published_at': r[11]
        } for r in rows]
    
    def get_threat_actors(self):
        """Get all threat actors."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT name, aliases, origin, motivation, targets, tools, techniques, last_seen
            FROM threat_actors
            ORDER BY last_seen DESC
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'name': r[0], 'aliases': json.loads(r[1]) if r[1] else None,
            'origin': r[2], 'motivation': r[3],
            'targets': json.loads(r[4]) if r[4] else None,
            'tools': json.loads(r[5]) if r[5] else None,
            'techniques': json.loads(r[6]) if r[6] else None,
            'last_seen': r[7]
        } for r in rows]
    
    def get_stats(self):
        """Get database statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute('SELECT COUNT(*) FROM intel_items')
        stats['intel_items'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM attack_chains')
        stats['attack_chains'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM threat_actors')
        stats['threat_actors'] = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT source, COUNT(*) as count 
            FROM intel_items 
            GROUP BY source 
            ORDER BY count DESC
        ''')
        stats['by_source'] = dict(cursor.fetchall())
        
        conn.close()
        return stats

    def add_ioc(self, value, ioc_type, source, source_url=None,
                confidence=None, first_seen=None, tags=None,
                context=None, related_threat_actors=None,
                related_techniques=None, malware_family=None):
        """Add or update an IOC."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO iocs 
                (value, ioc_type, source, source_url, confidence, first_seen,
                 tags, context, related_threat_actors, related_techniques,
                 malware_family, times_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(value, ioc_type) DO UPDATE SET
                    times_seen = times_seen + 1,
                    last_seen = ?,
                    source = excluded.source
            ''', (value, ioc_type, source, source_url, confidence,
                  first_seen, json.dumps(tags) if tags else None,
                  context, json.dumps(related_threat_actors) if related_threat_actors else None,
                  json.dumps(related_techniques) if related_techniques else None,
                  malware_family, datetime.now().isoformat(),
                  datetime.now().isoformat()))
            conn.commit()
        except Exception as e:
            print(f"Error adding IOC: {e}")
        finally:
            conn.close()
    
    def get_iocs(self, ioc_type=None, confidence=None, limit=500,
                 search_query=None, threat_actor=None):
        """Get IOCs with optional filters."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT value, ioc_type, source, source_url, confidence,
                   first_seen, tags, context, related_threat_actors,
                   related_techniques, malware_family, times_seen,
                   vt_permalink, vt_detection, is_active
            FROM iocs
            WHERE 1=1
        '''
        params = []
        
        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)
        
        if confidence:
            query += " AND confidence = ?"
            params.append(confidence)
        
        if search_query:
            query += " AND (value LIKE ? OR context LIKE ? OR malware_family LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
        
        if threat_actor:
            query += " AND related_threat_actors LIKE ?"
            params.append(f"%{threat_actor}%")
        
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'value': r[0], 'ioc_type': r[1], 'source': r[2],
            'source_url': r[3], 'confidence': r[4], 'first_seen': r[5],
            'tags': json.loads(r[6]) if r[6] else None,
            'context': r[7],
            'related_threat_actors': json.loads(r[8]) if r[8] else None,
            'related_techniques': json.loads(r[9]) if r[9] else None,
            'malware_family': r[10], 'times_seen': r[11],
            'vt_permalink': r[12], 'vt_detection': r[13],
            'is_active': r[14]
        } for r in rows]
    
    def get_ioc_stats(self):
        """Get IOC statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute('SELECT COUNT(*) FROM iocs')
        stats['total'] = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT ioc_type, COUNT(*) as count 
            FROM iocs 
            GROUP BY ioc_type 
            ORDER BY count DESC
        ''')
        stats['by_type'] = dict(cursor.fetchall())
        
        # Remove file_name from stats if present
        stats['by_type'].pop('file_name', None)
        
        cursor.execute('''
            SELECT confidence, COUNT(*) as count 
            FROM iocs 
            GROUP BY confidence 
            ORDER BY 
                CASE confidence 
                    WHEN 'High' THEN 1 
                    WHEN 'Medium' THEN 2 
                    WHEN 'Low' THEN 3 
                    ELSE 4 
                END
        ''')
        stats['by_confidence'] = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT source, COUNT(*) as count 
            FROM iocs 
            GROUP BY source 
            ORDER BY count DESC
            LIMIT 10
        ''')
        stats['by_source'] = dict(cursor.fetchall())
        
        conn.close()
        return stats
    
    def export_iocs(self, format='json', ioc_types=None):
        """Export IOCs in various formats."""
        iocs = self.get_iocs(limit=10000)
        
        if ioc_types:
            iocs = [i for i in iocs if i['ioc_type'] in ioc_types]
        
        if format == 'json':
            import json
            return json.dumps(iocs, indent=2)
        
        elif format == 'csv':
            import csv
            import io
            output = io.StringIO()
            if iocs:
                fieldnames = ['value', 'ioc_type', 'confidence', 'source',
                              'malware_family', 'related_threat_actors',
                              'first_seen', 'tags']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for ioc in iocs:
                    row = {k: ioc.get(k, '') for k in fieldnames}
                    if row.get('related_threat_actors'):
                        row['related_threat_actors'] = '|'.join(row['related_threat_actors'])
                    if row.get('tags'):
                        row['tags'] = '|'.join(row['tags'])
                    writer.writerow(row)
            return output.getvalue()
        
        elif format == 'stix':
            return self._export_stix(iocs)
        
        elif format == 'misp':
            return self._export_misp(iocs)
        
        elif format == 'opensearch':
            return self._export_opensearch(iocs)
        
        return json.dumps(iocs, indent=2)
    
    def _export_stix(self, iocs: List[dict]) -> str:
        """Export IOCs as STIX 2.1 bundle."""
        import json
        from uuid import uuid4
        
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": []
        }
        
        # Add identity (source)
        identity = {
            "type": "identity",
            "id": f"identity--{uuid4()}",
            "name": "Threat Intel Hub",
            "identity_class": "system"
        }
        bundle["objects"].append(identity)
        
        for ioc in iocs:
            stix_obj = self._ioc_to_stix(ioc, identity["id"])
            if stix_obj:
                bundle["objects"].append(stix_obj)
        
        return json.dumps(bundle, indent=2)
    
    def _ioc_to_stix(self, ioc: dict, identity_id: str) -> Optional[dict]:
        """Convert single IOC to STIX indicator."""
        from uuid import uuid4
        
        value = ioc['value']
        ioc_type = ioc['ioc_type']
        
        # Map IOC type to STIX pattern
        pattern = None
        if ioc_type == 'ip_address':
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == 'domain':
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == 'url':
            pattern = f"[url:value = '{value}']"
        elif ioc_type == 'md5':
            pattern = f"[file:hashes.MD5 = '{value}']"
        elif ioc_type == 'sha1':
            pattern = f"[file:hashes.'SHA-1' = '{value}']"
        elif ioc_type == 'sha256':
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
        elif ioc_type == 'email':
            pattern = f"[email-addr:value = '{value}']"
        else:
            return None
        
        return {
            "type": "indicator",
            "id": f"indicator--{uuid4()}",
            "created": ioc.get('first_seen', datetime.now().isoformat()),
            "modified": ioc.get('first_seen', datetime.now().isoformat()),
            "name": f"IOC: {value}",
            "description": ioc.get('context', ''),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get('first_seen', datetime.now().isoformat()),
            "created_by_ref": identity_id,
            "labels": (ioc.get('tags') or []) + [ioc.get('confidence') or 'Unknown']
        }
    
    def _export_misp(self, iocs: List[dict]) -> str:
        """Export IOCs as MISP JSON format."""
        import json
        
        misp_event = {
            "response": [{
                "Event": {
                    "id": "1",
                    "orgc": "Threat Intel Hub",
                    "date": datetime.now().strftime('%Y-%m-%d'),
                    "threat_level_id": "3",
                    "info": "Exported IOCs from Threat Intel Hub",
                    "published": True,
                    "uuid": str(hash(str(datetime.now()))),
                    "Attribute": []
                }
            }]
        }
        
        type_mapping = {
            'ip_address': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'md5': 'md5',
            'sha1': 'sha1',
            'sha256': 'sha256',
            'email': 'email-src',
            'file_name': 'filename',
            'file_path': 'filename|path',
        }
        
        for ioc in iocs:
            misp_type = type_mapping.get(ioc['ioc_type'], 'text')
            attr = {
                "uuid": str(hash(ioc['value'] + ioc['ioc_type'])),
                "type": misp_type,
                "category": "Network activity" if ioc['ioc_type'] in ['ip_address', 'domain', 'url'] else "Payload delivery",
                "value": ioc['value'],
                "comment": ioc.get('context', '')[:200],
                "to_ids": ioc.get('confidence') in ['High', 'Medium'],
                "distribution": "0",
                "Tag": [{"name": t} for t in (ioc.get('tags') or [])]
            }
            misp_event["response"][0]["Event"]["Attribute"].append(attr)
        
        return json.dumps(misp_event, indent=2)
    
    def _export_opensearch(self, iocs: List[dict]) -> str:
        """Export IOCs as OpenSearch/Sigma format."""
        import yaml
        
        rules = []
        
        # Group by malware family or source
        for ioc in iocs[:100]:  # Limit for Sigma rules
            if not ioc.get('malware_family') and ioc['ioc_type'] not in ['md5', 'sha1', 'sha256']:
                continue
            
            rule = {
                'title': f"IOC Detection - {ioc.get('malware_family', 'Unknown')}",
                'id': str(hash(ioc['value'] + ioc['ioc_type']))[:8],
                'status': 'test',
                'description': f"Detects IOC from {ioc['source']}",
                'author': 'Threat Intel Hub',
                'date': ioc.get('first_seen', '')[:10],
                'references': [ioc.get('source_url', '')],
                'tags': ioc.get('tags', []),
                'logsource': {'category': 'endpoint'},
                'detection': {
                    'selection': self._ioc_to_sigma_selection(ioc),
                    'condition': 'selection'
                },
                'level': 'high' if ioc.get('confidence') == 'High' else 'medium'
            }
            rules.append(rule)
        
        return yaml.dump_all(rules, default_flow_style=False)
    
    def _ioc_to_sigma_selection(self, ioc: dict) -> dict:
        """Convert IOC to Sigma detection selection."""
        if ioc['ioc_type'] == 'md5':
            return {'HashMD5': ioc['value']}
        elif ioc['ioc_type'] == 'sha1':
            return {'HashSHA1': ioc['value']}
        elif ioc['ioc_type'] == 'sha256':
            return {'HashSHA256': ioc['value']}
        elif ioc['ioc_type'] == 'file_name':
            return {'Image|endswith': ioc['value']}
        elif ioc['ioc_type'] == 'file_path':
            return {'Image': ioc['value']}
        elif ioc['ioc_type'] == 'domain':
            return {'DestinationDomain': ioc['value']}
        elif ioc['ioc_type'] == 'ip_address':
            return {'DestinationIp': ioc['value']}
        elif ioc['ioc_type'] == 'url':
            return {'Image|contains': ioc['value']}
        else:
            return {'CommandLine|contains': ioc['value']}
