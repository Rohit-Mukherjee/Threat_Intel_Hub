"""SQLite database for storing threat intelligence - Enhanced with proper NULL handling and deduplication."""
import sqlite3
from datetime import datetime
from pathlib import Path
import json
import logging
from typing import List, Dict, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/threat_intel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ThreatIntelDB')


class ThreatIntelDB:
    def __init__(self, db_path: str = "data/threat_intel.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Ensure logs directory exists
        Path('logs').mkdir(parents=True, exist_ok=True)
        self.init_db()
        logger.info(f"Database initialized at {db_path}")

    def init_db(self):
        """Initialize database tables with improved schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Threat intelligence feed items
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intel_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                url TEXT UNIQUE NOT NULL,
                summary TEXT DEFAULT '',
                threat_actors TEXT DEFAULT '[]',
                techniques TEXT DEFAULT '[]',
                severity TEXT DEFAULT 'Low',
                published_at TIMESTAMP,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT DEFAULT '[]',
                malware_families TEXT DEFAULT '[]',
                campaign_name TEXT DEFAULT ''
            )
        ''')

        # Attack chain data (kept for backward compatibility)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT NOT NULL,
                source TEXT NOT NULL,
                url TEXT UNIQUE NOT NULL,
                initial_access TEXT DEFAULT '',
                execution TEXT DEFAULT '',
                persistence TEXT DEFAULT '',
                privilege_escalation TEXT DEFAULT '',
                defense_evasion TEXT DEFAULT '',
                credential_access TEXT DEFAULT '',
                discovery TEXT DEFAULT '',
                lateral_movement TEXT DEFAULT '',
                collection TEXT DEFAULT '',
                command_control TEXT DEFAULT '',
                exfiltration TEXT DEFAULT '',
                impact TEXT DEFAULT '',
                mitre_techniques TEXT DEFAULT '[]',
                published_at TIMESTAMP,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Threat actors
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                aliases TEXT DEFAULT '[]',
                origin TEXT DEFAULT 'Unknown',
                motivation TEXT DEFAULT 'Unknown',
                targets TEXT DEFAULT '[]',
                tools TEXT DEFAULT '[]',
                techniques TEXT DEFAULT '[]',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # IOC storage with intel_id foreign key for proper linking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                source_url TEXT DEFAULT '',
                intel_id INTEGER,
                confidence TEXT DEFAULT 'Medium',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT DEFAULT '[]',
                context TEXT DEFAULT '',
                related_threat_actors TEXT DEFAULT '[]',
                related_techniques TEXT DEFAULT '[]',
                malware_family TEXT DEFAULT '',
                times_seen INTEGER DEFAULT 1,
                vt_permalink TEXT DEFAULT '',
                vt_detection INTEGER DEFAULT 0,
                abuse_ch_malware TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                UNIQUE(value, ioc_type),
                FOREIGN KEY (intel_id) REFERENCES intel_items(id) ON DELETE SET NULL
            )
        ''')

        # Create indexes for faster lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_intel_id ON iocs(intel_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_intel_severity ON intel_items(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_intel_published ON intel_items(published_at)')

        conn.commit()
        conn.close()
        logger.info("Database schema initialized/verified")

    def add_intel_item(self, title: str, source: str, url: str, summary: str = '',
                       threat_actors: List[str] = None, techniques: List[str] = None,
                       severity: str = 'Low', published_at: str = None,
                       tags: List[str] = None, malware_families: List[str] = None,
                       campaign_name: str = '') -> Optional[int]:
        """Add a new intelligence item with deduplication."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Ensure lists are never None
            threat_actors = threat_actors or []
            techniques = techniques or []
            tags = tags or []
            malware_families = malware_families or []

            cursor.execute('''
                INSERT OR REPLACE INTO intel_items
                (title, source, url, summary, threat_actors, techniques,
                 severity, published_at, tags, malware_families, campaign_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (title, source, url, summary or '',
                  json.dumps(threat_actors),
                  json.dumps(techniques),
                  severity or 'Low',
                  published_at,
                  json.dumps(tags),
                  json.dumps(malware_families),
                  campaign_name or ''))

            conn.commit()

            # Get the ID of the inserted/updated item
            cursor.execute('SELECT id FROM intel_items WHERE url = ?', (url,))
            row = cursor.fetchone()
            intel_id = row[0] if row else None

            logger.info(f"Added intel item: {title[:50]}... (ID: {intel_id})")
            return intel_id

        except sqlite3.IntegrityError as e:
            logger.warning(f"Integrity error adding intel item: {e}")
            return None
        except Exception as e:
            logger.error(f"Error adding intel item: {e}")
            return None
        finally:
            conn.close()

    def add_attack_chain(self, campaign_name: str, source: str, url: str,
                         chain_data: Dict = None, mitre_techniques: List[str] = None,
                         published_at: str = None):
        """Add attack chain data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        chain_data = chain_data or {}

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
                  chain_data.get('initial_access', ''),
                  chain_data.get('execution', ''),
                  chain_data.get('persistence', ''),
                  chain_data.get('privilege_escalation', ''),
                  chain_data.get('defense_evasion', ''),
                  chain_data.get('credential_access', ''),
                  chain_data.get('discovery', ''),
                  chain_data.get('lateral_movement', ''),
                  chain_data.get('collection', ''),
                  chain_data.get('command_control', ''),
                  chain_data.get('exfiltration', ''),
                  chain_data.get('impact', ''),
                  json.dumps(mitre_techniques or []),
                  published_at))
            conn.commit()
            logger.info(f"Added attack chain: {campaign_name}")
        except Exception as e:
            logger.error(f"Error adding attack chain: {e}")
        finally:
            conn.close()

    def add_threat_actor(self, name: str, aliases: List[str] = None,
                         origin: str = 'Unknown', motivation: str = 'Unknown',
                         targets: List[str] = None, tools: List[str] = None,
                         techniques: List[str] = None):
        """Add or update threat actor information."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO threat_actors
                (name, aliases, origin, motivation, targets, tools, techniques, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name,
                  json.dumps(aliases or []),
                  origin or 'Unknown',
                  motivation or 'Unknown',
                  json.dumps(targets or []),
                  json.dumps(tools or []),
                  json.dumps(techniques or []),
                  datetime.now().isoformat()))

            conn.commit()
            logger.info(f"Added/updated threat actor: {name}")
        except Exception as e:
            logger.error(f"Error adding threat actor: {e}")
        finally:
            conn.close()

    def get_recent_intel(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent intelligence items with proper NULL handling."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT title, source, url, summary, threat_actors, techniques,
                   severity, published_at, tags, malware_families, campaign_name
            FROM intel_items
            ORDER BY published_at DESC NULLS LAST, collected_at DESC
            LIMIT ?
        ''', (limit,))

        rows = cursor.fetchall()
        conn.close()

        result = []
        for r in rows:
            try:
                result.append({
                    'title': r[0] or '',
                    'source': r[1] or '',
                    'url': r[2] or '',
                    'summary': r[3] or '',
                    'threat_actors': json.loads(r[4]) if r[4] else [],
                    'techniques': json.loads(r[5]) if r[5] else [],
                    'severity': r[6] or 'Low',
                    'published_at': r[7],
                    'tags': json.loads(r[8]) if r[8] else [],
                    'malware_families': json.loads(r[9]) if r[9] else [],
                    'campaign_name': r[10] or ''
                })
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Error parsing intel item: {e}")
                continue

        return result

    def get_attack_chains(self, limit: int = 20) -> List[Dict[str, Any]]:
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
            'campaign_name': r[0] or '',
            'source': r[1] or '',
            'url': r[2] or '',
            'initial_access': r[3] or '',
            'execution': r[4] or '',
            'persistence': r[5] or '',
            'defense_evasion': r[6] or '',
            'lateral_movement': r[7] or '',
            'command_control': r[8] or '',
            'exfiltration': r[9] or '',
            'mitre_techniques': json.loads(r[10]) if r[10] else [],
            'published_at': r[11]
        } for r in rows]

    def get_threat_actors(self) -> List[Dict[str, Any]]:
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
            'name': r[0] or '',
            'aliases': json.loads(r[1]) if r[1] else [],
            'origin': r[2] or 'Unknown',
            'motivation': r[3] or 'Unknown',
            'targets': json.loads(r[4]) if r[4] else [],
            'tools': json.loads(r[5]) if r[5] else [],
            'techniques': json.loads(r[6]) if r[6] else [],
            'last_seen': r[7]
        } for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        cursor.execute('SELECT COUNT(*) FROM intel_items')
        stats['intel_items'] = cursor.fetchone()[0] or 0

        cursor.execute('SELECT COUNT(*) FROM attack_chains')
        stats['attack_chains'] = cursor.fetchone()[0] or 0

        cursor.execute('SELECT COUNT(*) FROM threat_actors')
        stats['threat_actors'] = cursor.fetchone()[0] or 0

        cursor.execute('SELECT COUNT(*) FROM iocs')
        stats['total_iocs'] = cursor.fetchone()[0] or 0

        cursor.execute('''
            SELECT COALESCE(source, 'Unknown'), COUNT(*) as count
            FROM intel_items
            GROUP BY source
            ORDER BY count DESC
        ''')
        stats['by_source'] = {r[0]: r[1] for r in cursor.fetchall()}

        conn.close()
        return stats

    def add_ioc(self, value: str, ioc_type: str, source: str, source_url: str = '',
                confidence: str = 'Medium', first_seen: str = None,
                tags: List[str] = None, context: str = '',
                related_threat_actors: List[str] = None,
                related_techniques: List[str] = None,
                malware_family: str = '', intel_id: int = None) -> bool:
        """Add or update an IOC with proper deduplication and NULL handling."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Ensure defaults
            tags = tags or []
            related_threat_actors = related_threat_actors or []
            related_techniques = related_techniques or []
            confidence = confidence or 'Medium'
            first_seen = first_seen or datetime.now().isoformat()

            cursor.execute('''
                INSERT INTO iocs
                (value, ioc_type, source, source_url, intel_id, confidence, first_seen,
                 tags, context, related_threat_actors, related_techniques,
                 malware_family, times_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(value, ioc_type) DO UPDATE SET
                    times_seen = times_seen + 1,
                    last_seen = excluded.last_seen,
                    source = excluded.source,
                    source_url = excluded.source_url,
                    intel_id = excluded.intel_id,
                    confidence = COALESCE(excluded.confidence, iocs.confidence),
                    malware_family = COALESCE(NULLIF(excluded.malware_family, ''), iocs.malware_family)
            ''', (value, ioc_type, source, source_url or '', intel_id, confidence,
                  first_seen, json.dumps(tags), context or '',
                  json.dumps(related_threat_actors), json.dumps(related_techniques),
                  malware_family or '', datetime.now().isoformat()))

            conn.commit()
            return True

        except Exception as e:
            logger.error(f"Error adding IOC {value}: {e}")
            return False
        finally:
            conn.close()

    def get_iocs(self, ioc_type: str = None, confidence: str = None,
                 limit: int = 500, search_query: str = None,
                 threat_actor: str = None, intel_id: int = None) -> List[Dict[str, Any]]:
        """Get IOCs with optional filters and proper NULL handling."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = '''
            SELECT value, ioc_type, source, source_url, intel_id, confidence,
                   first_seen, tags, context, related_threat_actors,
                   related_techniques, malware_family, times_seen,
                   vt_permalink, vt_detection, abuse_ch_malware, is_active
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

        if intel_id:
            query += " AND intel_id = ?"
            params.append(intel_id)

        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        result = []
        for r in rows:
            try:
                result.append({
                    'value': r[0] or '',
                    'ioc_type': r[1] or '',
                    'source': r[2] or '',
                    'source_url': r[3] or '',
                    'intel_id': r[4],
                    'confidence': r[5] or 'Medium',
                    'first_seen': r[6],
                    'tags': json.loads(r[7]) if r[7] else [],
                    'context': r[8] or '',
                    'related_threat_actors': json.loads(r[9]) if r[9] else [],
                    'related_techniques': json.loads(r[10]) if r[10] else [],
                    'malware_family': r[11] or '',
                    'times_seen': r[12] or 1,
                    'vt_permalink': r[13] or '',
                    'vt_detection': r[14] or 0,
                    'abuse_ch_malware': r[15] or '',
                    'is_active': bool(r[16]) if r[16] is not None else True
                })
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Error parsing IOC: {e}")
                continue

        return result

    def get_ioc_stats(self) -> Dict[str, Any]:
        """Get IOC statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        cursor.execute('SELECT COUNT(*) FROM iocs')
        stats['total'] = cursor.fetchone()[0] or 0

        cursor.execute('''
            SELECT COALESCE(ioc_type, 'unknown'), COUNT(*) as count
            FROM iocs
            GROUP BY ioc_type
            ORDER BY count DESC
        ''')
        stats['by_type'] = {r[0]: r[1] for r in cursor.fetchall()}
        stats['by_type'].pop('file_name', None)  # Remove legacy type

        cursor.execute('''
            SELECT COALESCE(confidence, 'Unknown'), COUNT(*) as count
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
        stats['by_confidence'] = {r[0]: r[1] for r in cursor.fetchall()}

        cursor.execute('''
            SELECT COALESCE(source, 'Unknown'), COUNT(*) as count
            FROM iocs
            GROUP BY source
            ORDER BY count DESC
            LIMIT 10
        ''')
        stats['by_source'] = {r[0]: r[1] for r in cursor.fetchall()}

        conn.close()
        return stats

    def export_iocs(self, format: str = 'json', ioc_types: List[str] = None) -> str:
        """Export IOCs in various formats."""
        iocs = self.get_iocs(limit=10000)

        if ioc_types:
            iocs = [i for i in iocs if i['ioc_type'] in ioc_types]

        if format == 'json':
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
        from uuid import uuid4

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": []
        }

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

        value = ioc.get('value', '')
        ioc_type = ioc.get('ioc_type', '')

        if not value or not ioc_type:
            return None

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

        # Safe list concatenation with defaults
        tags = ioc.get('tags') or []
        confidence = ioc.get('confidence') or 'Unknown'

        return {
            "type": "indicator",
            "id": f"indicator--{uuid4()}",
            "created": ioc.get('first_seen') or datetime.now().isoformat(),
            "modified": ioc.get('first_seen') or datetime.now().isoformat(),
            "name": f"IOC: {value}",
            "description": ioc.get('context') or '',
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get('first_seen') or datetime.now().isoformat(),
            "created_by_ref": identity_id,
            "labels": tags + [confidence]
        }

    def _export_misp(self, iocs: List[dict]) -> str:
        """Export IOCs as MISP JSON format."""
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
            misp_type = type_mapping.get(ioc.get('ioc_type', ''), 'text')
            tags = ioc.get('tags') or []

            attr = {
                "uuid": str(hash(ioc.get('value', '') + ioc.get('ioc_type', ''))),
                "type": misp_type,
                "category": "Network activity" if ioc.get('ioc_type') in ['ip_address', 'domain', 'url'] else "Payload delivery",
                "value": ioc.get('value', ''),
                "comment": (ioc.get('context') or '')[:200],
                "to_ids": ioc.get('confidence') in ['High', 'Medium'],
                "distribution": "0",
                "Tag": [{"name": t} for t in tags]
            }
            misp_event["response"][0]["Event"]["Attribute"].append(attr)

        return json.dumps(misp_event, indent=2)

    def _export_opensearch(self, iocs: List[dict]) -> str:
        """Export IOCs as OpenSearch/Sigma format."""
        import yaml

        rules = []

        for ioc in iocs[:100]:
            malware = ioc.get('malware_family') or 'Unknown'
            if not malware and ioc.get('ioc_type') not in ['md5', 'sha1', 'sha256']:
                continue

            tags = ioc.get('tags') or []
            rule = {
                'title': f"IOC Detection - {malware}",
                'id': str(hash(ioc.get('value', '') + ioc.get('ioc_type', '')))[:8],
                'status': 'test',
                'description': f"Detects IOC from {ioc.get('source', 'Unknown')}",
                'author': 'Threat Intel Hub',
                'date': (ioc.get('first_seen') or '')[:10],
                'references': [ioc.get('source_url') or ''],
                'tags': tags,
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
        value = ioc.get('value', '')
        ioc_type = ioc.get('ioc_type', '')

        if ioc_type == 'md5':
            return {'HashMD5': value}
        elif ioc_type == 'sha1':
            return {'HashSHA1': value}
        elif ioc_type == 'sha256':
            return {'HashSHA256': value}
        elif ioc_type == 'file_name':
            return {'Image|endswith': value}
        elif ioc_type == 'file_path':
            return {'Image': value}
        elif ioc_type == 'domain':
            return {'DestinationDomain': value}
        elif ioc_type == 'ip_address':
            return {'DestinationIp': value}
        elif ioc_type == 'url':
            return {'Image|contains': value}
        else:
            return {'CommandLine|contains': value}

    def get_iocs_by_intel_id(self, intel_id: int) -> List[Dict[str, Any]]:
        """Get all IOCs linked to a specific intel item."""
        return self.get_iocs(intel_id=intel_id)

    def cleanup_duplicates(self) -> int:
        """Remove duplicate IOCs (keep highest confidence)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Find and remove duplicates, keeping the one with highest confidence
        cursor.execute('''
            DELETE FROM iocs
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM iocs
                GROUP BY value, ioc_type
            )
        ''')

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted > 0:
            logger.info(f"Cleaned up {deleted} duplicate IOCs")

        return deleted

    def _get_connection(self):
        """Get database connection (for testing)."""
        return sqlite3.connect(self.db_path)
