"""Unit tests for Threat Intel Hub core functionality."""
import pytest
import os
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import ThreatIntelDB
from config_manager import ConfigManager
from ioc_extractor import IOCExtractor


class TestThreatIntelDB:
    """Test database operations."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create a temporary database for testing."""
        db_path = tmp_path / "test.db"
        return ThreatIntelDB(str(db_path))

    def test_init_creates_tables(self, db):
        """Test that database initialization creates all tables."""
        conn = db._get_connection()
        cursor = conn.cursor()

        # Check tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        assert 'intel_items' in tables
        assert 'iocs' in tables
        assert 'threat_actors' in tables

        conn.close()

    def test_add_intel_item(self, db):
        """Test adding intelligence items."""
        intel_id = db.add_intel_item(
            title="Test Threat Report",
            source="Test Source",
            url="https://example.com/report",
            summary="Test summary",
            threat_actors=["APT29"],
            techniques=["T1059"],
            severity="High"
        )

        assert intel_id is not None
        assert intel_id > 0

    def test_add_intel_item_deduplication(self, db):
        """Test that duplicate URLs are handled correctly."""
        url = "https://example.com/unique"

        id1 = db.add_intel_item(
            title="First Report",
            source="Source1",
            url=url,
            severity="Low"
        )

        id2 = db.add_intel_item(
            title="Updated Report",
            source="Source2",
            url=url,
            severity="High"
        )

        # Should return same ID for duplicate URL
        assert id1 == id2

    def test_get_recent_intel(self, db):
        """Test retrieving recent intelligence."""
        # Add test items
        for i in range(5):
            db.add_intel_item(
                title=f"Report {i}",
                source="Test",
                url=f"https://example.com/{i}",
                severity="High"
            )

        intel = db.get_recent_intel(limit=10)

        assert len(intel) == 5
        assert all('title' in item for item in intel)
        assert all('source' in item for item in intel)

    def test_add_ioc(self, db):
        """Test adding IOCs."""
        result = db.add_ioc(
            value="192.168.1.1",
            ioc_type="ip_address",
            source="Test",
            confidence="High"
        )

        assert result is True

    def test_add_ioc_deduplication(self, db):
        """Test IOC deduplication."""
        db.add_ioc(
            value="evil.com",
            ioc_type="domain",
            source="Source1",
            confidence="Low"
        )

        db.add_ioc(
            value="evil.com",
            ioc_type="domain",
            source="Source2",
            confidence="High"
        )

        iocs = db.get_iocs(ioc_type="domain")

        # Should only have one IOC
        assert len(iocs) == 1
        # Should have updated times_seen
        assert iocs[0]['times_seen'] == 2

    def test_get_iocs_with_filters(self, db):
        """Test IOC filtering."""
        # Add different types of IOCs
        db.add_ioc("1.1.1.1", "ip_address", "Source", confidence="High")
        db.add_ioc("2.2.2.2", "ip_address", "Source", confidence="Low")
        db.add_ioc("evil.com", "domain", "Source", confidence="High")

        # Filter by type
        ip_iocs = db.get_iocs(ioc_type="ip_address")
        assert len(ip_iocs) == 2

        # Filter by confidence
        high_iocs = db.get_iocs(confidence="High")
        assert len(high_iocs) == 2

        # Combined filters
        high_ip = db.get_iocs(ioc_type="ip_address", confidence="High")
        assert len(high_ip) == 1

    def test_get_iocs_null_handling(self, db):
        """Test that NULL values are handled correctly."""
        db.add_ioc(
            value="test.com",
            ioc_type="domain",
            source="Test",
            confidence=None,  # NULL confidence
            tags=None,  # NULL tags
            context=""
        )

        iocs = db.get_iocs()

        assert len(iocs) == 1
        assert iocs[0]['confidence'] == 'Medium'  # Default
        assert iocs[0]['tags'] == []  # Empty list, not None

    def test_add_threat_actor(self, db):
        """Test adding threat actors."""
        db.add_threat_actor(
            name="APT29",
            aliases=["Cozy Bear"],
            origin="Russia",
            motivation="Espionage"
        )

        actors = db.get_threat_actors()

        assert len(actors) >= 1
        apt29 = next((a for a in actors if a['name'] == 'APT29'), None)
        assert apt29 is not None
        assert apt29['origin'] == 'Russia'

    def test_get_stats(self, db):
        """Test database statistics."""
        # Add some data
        db.add_intel_item("Report", "Source", "https://example.com")
        db.add_ioc("1.1.1.1", "ip_address", "Source")
        db.add_threat_actor("APT1")

        stats = db.get_stats()

        assert stats['intel_items'] >= 1
        assert stats['total_iocs'] >= 1
        assert stats['threat_actors'] >= 1

    def test_export_iocs_json(self, db):
        """Test IOC export to JSON."""
        db.add_ioc("1.1.1.1", "ip_address", "Test")
        db.add_ioc("evil.com", "domain", "Test")

        exported = db.export_iocs(format='json')
        data = json.loads(exported)

        assert isinstance(data, list)
        assert len(data) >= 2

    def test_export_iocs_csv(self, db):
        """Test IOC export to CSV."""
        db.add_ioc("1.1.1.1", "ip_address", "Test")

        exported = db.export_iocs(format='csv')

        assert 'value' in exported
        assert '1.1.1.1' in exported

    def test_cleanup_duplicates(self, db):
        """Test duplicate cleanup."""
        # Manually insert duplicates (bypassing deduplication)
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO iocs (value, ioc_type, source) VALUES (?, ?, ?)",
            ("dup.com", "domain", "Source1")
        )
        cursor.execute(
            "INSERT INTO iocs (value, ioc_type, source) VALUES (?, ?, ?)",
            ("dup.com", "domain", "Source2")
        )
        conn.commit()
        conn.close()

        # Clean up
        deleted = db.cleanup_duplicates()

        assert deleted >= 1

        # Verify only one remains
        iocs = db.get_iocs(ioc_type="domain", search_query="dup")
        assert len(iocs) == 1

    # Helper method for tests
    def _get_connection(self):
        """Get database connection for testing."""
        import sqlite3
        return sqlite3.connect(self.db_path)


class TestConfigManager:
    """Test configuration management."""

    @pytest.fixture
    def config(self, tmp_path):
        """Create a temporary config for testing."""
        config_path = tmp_path / "config.json"
        return ConfigManager(str(config_path))

    def test_init_creates_default_config(self, config):
        """Test that config initializes with defaults."""
        assert config.get('api_keys.virustotal') == ""
        assert config.get('collection.days_back') == 7

    def test_get_nested_value(self, config):
        """Test getting nested configuration values."""
        value = config.get('api_keys.virustotal')
        assert value == ""

    def test_set_nested_value(self, config):
        """Test setting nested configuration values."""
        config.set('api_keys.virustotal', 'test-key-123')

        assert config.get('api_keys.virustotal') == 'test-key-123'

    def test_is_api_key_set(self, config):
        """Test API key status checking."""
        assert config.is_api_key_set('virustotal') is False

        config.set('api_keys.virustotal', 'real-key')
        assert config.is_api_key_set('virustotal') is True

    def test_get_all_api_keys_status(self, config):
        """Test getting status of all API keys."""
        config.set('api_keys.virustotal', 'key1')
        config.set('api_keys.shodan', '')

        status = config.get_all_api_keys()

        assert status['virustotal'] is True
        assert status['shodan'] is False

    def test_save_and_load_config(self, config, tmp_path):
        """Test config persistence."""
        config.set('api_keys.test', 'secret-key')

        # Create new config instance from same file
        config_path = tmp_path / "config.json"
        new_config = ConfigManager(str(config_path))

        assert new_config.get('api_keys.test') == 'secret-key'

    def test_reset_to_defaults(self, config):
        """Test resetting configuration to defaults."""
        config.set('api_keys.virustotal', 'modified-key')
        config.reset_to_defaults()

        assert config.get('api_keys.virustotal') == ""


class TestIOCExtractor:
    """Test IOC extraction."""

    @pytest.fixture
    def extractor(self):
        """Create IOC extractor instance."""
        return IOCExtractor()

    def test_extract_ip_addresses(self, extractor):
        """Test IP address extraction."""
        content = "Server at 192.168.1.1 and 10.0.0.1 were compromised"
        iocs = extractor.extract_ips(content)

        assert len(iocs) == 2
        values = [ioc.value for ioc in iocs]
        assert '192.168.1.1' in values
        assert '10.0.0.1' in values

    def test_extract_domains(self, extractor):
        """Test domain extraction."""
        content = "Malware connects to evil.com and bad-domain.org"
        iocs = extractor.extract_domains(content)

        assert len(iocs) == 2
        values = [ioc.value for ioc in iocs]
        assert 'evil.com' in values
        assert 'bad-domain.org' in values

    def test_extract_hashes(self, extractor):
        """Test hash extraction."""
        content = """
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
        """
        md5_iocs = extractor.extract_md5(content)
        sha256_iocs = extractor.extract_sha256(content)

        assert len(md5_iocs) == 1
        assert len(sha256_iocs) == 1

    def test_extract_urls(self, extractor):
        """Test URL extraction."""
        content = "Download from https://malicious.com/payload.exe"
        iocs = extractor.extract_urls(content)

        assert len(iocs) == 1
        assert 'https://malicious.com/payload.exe' in [ioc.value for ioc in iocs]

    def test_extract_all(self, extractor):
        """Test extracting all IOC types."""
        content = """
        IP: 192.168.1.1
        Domain: evil.com
        URL: https://bad.com/malware
        MD5: 5d41402abc4b2a76b9719d911017c592
        """

        iocs = extractor.extract_all(
            content=content,
            source="Test",
            source_url="https://test.com"
        )

        assert len(iocs) >= 4

    def test_ioc_has_metadata(self, extractor):
        """Test that extracted IOCs have proper metadata."""
        content = "192.168.1.1"
        iocs = extractor.extract_all(
            content=content,
            source="Test Source",
            source_url="https://test.com",
            threat_actors=["APT29"],
            tags=['test', 'malware']
        )

        assert len(iocs) == 1
        ioc = iocs[0]

        assert ioc.source == "Test Source"
        assert ioc.source_url == "https://test.com"
        assert 'APT29' in ioc.related_threat_actors
        assert 'test' in ioc.tags


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
