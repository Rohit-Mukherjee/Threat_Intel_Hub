#!/usr/bin/env python3
"""Main aggregator script - Run this to collect threat intelligence."""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from database import ThreatIntelDB
from collectors import run_collection


def main():
    """Run the threat intelligence aggregator."""
    print("=" * 60)
    print("🛡️  THREAT INTELLIGENCE HUB - Aggregator")
    print("=" * 60)
    
    # Initialize database
    db = ThreatIntelDB("data/threat_intel.db")
    print("✓ Database initialized")
    
    # Run collectors
    run_collection(db, days_back=7)
    
    # Print summary
    stats = db.get_stats()
    print("\n" + "=" * 60)
    print("📊 DATABASE SUMMARY")
    print("=" * 60)
    print(f"  Total Intel Items:    {stats.get('intel_items', 0)}")
    print(f"  Attack Chains:        {stats.get('attack_chains', 0)}")
    print(f"  Threat Actors:        {stats.get('threat_actors', 0)}")
    print("\n  By Source:")
    for source, count in stats.get('by_source', {}).items():
        print(f"    - {source}: {count}")
    
    print("\n" + "=" * 60)
    print("✅ Collection complete!")
    print("=" * 60)
    print("\n🚀 To view the dashboard, run:")
    print("   streamlit run dashboard/app.py")
    print("\n")


if __name__ == "__main__":
    main()
