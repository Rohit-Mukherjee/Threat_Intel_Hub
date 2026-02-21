#!/usr/bin/env python3
"""IOC Export Utility - Export IOCs in various formats."""
import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from database import ThreatIntelDB


def main():
    parser = argparse.ArgumentParser(description="Export IOCs from Threat Intel Hub")
    parser.add_argument("-f", "--format", choices=["csv", "json", "stix", "misp", "sigma"],
                       default="csv", help="Export format")
    parser.add_argument("-t", "--type", choices=["ip_address", "domain", "url", "md5", 
                       "sha1", "sha256", "email", "file_name"],
                       help="Filter by IOC type")
    parser.add_argument("-o", "--output", default="iocs_export",
                       help="Output filename prefix")
    parser.add_argument("-c", "--confidence", choices=["High", "Medium", "Low"],
                       help="Filter by confidence level")
    
    args = parser.parse_args()
    
    # Initialize database
    db = ThreatIntelDB("data/threat_intel.db")
    
    print(f"🛡️  Threat Intel Hub - IOC Export")
    print(f"=" * 50)
    
    # Get stats
    stats = db.get_ioc_stats()
    print(f"Total IOCs in database: {stats['total']}")
    print(f"\nBy Type:")
    for ioc_type, count in stats.get('by_type', {}).items():
        print(f"  - {ioc_type}: {count}")
    
    # Export
    print(f"\n📤 Exporting to {args.format.upper()} format...")
    
    ioc_types = [args.type] if args.type else None
    data = db.export_iocs(format=args.format, ioc_types=ioc_types)
    
    # Write to file
    ext = {
        'csv': 'csv',
        'json': 'json',
        'stix': 'stix.json',
        'misp': 'misp.json',
        'sigma': 'sigma.yml'
    }
    
    filename = f"{args.output}.{ext[args.format]}"
    
    with open(filename, 'w') as f:
        f.write(data)
    
    print(f"✅ Exported to: {filename}")
    print(f"   File size: {len(data):,} bytes")
    
    # Show sample
    print(f"\n📋 Sample (first 500 chars):")
    print("-" * 50)
    print(data[:500])


if __name__ == "__main__":
    main()
