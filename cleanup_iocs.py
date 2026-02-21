#!/usr/bin/env python3
"""Cleanup script to remove blog URLs and benign URLs from IOCs."""

import sqlite3
import re
from datetime import datetime

DB_PATH = "data/threat_intel.db"

# Patterns to identify blog/news URLs that should NOT be IOCs
BLOG_URL_PATTERNS = [
    # RSS/Feed URLs
    r'feedburner\.com',
    r'/feed/?$',
    r'/rss/?$',
    r'/rss\.xml',
    r'/feed\.xml',
    r'/feeds/',
    
    # News and security blogs
    r'thedfirreport\.com',
    r'mandiant\.com',
    r'microsoft\.com/.*/security',
    r'crowdstrike\.com',
    r'securelist\.com',
    r'sophos\.com',
    r'bleepingcomputer\.com',
    r'darkreading\.com',
    r'thehackernews\.com',
    r'threatpost\.com',
    r'securityweek\.com',
    r'sentinelone\.com',
    r'unit42\.paloaltonetworks\.com',
    r'recordedfuture\.com',
    r'elastic\.co',
    
    # Social media
    r'twitter\.com',
    r'linkedin\.com',
    r'facebook\.com',
    r'youtube\.com',
    r'reddit\.com',
    
    # Tech companies
    r'github\.com',
    r'google\.com',
    r'amazon\.com',
    r'apple\.com',
    r'microsoft\.com',
    
    # General news
    r'cnn\.com',
    r'bbc\.com',
    r'reuters\.com',
    r'zdnet\.com',
    r'techcrunch\.com',
    r'arstechnica\.com',
    r'wired\.com',
    r'theregister\.com',
    
    # CDN and infrastructure
    r'cdn\.',
    r'static\.',
    r'assets\.',
    r'media\.',
    r'cloudflare\.',
    r'akamai\.',
    r'amazonaws\.com',
    r'googleapis\.com',
    
    # Documentation
    r'docs\.',
    r'support\.',
    r'learn\.',
    r'help\.',
    r'developer\.',
    
    # Other benign
    r'example\.com',
    r'localhost',
    r'wikipedia\.org',
    r'stackoverflow\.com',
]

def cleanup_blog_urls():
    """Remove blog and benign URLs from IOCs."""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("=" * 60)
    print("🧹 Cleaning up blog/benign URLs from IOCs")
    print("=" * 60)
    
    # First, show current URL IOCs
    cursor.execute("SELECT COUNT(*) FROM iocs WHERE ioc_type = 'url'")
    total_urls = cursor.fetchone()[0]
    print(f"\n📊 Total URL IOCs before cleanup: {total_urls}")
    
    if total_urls == 0:
        print("✅ No URL IOCs to clean up!")
        conn.close()
        return
    
    # Show sample of current URL IOCs
    print("\n📋 Sample of current URL IOCs:")
    cursor.execute("SELECT value, source FROM iocs WHERE ioc_type = 'url' LIMIT 10")
    for row in cursor.fetchall():
        print(f"   - {row[0][:80]}... (from {row[1]})")
    
    # Build regex pattern
    combined_pattern = '|'.join(BLOG_URL_PATTERNS)
    print(f"\n🔍 Using pattern with {len(BLOG_URL_PATTERNS)} rules...")
    
    # Get all URL IOCs
    cursor.execute("SELECT id, value FROM iocs WHERE ioc_type = 'url'")
    url_iocs = cursor.fetchall()
    
    to_delete = []
    to_keep = []
    
    for ioc_id, url in url_iocs:
        # Check if URL matches any blog pattern
        is_blog = False
        for pattern in BLOG_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                is_blog = True
                break
        
        if is_blog:
            to_delete.append((ioc_id, url))
        else:
            to_keep.append((ioc_id, url))
    
    print(f"\n📊 Found {len(to_delete)} blog/benign URLs to remove")
    print(f"✅ Keeping {len(to_keep)} legitimate threat URLs")
    
    if to_delete:
        print("\n🗑️ URLs to be deleted:")
        for ioc_id, url in to_delete[:20]:
            print(f"   - {url[:80]}...")
        if len(to_delete) > 20:
            print(f"   ... and {len(to_delete) - 20} more")
        
        confirm = input("\n❓ Delete these blog URLs from database? (yes/no): ")
        if confirm.lower() in ['yes', 'y']:
            # Delete blog URLs
            for ioc_id, _ in to_delete:
                cursor.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
            
            conn.commit()
            print(f"\n✅ Deleted {len(to_delete)} blog/benign URLs!")
        else:
            print("\n❌ Cleanup cancelled")
    
    # Show remaining URLs
    if to_keep:
        print("\n✅ Legitimate threat URLs kept:")
        for ioc_id, url in to_keep[:10]:
            print(f"   - {url[:80]}...")
        if len(to_keep) > 10:
            print(f"   ... and {len(to_keep) - 10} more")
    
    # Show final count
    cursor.execute("SELECT COUNT(*) FROM iocs WHERE ioc_type = 'url'")
    remaining_urls = cursor.fetchone()[0]
    print(f"\n📊 Total URL IOCs after cleanup: {remaining_urls}")
    
    conn.close()
    print("\n" + "=" * 60)
    print("✅ Cleanup complete!")
    print("=" * 60)


if __name__ == "__main__":
    cleanup_blog_urls()
