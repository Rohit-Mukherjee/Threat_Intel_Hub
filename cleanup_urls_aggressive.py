#!/usr/bin/env python3
"""Aggressive cleanup script to remove ALL benign URLs from IOCs."""

import sqlite3
import re

DB_PATH = "data/threat_intel.db"

# ONLY keep URLs that are clearly malicious
# Everything else will be deleted
KEEP_URL_PATTERNS = [
    # Known malware distribution domains
    r'\.ru/',
    r'\.cn/',
    r'\.tk/',
    r'\.ml/',
    r'\.ga/',
    r'\.cf/',
    r'\.gq/',
    r'\.pw/',
    r'\.top/',
    r'\.xyz/',
    r'\.buzz/',
    r'\.work/',
    r'\.click/',
    r'\.link/',
    
    # Known C2 patterns
    r'c2',
    r'command.*control',
    r'backdoor',
    r'rat.*server',
    r'botnet',
    
    # Paste sites (often used for malware distribution)
    r'pastebin\.com',
    r'paste\.ee',
    r'ghostbin\.com',
    
    # File hosting (often abused)
    r'mega\.nz',
    r'mediafire\.com',
    r'zippyshare',
    r'uploadhaven',
    
    # Dynamic DNS (often used by malware)
    r'\.ddns\.net',
    r'\.no-ip\.com',
    r'\.dyndns\.org',
    r'\.afraid\.org',
]

# URLs to ALWAYS delete (comprehensive list)
DELETE_URL_PATTERNS = [
    # Tech companies
    r'microsoft\.com',
    r'google\.com',
    r'apple\.com',
    r'amazon\.com',
    r'facebook\.com',
    r'twitter\.com',
    r'linkedin\.com',
    r'github\.com',
    r'stackoverflow\.com',
    r'youtube\.com',
    r'windows\.com',
    r'office\.com',
    r'azure\.com',
    r'aws\.amazon\.com',
    
    # Security vendors
    r'virustotal\.com',
    r'mandiant\.com',
    r'crowdstrike\.com',
    r'sentinelone\.com',
    r'paloaltonetworks\.com',
    r'unit42\.com',
    r'kaspersky\.com',
    r'securelist\.com',
    r'eset\.com',
    r'malwarebytes\.com',
    r'sophos\.com',
    r'symantec\.com',
    r'mcafee\.com',
    r'trendmicro\.com',
    r'bitdefender\.com',
    r'avast\.com',
    r'avg\.com',
    r'f-secure\.com',
    r'drweb\.com',
    r'gdatasoftware\.com',
    r'humansecurity\.com',
    
    # News and blogs
    r'thedfirreport\.com',
    r'bleepingcomputer\.com',
    r'darkreading\.com',
    r'thehackernews\.com',
    r'threatpost\.com',
    r'securityweek\.com',
    r'recordedfuture\.com',
    r'zdnet\.com',
    r'techcrunch\.com',
    r'arstechnica\.com',
    r'wired\.com',
    r'theregister\.com',
    r'cnn\.com',
    r'bbc\.com',
    r'reuters\.com',
    
    # Government/Education
    r'cisa\.gov',
    r'fbi\.gov',
    r'nsa\.gov',
    r'nist\.gov',
    r'mitre\.org',
    r'sans\.org',
    r'owasp\.org',
    r'wikipedia\.org',
    r'edu/',
    r'\.edu',
    
    # CDN/Infrastructure
    r'cdn',
    r'cloudflare',
    r'akamai',
    r'fastly',
    r'cloudfront',
    r'amazonaws\.com',
    r'googleapis\.com',
    r'gstatic\.com',
    r'googleusercontent\.com',
    r'fbcdn\.net',
    r'twimg\.com',
    r'licdn\.com',
    
    # Documentation/Learning
    r'docs\.',
    r'learn\.',
    r'support\.',
    r'help\.',
    r'developer\.',
    r'blog\.',
    
    # Feed/RSS
    r'/feed',
    r'/rss',
    r'feedburner',
    
    # Other benign
    r'example\.com',
    r'localhost',
    r'w3\.org',
    r'mozilla\.org',
    r'apache\.org',
    r'ubuntu\.com',
    r'debian\.org',
    r'reddit\.com',
    r'medium\.com',
    r'substack\.com',
]


def cleanup_all_benign_urls():
    """Aggressively remove all benign URLs from IOCs."""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("=" * 60)
    print("🧹 AGGRESSIVE URL IOC Cleanup")
    print("=" * 60)
    
    # Get all URL IOCs
    cursor.execute("SELECT id, value, source FROM iocs WHERE ioc_type = 'url'")
    url_iocs = cursor.fetchall()
    
    total_urls = len(url_iocs)
    print(f"\n📊 Total URL IOCs to review: {total_urls}")
    
    if total_urls == 0:
        print("✅ No URL IOCs to clean up!")
        conn.close()
        return
    
    to_delete = []
    to_keep = []
    
    for ioc_id, url, source in url_iocs:
        should_delete = False
        keep_reason = ""
        
        # First check if it matches any KEEP pattern
        should_keep = False
        for pattern in KEEP_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                should_keep = True
                keep_reason = f"Matches keep pattern: {pattern}"
                break
        
        # If not explicitly kept, check if it should be deleted
        if not should_keep:
            for pattern in DELETE_URL_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    should_delete = True
                    break
        
        # If it's a generic HTTP URL without clear malicious indicators, delete it
        if not should_keep and not should_delete:
            # Check if it looks like a normal website (likely benign)
            benign_indicators = [
                '/blog/', '/news/', '/article/', '/post/',
                'www.', '://www.',
                '/category/', '/tag/',
                '.html', '.php', '.aspx',
                'article', 'news', 'report', 'analysis',
                'www.', 'm.', 'mobile.',
            ]
            
            for indicator in benign_indicators:
                if indicator in url.lower():
                    should_delete = True
                    break
        
        if should_delete or (not should_keep and not should_delete):
            to_delete.append((ioc_id, url, source))
        else:
            to_keep.append((ioc_id, url, source, keep_reason))
    
    print(f"\n📊 Analysis Results:")
    print(f"   🔴 To DELETE: {len(to_delete)} URLs")
    print(f"   🟢 To KEEP: {len(to_keep)} URLs")
    
    if to_delete:
        print(f"\n🗑️ URLs to be DELETED (sample):")
        for ioc_id, url, source in to_delete[:30]:
            print(f"   [{source}] {url[:70]}...")
        if len(to_delete) > 30:
            print(f"   ... and {len(to_delete) - 30} more")
    
    if to_keep:
        print(f"\n✅ URLs to KEEP:")
        for ioc_id, url, source, reason in to_keep:
            print(f"   [{source}] {url[:70]}...")
            print(f"      → {reason}")
    
    confirm = input("\n❓ Proceed with deletion? (yes/no): ")
    if confirm.lower() not in ['yes', 'y']:
        print("\n❌ Cleanup cancelled")
        conn.close()
        return
    
    # Delete the URLs
    for ioc_id, _, _ in to_delete:
        cursor.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    
    conn.commit()
    
    print(f"\n✅ Deleted {len(to_delete)} benign URLs!")
    
    # Show final count
    cursor.execute("SELECT COUNT(*) FROM iocs WHERE ioc_type = 'url'")
    remaining = cursor.fetchone()[0]
    print(f"\n📊 Remaining URL IOCs: {remaining}")
    
    # Show what's left
    if to_keep:
        print(f"\n✅ Kept {len(to_keep)} potentially malicious URLs:")
        for ioc_id, url, source, reason in to_keep:
            print(f"   - {url[:80]}...")
    
    conn.close()
    print("\n" + "=" * 60)
    print("✅ Aggressive cleanup complete!")
    print("=" * 60)


if __name__ == "__main__":
    cleanup_all_benign_urls()
