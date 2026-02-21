# 🛡️ Threat Intelligence Hub

A **free, open-source threat intelligence aggregator** with a beautiful dashboard for tracking threat actors, attack chains, and latest security advisories.

## Features

- 📰 **RSS Feed Aggregation** - Collects from 14+ top security blogs (DFIR Report, Mandiant, Microsoft, CrowdStrike, CISA, etc.)
- 🎯 **IOC Extraction** - Auto-extracts IPs, domains, URLs, hashes, CVEs, file paths, mutexes from articles
- 📤 **Multi-Format Export** - Export IOCs to CSV, JSON, STIX 2.1, MISP, and Sigma rules
- 🔬 **IOC Enrichment** - Optional VirusTotal, Abuse.ch integration for reputation data
- ⛓️ **Attack Chain Tracking** - Documents full kill chains mapped to MITRE ATT&CK
- 👤 **Threat Actor Profiles** - Pre-loaded with major APT groups
- 🎯 **MITRE ATT&CK Mapping** - Auto-extracts technique IDs from articles
- 📊 **Interactive Dashboard** - Beautiful Streamlit UI with filters and analytics
- 🔄 **Auto-refresh** - Set up cron jobs for continuous collection

## Quick Start

### Option 1: Automated Setup (Recommended)

**Linux/macOS:**
```bash
cd threat_intel_hub
python3 setup.py          # Creates venv and installs dependencies
./run_aggregator.sh       # Run the aggregator
./run_dashboard.sh        # Launch the dashboard
```

**Windows:**
```bash
cd threat_intel_hub
python setup.py           # Creates venv and installs dependencies
run_aggregator.bat        # Run the aggregator
run_dashboard.bat         # Launch the dashboard
```

### Option 2: Manual Setup

```bash
cd threat_intel_hub
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python aggregator.py
streamlit run dashboard/app.py
```

The dashboard will open at `http://localhost:8501`

### What the Aggregator Does

When you run the aggregator, it will:
- Create the SQLite database
- Collect intelligence from all RSS feeds (last 7 days)
- Extract IOCs (IPs, domains, URLs, hashes, etc.) from articles
- Fetch CISA alerts and known exploited vulnerabilities
- Load threat actor profiles

## Dashboard Tabs

### 📰 Latest Intelligence
View all collected intelligence with severity ratings, threat actors, and MITRE techniques.

### 🎯 IOCs
- **Clean IOCs only** - Security vendor domains filtered out
- **Types extracted:** IP addresses, domains, URLs, MD5/SHA1/SHA256 hashes, CVEs, file names, file paths, emails
- Filter by type (IP, domain, URL, hash, etc.) and confidence
- **Export buttons** for one-click download:
  - CSV - Import into Excel, SIEM, or firewall
  - JSON - API integration
  - STIX 2.1 - Threat intel sharing platforms
  - MISP - Import into MISP instances
  - Sigma Rules - Detection rules for SIEM
- VirusTotal enrichment (add API key)
- Abuse.ch blocklist checking (free)

### 👥 APT Intelligence (NEW!)
- **Segregated intelligence by APT group**
- Select any APT from dropdown to view:
  - Full APT profile (origin, motivation, aliases, targets, tools, techniques)
  - All intel items related to that specific APT
  - MITRE ATT&CK techniques used
- Automatically groups intel by extracted threat actor names

### ⛓️ Attack Chains
Documented attack chains with full kill chain phases.

### 👤 Threat Actors
Pre-loaded APT profiles with tools, techniques, targets.

### 📊 Analytics
Charts for sources, severity, top techniques, top actors.

## IOC Export Examples

### Export IOCs via CLI

```bash
# Export all IOCs to CSV
python export_iocs.py -f csv -o all_iocs

# Export only high-confidence domains
python export_iocs.py -f csv -t domain -c High -o malicious_domains

# Export to STIX 2.1 format
python export_iocs.py -f stix -o threat_intel_stix

# Export to MISP format
python export_iocs.py -f misp -o misp_event

# Generate Sigma detection rules
python export_iocs.py -f sigma -o sigma_rules
```

### Export from Dashboard
1. Go to the **🎯 IOCs** tab
2. Apply filters (type, confidence, search)
3. Click any export button (CSV, JSON, STIX, MISP, Sigma)
4. Download the file directly

### Import into Security Tools

**Firewall/Blocklist:**
```bash
# Export high-confidence IPs and domains
python export_iocs.py -f csv -t ip_address -c High -o firewall_blocklist
python export_iocs.py -f csv -t domain -c High -o domain_blocklist
```

**SIEM (Splunk, Elastic, Sentinel):**
```bash
# Export STIX 2.1 format
python export_iocs.py -f stix -o siem_intel
```

**MISP:**
```bash
# Export MISP event format
python export_iocs.py -f misp -o misp_export
# Import via MISP UI: Events > Import Event > From JSON
```

**Sigma Rules:**
```bash
# Generate Sigma detection rules
python export_iocs.py -f sigma -o sigma_ioc_rules
# Deploy to Sigma-compatible SIEM
```

## Data Sources

| Source | Type | Update Frequency |
|--------|------|------------------|
| The DFIR Report | Blog RSS | Weekly |
| Mandiant | Blog RSS | Daily |
| Microsoft Security | Blog RSS | Daily |
| CrowdStrike | Blog RSS | Daily |
| SecureList (Kaspersky) | Blog RSS | Weekly |
| BleepingComputer | Blog RSS | Daily |
| The Hacker News | Blog RSS | Daily |
| DarkReading | Blog RSS | Daily |
| CISA Alerts | Government | Real-time |
| SentinelOne | Blog RSS | Weekly |
| Unit42 (Palo Alto) | Blog RSS | Daily |
| Threatpost | Blog RSS | Daily |
| SecurityWeek | Blog RSS | Daily |
| Malpedia | Malware API | On-demand |
| ESET Malware IOCs | GitHub | Weekly |

## Automation

### Set up cron job for automatic collection:

```bash
# Edit crontab
crontab -e

# Add this line to run every 6 hours
0 */6 * * * cd /path/to/threat_intel_hub && /usr/bin/python3 aggregator.py >> logs/aggregator.log 2>&1
```

### Windows Task Scheduler:

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "python" -Argument "aggregator.py" -WorkingDirectory "C:\path\to\threat_intel_hub"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 6)
Register-ScheduledTask -TaskName "ThreatIntelHub" -Action $action -Trigger $trigger
```

## Database Schema

### intel_items
- Intelligence feed items with metadata
- Extracted threat actors and techniques
- Severity assessment

### attack_chains
- Full kill chain documentation
- MITRE ATT&CK phase mapping

### threat_actors
- APT group profiles
- Tools, techniques, targets

## Customization

### Add Custom RSS Feeds

Edit `collectors/__init__.py`:

```python
FEEDS = {
    'Your Custom Source': 'https://example.com/feed.xml',
    # ... existing feeds
}
```

### Add Threat Actors

Edit `collectors/__init__.py`:

```python
ACTORS = {
    'Your APT Name': {
        'aliases': ['Alias1', 'Alias2'],
        'origin': 'Country',
        'motivation': 'Espionage',
        'targets': ['Sector1', 'Sector2'],
        'tools': ['Tool1', 'Tool2'],
        'techniques': ['T1059', 'T1566']
    },
}
```

## API Usage

```python
from database import ThreatIntelDB

db = ThreatIntelDB("data/threat_intel.db")

# Get recent intel
items = db.get_recent_intel(limit=50)

# Get attack chains
chains = db.get_attack_chains(limit=20)

# Get threat actors
actors = db.get_threat_actors()

# Get stats
stats = db.get_stats()
```

## Troubleshooting

### "Module not found" error
```bash
pip install -r requirements.txt --upgrade
```

### Dashboard won't start
```bash
# Check if port 8501 is in use
streamlit run dashboard/app.py --server.port 8502
```

### No data showing
Run the aggregator first:
```bash
python aggregator.py
```

## License

MIT License - Free for personal and commercial use.

## Contributing

Feel free to:
- Add new RSS feeds
- Add threat actor profiles
- Improve extraction algorithms
- Add new dashboard visualizations

---

**Built with ❤️ for the DFIR community**
