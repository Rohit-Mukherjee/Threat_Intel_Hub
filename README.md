# 🛡️ Threat Intelligence Hub

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-green.svg)](https://www.docker.com/)

A **free, open-source threat intelligence aggregator** with a beautiful cyber-security themed dashboard for tracking threat actors, IOCs, and latest security advisories.

## ✨ What's New (v2.0)

- 🎨 **Stunning Dark UI** - Modern cyber-security theme with gradient colors and glow effects
- ⚙️ **Settings Panel** - Configure API keys, notifications, and collection preferences
- 🔔 **Alerts** - Email and Slack notifications for critical threats
- 🐳 **Docker Support** - One-command deployment with docker-compose
- 🧪 **Unit Tests** - Comprehensive test coverage for core functions
- 🔧 **Bug Fixes** - Fixed NULL handling, deduplication, and export issues
- 📊 **Enhanced APT Intel** - Related IOCs, malware families, external intelligence links

---

## 🚀 Quick Start

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

### Option 2: Docker (Easiest!)

```bash
# Clone and run with docker-compose
docker-compose up -d

# Dashboard available at http://localhost:8501
```

### Option 3: Manual Setup

```bash
cd threat_intel_hub
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python aggregator.py
streamlit run dashboard/app.py
```

---

## 🎯 Features

### Data Collection
- 📰 **RSS Feed Aggregation** - 15+ top security blogs (Mandiant, Microsoft, CrowdStrike, CISA, etc.)
- 🐦 **Twitter/X Integration** - Track security researchers via Nitter RSS
- 📧 **CISA Alerts** - Known Exploited Vulnerabilities (KEV) catalog
- 🦠 **Malware IOCs** - ESET malware intelligence from GitHub
- 👤 **Threat Actor Profiles** - Pre-loaded with major APT groups

### IOC Processing
- 🎯 **Auto-Extraction** - IPs, domains, URLs, hashes, CVEs, emails, file paths
- 🔬 **Enrichment** - VirusTotal, Abuse.ch, Shodan integration (optional API keys)
- 📤 **Multi-Format Export** - CSV, JSON, STIX 2.1, MISP, Sigma rules
- 🔄 **Deduplication** - Automatic duplicate detection and merging

### Dashboard
- 🎨 **Modern Dark Theme** - Cyber-security inspired design with neon accents
- 📊 **Real-time Analytics** - Severity distribution, timelines, top techniques
- 🔍 **Advanced Search** - Full-text search across intelligence and IOCs
- 👥 **APT Intelligence** - Grouped intel by threat actor with external links
- ⚙️ **Settings UI** - Configure API keys, notifications, preferences

### Alerts & Notifications
- 📧 **Email Alerts** - SMTP integration for critical threat notifications
- 💬 **Slack Integration** - Webhook-based alerts to Slack channels
- 🎯 **Threshold-based** - Alert on multiple IOCs from same source

---

## 📊 Dashboard Tabs

| Tab | Description |
|-----|-------------|
| **📰 Latest Intelligence** | Real-time threat intel feed with severity ratings and MITRE techniques |
| **🎯 IOCs** | Filterable IOC database with one-click export to security tools |
| **👥 APT Intelligence** | Intel grouped by threat actor with malware, campaigns, techniques |
| **👤 Threat Actors** | Expandable cards with full APT profiles and external links |
| **📊 Analytics** | Charts for sources, severity, timelines, top techniques and actors |
| **⚙️ Settings** | API keys, notifications, collection config, dashboard preferences |

---

## ⚙️ Configuration

### API Keys (Optional)

Configure in the **Settings** tab or edit `data/config.json`:

```json
{
  "api_keys": {
    "virustotal": "your-vt-api-key",
    "shodan": "your-shodan-api-key",
    "abusech": "",
    "censys": ""
  }
}
```

Get free API keys:
- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [Shodan](https://account.shodan.io/register)
- [Abuse.ch](https://abuse.ch/api/)

### Notifications

**Slack:**
1. Create incoming webhook in Slack
2. Go to Settings tab → Slack Notifications
3. Enable and paste webhook URL

**Email:**
1. Go to Settings tab → Email Notifications
2. Configure SMTP settings
3. Add recipient addresses

---

## 📤 IOC Export Examples

### Export via CLI

```bash
# Export all IOCs to CSV
python export_iocs.py -f csv -o all_iocs

# Export high-confidence domains only
python export_iocs.py -f csv -t domain -c High -o malicious_domains

# Export to STIX 2.1 format
python export_iocs.py -f stix -o threat_intel_stix

# Generate Sigma detection rules
python export_iocs.py -f sigma -o sigma_rules
```

### Import into Security Tools

**Firewall/SIEM Blocklist:**
```bash
python export_iocs.py -f csv -t ip_address,domain -c High -o blocklist
```

**MISP:**
```bash
python export_iocs.py -f misp -o misp_event
# Import via MISP: Events > Import Event > From JSON
```

---

## 🐳 Docker Deployment

### Basic Usage

```bash
# Start the dashboard
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### With Persistent Data

```yaml
# docker-compose.yml already mounts:
# - ./data:/app/data   (database and config)
# - ./logs:/app/logs   (log files)
```

### Run Aggregator Separately

```bash
# One-time collection
docker-compose run aggregator

# Schedule with cron (host system)
0 */6 * * * docker-compose run --rm aggregator
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_core.py -v
```

---

## 📁 Project Structure

```
threat_intel_hub/
├── dashboard/
│   └── app.py              # Streamlit dashboard
├── collectors/
│   └── __init__.py         # RSS, Twitter, CISA collectors
├── data/
│   ├── threat_intel.db     # SQLite database
│   └── config.json         # Configuration (API keys, etc.)
├── logs/
│   └── threat_intel.log    # Application logs
├── tests/
│   └── test_core.py        # Unit tests
├── aggregator.py           # Main collection script
├── database.py             # Database layer
├── config_manager.py       # Configuration management
├── notification_manager.py # Email/Slack alerts
├── ioc_extractor.py        # IOC pattern extraction
├── export_iocs.py          # Export utilities
├── setup.py                # Automated setup
├── Dockerfile              # Docker image
└── docker-compose.yml      # Docker orchestration
```

---

## 🔧 Troubleshooting

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
```bash
# Run the aggregator first
python aggregator.py
```

### Database errors
```bash
# Clean up duplicates
# Go to Settings → Danger Zone → Clean Up Duplicate IOCs
```

### Docker issues
```bash
# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 🛣️ Roadmap

- [ ] Geomap visualization for IP attribution
- [ ] REST API for SIEM/SOAR integration
- [ ] PDF report generation
- [ ] User authentication and RBAC
- [ ] Saved searches and custom dashboards
- [ ] Automated scheduled collection (built-in)
- [ ] More threat intel sources (MISP feeds, OTX)

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Add new RSS feeds or data sources
- Improve IOC extraction accuracy
- Add new export formats
- Create new dashboard visualizations
- Write additional unit tests

---

## 📄 License

MIT License - Free for personal and commercial use.

---

## 🙏 Acknowledgments

Data sources:
- RSS feeds from leading security vendors
- CISA Known Exploited Vulnerabilities
- ESET Malware IOC Repository
- Malpedia Malware Encyclopedia
- MITRE ATT&CK Framework

---

**Built with ❤️ for the DFIR community**

[Report a Bug](https://github.com/Rohit-Mukherjee/Threat_Intel_Hub/issues) | [Request Feature](https://github.com/Rohit-Mukherjee/Threat_Intel_Hub/issues) | [View on GitHub](https://github.com/Rohit-Mukherjee/Threat_Intel_Hub)
