"""Threat Intelligence Dashboard - Streamlit App with Modern UI."""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import ThreatIntelDB

# Page config - must be first Streamlit command
st.set_page_config(
    page_title="Threat Intel Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/Rohit-Mukherjee/Threat_Intel_Hub',
        'Report a bug': 'https://github.com/Rohit-Mukherjee/Threat_Intel_Hub/issues',
        'About': "# 🛡️ Threat Intel Hub\nA free, open-source threat intelligence aggregator."
    }
)

# Custom CSS with modern cyber-security theme
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');

    /* Root variables for theme */
    :root {
        --primary-color: #00d4ff;
        --secondary-color: #7b2cbf;
        --accent-color: #ff006e;
        --success-color: #00ff88;
        --warning-color: #ffbe0b;
        --danger-color: #ff0040;
        --bg-dark: #0a0e1a;
        --bg-card: #131b2e;
        --bg-card-hover: #1a2542;
        --text-primary: #ffffff;
        --text-secondary: #a0aec0;
        --border-color: #2d3748;
        --glow-color: rgba(0, 212, 255, 0.3);
    }

    /* Global styles */
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #1a1025 50%, #0f172a 100%);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: var(--bg-dark);
    }
    ::-webkit-scrollbar-thumb {
        background: var(--primary-color);
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: var(--accent-color);
    }

    /* Metric cards with glow effect */
    .metric-card {
        background: linear-gradient(145deg, var(--bg-card) 0%, #1a2332 100%);
        border-radius: 16px;
        padding: 24px;
        margin: 10px 0;
        border: 1px solid var(--border-color);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, var(--primary-color), var(--secondary-color), var(--accent-color));
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px var(--glow-color);
        border-color: var(--primary-color);
    }

    /* Severity badges */
    .severity-critical {
        background: linear-gradient(135deg, #ff0040 0%, #ff006e 100%);
        color: white;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        box-shadow: 0 2px 10px rgba(255, 0, 64, 0.4);
    }
    .severity-high {
        background: linear-gradient(135deg, #ff6b35 0%, #ff8c42 100%);
        color: white;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        box-shadow: 0 2px 10px rgba(255, 107, 53, 0.4);
    }
    .severity-medium {
        background: linear-gradient(135deg, #ffbe0b 0%, #ffd60a 100%);
        color: #1a1a2e;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        box-shadow: 0 2px 10px rgba(255, 190, 11, 0.4);
    }
    .severity-low {
        background: linear-gradient(135deg, #00ff88 0%, #00d4aa 100%);
        color: #1a1a2e;
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        box-shadow: 0 2px 10px rgba(0, 255, 136, 0.4);
    }

    /* Intel cards */
    .intel-card {
        background: linear-gradient(145deg, var(--bg-card) 0%, #1a2332 100%);
        border-radius: 12px;
        padding: 20px;
        margin: 16px 0;
        border: 1px solid var(--border-color);
        transition: all 0.3s ease;
    }
    .intel-card:hover {
        border-color: var(--primary-color);
        box-shadow: 0 4px 20px rgba(0, 212, 255, 0.15);
    }

    /* Tags */
    .tag {
        background: rgba(0, 212, 255, 0.15);
        color: var(--primary-color);
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
        margin: 2px;
        border: 1px solid rgba(0, 212, 255, 0.3);
    }
    .tag-actor {
        background: rgba(123, 44, 191, 0.2);
        color: #c77dff;
        border-color: rgba(123, 44, 191, 0.4);
    }
    .tag-technique {
        background: rgba(0, 255, 136, 0.15);
        color: var(--success-color);
        border-color: rgba(0, 255, 136, 0.3);
    }

    /* Threat actor cards */
    .apt-card {
        background: linear-gradient(145deg, #1a1025 0%, #2d1b4e 100%);
        border-radius: 16px;
        padding: 24px;
        margin: 16px 0;
        border: 1px solid rgba(123, 44, 191, 0.3);
        position: relative;
        overflow: hidden;
    }
    .apt-card::before {
        content: '🎯';
        position: absolute;
        top: 10px;
        right: 15px;
        font-size: 2rem;
        opacity: 0.3;
    }

    /* Section headers */
    .section-header {
        background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 30px 0 20px 0;
    }

    /* Custom button styles */
    .stButton > button {
        background: linear-gradient(135deg, var(--primary-color) 0%, #0099cc 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 10px 24px;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 25px rgba(0, 212, 255, 0.5);
    }

    /* Dataframe styling */
    .dataframe {
        background: var(--bg-card);
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid var(--border-color);
    }
    .dataframe th {
        background: linear-gradient(135deg, #1a2332 0%, #253045 100%);
        color: var(--primary-color);
        font-weight: 600;
        padding: 12px;
        border-bottom: 2px solid var(--primary-color);
    }
    .dataframe td {
        background: var(--bg-card);
        color: var(--text-primary);
        padding: 10px;
        border-bottom: 1px solid var(--border-color);
    }
    .dataframe tr:hover td {
        background: var(--bg-card-hover);
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
        border-right: 1px solid var(--border-color);
    }

    /* Alert boxes */
    .alert-info {
        background: rgba(0, 212, 255, 0.1);
        border-left: 4px solid var(--primary-color);
        padding: 16px;
        border-radius: 8px;
        margin: 16px 0;
    }
    .alert-warning {
        background: rgba(255, 190, 11, 0.1);
        border-left: 4px solid var(--warning-color);
        padding: 16px;
        border-radius: 8px;
        margin: 16px 0;
    }
    .alert-danger {
        background: rgba(255, 0, 64, 0.1);
        border-left: 4px solid var(--danger-color);
        padding: 16px;
        border-radius: 8px;
        margin: 16px 0;
    }
    .alert-success {
        background: rgba(0, 255, 136, 0.1);
        border-left: 4px solid var(--success-color);
        padding: 16px;
        border-radius: 8px;
        margin: 16px 0;
    }

    /* Divider */
    .custom-divider {
        height: 1px;
        background: linear-gradient(90deg, transparent, var(--border-color), transparent);
        margin: 30px 0;
    }

    /* Code blocks */
    pre {
        background: #0d1117;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 16px;
    }

    /* Links */
    a {
        color: var(--primary-color);
        text-decoration: none;
        transition: color 0.2s ease;
    }
    a:hover {
        color: var(--accent-color);
    }
</style>
""", unsafe_allow_html=True)

# Initialize database
db = ThreatIntelDB("data/threat_intel.db")

# Sidebar
with st.sidebar:
    st.markdown("""
    <div style='text-align: center; padding: 20px 0;'>
        <h1 style='margin: 0; font-size: 3rem;'>🛡️</h1>
        <h2 style='margin: 10px 0; background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>Threat Intel Hub</h2>
        <p style='color: #a0aec0; font-size: 0.85rem;'>Real-time Intelligence Aggregation</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

    # Auto-refresh option
    auto_refresh = st.checkbox("🔄 Auto-refresh (30s)", value=False)
    if auto_refresh:
        st.rerun()

    # Manual refresh button
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

    st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

    # Quick Filters
    st.markdown("### 🎚️ Quick Filters")

    # Get stats
    stats = db.get_stats()

    # Sidebar filters
    severity_filter = st.multiselect(
        "Severity",
        options=['Critical', 'High', 'Medium', 'Low'],
        default=['Critical', 'High', 'Medium']
    )

    available_sources = list(stats.get('by_source', {}).keys())[:10]
    source_filter = st.multiselect(
        "Sources",
        options=available_sources,
        default=available_sources[:5] if available_sources else []
    )

    st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

    # Database Stats
    st.markdown("### 📊 Database Stats")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Intel Items", stats.get('intel_items', 0))
        st.metric("Attack Chains", stats.get('attack_chains', 0))
    with col2:
        st.metric("Threat Actors", stats.get('threat_actors', 0))
        st.metric("IOCs", stats.get('total_iocs', 0))

    st.markdown("<div class='custom-divider'></div>")

    # Footer in sidebar
    st.markdown("""
    <div style='text-align: center; padding: 20px 0; color: #4a5568; font-size: 0.75rem;'>
        <p>Built with ❤️ for DFIR</p>
        <p>Open Source on GitHub</p>
    </div>
    """, unsafe_allow_html=True)

# Main content
st.markdown("""
<div style='padding: 20px 0 30px 0;'>
    <h1 style='font-size: 2.5rem; margin-bottom: 10px; background: linear-gradient(90deg, #00d4ff, #7b2cbf, #ff006e); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
        🛡️ Threat Intelligence Dashboard
    </h1>
    <p style='color: #a0aec0; font-size: 1.1rem;'>Real-time threat intelligence aggregation and analysis</p>
</div>
""", unsafe_allow_html=True)

# Top metrics row with custom cards - Clickable navigation
st.markdown("### 📊 Quick Stats")

col1, col2, col3 = st.columns(3)

# Track which tab to navigate to
if 'selected_tab' not in st.session_state:
    st.session_state.selected_tab = 0

with col1:
    if st.button(
        f"📰 Intel Items\n{stats.get('intel_items', 0):,}",
        use_container_width=True,
        key="btn_intel",
        help="View latest intelligence feeds"
    ):
        st.session_state.selected_tab = 0
        st.rerun()
    st.caption("▲ Total collected")

with col2:
    if st.button(
        f"👤 Threat Actors\n{stats.get('threat_actors', 0)}",
        use_container_width=True,
        key="btn_actors",
        help="View tracked threat actors"
    ):
        st.session_state.selected_tab = 3
        st.rerun()
    st.caption("◆ Tracked groups")

with col3:
    critical_count = len([i for i in db.get_recent_intel(100) if i.get('severity') == 'Critical'])
    if st.button(
        f"🔴 Critical Alerts\n{critical_count}",
        use_container_width=True,
        key="btn_critical",
        help="View critical severity alerts"
    ):
        st.session_state.selected_tab = 0
        st.rerun()
    st.caption("⚠ Recent critical")

st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

# Tabs for different views
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📰 Latest Intelligence",
    "🎯 IOCs",
    "👥 APT Intelligence",
    "👤 Threat Actors",
    "📊 Analytics"
])

# Auto-switch tabs based on button clicks
if st.session_state.selected_tab == 1:
    tab2.select()
elif st.session_state.selected_tab == 2:
    tab3.select()
elif st.session_state.selected_tab == 3:
    tab4.select()
elif st.session_state.selected_tab == 4:
    tab5.select()

# Tab 1: Latest Intelligence
with tab1:
    st.markdown("<div class='section-header'>📰 Latest Threat Intelligence</div>", unsafe_allow_html=True)

    # Search box
    search_query = st.text_input(
        "🔍 Search intelligence...",
        placeholder="Search by title, technique, or actor...",
        label_visibility="collapsed"
    )

    # Get recent intel
    intel_items = db.get_recent_intel(limit=100)

    # Filter items
    filtered_items = []
    for item in intel_items:
        if severity_filter and item.get('severity') not in severity_filter:
            continue
        if source_filter and item.get('source') not in source_filter:
            continue
        if search_query:
            query_lower = search_query.lower()
            threat_actors = item.get('threat_actors') or []
            techniques = item.get('techniques') or []
            if not (query_lower in item.get('title', '').lower() or
                    query_lower in item.get('summary', '').lower() or
                    query_lower in ' '.join(threat_actors).lower() or
                    query_lower in ' '.join(techniques).lower()):
                continue
        filtered_items.append(item)

    if not filtered_items:
        st.info("📭 No intelligence items found matching your filters.")
    else:
        # Display intel items
        for item in filtered_items[:30]:
            severity = item.get('severity', 'Low')
            severity_class = f"severity-{severity.lower()}"

            st.markdown(f"""
            <div class='intel-card'>
                <div style='display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;'>
                    <div style='flex: 1;'>
                        <h3 style='margin: 0 0 8px 0; font-size: 1.2rem;'>
                            <a href='{item.get('url', '#')}' target='_blank' style='color: #00d4ff;'>
                                {item.get('title', 'Unknown')}
                            </a>
                        </h3>
                        <div style='color: #a0aec0; font-size: 0.85rem;'>
                            📍 {item.get('source', 'Unknown')} &nbsp;|&nbsp;
                            📅 {item.get('published_at', '')[:10] if item.get('published_at') else 'Unknown'}
                        </div>
                    </div>
                    <div>
                        <span class='{severity_class}'>{severity}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            if item.get('summary'):
                summary = item['summary'][:300] + '...' if len(item.get('summary', '')) > 300 else item.get('summary', '')
                st.markdown(f"<p style='color: #d1d5db; margin: 12px 0;'>{summary}</p>", unsafe_allow_html=True)

            # Tags
            threat_actors = item.get('threat_actors', [])
            techniques = item.get('techniques', [])
            tags = item.get('tags', [])

            if threat_actors or techniques or tags:
                st.markdown("<div style='margin-top: 12px;'>", unsafe_allow_html=True)

                if threat_actors:
                    st.markdown(" ".join([f"<span class='tag tag-actor'>👤 {a}</span>" for a in threat_actors[:3]]), unsafe_allow_html=True)

                if techniques:
                    st.markdown(" ".join([f"<span class='tag tag-technique'>🎯 {t}</span>" for t in techniques[:5]]), unsafe_allow_html=True)

                if tags:
                    st.markdown(" ".join([f"<span class='tag'>{t}</span>" for t in tags[:5]]), unsafe_allow_html=True)

                st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

# Tab 2: IOCs
with tab2:
    st.markdown("<div class='section-header'>🎯 Indicators of Compromise</div>", unsafe_allow_html=True)
    st.markdown("<p style='color: #a0aec0; margin-bottom: 20px;'>Extracted, enriched, and ready for export to your security tools</p>", unsafe_allow_html=True)

    # IOC Stats
    ioc_stats = db.get_ioc_stats()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class='metric-card'>
            <div style='font-size: 0.85rem; color: #a0aec0;'>Total IOCs</div>
            <div style='font-size: 2rem; font-weight: 700; color: #00d4ff;'>{ioc_stats.get('total', 0):,}</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        high_conf = ioc_stats.get('by_confidence', {}).get('High', 0)
        st.markdown(f"""
        <div class='metric-card'>
            <div style='font-size: 0.85rem; color: #a0aec0;'>High Confidence</div>
            <div style='font-size: 2rem; font-weight: 700; color: #00ff88;'>{high_conf:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        domains = ioc_stats.get('by_type', {}).get('domain', 0)
        st.markdown(f"""
        <div class='metric-card'>
            <div style='font-size: 0.85rem; color: #a0aec0;'>Domains</div>
            <div style='font-size: 2rem; font-weight: 700; color: #7b2cbf;'>{domains:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        hashes = (ioc_stats.get('by_type', {}).get('md5', 0) +
                  ioc_stats.get('by_type', {}).get('sha256', 0))
        st.markdown(f"""
        <div class='metric-card'>
            <div style='font-size: 0.85rem; color: #a0aec0;'>File Hashes</div>
            <div style='font-size: 2rem; font-weight: 700; color: #ff006e;'>{hashes:,}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        ioc_type_filter = st.selectbox(
            "IOC Type",
            options=['All'] + ['ip_address', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email']
        )

    with col2:
        confidence_filter = st.selectbox(
            "Confidence",
            options=['All'] + ['High', 'Medium', 'Low']
        )

    with col3:
        search_query_ioc = st.text_input("Search", placeholder="Search IOCs...", label_visibility="collapsed")

    # Get IOCs
    ioc_type = None if ioc_type_filter == 'All' else ioc_type_filter
    confidence = None if confidence_filter == 'All' else confidence_filter

    iocs = db.get_iocs(
        ioc_type=ioc_type,
        confidence=confidence,
        search_query=search_query_ioc if search_query_ioc else None,
        limit=500
    )

    if not iocs:
        st.info("📭 No IOCs found. Run the aggregator to extract IOCs from threat intel feeds.")
    else:
        # Export options
        st.markdown("### 📤 Export IOCs")

        export_cols = st.columns(5)

        export_configs = [
            ("CSV", "csv", f"iocs_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv"),
            ("JSON", "json", f"iocs_{datetime.now().strftime('%Y%m%d')}.json", "application/json"),
            ("STIX 2.1", "stix", f"iocs_{datetime.now().strftime('%Y%m%d')}.stix.json", "application/json"),
            ("MISP", "misp", f"iocs_{datetime.now().strftime('%Y%m%d')}.misp.json", "application/json"),
            ("Sigma Rules", "opensearch", f"iocs_{datetime.now().strftime('%Y%m%d')}.sigma.yml", "text/yaml"),
        ]

        for i, (label, fmt, filename, mime) in enumerate(export_configs):
            with export_cols[i]:
                data_func = getattr(db, 'export_iocs')
                data = data_func(format=fmt, ioc_types=[ioc_type] if ioc_type else None)
                st.download_button(
                    label=f"⬇️ {label}",
                    data=data,
                    file_name=filename,
                    mime=mime,
                    use_container_width=True
                )

        st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

        # IOC Table
        st.markdown("### 📋 IOC List")

        display_data = []
        for ioc in iocs[:100]:
            display_data.append({
                "Value": ioc['value'][:40] + "..." if len(ioc['value']) > 40 else ioc['value'],
                "Type": ioc['ioc_type'],
                "Confidence": ioc['confidence'],
                "Source": ioc['source'],
                "Malware": ioc.get('malware_family', '-') or '-',
            })

        st.dataframe(
            pd.DataFrame(display_data),
            use_container_width=True,
            hide_index=True
        )

        # Quick Threat Intel Lookup Section
        st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
        st.markdown("### 🔬 Quick Threat Intel Lookup")
        st.markdown("*Select an IOC to check across multiple threat intelligence platforms*")

        lookup_iocs = [(f"{ioc['value']} ({ioc['ioc_type']})", ioc['value'], ioc['ioc_type'])
                       for ioc in iocs[:100]]

        if lookup_iocs:
            selected_lookup_ioc = st.selectbox(
                "Choose IOC to lookup",
                options=[v[0] for v in lookup_iocs],
                key="lookup_selector"
            )

            if selected_lookup_ioc:
                ioc_value = next(v[1] for v in lookup_iocs if v[0] == selected_lookup_ioc)
                ioc_type_lookup = next(v[2] for v in lookup_iocs if v[0] == selected_lookup_ioc)

                st.markdown(f"**Selected IOC:** `{ioc_value}` ({ioc_type_lookup})")
                st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

                # Build lookup URLs based on IOC type
                vt_url = None
                abuseipdb_url = None
                shodan_url = None
                censys_url = None
                urlhaus_url = None
                malwarebazaar_url = None

                if ioc_type_lookup in ['md5', 'sha1', 'sha256']:
                    vt_url = f"https://www.virustotal.com/gui/file/{ioc_value}"
                    malwarebazaar_url = f"https://bazaar.abuse.ch/browse.php?search={ioc_value}"
                elif ioc_type_lookup == 'ip_address':
                    vt_url = f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
                    abuseipdb_url = f"https://www.abuseipdb.com/check/{ioc_value}"
                    shodan_url = f"https://www.shodan.io/host/{ioc_value}"
                    censys_url = f"https://search.censys.io/hosts/{ioc_value}"
                elif ioc_type_lookup == 'domain':
                    vt_url = f"https://www.virustotal.com/gui/domain/{ioc_value}"
                    shodan_url = f"https://www.shodan.io/domain/{ioc_value}"
                elif ioc_type_lookup == 'url':
                    import base64
                    url_b64 = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip('=')
                    vt_url = f"https://www.virustotal.com/gui/url/{url_b64}"
                    urlhaus_url = f"https://urlhaus.abuse.ch/browse.php?search={ioc_value}"

                # Display buttons in columns
                cols = st.columns(4)

                with cols[0]:
                    if vt_url:
                        st.link_button("🔍 VirusTotal", vt_url)

                with cols[1]:
                    if abuseipdb_url:
                        st.link_button("🚫 AbuseIPDB", abuseipdb_url)

                with cols[2]:
                    if shodan_url:
                        st.link_button("🌐 Shodan", shodan_url)

                with cols[3]:
                    if censys_url:
                        st.link_button("🔎 Censys", censys_url)

                # Second row for malware-specific lookups
                malwares_urls = [url for url in [malwarebazaar_url, urlhaus_url] if url]
                if malwares_urls:
                    cols2 = st.columns(2)
                    with cols2[0]:
                        if malwarebazaar_url:
                            st.link_button("🦠 MalwareBazaar", malwarebazaar_url)
                    with cols2[1]:
                        if urlhaus_url:
                            st.link_button("🔗 URLhaus", urlhaus_url)

                st.info("**Tip:** Click any button above to open the IOC in that threat intelligence platform.")

        # Detailed view
        if iocs:
            st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
            st.markdown("### 🔍 Detailed IOC View")

            selected_ioc = st.selectbox(
                "Select IOC for details",
                options=[f"{ioc['value']} ({ioc['ioc_type']})" for ioc in iocs[:50]],
                key="detail_selector"
            )

            if selected_ioc:
                ioc_value = selected_ioc.split(' (')[0]
                matching_iocs = [i for i in iocs if i['value'] == ioc_value]

                if matching_iocs:
                    ioc = matching_iocs[0]

                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown(f"**Value:** `{ioc['value']}`")
                        st.markdown(f"**Type:** {ioc['ioc_type']}")
                        st.markdown(f"**Confidence:** {ioc['confidence']}")
                        st.markdown(f"**Source:** {ioc['source']}")

                        if ioc.get('source_url'):
                            st.markdown(f"**Source URL:** [Link]({ioc['source_url']})")

                    with col2:
                        if ioc.get('malware_family'):
                            st.markdown(f"**Malware Family:** {ioc['malware_family']}")

                        if ioc.get('related_threat_actors'):
                            st.markdown("**Threat Actors:**")
                            for actor in ioc['related_threat_actors']:
                                st.markdown(f"- {actor}")

                        if ioc.get('related_techniques'):
                            st.markdown("**MITRE ATT&CK:**")
                            for tech in ioc['related_techniques']:
                                st.markdown(f"- `{tech}`")

                    if ioc.get('context'):
                        st.markdown("**Context:**")
                        st.code(ioc['context'])

                    if ioc.get('tags'):
                        st.markdown("**Tags:**")
                        for tag in ioc['tags']:
                            st.markdown(f"`{tag}`")

                    # Enrichment data
                    st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
                    st.markdown("### 🔬 Enrichment Data")

                    if ioc.get('vt_permalink'):
                        st.info(f"**VirusTotal:** [{ioc.get('vt_detection', 'N/A')}]({ioc['vt_permalink']})")
                    else:
                        st.info("**VirusTotal:** Not enriched (add VT API key for enrichment)")

                    if ioc.get('abuse_ch_malware'):
                        st.warning(f"**Abuse.ch:** Listed in {ioc['abuse_ch_malware']}")
                    else:
                        st.success("**Abuse.ch:** Not listed")

# Tab 3: APT Intelligence
with tab3:
    st.markdown("<div class='section-header'>👥 APT Intelligence by Group</div>", unsafe_allow_html=True)
    st.markdown("<p style='color: #a0aec0; margin-bottom: 20px;'>Threat intelligence segregated by APT groups and threat actors</p>", unsafe_allow_html=True)

    # Get all intel items
    intel_items = db.get_recent_intel(limit=500)

    # Group by threat actors
    apt_intel = {}
    for item in intel_items:
        actors = item.get('threat_actors', [])
        if actors:
            for actor in actors:
                if actor not in apt_intel:
                    apt_intel[actor] = []
                apt_intel[actor].append(item)

    # Also get threat actor profiles
    threat_actors = db.get_threat_actors()
    actor_profiles = {ta['name']: ta for ta in threat_actors}

    if not apt_intel:
        st.info("📭 No APT-specific intelligence collected yet. Run the aggregator to collect more data.")
    else:
        # APT Summary metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("APT Groups Tracked", len(apt_intel))
        with col2:
            total_intel = sum(len(v) for v in apt_intel.values())
            st.metric("APT Intel Items", total_intel)
        with col3:
            avg_per_actor = total_intel // len(apt_intel) if apt_intel else 0
            st.metric("Avg Intel per APT", avg_per_actor)

        st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

        # APT Selector
        st.subheader("🎯 Select APT Group")

        sorted_apts = sorted(apt_intel.items(), key=lambda x: len(x[1]), reverse=True)
        apt_names = [apt[0] for apt in sorted_apts]
        selected_apt = st.selectbox("Choose an APT group", options=apt_names)

        if selected_apt:
            st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

            if selected_apt in actor_profiles:
                profile = actor_profiles[selected_apt]
                st.markdown(f"""
                <div class='apt-card'>
                    <h3 style='margin-top: 0; color: #c77dff;'>📋 {selected_apt} Profile</h3>
                </div>
                """, unsafe_allow_html=True)

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**📍 Origin:**")
                    st.write(profile.get('origin', 'Unknown'))
                    st.markdown("**💰 Motivation:**")
                    st.write(profile.get('motivation', 'Unknown'))
                    if profile.get('aliases'):
                        st.markdown("**🎭 Aliases:**")
                        for alias in profile['aliases']:
                            st.markdown(f"`{alias}`")
                with col2:
                    if profile.get('targets'):
                        st.markdown("**🎯 Target Sectors:**")
                        for target in profile['targets']:
                            st.markdown(f"`{target}`")
                    if profile.get('tools'):
                        st.markdown("**🛠️ Known Tools:**")
                        for tool in profile['tools'][:5]:
                            st.markdown(f"- {tool}")
                    if profile.get('techniques'):
                        st.markdown("**🎭 Common Techniques:**")
                        cols = st.columns(3)
                        for i, tech in enumerate(profile['techniques'][:6]):
                            with cols[i % 3]:
                                st.markdown(f"`{tech}`")

            st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
            st.subheader(f"📰 Intelligence for {selected_apt}")
            apt_items = apt_intel.get(selected_apt, [])

            # Extract related IOCs, malware, and techniques for this APT
            apt_iocs = []
            apt_malware = set()
            apt_techniques = set()
            apt_campaigns = set()
            
            for item in apt_items:
                # Get IOCs related to this intel
                item_iocs = db.get_iocs(limit=100)
                for ioc in item_iocs:
                    if ioc.get('source_url') == item.get('url'):
                        apt_iocs.append(ioc)
                # Collect malware families
                if item.get('malware_families'):
                    for m in item['malware_families']:
                        apt_malware.add(m)
                # Collect techniques
                if item.get('techniques'):
                    for t in item['techniques']:
                        apt_techniques.add(t)
                # Collect campaign names
                if item.get('campaign_name'):
                    apt_campaigns.add(item['campaign_name'])

            # Additional APT insights section
            st.markdown("### 🔍 APT Insights")
            
            insight_cols = st.columns(4)
            with insight_cols[0]:
                st.metric("Related IOCs", len(apt_iocs))
            with insight_cols[1]:
                st.metric("Malware Families", len(apt_malware))
            with insight_cols[2]:
                st.metric("Techniques Used", len(apt_techniques))
            with insight_cols[3]:
                st.metric("Campaigns", len(apt_campaigns))

            # Show malware, techniques, campaigns if available
            if apt_malware or apt_techniques or apt_campaigns:
                st.markdown("")
                meta_cols = st.columns(3)
                
                with meta_cols[0]:
                    if apt_malware:
                        st.markdown("**🦠 Malware:**")
                        for malware in list(apt_malware)[:5]:
                            st.markdown(f"`{malware}`")
                
                with meta_cols[1]:
                    if apt_campaigns:
                        st.markdown("**🎯 Campaigns:**")
                        for campaign in list(apt_campaigns)[:5]:
                            st.markdown(f"`{campaign}`")
                
                with meta_cols[2]:
                    if apt_techniques:
                        st.markdown("**🎭 Techniques:**")
                        for tech in list(apt_techniques)[:5]:
                            st.markdown(f"`{tech}`")

            # Related IOCs section
            if apt_iocs:
                st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
                st.markdown("### 🎯 Related IOCs")
                
                ioc_type_counts = {}
                for ioc in apt_iocs:
                    ioc_type = ioc.get('ioc_type', 'unknown')
                    ioc_type_counts[ioc_type] = ioc_type_counts.get(ioc_type, 0) + 1
                
                type_cols = st.columns(len(ioc_type_counts) if ioc_type_counts else 1)
                for i, (ioc_type, count) in enumerate(ioc_type_counts.items()):
                    with type_cols[i % len(type_cols)]:
                        st.metric(ioc_type.replace('_', ' ').title(), count)
                
                # Show IOC table
                ioc_display = []
                for ioc in apt_iocs[:20]:
                    ioc_display.append({
                        "Value": ioc['value'][:35] + "..." if len(ioc['value']) > 35 else ioc['value'],
                        "Type": ioc['ioc_type'],
                        "Confidence": ioc['confidence'],
                    })
                if ioc_display:
                    st.dataframe(pd.DataFrame(ioc_display), use_container_width=True, hide_index=True)

            # External Intelligence Links
            st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
            st.markdown("### 🔗 External Intelligence")
            
            ext_cols = st.columns(4)
            with ext_cols[0]:
                st.link_button("🔍 MITRE ATT&CK", f"https://attack.mitre.org/groups/")
            with ext_cols[1]:
                st.link_button("🦠 MalwareBazaar", f"https://bazaar.abuse.ch/browse/?search={selected_apt.replace(' ', '+')}")
            with ext_cols[2]:
                st.link_button("🌐 VirusTotal", f"https://www.virustotal.com/gui/search/{selected_apt.replace(' ', '+')}")
            with ext_cols[3]:
                st.link_button("📰 Google Search", f"https://www.google.com/search?q={selected_apt.replace(' ', '+')}+APT")

            st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
            
            # Intelligence items
            for item in apt_items[:20]:
                severity = item.get('severity', 'Low')
                sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                st.markdown(f"""
                <div class='intel-card'>
                    <h4 style='margin: 0 0 8px 0;'>{sev_icon} [{item.get('title', 'Unknown')}]({item.get('url', '#')})</h4>
                    <div style='color: #a0aec0; font-size: 0.85rem;'>
                        📍 {item.get('source', 'Unknown')} | 📅 {item.get('published_at', '')[:10] if item.get('published_at') else 'Unknown'}
                    </div>
                </div>
                """, unsafe_allow_html=True)
                if item.get('summary'):
                    st.markdown(item.get('summary', '')[:250] + '...')
                techniques = item.get('techniques', [])
                if techniques:
                    st.markdown("**MITRE ATT&CK:** " + " ".join([f"`{t}`" for t in techniques[:5]]))
                st.markdown("---")

# Tab 4: Threat Actors
with tab4:
    st.markdown("<div class='section-header'>👤 Tracked Threat Actors</div>", unsafe_allow_html=True)

    threat_actors = db.get_threat_actors()

    if not threat_actors:
        st.info("📭 No threat actors tracked yet.")
    else:
        # Threat Actor Summary
        st.markdown("### 📊 Overview")
        summary_cols = st.columns(3)
        with summary_cols[0]:
            st.metric("Total Groups", len(threat_actors))
        with summary_cols[1]:
            origins = set(a.get('origin', 'Unknown') for a in threat_actors if a.get('origin'))
            st.metric("Countries Represented", len(origins))
        with summary_cols[2]:
            all_tools = set()
            for a in threat_actors:
                if a.get('tools'):
                    all_tools.update(a.get('tools', []))
            st.metric("Unique Tools", len(all_tools))
        
        st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

        # Threat Actor Cards
        for actor in threat_actors:
            with st.expander(f"### {actor.get('name', 'Unknown')} - {actor.get('origin', 'Unknown')}", expanded=False):
                st.markdown(f"""
                <div class='apt-card'>
                    <h4 style='margin-top: 0; color: #c77dff;'>{actor.get('name', 'Unknown')}</h4>
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("**📍 Origin:**")
                    st.markdown(actor.get('origin', 'Unknown'))
                    st.markdown("**💰 Motivation:**")
                    st.markdown(actor.get('motivation', 'Unknown'))
                    if actor.get('aliases'):
                        st.markdown("**🎭 Aliases:**")
                        for alias in actor.get('aliases', []):
                            st.markdown(f"`{alias}`")
                
                with col2:
                    if actor.get('targets'):
                        st.markdown("**🎯 Target Sectors:**")
                        for target in actor.get('targets', []):
                            st.markdown(f"`{target}`")
                    if actor.get('tools'):
                        st.markdown("**🛠️ Known Tools:**")
                        for tool in actor.get('tools', [])[:8]:
                            st.markdown(f"- {tool}")
                
                with col3:
                    if actor.get('techniques'):
                        st.markdown("**🎭 MITRE ATT&CK:**")
                        for tech in actor.get('techniques', [])[:10]:
                            st.markdown(f"`{tech}`")
                
                # External Links
                st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
                st.markdown("**🔗 External Intelligence:**")
                
                actor_name = actor.get('name', '').replace(' ', '+')
                link_cols = st.columns(4)
                
                with link_cols[0]:
                    st.link_button("🔍 MITRE ATT&CK", f"https://attack.mitre.org/groups/?search={actor_name}")
                with link_cols[1]:
                    st.link_button("🦠 MalwareBazaar", f"https://bazaar.abuse.ch/browse/?search={actor_name}")
                with link_cols[2]:
                    st.link_button("🌐 VirusTotal", f"https://www.virustotal.com/gui/search/{actor_name}")
                with link_cols[3]:
                    st.link_button("📰 Google Search", f"https://www.google.com/search?q={actor_name}+APT+threat+actor")
                
                st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)

# Tab 5: Analytics
with tab5:
    st.markdown("<div class='section-header'>📊 Threat Intelligence Analytics</div>", unsafe_allow_html=True)

    stats = db.get_stats()
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📍 Intelligence by Source")
        if stats.get('by_source'):
            source_df = pd.DataFrame(list(stats['by_source'].items()), columns=['Source', 'Count'])
            st.bar_chart(source_df.set_index('Source'))

    with col2:
        st.subheader("⚠️ Severity Distribution")
        intel_items = db.get_recent_intel(limit=500)
        severity_counts = {}
        for item in intel_items:
            sev = item.get('severity', 'Unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if severity_counts:
            sev_df = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
            st.bar_chart(sev_df.set_index('Severity'))

    st.subheader("📈 Collection Timeline")
    intel_items = db.get_recent_intel(limit=200)
    timeline_data = {}
    for item in intel_items:
        date = item.get('published_at', '')[:10] if item.get('published_at') else 'Unknown'
        timeline_data[date] = timeline_data.get(date, 0) + 1
    if timeline_data:
        timeline_df = pd.DataFrame(list(timeline_data.items()), columns=['Date', 'Count'])
        timeline_df = timeline_df.sort_values('Date')
        st.line_chart(timeline_df.set_index('Date'))

    st.subheader("🎯 Top MITRE ATT&CK Techniques")
    technique_counts = {}
    for item in intel_items:
        techniques = item.get('techniques', [])
        if techniques:
            for tech in techniques:
                technique_counts[tech] = technique_counts.get(tech, 0) + 1
    if technique_counts:
        top_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        tech_df = pd.DataFrame(top_techniques, columns=['Technique', 'Count'])
        st.bar_chart(tech_df.set_index('Technique'))

    st.subheader("👤 Most Mentioned Threat Actors")
    actor_counts = {}
    for item in intel_items:
        actors = item.get('threat_actors', [])
        if actors:
            for actor in actors:
                actor_counts[actor] = actor_counts.get(actor, 0) + 1
    if actor_counts:
        top_actors = sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        actor_df = pd.DataFrame(top_actors, columns=['Actor', 'Mentions'])
        st.bar_chart(actor_df.set_index('Actor'))

# Footer
st.markdown("<div class='custom-divider'></div>", unsafe_allow_html=True)
st.markdown("""
<div style='text-align: center; color: #4a5568; padding: 30px 0;'>
    <p style='margin: 5px 0;'>🛡️ Threat Intel Hub | Free Threat Intelligence Aggregator</p>
    <p style='margin: 5px 0; font-size: 0.85rem;'>Data sources: RSS feeds, CISA, GitHub, and open-source intelligence</p>
</div>
""", unsafe_allow_html=True)