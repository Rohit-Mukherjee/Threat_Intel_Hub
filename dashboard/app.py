"""Threat Intelligence Dashboard - Streamlit App."""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import ThreatIntelDB

# Page config
st.set_page_config(
    page_title="Threat Intel Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #1e1e1e;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        border-left: 4px solid #ff4b4b;
    }
    .threat-actor-card {
        background-color: #262730;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .severity-critical { border-left-color: #ff0000; }
    .severity-high { border-left-color: #ff6b6b; }
    .severity-medium { border-left-color: #ffa500; }
    .severity-low { border-left-color: #00ff00; }
    
    [data-testid="stMetricValue"] {
        font-size: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize database
db = ThreatIntelDB("data/threat_intel.db")

# Sidebar
st.sidebar.title("🛡️ Threat Intel Hub")
st.sidebar.markdown("---")

# Auto-refresh option
auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
if auto_refresh:
    st.rerun()

# Manual refresh button
if st.sidebar.button("🔄 Refresh Data"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### Quick Filters")

# Get stats
stats = db.get_stats()

# Sidebar filters
severity_filter = st.sidebar.multiselect(
    "Severity",
    options=['Critical', 'High', 'Medium', 'Low'],
    default=['Critical', 'High', 'Medium']
)

source_filter = st.sidebar.multiselect(
    "Sources",
    options=list(stats.get('by_source', {}).keys()),
    default=list(stats.get('by_source', {}).keys())[:5]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Database Stats")
st.sidebar.metric("Intel Items", stats.get('intel_items', 0))
st.sidebar.metric("Attack Chains", stats.get('attack_chains', 0))
st.sidebar.metric("Threat Actors", stats.get('threat_actors', 0))

# Main content
st.title("🛡️ Threat Intelligence Dashboard")
st.markdown("*Real-time threat intelligence aggregation and analysis*")

# Top metrics row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="📰 Intel Items",
        value=stats.get('intel_items', 0),
        delta="Total"
    )

with col2:
    st.metric(
        label="⛓️ Attack Chains",
        value=stats.get('attack_chains', 0),
        delta="Documented"
    )

with col3:
    st.metric(
        label="👤 Threat Actors",
        value=stats.get('threat_actors', 0),
        delta="Tracked"
    )

with col4:
    critical_count = len([i for i in db.get_recent_intel(100) if i.get('severity') == 'Critical'])
    st.metric(
        label="🔴 Critical Alerts",
        value=critical_count,
        delta="Recent"
    )

st.markdown("---")

# Tabs for different views
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📰 Latest Intelligence",
    "🎯 IOCs",
    "👥 APT Intelligence",
    "⛓️ Attack Chains",
    "👤 Threat Actors",
    "📊 Analytics"
])

# Tab 1: Latest Intelligence
with tab1:
    st.header("Latest Threat Intelligence")
    
    # Search box
    search_query = st.text_input("🔍 Search intelligence...", placeholder="Search by title, technique, or actor...")
    
    # Get recent intel
    intel_items = db.get_recent_intel(limit=100)
    
    # Filter items
    filtered_items = []
    for item in intel_items:
        if item.get('severity') not in severity_filter:
            continue
        if item.get('source') not in source_filter and source_filter:
            continue
        if search_query:
            query_lower = search_query.lower()
            if not (query_lower in item.get('title', '').lower() or
                    query_lower in item.get('summary', '').lower()):
                continue
        filtered_items.append(item)
    
    # Display intel items
    for item in filtered_items[:30]:  # Limit display
        severity_class = f"severity-{item.get('severity', 'low').lower()}"
        
        with st.container():
            col1, col2 = st.columns([4, 1])
            
            with col1:
                st.markdown(f"### [{item.get('title', 'Unknown')}]({item.get('url', '#')})")
                
                # Metadata
                meta = []
                if item.get('source'):
                    meta.append(f"📍 {item.get('source')}")
                if item.get('published_at'):
                    try:
                        pub_date = datetime.fromisoformat(item.get('published_at'))
                        meta.append(f"📅 {pub_date.strftime('%Y-%m-%d')}")
                    except:
                        pass
                
                st.markdown(" | ".join(meta))
                
                # Summary
                if item.get('summary'):
                    st.markdown(item.get('summary'))
                
                # Tags
                tags = item.get('tags', [])
                threat_actors = item.get('threat_actors', [])
                techniques = item.get('techniques', [])
                
                tag_cols = st.columns(3)
                
                with tag_cols[0]:
                    if threat_actors:
                        st.markdown("**👤 Threat Actors:**")
                        for actor in threat_actors[:3]:
                            st.markdown(f"`{actor}`")
                
                with tag_cols[1]:
                    if techniques:
                        st.markdown("**🎯 MITRE ATT&CK:**")
                        for tech in techniques[:5]:
                            st.markdown(f"`{tech}`")
                
                with tag_cols[2]:
                    if tags:
                        st.markdown("**🏷️ Tags:**")
                        for tag in tags[:5]:
                            st.markdown(f"`{tag}`")
            
            with col2:
                severity = item.get('severity', 'Low')
                if severity == 'Critical':
                    st.error(f"**{severity}**")
                elif severity == 'High':
                    st.warning(f"**{severity}**")
                elif severity == 'Medium':
                    st.info(f"**{severity}**")
                else:
                    st.success(f"**{severity}**")
            
            st.markdown("---")

# Tab 2: IOCs
with tab2:
    st.header("🎯 Indicators of Compromise (IOCs)")
    st.markdown("*Extracted, enriched, and ready for export to your security tools*")
    
    # IOC Stats
    ioc_stats = db.get_ioc_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total IOCs", ioc_stats.get('total', 0))
    with col2:
        high_conf = ioc_stats.get('by_confidence', {}).get('High', 0)
        st.metric("High Confidence", high_conf)
    with col3:
        domains = ioc_stats.get('by_type', {}).get('domain', 0)
        st.metric("Domains", domains)
    with col4:
        hashes = (ioc_stats.get('by_type', {}).get('md5', 0) + 
                  ioc_stats.get('by_type', {}).get('sha256', 0))
        st.metric("File Hashes", hashes)
    
    st.markdown("---")
    
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
        search_query = st.text_input("Search", placeholder="Search IOCs...")
    
    # Get IOCs
    ioc_type = None if ioc_type_filter == 'All' else ioc_type_filter
    confidence = None if confidence_filter == 'All' else confidence_filter
    
    iocs = db.get_iocs(
        ioc_type=ioc_type,
        confidence=confidence,
        search_query=search_query if search_query else None,
        limit=500
    )
    
    # Display IOCs
    if not iocs:
        st.info("No IOCs found. Run the aggregator to extract IOCs from threat intel feeds.")
    else:
        # Export options
        st.markdown("### 📤 Export IOCs")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            if st.button("CSV", use_container_width=True):
                csv_data = db.export_iocs(format='csv', ioc_types=[ioc_type] if ioc_type else None)
                st.download_button(
                    label="⬇️ Download CSV",
                    data=csv_data,
                    file_name=f"iocs_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("JSON", use_container_width=True):
                json_data = db.export_iocs(format='json', ioc_types=[ioc_type] if ioc_type else None)
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_data,
                    file_name=f"iocs_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )
        
        with col3:
            if st.button("STIX 2.1", use_container_width=True):
                stix_data = db.export_iocs(format='stix', ioc_types=[ioc_type] if ioc_type else None)
                st.download_button(
                    label="⬇️ Download STIX",
                    data=stix_data,
                    file_name=f"iocs_{datetime.now().strftime('%Y%m%d')}.stix.json",
                    mime="application/json"
                )
        
        with col4:
            if st.button("MISP", use_container_width=True):
                misp_data = db.export_iocs(format='misp', ioc_types=[ioc_type] if ioc_type else None)
                st.download_button(
                    label="⬇️ Download MISP",
                    data=misp_data,
                    file_name=f"iocs_{datetime.now().strftime('%Y%m%d')}.misp.json",
                    mime="application/json"
                )
        
        with col5:
            if st.button("Sigma Rules", use_container_width=True):
                sigma_data = db.export_iocs(format='opensearch', ioc_types=[ioc_type] if ioc_type else None)
                st.download_button(
                    label="⬇️ Download Sigma",
                    data=sigma_data,
                    file_name=f"iocs_{datetime.now().strftime('%Y%m%d')}.sigma.yml",
                    mime="text/yaml"
                )
        
        st.markdown("---")

        # IOC Table
        st.markdown("### 📋 IOC List")

        # Prepare data for display
        display_data = []
        for ioc in iocs[:100]:  # Limit display
            display_data.append({
                "Value": ioc['value'][:40] + "..." if len(ioc['value']) > 40 else ioc['value'],
                "Type": ioc['ioc_type'],
                "Confidence": ioc['confidence'],
                "Source": ioc['source'],
                "Malware": ioc.get('malware_family', '-') or '-',
            })

        st.dataframe(
            display_data,
            use_container_width=True,
            hide_index=True
        )

        # Quick Threat Intel Lookup Section
        st.markdown("---")
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
                ioc_type = next(v[2] for v in lookup_iocs if v[0] == selected_lookup_ioc)
                
                st.markdown(f"**Selected IOC:** `{ioc_value}` ({ioc_type})")
                st.markdown("---")
                
                # Build lookup URLs based on IOC type
                vt_url = None
                abuseipdb_url = None
                shodan_url = None
                censys_url = None
                urlhaus_url = None
                malwarebazaar_url = None
                
                if ioc_type in ['md5', 'sha1', 'sha256']:
                    vt_url = f"https://www.virustotal.com/gui/file/{ioc_value}"
                    malwarebazaar_url = f"https://bazaar.abuse.ch/browse.php?search={ioc_value}"
                elif ioc_type == 'ip_address':
                    vt_url = f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
                    abuseipdb_url = f"https://www.abuseipdb.com/check/{ioc_value}"
                    shodan_url = f"https://www.shodan.io/host/{ioc_value}"
                    censys_url = f"https://search.censys.io/hosts/{ioc_value}"
                elif ioc_type == 'domain':
                    vt_url = f"https://www.virustotal.com/gui/domain/{ioc_value}"
                    shodan_url = f"https://www.shodan.io/domain/{ioc_value}"
                elif ioc_type == 'url':
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
                    elif ioc_type not in ['ip_address']:
                        st.markdown("")
                
                with cols[2]:
                    if shodan_url:
                        st.link_button("🌐 Shodan", shodan_url)
                    elif ioc_type not in ['ip_address', 'domain']:
                        st.markdown("")
                
                with cols[3]:
                    if censys_url:
                        st.link_button("🔎 Censys", censys_url)
                    elif ioc_type != 'ip_address':
                        st.markdown("")
                
                # Second row for malware-specific lookups
                if malwares_urls := [url for url in [malwarebazaar_url, urlhaus_url] if url]:
                    cols2 = st.columns(2)
                    with cols2[0]:
                        if malwarebazaar_url:
                            st.link_button("🦠 MalwareBazaar", malwarebazaar_url)
                    with cols2[1]:
                        if urlhaus_url:
                            st.link_button("🔗 URLhaus", urlhaus_url)
                
                st.info(f"**Tip:** Click any button above to open the IOC in that threat intelligence platform.")

        # Detailed view
        if iocs:
            st.markdown("---")
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
                    st.markdown("---")
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
    st.header("👥 APT Intelligence by Group")
    st.markdown("*Threat intelligence segregated by APT groups and threat actors*")
    
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
        st.info("No APT-specific intelligence collected yet. Run the aggregator to collect more data.")
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
        
        st.markdown("---")
        
        # APT Selector
        st.subheader("🎯 Select APT Group")
        
        # Sort by number of intel items
        sorted_apts = sorted(apt_intel.items(), key=lambda x: len(x[1]), reverse=True)
        
        apt_names = [apt[0] for apt in sorted_apts]
        selected_apt = st.selectbox("Choose an APT group", options=apt_names)
        
        if selected_apt:
            st.markdown("---")
            
            # Display APT profile if available
            if selected_apt in actor_profiles:
                profile = actor_profiles[selected_apt]
                
                st.subheader(f"📋 {selected_apt} Profile")
                
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
                
                st.markdown("---")
            
            # Display intel for selected APT
            st.subheader(f"📰 Intelligence for {selected_apt}")
            
            apt_items = apt_intel.get(selected_apt, [])
            
            for item in apt_items[:20]:  # Limit display
                with st.container():
                    severity = item.get('severity', 'Low')
                    
                    # Severity indicator
                    if severity == 'Critical':
                        sev_icon = "🔴"
                    elif severity == 'High':
                        sev_icon = "🟠"
                    elif severity == 'Medium':
                        sev_icon = "🟡"
                    else:
                        sev_icon = "🟢"
                    
                    st.markdown(f"### {sev_icon} [{item.get('title', 'Unknown')}]({item.get('url', '#')})")
                    
                    meta = []
                    if item.get('source'):
                        meta.append(f"📍 {item.get('source')}")
                    if item.get('published_at'):
                        try:
                            pub_date = datetime.fromisoformat(item.get('published_at'))
                            meta.append(f"📅 {pub_date.strftime('%Y-%m-%d')}")
                        except:
                            pass
                    
                    st.markdown(" | ".join(meta))
                    
                    if item.get('summary'):
                        st.markdown(item.get('summary'))
                    
                    # Show techniques
                    techniques = item.get('techniques', [])
                    if techniques:
                        st.markdown("**MITRE ATT&CK:**")
                        for tech in techniques[:5]:
                            st.markdown(f"`{tech}`")
                    
                    st.markdown("---")

# Tab 4: Attack Chains
with tab4:
    st.header("⛓️ Attack Chain Analysis")
    st.markdown("*Detailed attack chains mapped to MITRE ATT&CK kill chain*")
    
    attack_chains = db.get_attack_chains(limit=20)
    
    if not attack_chains:
        st.info("No attack chains documented yet. The collectors will populate this as data becomes available.")
    else:
        for chain in attack_chains:
            with st.expander(f"🎯 {chain.get('campaign_name', 'Unknown Campaign')} - {chain.get('source', 'Unknown')}"):
                st.markdown(f"**Source:** [{chain.get('source')}]({chain.get('url', '#')})")
                
                if chain.get('published_at'):
                    try:
                        pub_date = datetime.fromisoformat(chain.get('published_at'))
                        st.markdown(f"**Published:** {pub_date.strftime('%Y-%m-%d')}")
                    except:
                        pass
                
                st.markdown("---")
                st.markdown("### 🔗 Kill Chain Phases")
                
                # Display attack chain phases
                phases = [
                    ('Initial Access', chain.get('initial_access')),
                    ('Execution', chain.get('execution')),
                    ('Persistence', chain.get('persistence')),
                    ('Defense Evasion', chain.get('defense_evasion')),
                    ('Lateral Movement', chain.get('lateral_movement')),
                    ('Command & Control', chain.get('command_control')),
                    ('Exfiltration', chain.get('exfiltration')),
                ]
                
                for phase_name, phase_data in phases:
                    if phase_data:
                        st.markdown(f"**{phase_name}:** {phase_data}")
                
                # MITRE Techniques
                mitre_techniques = chain.get('mitre_techniques', [])
                if mitre_techniques:
                    st.markdown("---")
                    st.markdown("### 🎯 MITRE ATT&CK Techniques")
                    cols = st.columns(4)
                    for i, tech in enumerate(mitre_techniques[:12]):
                        with cols[i % 4]:
                            st.markdown(f"`{tech}`")

# Tab 5: Threat Actors
with tab5:
    st.header("👤 Tracked Threat Actors")
    
    threat_actors = db.get_threat_actors()
    
    if not threat_actors:
        st.info("No threat actors tracked yet.")
    else:
        # Create cards for each threat actor
        for actor in threat_actors:
            with st.container():
                st.markdown(f"### {actor.get('name', 'Unknown')}")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📍 Origin:**")
                    st.markdown(actor.get('origin', 'Unknown'))
                    
                    st.markdown("**💰 Motivation:**")
                    st.markdown(actor.get('motivation', 'Unknown'))
                    
                    if actor.get('aliases'):
                        st.markdown("**🎭 Aliases:**")
                        for alias in actor.get('aliases', []):
                            st.markdown(f"- {alias}")
                
                with col2:
                    if actor.get('targets'):
                        st.markdown("**🎯 Target Sectors:**")
                        for target in actor.get('targets', []):
                            st.markdown(f"`{target}`")
                    
                    if actor.get('tools'):
                        st.markdown("**🛠️ Known Tools:**")
                        for tool in actor.get('tools', [])[:5]:
                            st.markdown(f"- {tool}")
                    
                    if actor.get('techniques'):
                        st.markdown("**🎭 Common Techniques:**")
                        for tech in actor.get('techniques', [])[:5]:
                            st.markdown(f"`{tech}`")
                
                st.markdown("---")

# Tab 6: Analytics
with tab6:
    st.header("📊 Threat Intelligence Analytics")
    
    # Get fresh stats
    stats = db.get_stats()
    
    # Source distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📍 Intelligence by Source")
        if stats.get('by_source'):
            source_df = pd.DataFrame(
                list(stats['by_source'].items()),
                columns=['Source', 'Count']
            )
            st.bar_chart(source_df.set_index('Source'))
    
    with col2:
        st.subheader("⚠️ Severity Distribution")
        intel_items = db.get_recent_intel(limit=500)
        severity_counts = {}
        for item in intel_items:
            sev = item.get('severity', 'Unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        if severity_counts:
            sev_df = pd.DataFrame(
                list(severity_counts.items()),
                columns=['Severity', 'Count']
            )
            st.bar_chart(sev_df.set_index('Severity'))
    
    # Recent activity timeline
    st.subheader("📈 Collection Timeline")
    
    # Get items with dates
    intel_items = db.get_recent_intel(limit=200)
    timeline_data = {}
    
    for item in intel_items:
        date = item.get('published_at', '')[:10] if item.get('published_at') else 'Unknown'
        timeline_data[date] = timeline_data.get(date, 0) + 1
    
    if timeline_data:
        timeline_df = pd.DataFrame(
            list(timeline_data.items()),
            columns=['Date', 'Count']
        )
        timeline_df = timeline_df.sort_values('Date')
        st.line_chart(timeline_df.set_index('Date'))
    
    # Top techniques
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
    
    # Top threat actors mentioned
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
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: gray;'>
    <p>🛡️ Threat Intel Hub | Free Threat Intelligence Aggregator</p>
    <p>Data sources: RSS feeds, CISA, GitHub, and open-source intelligence</p>
</div>
""", unsafe_allow_html=True)
