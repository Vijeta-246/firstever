import streamlit as st
import requests
import json

# Set up page configurations
st.set_page_config(page_title="Advanced Threat Intelligence Scanner", page_icon="🛡️", layout="centered")

# Retrieve the API key safely from Streamlit's secrets
try:
    API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except KeyError:
    st.error("🔑 **Missing API Key!** Please add `VIRUSTOTAL_API_KEY` to your Streamlit Secrets panel.")
    st.stop()

def get_risk_badge(malicious_count):
    """Determines risk tiers and prints semantic alert badges."""
    if malicious_count > 10:
        st.error("🚨 **RISK STATUS: HIGHLY DANGEROUS** (This IP is associated with known malicious activity)")
    elif 1 <= malicious_count <= 10:
        st.warning("⚠️ **RISK STATUS: SUSPICIOUS** (Potential threat detected by a limited subset of engine scanners)")
    else:
        st.success("✅ **RISK STATUS: CLEAN / SAFE** (No security engines flagged this IP address)")

def scan_suspicious_ip(ip_address):
    clean_ip = str(ip_address).strip()
    full_url = f"https://virustotal.com{clean_ip}"
    
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }
    
    status_box = st.info(f"🔄 Querying VirusTotal database for IP: `{clean_ip}`...")
    
    try:
        # 12-second timeout to handle proxy lags cleanly
        response = requests.get(full_url, headers=headers, timeout=12)
        status_box.empty()
        
        if response.status_code == 200:
            raw_data = response.json()
            attributes = raw_data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            st.success(f"📊 Assessment Completed for: `{clean_ip}`")
            
            # --- RISK BADGE SUMMARY ---
            get_risk_badge(malicious)
            
            # Metric Columns Layout
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric(label="🚨 Malicious", value=malicious)
            with col2:
                st.metric(label="⚠️ Suspicious", value=stats.get('suspicious', 0))
            with col3:
                st.metric(label="🛡️ Harmless", value=stats.get('harmless', 0))
            with col4:
                st.metric(label="⚪ Undetected", value=stats.get('undetected', 0))
            
            # Extracting Network & Regional Info
            as_owner = attributes.get('as_owner', 'Unknown Provider')
            country = attributes.get('country', 'Unknown Country')
            reputation = attributes.get('reputation', 0)
            
            # --- TEXT DETAILS LAYOUT ---
            st.markdown("### 🏢 Infrastructure Profile")
            st.write(f"* **Network Autonomous System (ASN):** `{as_owner}`")
            st.write(f"* **Country Registry:** `{country}`")
            st.write(f"* **Global Trust Reputation Score:** `{reputation}` points")
            
            # --- DOWNLOADABLE SCAN DATA REPORT ---
            st.markdown("### 📥 Threat Record Export")
            report_content = (
                f"### Threat Intel Scan Report\n"
                f"- **Target IP Address:** {clean_ip}\n"
                f"- **ISP/Host Owner:** {as_owner}\n"
                f"- **Country Registry:** {country}\n"
                f"- **Malicious Flags Total:** {malicious}\n"
                f"- **Full Intelligence JSON Block:**\n\n```json\n"
                f"{json.dumps(raw_data, indent=2)}\n```"
            )
            
            st.download_button(
                label="📥 Download Markdown Scan Report (.md)",
                data=report_content,
                file_name=f"VT_Report_{clean_ip}.md",
                mime="text/markdown"
            )
                
        elif response.status_code in:
            st.error("🔑 **Authentication Failed.** Confirm that your configured Streamlit Secrets API token string is correct.")
        elif response.status_code == 404:
            st.warning(f"🔍 IP address `{clean_ip}` was not discovered in VirusTotal's indexed logs.")
        elif response.status_code == 429:
            st.error("⏱️ **API Volumetric Cap Hit.** Standard evaluation keys are limited to 4 lookups per minute.")
        else:
            st.error(f"🌐 Upstream routing pipeline error. Service Status Code: {response.status_code}")

    except requests.exceptions.Timeout:
        status_box.empty()
        st.error("⏱️ **Proxy Timeout Encountered.** The server took too long handling the backend socket thread. Resubmit.")
    except Exception as e:
        status_box.empty()
        st.error(f"❌ **Unexpected script error condition:** {e}")

# --- Front End Layout View ---
st.title("🛡️Automated Threat Intelligence Web IP Scanner")
st.write("Perform automated indicators-of-compromise (IoC) evaluation on network endpoints to isolate malicious domains.")

user_ip = st.text_input("Enter a target server IP address to evaluate:", placeholder="e.g., 8.8.8.8")

if user_ip:
    scan_suspicious_ip(user_ip)
