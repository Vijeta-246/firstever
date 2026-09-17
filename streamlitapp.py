import streamlit as st
import requests
import json
import base64

# Set up page configurations
st.set_page_config(page_title="Universal Threat Intelligence Scanner", page_icon="🛡️", layout="centered")

# Retrieve the API key safely from Streamlit's secrets
try:
    API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except KeyError:
    st.error("🔑 **Missing API Key!** Please add `VIRUSTOTAL_API_KEY` to your Streamlit Secrets panel.")
    st.stop()

def get_risk_badge(malicious_count):
    """Determines risk tiers and prints semantic alert badges."""
    if malicious_count > 10:
        st.error(f"🚨 **RISK STATUS: HIGHLY DANGEROUS** ({malicious_count} security engines flagged this target)")
    elif 1 <= malicious_count <= 10:
        st.warning(f"⚠️ **RISK STATUS: SUSPICIOUS** ({malicious_count} security engines flagged this target)")
    else:
        st.success("✅ **RISK STATUS: CLEAN / SAFE** (No security engines flagged this target address)")

def is_valid_ip(input_string):
    """
    Fixed IP Checker: Reliably splits by dots and validates numbers
    without relying on broken regex strings.
    """
    parts = input_string.strip().split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def scan_target(user_input):
    raw_input = user_input.strip()
    if not raw_input:
        return
        
    # --- FIXED ROUTING LOGIC ---
    if is_valid_ip(raw_input):
        target_type = "IP Address"
        full_url = f"https://virustotal.com{raw_input}"
    else:
        target_type = "URL/Domain"
        # Clean potential http prefixes from raw domains if users type them out
        clean_url = raw_input
        if "://" in clean_url:
            clean_url = clean_url.split("://")[-1]
            
        # VirusTotal V3 endpoints require target URLs to be converted into an unpadded Base64 encoded alphanumeric string
        encoded_url = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
        full_url = f"https://virustotal.com{encoded_url}"
    
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }
    
    status_box = st.info(f"🔄 Querying VirusTotal database for {target_type}: `{raw_input}`...")
    
    try:
        # 12-second timeout to handle proxy lags cleanly
        response = requests.get(full_url, headers=headers, timeout=12)
        status_box.empty()
        
        if response.status_code == 200:
            raw_data = response.json()
            attributes = raw_data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            st.success(f"📊 Assessment Completed for {target_type}: `{raw_input}`")
            
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
            
            # --- CONTEXT-AWARE DETAILS LAYOUT ---
            st.markdown("### 🏢 Infrastructure Profile")
            if target_type == "IP Address":
                as_owner = attributes.get('as_owner', 'Unknown Provider')
                country = attributes.get('country', 'Unknown Country')
                st.write(f"* **Network Autonomous System (ASN):** `{as_owner}`")
                st.write(f"* **Country Registry:** `{country}`")
            else:
                title = attributes.get('title', 'No Site Title Registered')
                categories = attributes.get('categories', {})
                category_str = ", ".join(categories.values()) if categories else "Uncategorized"
                st.write(f"* **HTML Page Title:** `{title}`")
                st.write(f"* **Content Categories:** `{category_str}`")

            reputation = attributes.get('reputation', 0)
            st.write(f"* **Global Trust Reputation Score:** `{reputation}` points")
            
            # --- DOWNLOADABLE SCAN DATA REPORT ---
            st.markdown("### 📥 Threat Record Export")
            report_content = (
                f"### Threat Intel Scan Report\n"
                f"- **Target Type Verified:** {target_type}\n"
                f"- **Scanned Target:** {raw_input}\n"
                f"- **Malicious Flags Total:** {malicious}\n"
                f"- **Full Intelligence JSON Block:**\n\n```json\n"
                f"{json.dumps(raw_data, indent=2)}\n```"
            )
            
            st.download_button(
                label="📥 Download Markdown Scan Report (.md)",
                data=report_content,
                file_name=f"VT_{target_type.replace(' ', '_')}_{raw_input}.md",
                mime="text/markdown"
            )
                
        elif response.status_code == 401 or response.status_code == 403:
            st.error("🔑 **Authentication Failed.** Confirm that your configured Streamlit Secrets API token string is correct.")
        elif response.status_code == 404:
            st.warning(f"🔍 The {target_type} `{raw_input}` was not discovered in VirusTotal's indexed logs.")
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
st.title("🛡️ Automated Threat Intelligence Analysis Engine")
st.write("Perform automated indicators-of-compromise (IoC) evaluation on network endpoints or URLs instantly.")

user_input = st.text_input("Enter a target server IP address or Website URL to evaluate:", placeholder="e.g., 8.8.8.8 or google.com")

if user_input:
    scan_target(user_input)
