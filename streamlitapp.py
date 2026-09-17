import streamlit as st
import requests
import json

# Set up page configurations
st.set_page_config(page_title="Easy IP Security Checker", page_icon="🛡️", layout="centered")

# Retrieve the API key safely from Streamlit's secrets
try:
    API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except KeyError:
    st.error("🔑 **Missing API Key!** Please add `VIRUSTOTAL_API_KEY` to your Streamlit Secrets panel.")
    st.stop()

def get_risk_badge(malicious_count):
    """Determines risk tiers and prints semantic alert badges."""
    if malicious_count > 10:
        st.error("🚨 **RISK STATUS: VERY DANGEROUS** (This IP address is blocked or flagged for bad activity!)")
    elif 1 <= malicious_count <= 10:
        st.warning("⚠️ **RISK STATUS: SUSPICIOUS** (A few security tools flagged this IP. Use with caution.)")
    else:
        st.success("✅ **RISK STATUS: CLEAN & SAFE** (No security tools found anything bad here!)")

def scan_suspicious_ip(ip_address):
    clean_ip = str(ip_address).strip()
    
    # BULLETPROOF FIXED URL: Directly hardcoded with explicit trailing slash
    full_url = "https://virustotal.com" + clean_ip
    
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }
    
    status_box = st.info(f"🔄 Scanning... Checking the history of IP address: `{clean_ip}`")
    
    try:
        # 12-second timeout to handle proxy lags cleanly
        response = requests.get(full_url, headers=headers, timeout=12)
        status_box.empty()
        
        if response.status_code == 200:
            raw_data = response.json()
            attributes = raw_data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            st.success(f"📊 Scan Finished for: `{clean_ip}`")
            
            # --- RISK BADGE SUMMARY ---
            get_risk_badge(malicious)
            
            # Metric Columns Layout (Simple clear vocabulary)
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric(label="🚨 Dangerous", value=malicious)
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
            
            # --- TEXT DETAILS LAYOUT (Simplified descriptions) ---
            st.markdown("### 🏢 Network & Owner Details")
            st.write(f"* **Company / Internet Provider:** `{as_owner}`")
            st.write(f"* **Country Where Registered:** `{country}`")
            st.write(f"* **Overall Safety Trust Score:** `{reputation}` points")
            
            # --- DOWNLOADABLE SCAN DATA REPORT ---
            st.markdown("### 📥 Save Results")
            report_content = (
                f"### IP Security Scan Report\n"
                f"- **Scanned IP Address:** {clean_ip}\n"
                f"- **Company / Owner:** {as_owner}\n"
                f"- **Registered Country:** {country}\n"
                f"- **Total Dangerous Flags:** {malicious}\n"
                f"- **Full Technical Data Block:**\n\n```json\n"
                f"{json.dumps(raw_data, indent=2)}\n```"
            )
            
            st.download_button(
                label="📥 Download Scan Report (.md)",
                data=report_content,
                file_name=f"IP_Report_{clean_ip}.md",
                mime="text/markdown"
            )
                
        elif response.status_code == 401 or response.status_code == 403:
            st.error("🔑 **Key Error.** Your VirusTotal API key is wrong. Please update it in your secrets setup.")
        elif response.status_code == 404:
            st.warning(f"🔍 Sorry, this IP address `{clean_ip}` could not be found in the database system.")
        elif response.status_code == 429:
            st.error("⏱️ **Too Many Requests.** Free accounts can only scan 4 IPs per minute. Please wait 60 seconds.")
        else:
            st.error(f"🌐 Server connection error. Code: {response.status_code}")

    except requests.exceptions.Timeout:
        status_box.empty()
        st.error("⏱️ **Time Out.** The server took too long to reply. Please click scan again.")
    except Exception as e:
        status_box.empty()
        st.error(f"❌ **An unexpected issue occurred:** {e}")

# --- Front End Layout View (Easy Words) ---
st.title("🛡️ Automated Threat Intelligence Web IP Scanner")
st.write("Type any network IP address down below to check if it is safe, suspicious, or dangerous to use.")

user_ip = st.text_input("Enter the IP address you want to check:", placeholder="e.g., 8.8.8.8")

if user_ip:
    scan_suspicious_ip(user_ip)
