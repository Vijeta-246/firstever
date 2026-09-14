import streamlit as st
import requests

# Set page layout and design
st.set_page_config(page_title="Threat Intelligence Scanner", page_icon="🛡️", layout="centered")

# Retrieve the API key safely from Streamlit's secrets
try:
    API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except KeyError:
    st.error("🔑 **Missing API Key!** Please add `VIRUSTOTAL_API_KEY` to your Streamlit Secrets panel.")
    st.stop()

def scan_suspicious_ip(ip_address):
    # Clean the input to ensure there are no lingering spaces
    clean_ip = str(ip_address).strip()
    
    # SAFE URL CONSTRUCTION: Employs an f-string to guarantee a trailing slash separator
    full_url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
    
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }
    
    # Status loading message
    status_box = st.info(f"🔄 Contacting VirusTotal to scan IP: `{clean_ip}`...")
    
    try:
        # Added a 10-second timeout to handle slow cloud proxies
        response = requests.get(full_url, headers=headers, timeout=10)
        
        # Clear the status indicator
        status_box.empty()
        
        if response.status_code == 200:
            raw_data = response.json()
            
            # Navigate safety fields inside the nested JSON response safely
            attributes = raw_data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            # Visual presentation of results
            st.success(f"✅ Scan completed for: `{clean_ip}`")
            
            # Display stats inside structured metrics layout
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(label="🚨 Malicious", value=stats.get('malicious', 0))
            with col2:
                st.metric(label="⚠️ Suspicious", value=stats.get('suspicious', 0))
            with col3:
                st.metric(label="🛡️ Harmless", value=stats.get('harmless', 0))
                
            # Extra context data if available
            as_owner = attributes.get('as_owner', 'Unknown Provider')
            country = attributes.get('country', 'Unknown Country')
            st.caption(f"**Network Details:** Provided by `{as_owner}` | Country Code: `{country}`")
            
        elif response.status_code == 401 or response.status_code == 403:
            st.error("🔑 **Authentication Failed.** Your VirusTotal API key is invalid or lacks access permissions.")
        elif response.status_code == 404:
            st.warning(f"🔍 IP address `{clean_ip}` was not found in the VirusTotal index.")
        elif response.status_code == 429:
            st.error("⏱️ **Rate Limit Exceeded.** Free keys are capped at 4 requests per minute. Wait a bit and try again.")
        else:
            st.error(f"🌐 Cloud server failed to fetch data. HTTP Code: {response.status_code}")

    except requests.exceptions.Timeout:
        status_box.empty()
        st.error("⏱️ **Connection Timed Out.** The cloud proxy took too long to reach VirusTotal. Please click scan again.")
    except Exception as e:
        status_box.empty()
        st.error(f"❌ **An unexpected error occurred:** {e}")

# --- Streamlit UI App Interface ---
st.title("🛡️ Automated Threat Intelligence IP Scanner")
st.write("Input a suspicious network IP address below to inspect live risk attributes and safety metrics.")

user_ip = st.text_input("Enter a suspicious IP address to scan:", placeholder="e.g., 8.8.8.8")

# Trigger scan only when user provides an input string
if user_ip:
    scan_suspicious_ip(user_ip)
