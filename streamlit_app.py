import streamlit as st
import requests

# SECURE: Fetch the API key safely from Streamlit's environment secrets
# (Do NOT paste your raw API key string here anymore)
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]

def scan_suspicious_ip(ip_address):
    # ❌ If your line looks like this, it causes a 404:
    # base_url = "https://virustotal.com" 
    
    # ✅ Change it to this exact V3 API path:
    base_url = "https://virustotal.comapi/v3/ip_addresses/"
    
    full_url = f"{base_url}{str(ip_address).strip()}"

    
    # 📥 ADD THE NEW CODE RIGHT HERE:
    headers = {
        "accept": "application/json",
        "x-apikey": "YOUR_ACTUAL_VIRUSTOTAL_API_KEY"
    }
    
    # Update your request line to look like this:
    response = requests.get(full_url, headers=headers)

    
    try:
        response = requests.get(full_url, headers=headers)
        
        if response.status_code != 200:
            st.error(f"Connection failed. Server Status Code: {response.status_code}")
            return

        raw_data = response.json()
        stats = raw_data['data']['attributes']['last_analysis_stats']
        
        # Display the results neatly using Streamlit metrics
        st.subheader(f"📊 Scan Results for: `{ip_address}`")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric(label="Malicious Flags 🚨", value=stats['malicious'])
        with col2:
            st.metric(label="Harmless Flags ✅", value=stats['harmless'])

    except Exception as e:
        st.error(f"An unexpected issue occurred: {e}")

# --- Streamlit UI Setup ---
st.title("🛡️ VirusTotal IP Threat Scanner")
st.write("Enter a suspicious IP address below to query live reputation metrics from VirusTotal.")

# Replaces input() with a text field widget
user_ip = st.text_input("Enter a suspicious IP address:", placeholder="e.g., 8.8.8.8")

# Replaces standard script execution with an interactive button trigger
if st.button("Run Threat Scan"):
    if user_ip:
        scan_suspicious_ip(user_ip)
    else:
        st.warning("Please type a valid IP address first.")
