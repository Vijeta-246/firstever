import streamlit as st
import requests

# Fetch the API key safely from Streamlit's secrets
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]

def scan_suspicious_ip(ip_address):
    # PERMANENT FIX: Using the global API endpoint with an explicit timeout 
    # to prevent Streamlit Cloud server routing freezes
    #  RIGHT: Notice the "/" at the very end of the string
    #  RIGHT: Notice the "/" at the very end of the string
  base_url = "https://virustotal.com"  
  full_url = f"https://virustotal.com{str(ip_address).strip()}"




    
headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }
    
    # Visual status indicator inside the app
status_box = st.info(f"🔄 Connecting to VirusTotal... Scanning IP: {ip_address}")
    
try:
        # Added a 10-second timeout to handle slow cloud server proxies
        response = requests.get(full_url, headers=headers, timeout=10)
        
        # Clear the loading status box
        status_box.empty()
        
        if response.status_code == 200:
            raw_data = response.json()
            stats = raw_data['data']['attributes']['last_analysis_stats']
            
            st.subheader(f"📊 Scan Results for: `{ip_address}`")
            col1, col2 = st.columns(2)
            with col1:
                st.metric(label="Malicious Flags 🚨", value=stats['malicious'])
            with col2:
                st.metric(label="Harmless Flags ✅", value=stats['harmless'])
                
        elif response.status_code == 403:
            st.error("🔑 Invalid API Key! Please verify the key in your Streamlit Secrets panel.")
        else:
            st.error(f"🌐 Cloud network routing failed. Status Code: {response.status_code}")

except requests.exceptions.Timeout:
        status_box.empty()
        st.error("⏱️ Connection Timed Out. The cloud server took too long to reach VirusTotal. Try running the scan again.")
except Exception as e:
        status_box.empty()
        st.error(f"❌ An unexpected error occurred: {e}")

# --- Streamlit UI Setup ---
st.title("🛡️ Automated Threat Intelligence Web IP Scanner")
st.write("Enter a suspicious IP address below to query live reputation metrics.")

user_ip = st.text_input("Enter a suspicious IP address to scan:", placeholder="e.g., 8.8.8.8")

if user_ip:
    scan_suspicious_ip(user_ip)
