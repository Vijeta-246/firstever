import requests
import streamlit as st


# SECURE: Fetch the API key safely from Streamlit's environment secrets
# (Do NOT paste your raw API key string here anymore)
API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]

def scan_suspicious_ip(ip_address):
    # ✅ Make sure 'https://' is at the very beginning of the string
    base_url = "https://virustotal.com"
    
    # Clean the IP and combine it into a perfect web address
    clean_ip = str(ip_address).strip()
    full_url = f"{base_url}{clean_ip}"
    
    # Your VirusTotal authentication headers
    headers = {
        "accept": "application/json",
        "x-apikey": "YOUR_ACTUAL_VIRUSTOTAL_API_KEY"
    }
    
    # Send the request securely
    response = requests.get(full_url, headers=headers)
    return response

    
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
# ✅ The correct code with perfect indentation spacing
if user_ip.strip():
    response = scan_suspicious_ip(user_ip)
    
    if response.status_code == 200:
        st.success("Scan complete!")
        st.json(response.json())
    else:
        st.error(f"Error from VirusTotal: {response.status_code}")
else:
    st.info("Please enter an IP address above to start the scan.")


