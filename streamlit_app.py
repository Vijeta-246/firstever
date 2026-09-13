import streamlit as st
import requests

def scan_suspicious_ip(ip_address):
    # Ensure you replace this placeholder string with your real API token!
    api_key = "YOUR_VIRUSTOTAL_API_KEY_HERE" 
    
    # Clean the input parameter string entirely
    clean_ip = str(ip_address).strip()
    full_url = f"https://virustotal.com{clean_ip}"
    
    # Added a standard User-Agent so the request looks like a standard browser request
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    info_box = st.info(f"🔄 Connecting to VirusTotal... Scanning IP: {clean_ip}")
    
    try:
        # Added a longer timeout window (15s) to survive temporary cloud lag spikes
        response = requests.get(full_url, headers=headers, timeout=15)
        
        # Instantly clear out the initial loading info bar when data lands
        info_box.empty()
        
        # Catch explicit status blocks before running operations on missing keys
        if response.status_code == 401:
            st.error("❌ **Authentication Failure:** The API key inside the script is invalid or expired.")
            return
        elif response.status_code == 403:
            st.error("❌ **Access Forbidden:** Your API key does not have permissions to query this endpoint, or your request limit was hit.")
            return
        elif response.status_code == 404:
            st.warning("⚠️ **Record Not Found:** VirusTotal doesn't have security reports for this specific IP address structure yet.")
            return
        
        # If any other bad status happens (like a remote server 500 error)
        response.raise_for_gradual_failures = response.raise_for_status() 
        
        # Parse output data packages safely
        raw_data = response.json()
        stats = raw_data['data']['attributes']['last_analysis_stats']
        
        st.subheader("📊 Threat Intelligence Report")
        col1, col2 = st.columns(2)
        col1.metric(label="🚨 Malicious Flags", value=f"{stats['malicious']} engines")
        col2.metric(label="✅ Harmless Flags", value=f"{stats['harmless']} engines")
        
        # Evaluation Banner Logic
        if stats['malicious'] > 0:
            st.error("🛑 RISK ASSESSMENT: DANGER (This IP matches threat indicators)")
        else:
            st.success("🟢 RISK ASSESSMENT: SAFE (Verified clear by security scanners)")
            
    except requests.exceptions.ConnectionError:
        st.error("🌐 **Network Connection Error:** Could not reach the threat intelligence network server. Please verify your script's API URL configuration or try hosting locally.")
    except requests.exceptions.Timeout:
        st.error("⏳ **Timeout Error:** The VirusTotal gateway server took too long to reply to the cloud instance request.")
    except Exception as e:
        st.error(f"⚠️ **Application Parsing Exception:** {e}")

# Render Title layout onto canvas
st.title("🛡️ Automated Threat Intelligence Web IP Scanner")
user_ip = st.text_input("Enter a suspicious IP address to scan:", value="8.8.8.8")

if user_ip:
    scan_suspicious_ip(user_ip)
