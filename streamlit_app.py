import streamlit as st
import requests

# 1. Define the scanner function with network error handling
def scan_suspicious_ip(ip_address):
    # Base configuration
    api_key = "YOUR_VIRUSTOTAL_API_KEY_HERE"  # Replace with your actual key
    full_url = f"https://virustotal.com{ip_address}"
    headers = {"x-apikey": api_key}
    
    st.info(f"🔄 Connecting to VirusTotal... Scanning IP: {ip_address}")
    
    try:
        # Wrap the network connection in a try block
        response = requests.get(full_url, headers=headers, timeout=10)
        
        # Check if the API returned an authorized error status
        if response.status_code == 401:
            st.error("❌ Invalid API Key. Please verify your VirusTotal token configuration.")
            return
        elif response.status_code == 404:
            st.warning("⚠️ No data found for this IP address in the threat database.")
            return
            
        # Parse and display successful results
        raw_data = response.json()
        stats = raw_data['data']['attributes']['last_analysis_stats']
        
        st.subheader("📊 Threat Intelligence Report")
        col1, col2 = st.columns(2)
        col1.metric(label="🚨 Malicious Flags", value=f"{stats['malicious']} engines")
        col2.metric(label="✅ Harmless Flags", value=f"{stats['harmless']} engines")
        
        # Final Decision Logic
        if stats['malicious'] > 0:
            st.error("🛑 RISK ASSESSMENT: DANGER (This IP matches threat indicators)")
        else:
            st.success("🟢 RISK ASSESSMENT: SAFE (Verified clear by security scanners)")
            
    except requests.exceptions.ConnectionError:
        st.error("🌐 **Network Connection Error:** Could not reach the threat intelligence network server. Please try again in a few moments.")
    except requests.exceptions.Timeout:
        st.error("⏳ **Timeout Error:** The external security server took too long to reply. Try checking your internet load.")
    except Exception as e:
        st.error(f"⚠️ An unexpected application error occurred: {e}")

# 2. Render UI Layout storefront
st.title("🛡️ Automated Threat Intelligence Web IP Scanner")
user_ip = st.text_input("Enter a suspicious IP address to scan:", value="8.8.8.8").strip()

if user_ip:
    scan_suspicious_ip(user_ip)
