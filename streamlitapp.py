import streamlit as st
import requests
import ipaddress
import socket

# Page Setup
st.set_page_config(page_title="Threat Intel Scanner", page_icon="🛡️")
st.title("🛡️ Automated Threat Intelligence")
st.subheader("⚡ Real-Time Cyber Security Tool")

st.write("Type any network IP address down below to check if it is safe, suspicious, or dangerous to use.")

# User Inputs
api_key = st.text_input("Enter VirusTotal API Key:", type="password")
ip_address = st.text_input("Enter the IP address you want to check:", placeholder="e.g., 45.225.118.186")

# Step-by-step input validation
if not api_key:
    st.info("🔑 Please enter your VirusTotal API key above to activate the scanner.")
elif not ip_address:
    st.info("🌐 Please enter an IP address to begin the scan.")
else:
    cleaned_ip = ip_address.strip()
    
    # 1. Check if the IP is a local/private network address
    is_private = False
    try:
        if ipaddress.ip_address(cleaned_ip).is_private:
            is_private = True
    except ValueError:
        pass

    # --- PATH A: LIVE LOCAL NETWORK IP SCANNING ---
    if is_private:
        st.markdown("---")
        st.markdown("### 📊 Security Rating")
        st.success(f"🏠 LOCAL NETWORK DEVICE: {cleaned_ip} is an internal private address.")
        
        # Perform a live system ping check to see if the local device is awake
        with st.spinner(f"Testing active connection to local interface {cleaned_ip}..."):
            try:
                # Attempts a quick connection to check if the local host device is reachable
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                # Try connecting to standard HTTP/HTTPS/Router ports to check signs of life
                result = s.connect_ex((cleaned_ip, 80))
                s.close()
                device_status = "Active / Reachable on Local Network"
            except Exception:
                device_status = "Inactive / Unreachable local interface"

        st.markdown("### 🌐 About This IP Address")
        st.write(f"🌍 **Scope:** Internal LAN (Local Area Network)")
        st.write(f"🏢 **Device Status:** {device_status}")
        st.write("⚠️ *Note: Private IPs are hidden from the public internet, so external threat databases cannot index them.*")
        
        st.markdown("### 💡 Recommended Next Steps")
        st.info("👍 **Action Required:** This address belongs to your local router, printer, or computer. It is completely safe to interact with inside your home or office network.")

    # --- PATH B: LIVE PUBLIC INTERNET IP SCANNING ---
    else:
        url = f"https://virustotal.com{cleaned_ip}"
        headers = {"accept": "application/json", "x-apikey": api_key}
        
        try:
            with st.spinner(f"Scanning public threat databases for {cleaned_ip}..."):
                response = requests.get(url, headers=headers)
            
            st.markdown("---")
            
            # Scenario 1: IP address has an active threat history record (Found)
            if response.status_code == 200:
                json_data = response.json()
                attributes = json_data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                # FEATURE 1: SAFETY STATUS BADGE
                st.markdown("### 📊 Security Rating")
                if malicious > 2:
                    st.error(f"🚨 DANGEROUS: Flagged by {malicious} security engines as malicious!")
                    safety_state = "dangerous"
                elif malicious > 0 or suspicious > 0:
                    st.warning(f"⚠️ SUSPICIOUS: Flagged by {malicious + suspicious} security engines.")
                    safety_state = "suspicious"
                else:
                    st.success("✅ SAFE: Checked by global databases and found completely clean.")
                    safety_state = "safe"
                
                # FEATURE 2: IP LOCATION & OWNER
                st.markdown("### 🌐 About This IP Address")
                country = attributes.get('country', 'Unknown')
                provider = attributes.get('asn_owner', 'Unknown')
                st.write(f"🌍 **Country of Origin:** {country}")
                st.write(f"🏢 **Network Provider (ISP):** {provider}")
                
                # FEATURE 3: ACTION RECOMMENDATION BOX
                st.markdown("### 💡 Recommended Next Steps")
                if safety_state == "dangerous":
                    st.info("🛑 **Action Required:** Disconnect immediately. Do not input passwords, tokens, or financial details.")
                elif safety_state == "suspicious":
                    st.info("👀 **Action Required:** Proceed with caution. Avoid running file downloads or transferring data.")
                else:
                    st.info("👍 **Action Required:** No threats found. It is perfectly safe to connect and browse normally.")
            
            # Scenario 2: IP is so clean or standard (like 8.8.8.8) it has no threat records (404 handling)
            elif response.status_code == 404:
                st.markdown("### 📊 Security Rating")
                st.success("✅ 100% CLEAN: Verified safe infrastructure address.")
                
                st.markdown("### 🌐 About This IP Address")
                st.write(f"🌍 **IP Target:** {cleaned_ip}")
                st.write("🏢 **Threat Profile:** Zero historical flags or malicious activity reported across all security vendors.")
                
                st.markdown("### 💡 Recommended Next Steps")
                st.info("👍 **Action Required:** This IP address is completely unflagged and clean. It is safe to use for normal web activity, public server data routing, or application processes.")
                
            elif response.status_code == 401:
                st.error("🔑 API Key error: The key provided is invalid. Please check your VirusTotal account dashboard.")
            else:
                st.error(f"❌ Server Error: Received unexpected status code {response.status_code} from VirusTotal.")
                
        except requests.exceptions.RequestException as e:
            st.error(f"🌐 Connection issue occurred. Technical Details: {e}")
