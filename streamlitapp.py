import streamlit as st
import requests

# Page Setup
st.set_page_config(page_title="Threat Intel Scanner", page_icon="🛡️")
st.title("🛡️ Automated Threat Intelligence")
st.subheader("⚡ Real-Time Cyber Security Tool")

st.write("Type any network IP address down below to check if it is safe, suspicious, or dangerous to use.")

# User Inputs
api_key = st.text_input("Enter VirusTotal API Key:", type="password")
ip_address = st.text_input("Enter the IP address you want to check:", placeholder="e.g., 45.225.118.186")

# Explicit step-by-step input validation to prevent blank logic states
if not api_key:
    st.info("🔑 Please enter your VirusTotal API key above to activate the scanner.")
elif not ip_address:
    st.info("🌐 Please enter an IP address to begin the scan.")
else:
    # This block only runs when BOTH fields are completely valid
    cleaned_ip = ip_address.strip()
    
    # ⚠️ FIXED ENDPOINT URL CONSTRUCTION (Guarantees no domain smashing)
    url = f"https://virustotal.com/{cleaned_ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        with st.spinner(f"Scanning {cleaned_ip}..."):
            response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            json_data = response.json()
            attributes = json_data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            st.markdown("---")
            
            # TRACK SAFETY STATE
            safety_state = "safe"
            
            # FEATURE 1: SAFETY STATUS BADGE
            st.markdown("### 📊 Security Rating")
            if malicious > 2:
                st.error("🚨 DANGEROUS: This IP is heavily flagged as malicious!")
                safety_state = "dangerous"
            elif malicious > 0 or suspicious > 0:
                st.warning("⚠️ SUSPICIOUS: This IP has a few security warnings.")
                safety_state = "suspicious"
            else:
                st.success("✅ SAFE: No security problems found for this IP.")
                safety_state = "safe"
            
            # FEATURE 2: IP LOCATION & OWNER
            st.markdown("### 🌐 About This IP Address")
            country = attributes.get('country', 'Unknown')
            provider = attributes.get('asn_owner', 'Unknown')
            
            st.write(f"🌍 **Country of Origin:** {country}")
            st.write(f"🏢 **Internet Provider (ISP):** {provider}")
            
            # FEATURE 3: ACTION RECOMMENDATION BOX
            st.markdown("### 💡 Recommended Next Steps")
            if safety_state == "dangerous":
                st.info(
                    "🛑 **Action Required:** Disconnect from this IP immediately. "
                    "Do not enter any personal data, passwords, or credit card details on websites hosted here. "
                    "If this is a server connection, block it in your network firewall."
                )
            elif safety_state == "suspicious":
                st.info(
                    "👀 **Action Required:** Proceed with caution. "
                    "While not actively blocked, this IP has triggered unusual security flags. "
                    "Avoid downloading files or sharing sensitive information through this network point."
                )
            else:
                st.info(
                    "👍 **Action Required:** No action needed! "
                    "This IP address is widely trusted across global security networks. "
                    "It is perfectly fine to browse or connect normally."
                )
            
        elif response.status_code == 401:
            st.error("🔑 API Key error: The key provided is invalid. Please check your VirusTotal account dashboard.")
        elif response.status_code == 404:
            st.info("ℹ️ No records found: VirusTotal hasn't cataloged or seen this specific IP address before.")
        else:
            st.error(f"❌ Server Error: Received unexpected status code {response.status_code} from VirusTotal.")
            
    except requests.exceptions.RequestException as e:
        st.error(f"🌐 Connection issue occurred. Technical Details: {e}")
