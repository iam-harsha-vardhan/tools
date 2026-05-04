import streamlit as st
import pandas as pd
import requests
import io
import time
import urllib3
import concurrent.futures
import re

# 1. Hide "Insecure Request" warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Page Config ---
st.set_page_config(page_title="Redirect Validator", page_icon="🔗", layout="wide")

# --- Custom CSS ---
st.markdown("""
<style>
    html, body, [class*="css"] { font-family: 'Inter', 'Segoe UI', sans-serif; }
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 15px !important;
        height: 3em;
        transition: all 0.15s ease !important;
        width: 100%;
    }
    .stButton > button:hover { 
        transform: translateY(-2px); 
        box-shadow: 0 4px 12px rgba(0,0,0,0.12); 
    }
    .stDownloadButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        width: 100%;
        height: 3em;
    }
    div[data-testid="column"] { text-align: center; }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---

def clean_url_logic(url):
    """Strips protocol and www for comparison."""
    if not url or pd.isna(url): return ""
    u = str(url).strip().lower()
    if u.startswith("https://"): u = u[8:]
    if u.startswith("http://"): u = u[7:]
    if u.startswith("www."): u = u[4:]
    return u.rstrip('/')

def make_request(url, max_retries):
    """Tries to connect with REAL BROWSER HEADERS, enforcing retries for failed pages."""
    target_url = str(url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url 

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    last_err = None
    
    # Retry Loop Logic
    for attempt in range(max_retries):
        try:
            response = requests.get(target_url, headers=headers, allow_redirects=True, timeout=10)
            return response
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
            last_err = e
            time.sleep(1) # Wait 1 second before retrying
            
    # If standard attempts fail, try a protocol swap as a last resort
    try:
        if target_url.startswith("http://"):
            retry_url = target_url.replace("http://", "https://", 1)
        else:
            retry_url = target_url.replace("https://", "http://", 1)
        response = requests.get(retry_url, headers=headers, allow_redirects=True, timeout=10)
        return response
    except Exception:
        raise last_err # Raise the original error if the fallback fails

def check_safe_browsing(url, api_key):
    """Queries the Google Safe Browsing API to see if the site is dangerous and returns the specific threat type."""
    if not api_key:
        return None
        
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "redirect-validator", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        resp = requests.post(api_url, json=payload, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if "matches" in data and len(data["matches"]) > 0:
                # Return the exact threat type (e.g., 'SOCIAL_ENGINEERING' or 'MALWARE')
                return data["matches"][0].get("threatType", "UNKNOWN_THREAT")
    except Exception:
        pass
    return None

def check_redirect(source, expected_target, google_api_key=None, max_retries=3):
    if expected_target and "httpts" in str(expected_target):
        return {
            "Source Domain": source, "Expected Target": expected_target,
            "Actual Final URL": "-", "Status": "❌ BROKEN", "Details": "Fix 'httpts' in Excel", "Page Output": "N/A"
        }

    core_source = clean_url_logic(source)
    core_expected = clean_url_logic(expected_target)
    
    result = {
        "Source Domain": source, "Expected Target": expected_target,
        "Actual Final URL": "-", "Status": "Checking...", "Details": "", "Page Output": ""
    }
    
    try:
        response = make_request(source, max_retries)
        final_url = response.url
        result["Actual Final URL"] = final_url
        
        page_content = response.text[:1000] if response.text else "No content returned."
        result["Page Output"] = page_content
        
        core_actual = clean_url_logic(final_url)

        # --- BLANK PAGE REDIRECTION LOGIC (Domain just goes to itself) ---
        if core_expected != core_source and core_actual == core_source:
            result["Status"] = "❌ MISMATCH"
            result["Details"] = "Blank page redirection"
            return result

        # --- GOOGLE SAFE BROWSING CHECK ---
        if google_api_key:
            threat_type = check_safe_browsing(final_url, google_api_key)
            if threat_type:
                if threat_type == "SOCIAL_ENGINEERING":
                    result["Status"] = "🚨 DECEPTIVE"
                    result["Details"] = "Google Warning: Phishing/Social Engineering"
                elif threat_type in ["MALWARE", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"]:
                    result["Status"] = "🚨 HARMFUL"
                    result["Details"] = "Google Warning: Malware/Harmful Programs"
                else:
                    result["Status"] = "🚨 DANGEROUS"
                    result["Details"] = f"Google Warning: {threat_type}"
                
                result["Page Output"] = f"Site blocked by Google. Threat type identified: {threat_type}"
                return result
                
        # --- STANDARD COMPARISON LOGIC ---
        if core_expected == core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "OK"
        elif core_expected in core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "OK (Sub-page)"
        else:
            if response.status_code == 403:
                if core_expected in core_actual:
                    result["Status"] = "✅ MATCH"
                    result["Details"] = "OK (Ignore 403)"
                else:
                    result["Status"] = "❌ BROKEN"
                    result["Details"] = "Access Denied (403)"
            elif response.status_code >= 400:
                result["Status"] = "❌ BROKEN"
                result["Details"] = f"Page Error: {response.status_code}"
            else:
                result["Status"] = "❌ MISMATCH"
                result["Details"] = "Redirected to wrong site"

    except requests.exceptions.InvalidSchema as e:
        result["Status"] = "❌ BROKEN"
        result["Details"] = "Redirects to invalid URL (Typo)"
        result["Page Output"] = f"Invalid Schema Error: {str(e)}"
    except requests.exceptions.MissingSchema as e:
        result["Status"] = "❌ BROKEN"
        result["Details"] = "Redirects to broken URL"
        result["Page Output"] = f"Missing Schema Error: {str(e)}"
    except requests.exceptions.SSLError as ssl_err:
        result["Status"] = "🔒 NOT SECURE"
        result["Details"] = "Invalid/Missing SSL Certificate"
        result["Page Output"] = f"SSL Error Caught:\n{str(ssl_err)}"
    except requests.exceptions.ConnectionError:
        result["Status"] = "🚫 DOWN"
        result["Details"] = "Connection Refused (DNS/Server)"
        result["Page Output"] = "DNS Error or Server Offline."
    except requests.exceptions.Timeout:
        result["Status"] = "⏱️ TIMEOUT"
        result["Details"] = "Server too slow (>10s)"
        result["Page Output"] = "Request Timed Out."
    except Exception as e:
        result["Status"] = "❗ ERROR"
        result["Details"] = "Connection Failed"
        result["Page Output"] = str(e)
        
    return result

def process_single_row(row_data):
    src = row_data['src']
    tgt = row_data['tgt']
    api_key = row_data.get('api_key')
    retries = row_data.get('max_retries', 3)
    
    if pd.isna(tgt) or str(tgt).strip() == "":
        return {
            "Source Domain": src, "Status": "⚠️ NO TARGET", 
            "Actual Final URL": "-", "Details": "No target in rules sheet", "Page Output": "N/A"
        }
    return check_redirect(src, tgt, api_key, retries)

def sanitize_for_excel(val):
    """Removes control characters that cause 'cannot be used in worksheets' errors."""
    if isinstance(val, str):
        # Strip ASCII control characters 0-8, 11-12, 14-31
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', val)
    return val

def convert_df_to_excel(df):
    buffer = io.BytesIO()
    
    # Clean the dataframe of illegal Excel characters before exporting
    clean_df = df.copy()
    for col in clean_df.columns:
        if clean_df[col].dtype == object:
            clean_df[col] = clean_df[col].apply(sanitize_for_excel)
            
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        clean_df.to_excel(writer, index=False)
    return buffer.getvalue()

def generate_sample_file():
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame({'Feed Name': ['ExampleFeed'], 'Target Website': ['arise-cash.com']}).to_excel(writer, sheet_name='Target_Rules', index=False)
        pd.DataFrame({'Feed Name': ['ExampleFeed'], 'Source Domain': ['arisefinancepro.com']}).to_excel(writer, sheet_name='Source_Domains', index=False)
        # Added the 3rd sheet for the API Key
        pd.DataFrame({'Google Safe Browsing API Key': ['PASTE_YOUR_API_KEY_HERE']}).to_excel(writer, sheet_name='API_Settings', index=False)
    return output.getvalue()

# --- Main App ---

st.title("Redirect Validator 🚀")

with st.sidebar:
    st.header("Settings & Actions")
    st.download_button("📥 Download Template", generate_sample_file(), "redirect_template.xlsx")
    
    st.markdown("---")
    # Added UI control for Max Retries
    max_retries_input = st.number_input("Max Retries for Timeouts/Errors", min_value=1, max_value=10, value=3, help="How many times to retry a domain if the server drops the connection.")
    
    st.markdown("---")
    st.header("Security Integrations")
    ui_api_key = st.text_input("Google API Key (Optional)", type="password", help="If you don't add the API Key in the 3rd sheet of the Excel file, you can paste it here.")

uploaded_file = st.file_uploader("Upload Excel File", type=['xlsx', 'xls'])

if uploaded_file:
    if st.button("🚀 Start Validation", type="primary"):
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            xls = pd.ExcelFile(uploaded_file)
            all_sheets = xls.sheet_names
            
            # Identify the primary sheets
            sheet_rules = next((s for s in all_sheets if 'target' in s.lower() or 'rule' in s.lower()), all_sheets[0])
            sheet_domains = next((s for s in all_sheets if 'source' in s.lower() or 'domain' in s.lower()), all_sheets[1] if len(all_sheets)>1 else all_sheets[0])
            
            df_rules = pd.read_excel(uploaded_file, sheet_name=sheet_rules)
            df_domains = pd.read_excel(uploaded_file, sheet_name=sheet_domains)
            
            # --- Extract API Key from 3rd Sheet (if exists) ---
            excel_api_key = ""
            if len(all_sheets) >= 3:
                api_sheet = next((s for s in all_sheets if 'api' in s.lower()), None)
                if not api_sheet:
                    remaining_sheets = [s for s in all_sheets if s not in (sheet_rules, sheet_domains)]
                    if remaining_sheets:
                        api_sheet = remaining_sheets[0]
                
                if api_sheet:
                    df_api = pd.read_excel(uploaded_file, sheet_name=api_sheet)
                    # Search for something that looks like an API key in the sheet
                    for col in df_api.columns:
                        for val in df_api[col].dropna():
                            if isinstance(val, str) and len(val.strip()) > 25: 
                                excel_api_key = val.strip()
                                break
                        if excel_api_key:
                            break
            
            # Prioritize Excel API Key over UI input
            final_api_key = excel_api_key if excel_api_key else ui_api_key
            
            # Prep data for merge
            df_rules.columns = df_rules.columns.str.strip()
            df_domains.columns = df_domains.columns.str.strip()
            common_col = list(set(df_rules.columns) & set(df_domains.columns))[0]
            
            df_rules = df_rules.drop_duplicates(subset=[common_col])
            merged = pd.merge(df_domains, df_rules, on=common_col, how='left')
            
            target_col = next(c for c in df_rules.columns if 'target' in c.lower() or 'web' in c.lower())
            source_col = next(c for c in df_domains.columns if 'source' in c.lower() or 'domain' in c.lower())
            
            tasks = []
            for index, row in merged.iterrows():
                src = row[source_col]
                if pd.isna(src) or str(src).strip() == "" or str(src).lower() == "nan":
                    continue
                tasks.append({
                    'src': src, 
                    'tgt': row[target_col], 
                    'api_key': final_api_key,
                    'max_retries': max_retries_input
                })
            
            total_tasks = len(tasks)
            results = []
            completed_count = 0
            
            if total_tasks == 0:
                st.warning("No valid domains found to check.")
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(process_single_row, task) for task in tasks]
                    for future in concurrent.futures.as_completed(futures):
                        results.append(future.result())
                        completed_count += 1
                        progress_bar.progress(completed_count / total_tasks)
                        status_text.markdown(f"**⚡ Processing:** Checked **{completed_count}/{total_tasks}** domains")

                progress_bar.empty()
                status_text.success(f"✅ Finished checking {total_tasks} valid domains!")
                
                df_res = pd.DataFrame(results)
                df_res.index = range(1, len(df_res) + 1)
                
                df_failed = df_res[~df_res['Status'].str.contains("MATCH")]
                
                def color_status(val):
                    if 'MATCH' in str(val): return 'background-color: #d1fae5; color: #065f46; font-weight: bold'
                    if 'NOT SECURE' in str(val): return 'background-color: #ffedd5; color: #c2410c; font-weight: bold'
                    # All Safe Browsing Threat Types get the purple highlighting
                    if 'DECEPTIVE' in str(val) or 'HARMFUL' in str(val) or 'DANGEROUS' in str(val): 
                        return 'background-color: #4c1d95; color: #ffffff; font-weight: bold'
                    return 'background-color: #fee2e2; color: #991b1b; font-weight: bold'

                st.subheader("Results Table")
                st.dataframe(
                    df_res.style.map(color_status, subset=['Status']), 
                    use_container_width=True, 
                    height=600,
                    column_config={"Page Output": None} 
                )
                
                st.divider()

                if not df_failed.empty:
                    st.subheader("🔍 Inspect Raw Page Output")
                    st.markdown("Select a failed domain to see the exact HTML response or SSL error it returned.")
                    
                    failed_domains_list = df_failed["Source Domain"].tolist()
                    selected_domain = st.selectbox("Select Domain:", ["-- Choose a domain --"] + failed_domains_list)
                    
                    if selected_domain and selected_domain != "-- Choose a domain --":
                        raw_html = df_failed[df_failed["Source Domain"] == selected_domain].iloc[0]["Page Output"]
                        st.code(raw_html, language="text")
                
                st.divider()
                
                st.subheader("Download Reports")
                btn_col1, btn_col2 = st.columns(2)
                timestamp = time.strftime('%Y%m%d_%H%M')
                
                with btn_col1:
                    st.download_button(
                        label="Download Whole Report",
                        data=convert_df_to_excel(df_res),
                        file_name=f"Full_Report_{timestamp}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="secondary",
                        use_container_width=True
                    )
                    
                with btn_col2:
                    st.download_button(
                        label="Download Failed Only",
                        data=convert_df_to_excel(df_failed),
                        file_name=f"Failed_Report_{timestamp}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="primary",
                        use_container_width=True
                    )

        except Exception as e:
            st.error(f"An error occurred: {e}")
