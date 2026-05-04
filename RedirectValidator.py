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
    """Tries to connect with REAL BROWSER HEADERS, enforcing identity encoding."""
    target_url = str(url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url 

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        # CRITICAL: Force 'identity' to prevent compressed binary data from leaking into text
        'Accept-Encoding': 'identity',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    last_err = None
    for attempt in range(max_retries):
        try:
            response = requests.get(target_url, headers=headers, allow_redirects=True, timeout=10)
            return response
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
            last_err = e
            time.sleep(1) 
            
    try:
        if target_url.startswith("http://"):
            retry_url = target_url.replace("http://", "https://", 1)
        else:
            retry_url = target_url.replace("https://", "http://", 1)
        response = requests.get(retry_url, headers=headers, allow_redirects=True, timeout=10)
        return response
    except Exception:
        raise last_err

def check_safe_browsing(url, api_key):
    """Queries the Google Safe Browsing API."""
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
                return data["matches"][0].get("threatType", "UNKNOWN_THREAT")
    except Exception:
        pass
    return None

def check_redirect(source, expected_target, google_api_key=None, max_retries=3):
    if expected_target and "httpts" in str(expected_target):
        return {
            "Source Domain": source, "Expected Target": expected_target,
            "Actual Final URL": "-", "Status": "❌ BROKEN", "Details": "Fix 'httpts' typo in Excel", "Page Output": "N/A"
        }

    core_source = clean_url_logic(source)
    core_expected = clean_url_logic(expected_target)
    
    result = {
        "Source Domain": source, "Expected Target": expected_target,
        "Actual Final URL": "-", "Status": "Checking...", "Details": "", "Page Output": ""
    }

    # --- PRIORITY 0: GOOGLE SAFE BROWSING ON SOURCE ---
    if google_api_key:
        threat_type = check_safe_browsing(source, google_api_key)
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
            result["Page Output"] = f"Source site blocked by Google. Threat: {threat_type}"
            return result
    
    try:
        response = make_request(source, max_retries)
        final_url = response.url
        result["Actual Final URL"] = final_url
        
        # CRITICAL FIX: Use response.content.decode to safely ignore binary junk/bad bytes
        try:
            page_content = response.content.decode('utf-8', errors='ignore')[:1000]
        except:
            page_content = "Unreadable Content"
            
        result["Page Output"] = page_content
        
        core_actual = clean_url_logic(final_url)

        # --- PRIORITY 1: GOOGLE SAFE BROWSING ON FINAL ---
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
                result["Page Output"] = f"Final destination blocked by Google. Threat: {threat_type}"
                return result

        # --- PRIORITY 2: BLANK PAGE REDIRECTION ---
        if core_expected != core_source and core_actual == core_source:
            result["Status"] = "❌ MISMATCH"
            result["Details"] = "Blank page redirection"
            return result
                
        # --- PRIORITY 3: STANDARD LOGIC ---
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
        result["Details"] = "Invalid URL (Typo)"
        result["Page Output"] = str(e)
    except requests.exceptions.SSLError as ssl_err:
        result["Status"] = "🔒 NOT SECURE"
        result["Details"] = "Invalid/Missing SSL"
        result["Page Output"] = str(ssl_err)
    except requests.exceptions.ConnectionError:
        result["Status"] = "🚫 DOWN"
        result["Details"] = "DNS/Server Error"
    except requests.exceptions.Timeout:
        result["Status"] = "⏱️ TIMEOUT"
        result["Details"] = "Server too slow (>10s)"
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
            "Actual Final URL": "-", "Details": "No target in rules", "Page Output": "N/A"
        }
    return check_redirect(src, tgt, api_key, retries)

def sanitize_for_excel(val):
    """
    STRICT SANITIZER: Removes all non-printable/illegal characters that crash openpyxl.
    Matches the logic: re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', x)
    """
    if isinstance(val, str):
        # Allow Tab, LF, CR, and printable ASCII space to tilde.
        return re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', val)
    return val

def convert_df_to_excel(df):
    buffer = io.BytesIO()
    clean_df = df.copy()
    for col in clean_df.columns:
        # Force to string then apply the strict sanitizer
        if clean_df[col].dtype == object:
            clean_df[col] = clean_df[col].astype(str).apply(sanitize_for_excel)
            
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        clean_df.to_excel(writer, index=False)
    return buffer.getvalue()

def generate_sample_file():
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame({'Feed Name': ['Sample'], 'Target Website': ['arise-cash.com']}).to_excel(writer, sheet_name='Target_Rules', index=False)
        pd.DataFrame({'Feed Name': ['Sample'], 'Source Domain': ['arisefinancepro.com']}).to_excel(writer, sheet_name='Source_Domains', index=False)
        pd.DataFrame({'Google Safe Browsing API Key': ['PASTE_KEY_HERE']}).to_excel(writer, sheet_name='API_Settings', index=False)
    return output.getvalue()

# --- Main App ---

st.title("Redirect Validator 🚀")

with st.sidebar:
    st.header("Settings")
    st.download_button("📥 Download Template", generate_sample_file(), "redirect_template.xlsx")
    st.markdown("---")
    max_retries_input = st.number_input("Max Retries", min_value=1, max_value=10, value=3)
    st.markdown("---")
    st.header("Security")
    ui_api_key = st.text_input("API Key (Manual Override)", type="password")

uploaded_file = st.file_uploader("Upload Excel File", type=['xlsx', 'xls'])

if uploaded_file:
    if st.button("🚀 Start Validation", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            xls = pd.ExcelFile(uploaded_file)
            all_sheets = xls.sheet_names
            
            sheet_rules = next((s for s in all_sheets if 'target' in s.lower() or 'rule' in s.lower()), all_sheets[0])
            sheet_domains = next((s for s in all_sheets if 'source' in s.lower() or 'domain' in s.lower()), all_sheets[1] if len(all_sheets)>1 else all_sheets[0])
            
            df_rules = pd.read_excel(uploaded_file, sheet_name=sheet_rules)
            df_domains = pd.read_excel(uploaded_file, sheet_name=sheet_domains)
            
            # Extract API Key from sheet
            excel_api_key = ""
            if len(all_sheets) >= 3:
                api_sheet = next((s for s in all_sheets if 'api' in s.lower()), all_sheets[2] if len(all_sheets)>2 else None)
                if api_sheet:
                    df_api = pd.read_excel(uploaded_file, sheet_name=api_sheet)
                    for col in df_api.columns:
                        for val in df_api[col].dropna():
                            if isinstance(val, str) and len(val.strip()) > 25: 
                                excel_api_key = val.strip()
                                break
            
            final_api_key = excel_api_key if excel_api_key else ui_api_key
            
            df_rules.columns = df_rules.columns.str.strip()
            df_domains.columns = df_domains.columns.str.strip()
            common_col = list(set(df_rules.columns) & set(df_domains.columns))[0]
            
            df_rules = df_rules.drop_duplicates(subset=[common_col])
            merged = pd.merge(df_domains, df_rules, on=common_col, how='left')
            
            target_col = next(c for c in df_rules.columns if 'target' in c.lower() or 'web' in c.lower())
            source_col = next(c for c in df_domains.columns if 'source' in c.lower() or 'domain' in c.lower())
            
            tasks = [{'src': row[source_col], 'tgt': row[target_col], 'api_key': final_api_key, 'max_retries': max_retries_input} 
                     for _, row in merged.iterrows() if not pd.isna(row[source_col])]
            
            results = []
            if tasks:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(process_single_row, t) for t in tasks]
                    for i, future in enumerate(concurrent.futures.as_completed(futures)):
                        results.append(future.result())
                        progress_bar.progress((i+1) / len(tasks))
                        status_text.markdown(f"**⚡ Progress:** {i+1} / {len(tasks)}")

                status_text.success(f"✅ Finished {len(tasks)} domains!")
                df_res = pd.DataFrame(results)
                df_res.index = range(1, len(df_res) + 1)
                
                # Reorder to match your preferred view
                display_cols = ["Source Domain", "Status", "Expected Target", "Actual Final URL", "Details"]
                final_df_res = df_res[display_cols + ["Page Output"]]
                
                df_failed = final_df_res[~final_df_res['Status'].str.contains("MATCH")]
                
                def color_status(val):
                    if 'MATCH' in str(val): return 'background-color: #d1fae5; color: #065f46; font-weight: bold'
                    if 'DECEPTIVE' in str(val) or 'HARMFUL' in str(val): return 'background-color: #4c1d95; color: #ffffff; font-weight: bold'
                    return 'background-color: #fee2e2; color: #991b1b; font-weight: bold'

                st.subheader("Results")
                st.dataframe(final_df_res.drop(columns=["Page Output"]).style.map(color_status, subset=['Status']), use_container_width=True, height=600)
                
                st.divider()
                if not df_failed.empty:
                    st.subheader("🔍 Error Inspector")
                    sel = st.selectbox("Pick an error domain:", ["-- Select --"] + df_failed["Source Domain"].tolist())
                    if sel != "-- Select --":
                        st.code(df_failed[df_failed["Source Domain"] == sel].iloc[0]["Page Output"])

                st.divider()
                st.subheader("Reports")
                c1, c2 = st.columns(2)
                with c1:
                    st.download_button("Full Report", convert_df_to_excel(final_df_res), "full_report.xlsx", use_container_width=True)
                with c2:
                    st.download_button("Failed Only", convert_df_to_excel(df_failed), "failed_report.xlsx", type="primary", use_container_width=True)
        except Exception as e:
            st.error(f"Error: {e}")
