import streamlit as st
import pandas as pd
import requests
import io
import time
import urllib3
import concurrent.futures
import re
from urllib.parse import urlparse

# 1. Hide "Insecure Request" warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Page Config ---
st.set_page_config(page_title="Redirect Validator", page_icon="🔗", layout="wide")

# --- Initialize Session State (Persistent Memory) ---
if 'results_df' not in st.session_state:
    st.session_state['results_df'] = None
if 'failed_df' not in st.session_state:
    st.session_state['failed_df'] = None

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
    """Aggressive connection logic: Bypasses SSL errors and falls back to HTTP automatically."""
    target_url = str(url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url 

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'identity',
        'Connection': 'keep-alive'
    }
    
    timeout_val = 15 
    for attempt in range(max_retries):
        try:
            # verify=False allows us to see behind "Connection is private" block pages
            response = requests.get(target_url, headers=headers, allow_redirects=True, timeout=timeout_val, verify=False)
            return response, False
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            # Fallback: If https fails, try http to catch Enterprise/Sophos block pages
            if target_url.startswith("https://"):
                target_url = target_url.replace("https://", "http://", 1)
                continue 
            time.sleep(1) 
            
    try:
        response = requests.get(target_url, headers=headers, allow_redirects=True, timeout=timeout_val, verify=False)
        return response, True
    except Exception as e:
        raise e

def check_safe_browsing(url, api_key):
    """Queries Google Safe Browsing API to detect Deceptive/Harmful sites."""
    if not api_key: return None
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
            if "matches" in data:
                return data["matches"][0].get("threatType")
    except: pass
    return None

def check_redirect(source, expected_target, google_api_key=None, max_retries=3):
    core_source = clean_url_logic(source)
    core_expected = clean_url_logic(expected_target)
    
    result = {
        "Source Domain": source, "Expected Target": expected_target,
        "Actual Final URL": "-", "Status": "Checking...", "Details": "", "Error Snippet": "-"
    }

    # PRIORITY 0: Pre-check Source with Google Safe Browsing
    if google_api_key:
        threat = check_safe_browsing(source, google_api_key)
        if threat:
            status_map = {"SOCIAL_ENGINEERING": "🚨 DECEPTIVE", "MALWARE": "🚨 HARMFUL"}
            result["Status"] = status_map.get(threat, "🚨 DANGEROUS")
            result["Details"] = f"Google Block: {threat}"
            result["Error Snippet"] = f"Blocked by Google Safe Browsing: {threat}"
            return result
    
    try:
        response, ssl_fallback = make_request(source, max_retries)
        final_url = response.url
        result["Actual Final URL"] = final_url
        
        # Safe decode for binary/corrupted responses (up to 1500 chars)
        try:
            page_content = response.content.decode('utf-8', errors='ignore')[:1500]
        except:
            page_content = "Binary/Unreadable Content"
            
        # Temporarily store the snippet (we will clear it later if it's a normal match/mismatch)
        result["Error Snippet"] = page_content.strip()
        
        # PRIORITY 1: Enterprise Block Detection (Sophos/Filter)
        block_keywords = ["Sophos", "Website Blocked", "Spam URLs", "Your organization forbids access", "Fortinet", "Cisco Umbrella"]
        if any(kw.lower() in page_content.lower() for kw in block_keywords):
            category_match = re.search(r"category\s+([^.]+)", page_content, re.IGNORECASE)
            category = category_match.group(1).strip() if category_match else "Enterprise Filter"
            result["Status"] = "🚨 BLOCKED"
            result["Details"] = f"Network Block: {category}"
            # Returns early, keeping the Sophos HTML inside the Error Snippet column
            return result

        core_actual = clean_url_logic(final_url)

        # PRIORITY 2: Google Safe Browsing on Destination
        if google_api_key:
            threat = check_safe_browsing(final_url, google_api_key)
            if threat:
                result["Status"] = "🚨 DANGEROUS"
                result["Details"] = f"Google Destination Warning: {threat}"
                result["Error Snippet"] = f"Destination blocked by Google Safe Browsing: {threat}"
                return result

        # PRIORITY 3: Redirection Logic
        if core_actual == core_source:
            if core_expected == core_source:
                result["Status"] = "✅ MATCH"
                result["Error Snippet"] = "-" # Clear snippet for perfect matches
            else:
                result["Status"] = "❌ MISMATCH"
                result["Details"] = "Blank page redirection"
                result["Error Snippet"] = "-" # Clear snippet, as the page itself loaded fine
            return result

        if core_expected == core_actual or core_expected in core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "OK" + (" (SSL Insecure)" if ssl_fallback else "")
            result["Error Snippet"] = "-" # Clear snippet for matches
        else:
            result["Status"] = "❌ MISMATCH"
            detail = "Wrong destination"
            if response.status_code >= 400: 
                detail += f" (HTTP {response.status_code})"
                # Error Snippet remains intact to show the HTTP Error HTML (e.g., 502 Bad Gateway)
            else:
                # Clear snippet for standard wrong destination where page loaded successfully
                result["Error Snippet"] = "-"
            result["Details"] = detail

    except Exception as e:
        result["Status"] = "❌ BROKEN"
        result["Details"] = str(e)[:60]
        result["Error Snippet"] = str(e)[:1500] # Show raw exception/timeout in the snippet column
        
    return result

def sanitize_for_excel(val):
    """Removes non-printable ASCII chars to prevent Excel export crashes."""
    if isinstance(val, str):
        return re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', val)
    return val

def convert_df_to_excel(df):
    buffer = io.BytesIO()
    clean_df = df.copy()
    for col in clean_df.columns:
        if clean_df[col].dtype == object:
            clean_df[col] = clean_df[col].astype(str).apply(sanitize_for_excel)
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        clean_df.to_excel(writer, index=False)
    return buffer.getvalue()

# --- Application UI ---

st.title("Redirect Validator 🚀")

with st.sidebar:
    st.header("Settings")
    max_retries_input = st.number_input("Max Retries", 1, 10, 3)
    ui_api_key = st.text_input("API Key Override", type="password")
    if st.button("Reset / Clear Data"):
        st.session_state['results_df'] = None
        st.session_state['failed_df'] = None
        st.rerun()

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
            
            # API Key Auto-detection
            excel_api_key = ""
            if len(all_sheets) >= 3:
                api_sheet = next((s for s in all_sheets if 'api' in s.lower()), None)
                if api_sheet:
                    df_api = pd.read_excel(uploaded_file, sheet_name=api_sheet)
                    for col in df_api.columns:
                        for val in df_api[col].dropna():
                            if isinstance(val, str) and len(val.strip()) > 25: excel_api_key = val.strip()
            
            final_api_key = excel_api_key if excel_api_key else ui_api_key
            df_rules.columns = df_rules.columns.str.strip()
            df_domains.columns = df_domains.columns.str.strip()
            common_col = list(set(df_rules.columns) & set(df_domains.columns))[0]
            
            merged = pd.merge(df_domains, df_rules.drop_duplicates(subset=[common_col]), on=common_col, how='left')
            target_col = next(c for c in df_rules.columns if 'target' in c.lower() or 'web' in c.lower())
            source_col = next(c for c in df_domains.columns if 'source' in c.lower() or 'domain' in c.lower())
            
            tasks = [{'src': row[source_col], 'tgt': row[target_col], 'api_key': final_api_key, 'max_retries': max_retries_input} 
                     for _, row in merged.iterrows() if not pd.isna(row[source_col])]
            
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(check_redirect, t['src'], t['tgt'], t['api_key'], t['max_retries']) for t in tasks]
                for i, f in enumerate(concurrent.futures.as_completed(futures)):
                    results.append(f.result())
                    progress_bar.progress((i+1) / len(tasks))
                    status_text.text(f"Auditing: {i+1}/{len(tasks)}")

            st.session_state['results_df'] = pd.DataFrame(results)
            st.session_state['failed_df'] = st.session_state['results_df'][~st.session_state['results_df']['Status'].str.contains("MATCH")]
            st.rerun()
        except Exception as e:
            st.error(f"Error during validation: {e}")

# --- Result Display ---
if st.session_state['results_df'] is not None:
    df = st.session_state['results_df']
    df_failed = st.session_state['failed_df']

    def color_status(val):
        if 'MATCH' in str(val): return 'background-color: #d1fae5; color: #065f46; font-weight: bold'
        if any(x in str(val) for x in ['DANGEROUS', 'DECEPTIVE', 'HARMFUL', 'BLOCKED']): 
            return 'background-color: #4c1d95; color: #ffffff; font-weight: bold'
        return 'background-color: #fee2e2; color: #991b1b; font-weight: bold'

    st.subheader("Validation Results")
    # Render the table WITH the "Error Snippet" column explicitly included
    st.dataframe(df.style.map(color_status, subset=['Status']), use_container_width=True, height=600)
    
    st.divider()
    c1, c2 = st.columns(2)
    with c1:
        st.download_button("📥 Download Full Report", convert_df_to_excel(df), "full_audit_report.xlsx", use_container_width=True)
    with c2:
        st.download_button("📥 Download Failed Only", convert_df_to_excel(df_failed), "failed_items_report.xlsx", type="primary", use_container_width=True)
