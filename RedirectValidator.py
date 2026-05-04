import streamlit as st
import pandas as pd
import requests
import io
import time
import urllib3
import concurrent.futures
import re

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
</style>
""", unsafe_allow_html=True)

# ---------------- HELPERS ---------------- #

def clean_url_logic(url):
    if not url or pd.isna(url): return ""
    u = str(url).strip().lower()
    if u.startswith("https://"): u = u[8:]
    if u.startswith("http://"): u = u[7:]
    if u.startswith("www."): u = u[4:]
    return u.rstrip('/')


def safe_extract_text(response):
    try:
        return response.content.decode('utf-8', errors='ignore')[:1000]
    except:
        return "No readable content"


def find_column(df, keywords, fallback_index=0):
    for c in df.columns:
        if any(k in c.lower() for k in keywords):
            return c
    return df.columns[fallback_index]


def classify_ssl_error(e):
    msg = str(e).lower()
    if "expired" in msg:
        return "🔒 SSL EXPIRED", "Certificate expired"
    if "hostname" in msg or "doesn't match" in msg:
        return "⚠️ SSL MISMATCH", "Domain mismatch"
    if "self signed" in msg:
        return "⚠️ SELF SIGNED", "Self-signed certificate"
    if "verify failed" in msg:
        return "🔒 SSL FAILED", "Verification failed"
    return "🔒 NOT SECURE", "Unknown SSL issue"


def make_request(url, max_retries):
    target_url = str(url).strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'text/html',
        'Accept-Encoding': 'identity',
        'Connection': 'keep-alive'
    }

    last_err = None
    for _ in range(max_retries):
        try:
            return requests.get(target_url, headers=headers, allow_redirects=True, timeout=10)
        except requests.exceptions.SSLError as e:
            raise e
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise last_err


def check_safe_browsing(url, api_key):
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
        r = requests.post(api_url, json=payload, timeout=5)
        if r.status_code == 200 and "matches" in r.json():
            return r.json()["matches"][0].get("threatType")
    except:
        pass
    return None


def check_redirect(source, expected_target, api_key=None, max_retries=3):

    core_source = clean_url_logic(source)
    core_expected = clean_url_logic(expected_target)

    result = {
        "Source Domain": source,
        "Expected Target": expected_target,
        "Actual Final URL": "-",
        "Status": "Checking...",
        "Details": "",
        "Page Output": ""
    }

    # Safe Browsing Source
    threat = check_safe_browsing(source, api_key)
    if threat:
        result["Status"] = "🚨 DANGEROUS"
        result["Details"] = threat
        return result

    try:
        response = make_request(source, max_retries)
        final_url = response.url
        result["Actual Final URL"] = final_url

        if 'text/html' not in response.headers.get('Content-Type', '').lower():
            result["Page Output"] = "Non-HTML content"
        else:
            result["Page Output"] = safe_extract_text(response)

        core_actual = clean_url_logic(final_url)

        threat = check_safe_browsing(final_url, api_key)
        if threat:
            result["Status"] = "🚨 DANGEROUS"
            result["Details"] = threat
            return result

        if core_expected == core_actual:
            result["Status"] = "✅ MATCH"
        elif core_expected in core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "Sub-page"
        else:
            result["Status"] = "❌ MISMATCH"

    except requests.exceptions.SSLError as e:
        status, detail = classify_ssl_error(e)
        result["Status"] = status
        result["Details"] = detail

    except requests.exceptions.ConnectionError:
        result["Status"] = "🚫 DOWN"
        result["Details"] = "DNS/Server Error"

    except requests.exceptions.Timeout:
        result["Status"] = "⏱️ TIMEOUT"
        result["Details"] = "Slow server"

    except Exception as e:
        result["Status"] = "❗ ERROR"
        result["Details"] = str(e)

    return result


def sanitize_for_excel(val):
    if isinstance(val, str):
        return re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', val)
    return val


def convert_df_to_excel(df):
    buffer = io.BytesIO()
    df = df.applymap(sanitize_for_excel)
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    return buffer.getvalue()


def generate_sample_file():
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame({'Feed Name': ['Sample'], 'Target Website': ['example.com']}).to_excel(writer, sheet_name='Target_Rules', index=False)
        pd.DataFrame({'Feed Name': ['Sample'], 'Source Domain': ['test.com']}).to_excel(writer, sheet_name='Source_Domains', index=False)
        pd.DataFrame({'Google Safe Browsing API Key': ['PASTE_KEY_HERE']}).to_excel(writer, sheet_name='API_Settings', index=False)
    return output.getvalue()

# ---------------- UI ---------------- #

st.title("Redirect Validator 🚀")

with st.sidebar:
    st.download_button("📥 Download Template", generate_sample_file(), "redirect_template.xlsx")
    max_retries_input = st.number_input("Max Retries", 1, 10, 3)
    ui_api_key = st.text_input("API Key", type="password")

uploaded_file = st.file_uploader("Upload Excel", type=['xlsx'])

if uploaded_file:
    if st.button("🚀 Start Validation"):

        xls = pd.ExcelFile(uploaded_file)
        sheets = xls.sheet_names

        df_rules = pd.read_excel(uploaded_file, sheet_name=sheets[0])
        df_domains = pd.read_excel(uploaded_file, sheet_name=sheets[1] if len(sheets)>1 else sheets[0])

        df_rules.columns = df_rules.columns.str.strip()
        df_domains.columns = df_domains.columns.str.strip()

        common_col = list(set(df_rules.columns) & set(df_domains.columns))[0]

        df_rules = df_rules.drop_duplicates(subset=[common_col])
        merged = pd.merge(df_domains, df_rules, on=common_col, how='left')

        target_col = find_column(df_rules, ['target', 'web'])
        source_col = find_column(df_domains, ['source', 'domain'])

        tasks = [
            {'src': row[source_col], 'tgt': row[target_col], 'api_key': ui_api_key, 'max_retries': max_retries_input}
            for _, row in merged.iterrows() if not pd.isna(row[source_col])
        ]

        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            futures = [executor.submit(check_redirect, t['src'], t['tgt'], t['api_key'], t['max_retries']) for t in tasks]

            for i, f in enumerate(concurrent.futures.as_completed(futures)):
                results.append(f.result())

        df_res = pd.DataFrame(results)

        st.dataframe(df_res, use_container_width=True)

        st.download_button("Download Report", convert_df_to_excel(df_res), "report.xlsx")
