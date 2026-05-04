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
    height: 3em;
    width: 100%;
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

def make_request(url, retries):
    if not str(url).startswith(('http://', 'https://')):
        url = 'http://' + str(url)

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'text/html',
        'Accept-Encoding': 'identity'
    }

    for _ in range(retries):
        try:
            return requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        except requests.exceptions.SSLError as e:
            raise e
        except:
            time.sleep(1)

    raise Exception("Failed after retries")

def check_safe_browsing(url, api_key):
    if not api_key:
        return None
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "app", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }, timeout=5)
        if "matches" in r.json():
            return r.json()["matches"][0]["threatType"]
    except:
        pass
    return None

def check_redirect(source, target, api_key=None, retries=3):

    result = {
        "Source Domain": source,
        "Expected Target": target,
        "Actual Final URL": "-",
        "Status": "",
        "Details": "",
        "Page Output": ""
    }

    # Safe browsing
    threat = check_safe_browsing(source, api_key)
    if threat:
        result["Status"] = "🚨 DANGEROUS"
        result["Details"] = threat
        return result

    try:
        response = make_request(source, retries)

        result["Actual Final URL"] = response.url

        if 'text/html' in response.headers.get('Content-Type', '').lower():
            result["Page Output"] = safe_extract_text(response)
        else:
            result["Page Output"] = "Non-HTML content"

        threat = check_safe_browsing(response.url, api_key)
        if threat:
            result["Status"] = "🚨 DANGEROUS"
            result["Details"] = threat
            return result

        core_expected = clean_url_logic(target)
        core_actual = clean_url_logic(response.url)

        if core_expected == core_actual or core_expected in core_actual:
            result["Status"] = "✅ MATCH"
        else:
            result["Status"] = "❌ MISMATCH"

    except requests.exceptions.SSLError as e:
        status, detail = classify_ssl_error(e)
        result["Status"] = status
        result["Details"] = detail

    except requests.exceptions.ConnectionError:
        result["Status"] = "🚫 DOWN"

    except requests.exceptions.Timeout:
        result["Status"] = "⏱️ TIMEOUT"

    except Exception as e:
        result["Status"] = "❗ ERROR"
        result["Details"] = str(e)

    return result

# -------- Excel Fix -------- #

def sanitize_for_excel(val):
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
    st.download_button("📥 Download Template", generate_sample_file(), "template.xlsx")
    max_retries = st.number_input("Max Retries", 1, 10, 3)
    api_key = st.text_input("API Key", type="password")

file = st.file_uploader("Upload Excel", type=["xlsx"])

if file:
    if st.button("🚀 Start Validation"):

        progress = st.progress(0)
        status = st.empty()

        xls = pd.ExcelFile(file)
        sheets = xls.sheet_names

        df_rules = pd.read_excel(file, sheet_name=sheets[0])
        df_domains = pd.read_excel(file, sheet_name=sheets[1] if len(sheets)>1 else sheets[0])

        df_rules.columns = df_rules.columns.str.strip()
        df_domains.columns = df_domains.columns.str.strip()

        common = list(set(df_rules.columns) & set(df_domains.columns))[0]
        merged = pd.merge(df_domains, df_rules, on=common, how='left')

        source_col = find_column(df_domains, ['source','domain'])
        target_col = find_column(df_rules, ['target','web'])

        tasks = [
            (row[source_col], row[target_col])
            for _, row in merged.iterrows()
            if not pd.isna(row[source_col])
        ]

        results = []
        total = len(tasks)

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = [ex.submit(check_redirect, s, t, api_key, max_retries) for s,t in tasks]

            for i, f in enumerate(concurrent.futures.as_completed(futures)):
                results.append(f.result())
                progress.progress((i+1)/total)
                status.markdown(f"**⚡ Progress:** {i+1}/{total}")

        status.success("✅ Completed")

        df_res = pd.DataFrame(results)

        st.dataframe(df_res, use_container_width=True)

        st.download_button("📥 Download Report", convert_df_to_excel(df_res), "report.xlsx")
