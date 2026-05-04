import streamlit as st
import pandas as pd
import requests
import io
import time
import urllib3
import concurrent.futures
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="Redirect Validator", page_icon="🔗", layout="wide")

# ---------------- UI ---------------- #
st.title("Redirect Validator 🚀")

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

def is_html_response(response):
    return 'text/html' in response.headers.get('Content-Type', '').lower()

# ---------------- SSL CLASSIFICATION ---------------- #

def classify_ssl_error(e):
    msg = str(e).lower()

    if "expired" in msg:
        return "🔒 SSL EXPIRED", "Certificate expired"

    if "hostname" in msg or "doesn't match" in msg:
        return "⚠️ SSL MISMATCH", "Domain mismatch"

    if "self signed" in msg:
        return "⚠️ SELF SIGNED", "Self-signed certificate"

    if "verify failed" in msg:
        return "🔒 SSL FAILED", "Certificate verify failed"

    return "🔒 NOT SECURE", "Unknown SSL issue"

# ---------------- REQUEST ---------------- #

def make_request(url, retries=3):
    target_url = str(url).strip()

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'text/html',
        'Accept-Encoding': 'identity',  # IMPORTANT FIX
    }

    last_err = None

    for _ in range(retries):
        try:
            return requests.get(target_url, headers=headers, allow_redirects=True, timeout=10)
        except requests.exceptions.SSLError as e:
            raise e
        except Exception as e:
            last_err = e
            time.sleep(1)

    raise last_err

# ---------------- SAFE BROWSING ---------------- #

def check_safe_browsing(url, api_key):
    if not api_key:
        return None

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {"clientId": "redirect-validator", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
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

# ---------------- CORE ---------------- #

def check_redirect(source, expected, api_key=None, retries=3):

    core_expected = clean_url_logic(expected)

    result = {
        "Source Domain": source,
        "Expected Target": expected,
        "Actual Final URL": "-",
        "Status": "",
        "Details": "",
        "Page Output": ""
    }

    # Safe Browsing (source)
    threat = check_safe_browsing(source, api_key)
    if threat:
        result["Status"] = "🚨 DANGEROUS"
        result["Details"] = threat
        return result

    try:
        response = make_request(source, retries)

        final_url = response.url
        result["Actual Final URL"] = final_url

        # Extract content safely
        if is_html_response(response):
            content = safe_extract_text(response)
            result["Page Output"] = content if content.strip() else "Empty page"
        else:
            result["Page Output"] = "Non-HTML content"

        core_actual = clean_url_logic(final_url)

        # Safe Browsing (final)
        threat = check_safe_browsing(final_url, api_key)
        if threat:
            result["Status"] = "🚨 DANGEROUS"
            result["Details"] = threat
            return result

        # Redirect logic
        if core_expected == core_actual or core_expected in core_actual:
            result["Status"] = "✅ MATCH"
            result["Details"] = "OK"
        else:
            result["Status"] = "❌ MISMATCH"
            result["Details"] = "Wrong redirect"

    except requests.exceptions.SSLError as e:
        status, detail = classify_ssl_error(e)
        result["Status"] = status
        result["Details"] = detail

    except requests.exceptions.ConnectionError:
        result["Status"] = "🚫 DOWN"
        result["Details"] = "Server unreachable"

    except requests.exceptions.Timeout:
        result["Status"] = "⏱️ TIMEOUT"
        result["Details"] = "Slow response"

    except Exception as e:
        result["Status"] = "❗ ERROR"
        result["Details"] = str(e)

    return result

# ---------------- EXCEL ---------------- #

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

# ---------------- MAIN ---------------- #

file = st.file_uploader("Upload Excel File", type=["xlsx"])

if file:
    if st.button("🚀 Start Validation"):

        df = pd.read_excel(file)

        # CLEAN COLUMN NAMES
        df.columns = df.columns.str.strip()

        # AUTO DETECT COLUMNS
        source_col = next(c for c in df.columns if 'source' in c.lower() or 'domain' in c.lower())
        target_col = next(c for c in df.columns if 'target' in c.lower() or 'web' in c.lower())

        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [
                executor.submit(check_redirect, row[source_col], row[target_col])
                for _, row in df.iterrows()
                if not pd.isna(row[source_col])
            ]

            for f in futures:
                results.append(f.result())

        df_res = pd.DataFrame(results)

        st.dataframe(df_res, use_container_width=True)

        st.download_button(
            "📥 Download Report",
            convert_df_to_excel(df_res),
            "redirect_report.xlsx"
        )
