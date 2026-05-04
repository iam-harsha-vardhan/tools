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

# ---------------- HELPERS ---------------- #

def clean_url(url):
    if not url or pd.isna(url): return ""
    u = str(url).strip().lower()
    for p in ["https://","http://","www."]:
        if u.startswith(p): u = u[len(p):]
    return u.rstrip('/')

def safe_text(res):
    try:
        return res.content.decode('utf-8', errors='ignore')[:500]
    except:
        return ""

def find_col(df, keys, fallback=0):
    for c in df.columns:
        if any(k in c.lower() for k in keys):
            return c
    return df.columns[fallback]

def classify_ssl(e):
    msg = str(e).lower()
    if "expired" in msg: return "🔒 SSL EXPIRED"
    if "hostname" in msg: return "⚠️ SSL MISMATCH"
    if "self signed" in msg: return "⚠️ SELF SIGNED"
    return "🔒 NOT SECURE"

def make_request(url, retries=3, browser=False):
    if not str(url).startswith(('http://','https://')):
        url = "http://" + str(url)

    headers = {
        "User-Agent": "Mozilla/5.0" if browser else "python-requests/2.31",
        "Accept": "text/html",
        "Accept-Encoding": "identity"
    }

    for _ in range(retries):
        try:
            return requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        except requests.exceptions.SSLError as e:
            raise e
        except:
            time.sleep(1)

    raise requests.exceptions.ConnectionError("Connection failed")

# ---------------- CLOAKING ---------------- #

def detect_cloaking(url):
    try:
        bot = make_request(url, browser=False)
        human = make_request(url, browser=True)

        if bot.url != human.url:
            return True, f"Bot:{bot.url} | Browser:{human.url}"

        if safe_text(bot)[:200] != safe_text(human)[:200]:
            return True, "Content differs"

    except:
        pass

    return False, ""

# ---------------- SAFE BROWSING ---------------- #

def safe_browse(url, key):
    if not key: return None
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json={
                "client":{"clientId":"app","clientVersion":"1.0"},
                "threatInfo":{
                    "threatTypes":["MALWARE","SOCIAL_ENGINEERING"],
                    "platformTypes":["ANY_PLATFORM"],
                    "threatEntryTypes":["URL"],
                    "threatEntries":[{"url":url}]
                }
            }, timeout=5)
        if "matches" in r.json():
            return r.json()["matches"][0]["threatType"]
    except: pass
    return None

# ---------------- CORE ---------------- #

def check(source, target, key, retries):

    res = {
        "Source Domain": source,
        "Status": "",
        "Expected Target": target,
        "Actual Final URL": "-"
    }

    core_src = clean_url(source)
    core_exp = clean_url(target)

    # 1. Dangerous
    threat = safe_browse(source, key)
    if threat:
        res["Status"] = "🚨 DANGEROUS"
        return res

    try:
        r = make_request(source, retries)
        final = r.url
        res["Actual Final URL"] = final
        core_act = clean_url(final)

        # 2. Dangerous final
        threat = safe_browse(final, key)
        if threat:
            res["Status"] = "🚨 DANGEROUS"
            return res

        # 3. Cloaking
        cloaked, detail = detect_cloaking(source)
        if cloaked:
            res["Status"] = "⚠️ CLOAKING"
            return res

        # 4. Blank/self redirect
        if core_act == core_src:
            if core_exp == core_src:
                res["Status"] = "✅ MATCH"
            else:
                res["Status"] = "❌ BLANK"
            return res

        # 5. Match logic
        if core_exp == core_act or core_exp in core_act:
            res["Status"] = "✅ MATCH"
        else:
            res["Status"] = "❌ MISMATCH"

    except requests.exceptions.SSLError as e:
        res["Status"] = classify_ssl(e)

    except requests.exceptions.ConnectionError:
        res["Status"] = "🚫 DOWN"

    except requests.exceptions.Timeout:
        res["Status"] = "⏱️ TIMEOUT"

    except Exception:
        res["Status"] = "❗ ERROR"

    return res

# ---------------- EXCEL ---------------- #

def clean_excel(val):
    if isinstance(val,str):
        return re.sub(r'[^\x20-\x7E]', '', val)
    return val

def to_excel(df):
    buf = io.BytesIO()
    df = df.copy()

    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].astype(str).apply(clean_excel)

    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        df.to_excel(w, index=False)

    return buf.getvalue()

def sample():
    out = io.BytesIO()

    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df1 = pd.DataFrame({
            'Feed Name': ['Sample'],
            'Target Website': ['example.com']
        })
        df2 = pd.DataFrame({
            'Feed Name': ['Sample'],
            'Source Domain': ['test.com']
        })

        df1.to_excel(writer, sheet_name="Target_Rules", index=False)
        df2.to_excel(writer, sheet_name="Source_Domains", index=False)

        # 🔥 CRITICAL FIX → ensure at least one active sheet
        writer.book.active = 0

    # 🔥 ALSO IMPORTANT → reset buffer pointer
    out.seek(0)

    return out.getvalue()

# ---------------- UI ---------------- #

st.title("Redirect Validator 🚀")

with st.sidebar:
    st.download_button("📥 Template", sample(), "template.xlsx")
    retries = st.number_input("Retries",1,10,3)
    api_key = st.text_input("API Key (Optional)", type="password")

file = st.file_uploader("Upload Excel", type=["xlsx"])

if file:
    if st.button("🚀 Start"):

        progress = st.progress(0)
        status = st.empty()

        xls = pd.ExcelFile(file)
        sheets = xls.sheet_names

        df_rules = pd.read_excel(file, sheets[0])
        df_domains = pd.read_excel(file, sheets[1] if len(sheets)>1 else sheets[0])

        df_rules.columns = df_rules.columns.str.strip()
        df_domains.columns = df_domains.columns.str.strip()

        common = list(set(df_rules.columns)&set(df_domains.columns))[0]

        df_rules = df_rules.drop_duplicates(subset=[common])
        df_domains = df_domains.drop_duplicates(subset=[common])

        merged = pd.merge(df_domains, df_rules, on=common, how="left")

        src_col = find_col(df_domains,["source","domain"])
        tgt_col = find_col(df_rules,["target","web"])

        tasks = [(r[src_col], r[tgt_col]) for _,r in merged.iterrows() if pd.notna(r[src_col])]

        # dedupe
        seen=set()
        tasks=[t for t in tasks if not (t[0] in seen or seen.add(t[0]))]

        total=len(tasks)
        results=[]

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures=[ex.submit(check,s,t,api_key,retries) for s,t in tasks]

            for i,f in enumerate(concurrent.futures.as_completed(futures)):
                results.append(f.result())
                progress.progress((i+1)/total)
                status.markdown(f"⚡ {i+1}/{total}")

        status.success("✅ Done")

        df_res = pd.DataFrame(results)

        # reorder columns
        df_res = df_res[["Source Domain","Status","Expected Target","Actual Final URL"]]

        st.dataframe(df_res, use_container_width=True)

        st.download_button("📥 Download", to_excel(df_res), "report.xlsx")
