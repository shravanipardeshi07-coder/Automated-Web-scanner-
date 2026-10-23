from __future__ import annotations

import pandas as pd
import streamlit as st

from scanner import scan_url, SECURITY_HEADERS, save_report

st.set_page_config(
    page_title="Automated Web Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.stApp { background: #0b1020; }
.block-container { padding-top: 2rem; max-width: 1200px; }
.hero { padding: 1.6rem; border: 1px solid #26344d; border-radius: 18px;
        background: linear-gradient(130deg, #14213b, #111827); margin-bottom: 1rem; }
.hero h1 { margin: 0; font-size: 2.35rem; }
.hero p { color: #b6c3d8; margin-bottom: 0; }
div[data-testid="stMetric"] { background: #151f31; padding: 1rem;
    border: 1px solid #26344d; border-radius: 12px; }
.small-note { color: #9caec7; font-size: .9rem; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <h1>🛡️ Automated Web Scanner</h1>
  <p>Check common HTTP security headers and export a clear scan report.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("⚙️ Scan settings")
    timeout = st.slider("Request timeout (seconds)", min_value=3, max_value=20, value=10)
    verify_tls = st.checkbox("Verify TLS certificate", value=True)
    st.divider()
    st.caption("Use only on websites you own or are authorized to assess.")
    st.caption("This tool makes a single HTTP request and checks response headers. It does not exploit vulnerabilities.")

url = st.text_input("Website URL", placeholder="https://example.com")
scan_button = st.button("🔎 Scan website", type="primary", use_container_width=True)

if scan_button:
    if not url.strip():
        st.error("Enter a website URL first.")
    else:
        with st.spinner("Requesting the website and checking its response headers…"):
            result = scan_url(url.strip(), timeout=timeout, verify_tls=verify_tls)
        st.session_state["last_scan"] = result

result = st.session_state.get("last_scan")

if result:
    st.divider()
    if result.get("error"):
        st.error(result["error"])
    else:
        headers = result["headers"]
        present = sum(1 for item in headers if item["present"])
        total = len(headers)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("HTTP status", result["status_code"])
        c2.metric("Security headers found", f"{present}/{total}")
        c3.metric("Missing headers", total - present)
        c4.metric("Response time", f'{result["elapsed_ms"]} ms')

        st.subheader("Security header results")
        df = pd.DataFrame([
            {
                "Header": item["name"],
                "Status": "Present" if item["present"] else "Missing",
                "Value": item["value"] or "—",
                "Purpose": item["purpose"],
            }
            for item in headers
        ])
        st.dataframe(df, use_container_width=True, hide_index=True)

        missing = [item for item in headers if not item["present"]]
        if missing:
            st.warning("Missing headers are potential hardening opportunities, not proof that the website is vulnerable.")
            with st.expander("Recommendations for missing headers", expanded=True):
                for item in missing:
                    st.markdown(f"**{item['name']}** — {item['recommendation']}")
        else:
            st.success("All headers checked by this tool were present in the response.")

        report_text = result["report"]
        st.download_button(
            "⬇️ Download scan report (.txt)",
            data=report_text,
            file_name="web_scan_report.txt",
            mime="text/plain",
            use_container_width=True,
        )
        st.download_button(
            "⬇️ Download results (.csv)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="web_scan_results.csv",
            mime="text/csv",
            use_container_width=True,
        )

st.divider()
st.markdown("""
<div class="small-note">
<strong>Scope and limitations:</strong> This educational scanner checks a small set of HTTP response
security headers. It is not a penetration tester, does not test application logic, and cannot confirm
the absence of vulnerabilities. Results may vary by URL, redirects, server configuration, and network.
</div>
""", unsafe_allow_html=True)
