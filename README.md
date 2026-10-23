# Automated Web Scanner

A small educational Streamlit app that checks common HTTP response security headers and creates downloadable reports.

## Features

- URL validation and HTTPS default for bare hostnames
- Checks five headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`
- Shows HTTP status and response time
- Provides recommendations for missing headers
- Downloads text and CSV reports
- Handles timeouts, TLS errors, redirects, and connection failures
- Includes automated unit tests

## Run locally

Use Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

## Run tests

```bash
python -m unittest -v
```

## Deploy to Streamlit Community Cloud

1. Create a new GitHub repository, for example `automated-web-scanner`.
2. Upload `app.py`, `scanner.py`, `test_scanner.py`, `requirements.txt`, `README.md`, and `.gitignore` to the repository root.
3. Open https://share.streamlit.io/ and sign in with GitHub.
4. Select **Create app**, choose the new repository and branch, and set the main file path to `app.py`.
5. Deploy. Streamlit will install the dependencies from `requirements.txt`.

## Safety and limitations

- Only scan websites you own or have permission to assess.
- The scanner makes a single GET request and reads response headers; it does not exploit vulnerabilities or test application logic.
- A missing header is a hardening observation, not proof of a vulnerability.
- Do not disable TLS verification for normal use.
- Some headers may be set on different routes or by a CDN, so results can vary by URL.

## Project structure

```text
automated-web-scanner/
├── app.py
├── scanner.py
├── test_scanner.py
├── requirements.txt
├── README.md
└── .gitignore
```
