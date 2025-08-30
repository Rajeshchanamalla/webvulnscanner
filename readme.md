Web Application Vulnerability Scanner

A Web Application Vulnerability Scanner built in Python for detecting security flaws in websites.
This tool is designed for educational and research purposes only and supports scanning both real-world test environments and intentionally vulnerable applications.

🚀 Features

Crawling: Automatically discovers URLs, pages, and input fields.

Payload Injection: Uses crafted payloads to test for vulnerabilities.

OWASP Top 10 Coverage: Detects common web vulnerabilities, including:

SQL Injection (SQLi)

Cross-Site Scripting (XSS)

Command Injection

File Inclusion

Broken Authentication

Sensitive Data Exposure

Security Misconfiguration

Cross-Site Request Forgery (CSRF)

Using Components with Known Vulnerabilities

Insufficient Logging & Monitoring

Reporting: Generates detailed reports of findings.

📂 Project Structure
web_vulnscanner/
│── app.py               # Main entry point (Flask-based web UI / CLI runner)
│── crawler.py           # Module for crawling and discovering pages
│── detectors.py         # Detection engine for vulnerabilities
│── payloads.py          # Payload definitions for attacks
│── reporter.py          # Reporting module (logs, summaries, exports)
│── reporter_errors.log  # Error logs from scanning
│── requirements.txt     # Python dependencies
│── .venv/               # Virtual environment (can be ignored)

🛠️ Installation

Clone this repository:

git clone https://github.com/yourusername/web_vulnscanner.git
cd web_vulnscanner


Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows


Install dependencies:

pip install -r requirements.txt

▶️ Usage

Run the scanner:

python app.py


The app may launch a web interface (Flask UI) or run in CLI mode depending on configuration.

Enter the target URL for scanning.

View vulnerability reports in the terminal or generated report files.

⚠️ Disclaimer

This project is strictly for educational and research purposes only.
Do NOT use this tool against websites without proper authorization. Unauthorized testing is illegal and unethical.

📜 License

This project is licensed under the MIT License.