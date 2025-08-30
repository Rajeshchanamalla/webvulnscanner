from flask import Flask, render_template, request, send_file, make_response
import os
import threading
from crawler import crawl_website
from detectors import scan_vulnerabilities
from reporter import generate_html_report, generate_pdf_report, log_finding

app = Flask(__name__)

# Global variables for scan progress and results
scan_progress = 0
scan_results = []
scan_thread = None
target_url = ""
stop_scan_flag = False

@app.route('/', methods=['GET', 'POST'])
def index():
    global target_url, scan_progress, scan_results, scan_thread, stop_scan_flag
    if request.method == 'POST':
        target_url = request.form.get('url')
        scan_progress = 0
        scan_results = []
        stop_scan_flag = False
        scan_thread = threading.Thread(target=run_scan, args=(target_url,))
        scan_thread.start()
        return render_template('results.html', progress=scan_progress, results=scan_results)
    return render_template('index.html')

@app.route('/progress')
def progress():
    global scan_progress
    return {'progress': scan_progress}

@app.route('/results')
def results():
    global scan_results, scan_progress
    return render_template('results.html', progress=scan_progress, results=scan_results)

@app.route('/stop', methods=['POST'])
def stop_scan():
    global stop_scan_flag, scan_progress, scan_results
    stop_scan_flag = True
    scan_progress = 0
    scan_results = []
    return {'status': 'Scan stopped'}

@app.route('/report/html')
def report_html():
    html = generate_html_report(scan_results, target_url)
    response = make_response(html)
    response.headers["Content-Type"] = "text/html"
    response.headers["Content-Disposition"] = "attachment; filename=report.html"
    return response

@app.route('/report/pdf')
def report_pdf():
    pdf_path = generate_pdf_report(scan_results, target_url)
    return send_file(pdf_path, as_attachment=True, download_name='report.pdf')

def run_scan(url):
    global scan_progress, scan_results, stop_scan_flag
    urls, forms = crawl_website(url)
    total_steps = len(urls) + len(forms)
    step = 0
    for u in urls:
        if stop_scan_flag:
            break
        vulns = scan_vulnerabilities(u, forms.get(u, []))
        scan_results.extend(vulns)
        step += 1
        scan_progress = int((step / total_steps) * 100)
    if not stop_scan_flag:
        # Deduplicate ignoring 'url'
        unique = {}
        for v in scan_results:
            v_copy = v.copy()
            del v_copy['url']
            key = tuple(sorted(v_copy.items()))
            if key not in unique:
                unique[key] = v
        scan_results = list(unique.values())
        scan_progress = 100
    else:
        scan_progress = 0

if __name__ == '__main__':
    app.run(debug=True)