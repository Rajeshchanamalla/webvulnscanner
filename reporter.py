from jinja2 import Environment, FileSystemLoader
import pdfkit
import os

def log_finding(finding):
    with open('scan_log.txt', 'a') as f:
        f.write(f"URL: {finding['url']}\nType: {finding['type']}\nPayload: {finding['payload']}\nEvidence: {finding['evidence']}\nSeverity: {finding['severity']}\nLocation: {finding['location']}\nRating: {finding['rating']}\n\n")

def generate_html_report(results, target):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')
    grouped = {vuln: [] for vuln in set(r['type'] for r in results)}
    for r in results:
        grouped[r['type']].append(r)
    return template.render(target=target, results=grouped)

def generate_pdf_report(results, target):
    html = generate_html_report(results, target)
    pdf_path = 'report.pdf'
    config = pdfkit.configuration(wkhtmltopdf=os.environ.get('WKHTMLTOPDF_PATH', '/usr/local/bin/wkhtmltopdf'))  # Adjust path if needed
    pdfkit.from_string(html, pdf_path, configuration=config, options={'encoding': 'utf-8'})
    return pdf_path