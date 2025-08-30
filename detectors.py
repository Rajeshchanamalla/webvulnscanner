import requests
import re
import subprocess
import time
import difflib
from urllib.parse import urljoin
from payloads import *

def scan_vulnerabilities(url, forms):
    findings = []
    # A03: Injection
    findings.extend(test_injection(url, forms))
    # A01: Broken Access Control
    findings.extend(test_access_control(url))
    # A02: Cryptographic Failures
    findings.extend(test_crypto_failures(url))
    # A04: Insecure Design
    findings.extend(test_insecure_design(url))
    # A05: Security Misconfiguration
    findings.extend(test_misconfig(url))
    # A06: Vulnerable and Outdated Components
    findings.extend(test_vuln_components())
    # A07: Identification and Authentication Failures
    findings.extend(test_auth_failures(url, forms))
    # A08: Software and Data Integrity Failures
    findings.extend(test_integrity_failures(url))
    # A09: Security Logging and Monitoring Failures
    findings.extend(test_logging_failures(url))
    # A10: Server-Side Request Forgery
    findings.extend(test_ssrf(url, forms))
    return findings

def calculate_rating(severity, evidence_strength):
    base = {'High': 8, 'Medium': 5, 'Low': 2}.get(severity, 0)
    return min(10, base + evidence_strength)

def submit_payload(form, url, payload, method='get', location='input'):
    data = {inp['name']: payload for inp in form['inputs'] if inp['name']}
    target = urljoin(url, form['action'])
    if form['method'] == 'post':
        return requests.post(target, data=data), location
    return requests.get(target, params=data), location

def test_injection(url, forms):
    findings = []
    payloads = SQLI_PAYLOADS + XSS_PAYLOADS + COMMAND_INJ_PAYLOADS + NOSQL_PAYLOADS + LDAP_PAYLOADS
    benign_payload = "benign_test_input"
    for form in forms:
        benign_resp, _ = submit_payload(form, url, benign_payload, form['method'])
        benign_text = benign_resp.text
        for payload in payloads:
            start = time.time()
            resp, loc = submit_payload(form, url, payload, form['method'], f"Form: {form['action']}")
            elapsed = time.time() - start
            evidence = ''
            strength = 0
            diff = ''.join(difflib.ndiff(benign_text.splitlines(), resp.text.splitlines()))
            if re.search(r'(sql|syntax|error|command not found|alert\(.*\)|xss)', diff, re.I):
                evidence = diff[:200]
                strength += 2
            if payload.lower() in resp.text.lower() and payload.lower() not in benign_text.lower():
                evidence += ' (Payload reflected)'
                strength += 2
            if elapsed > 4 and elapsed > (time.time() - start - 0.5):
                evidence += ' (Time delay detected)'
                strength += 3
            if strength > 3:  # Raised threshold
                sev = 'High' if strength > 4 else 'Medium'
                findings.append({
                    'url': url, 'type': 'A03: Injection', 'payload': payload, 'evidence': evidence,
                    'severity': sev, 'location': loc, 'rating': calculate_rating(sev, strength)
                })
    return findings

def test_access_control(url):
    findings = []
    benign_payload = "/index"
    benign_resp = requests.get(urljoin(url, benign_payload))
    benign_text = benign_resp.text
    traversal_patterns = r'(root:|bin:|etc:|home:|/bin/bash|passwd)'
    for test in ACCESS_CONTROL_TESTS:
        test_url = urljoin(url, test)
        try:
            resp = requests.get(test_url, timeout=5)
            strength = 0
            evidence = ''
            diff = ''.join(difflib.ndiff(benign_text.splitlines(), resp.text.splitlines()))
            if resp.status_code == 200:
                if re.search(traversal_patterns, resp.text, re.I):  # Specific for traversal
                    evidence = 'Sensitive system file content leaked'
                    strength += 4
                elif re.search(r'(admin|dashboard|secret|unauthorized)', diff.lower(), re.I):
                    evidence = 'Accessed restricted resource (diff detected)'
                    strength += 2
            if strength > 3:  # Raised threshold, requires stronger evidence
                sev = 'High' if strength > 4 else 'Medium'
                findings.append({
                    'url': test_url, 'type': 'A01: Broken Access Control', 'payload': test,
                    'evidence': evidence, 'severity': sev, 'location': 'URL Path',
                    'rating': calculate_rating(sev, strength)
                })
        except requests.RequestException:
            pass
    return findings

def test_crypto_failures(url):
    findings = []
    resp = requests.get(url)
    strength = 0
    evidence = []
    for name, pattern in CRYPTO_PATTERNS.items():
        matches = re.findall(pattern, resp.text)
        if matches:
            evidence.append(f"Found {name}: {matches[:3]}")
            strength += len(matches)
    if not url.startswith('https'):
        evidence.append('Non-HTTPS connection')
        strength += 2
    if strength > 2:  # Raised threshold
        sev = 'High' if strength > 3 else 'Medium'
        findings.append({
            'url': url, 'type': 'A02: Cryptographic Failures', 'payload': '', 'evidence': '; '.join(evidence),
            'severity': sev, 'location': 'Page Content', 'rating': calculate_rating(sev, strength)
        })
    return findings

def test_insecure_design(url):
    findings = []
    login_url = url + '/login'
    try:
        resp_get = requests.get(login_url)
        if resp_get.status_code != 200:
            return []  # Skip if no login endpoint
    except:
        return []
    strength = 0
    evidence = []
    for _ in range(5):
        resp = requests.post(login_url, data={'user': 'test', 'pass': 'test'})
        if resp.status_code != 429:  # No rate limit
            strength += 1
    if strength > 3:
        evidence.append('No rate limiting detected')
        sev = 'Medium'
        findings.append({
            'url': url, 'type': 'A04: Insecure Design', 'payload': '', 'evidence': '; '.join(evidence),
            'severity': sev, 'location': 'Login Endpoint', 'rating': calculate_rating(sev, strength)
        })
    return findings

def test_misconfig(url):
    findings = []
    resp = requests.get(url)
    strength = 0
    evidence = []
    for pattern in MISCONFIG_PATTERNS:
        if pattern in resp.text.lower():
            evidence.append(pattern)
            strength += 1
    if strength > 1:  # Raised threshold
        sev = 'Medium' if strength < 3 else 'High'
        findings.append({
            'url': url, 'type': 'A05: Security Misconfiguration', 'payload': '', 'evidence': '; '.join(evidence),
            'severity': sev, 'location': 'Page Response', 'rating': calculate_rating(sev, strength)
        })
    return findings

def test_vuln_components():
    findings = []
    try:
        result = subprocess.run(VULN_COMPONENTS_CMD, shell=True, capture_output=True, text=True)
        strength = result.stdout.count('vulnerability')
        if strength > 0:
            findings.append({
                'url': '', 'type': 'A06: Vulnerable and Outdated Components', 'payload': '',
                'evidence': result.stdout[:200], 'severity': 'Medium', 'location': 'Dependencies',
                'rating': calculate_rating('Medium', strength)
            })
    except:
        pass
    return findings

def test_auth_failures(url, forms):
    findings = []
    for username, password in BROKEN_AUTH_PAYLOADS:
        for form in forms:
            if any(inp['type'] == 'password' for inp in form['inputs']):
                data = {'username': username, 'password': password}
                resp = requests.post(urljoin(url, form['action']), data=data)
                strength = 0
                if 'welcome' in resp.text.lower() or (resp.status_code == 200 and 'login failed' not in resp.text.lower()):
                    evidence = 'Successful login with weak creds'
                    strength += 3
                if strength > 2:  # Raised threshold
                    findings.append({
                        'url': url, 'type': 'A07: Identification and Authentication Failures', 'payload': f"{username}:{password}",
                        'evidence': evidence, 'severity': 'High', 'location': f"Form: {form['action']}",
                        'rating': calculate_rating('High', strength)
                    })
    return findings

def test_integrity_failures(url):
    findings = []
    benign_payload = "safe_data"
    try:
        benign_resp = requests.post(url, data=benign_payload, headers={'Content-Type': 'application/x-python-serialize'})
    except:
        return findings
    for payload in DESERIAL_PAYLOADS:
        try:
            resp = requests.post(url, data=payload, headers={'Content-Type': 'application/x-python-serialize'})
            strength = 0
            evidence = ''
            diff = ''.join(difflib.ndiff(benign_resp.text.splitlines(), resp.text.splitlines()))
            if re.search(r'(hacked|ls -la|bin|etc|root|system executed)', diff, re.I):  # Stricter regex for execution
                evidence = 'Payload executed (specific output detected in diff)'
                strength += 4
            if strength > 3:  # Raised threshold
                findings.append({
                    'url': url, 'type': 'A08: Software and Data Integrity Failures', 'payload': payload,
                    'evidence': evidence, 'severity': 'High', 'location': 'POST Data',
                    'rating': calculate_rating('High', strength)
                })
        except:
            pass
    return findings

def test_logging_failures(url):
    findings = []
    try:
        resp = requests.get(url + '?invalid=1')
        if resp.status_code < 400:
            return []  # No error triggered, skip
        strength = 0
        logged = any(p in resp.text.lower() for p in LOGGING_CHECKS)
        if not logged:
            evidence = 'No log evidence in response'
            strength += 2
        if strength > 2:  # Raised threshold
            findings.append({
                'url': url, 'type': 'A09: Security Logging and Monitoring Failures', 'payload': '',
                'evidence': evidence, 'severity': 'Low', 'location': 'Error Response',
                'rating': calculate_rating('Low', strength)
            })
    except:
        pass
    return findings

def test_ssrf(url, forms):
    findings = []
    benign_payload = "https://example.com"
    for form in forms:
        benign_resp, _ = submit_payload(form, url, benign_payload, form['method'])
        benign_text = benign_resp.text
        for payload in SSRF_PAYLOADS:
            resp, loc = submit_payload(form, url, payload, form['method'], f"Form: {form['action']}")
            evidence = ''
            strength = 0
            diff = ''.join(difflib.ndiff(benign_text.splitlines(), resp.text.splitlines()))
            if re.search(r'(localhost|127\.0\.0\.1|metadata|passwd|internal)', diff, re.I):
                evidence = diff[:200]
                strength += 3
            if strength > 2:  # Raised threshold
                findings.append({
                    'url': url, 'type': 'A10: SSRF', 'payload': payload, 'evidence': evidence,
                    'severity': 'High', 'location': loc, 'rating': calculate_rating('High', strength)
                })
    return findings