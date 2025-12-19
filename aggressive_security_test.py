#!/usr/bin/env python3
"""
AGGRESSIVE Security Testing - Find ALL Vulnerabilities
Focus on stack overflow, deep nesting, and extreme stress tests
"""

import requests
import json
import sys
import time
from datetime import datetime

BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"
AUTH_URL = f"{BASE_URL}/auth"

# Track all vulnerabilities
vulnerabilities = []
test_count = 0

def log_vuln(severity, endpoint, attack_type, details, payload_desc=""):
    """Log a vulnerability"""
    vuln = {
        "severity": severity,
        "endpoint": endpoint,
        "attack_type": attack_type,
        "details": details,
        "payload": payload_desc,
        "timestamp": datetime.now().isoformat()
    }
    vulnerabilities.append(vuln)
    print(f"\n{'='*80}")
    print(f"[VULNERABILITY FOUND] {severity}")
    print(f"Type: {attack_type}")
    print(f"Endpoint: {endpoint}")
    print(f"Details: {details}")
    if payload_desc:
        print(f"Payload: {payload_desc}")
    print(f"{'='*80}\n")

def test_result(name, passed):
    """Log test result"""
    global test_count
    test_count += 1
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} Test #{test_count}: {name}")

print("="*80)
print("AGGRESSIVE SECURITY TESTING - BlogCMS")
print("Testing for: Stack Overflow, Deep Nesting, Extreme Payloads")
print("="*80)

# ============================================================================
# STEP 1: GET ADMIN AUTHENTICATION
# ============================================================================
print("\n[STEP 1] Authenticating as admin...")

try:
    login_response = requests.post(
        f"{AUTH_URL}/login",
        data={
            "username": "admin@blogcms.local",
            "password": "AdminBlogCMS2025!"
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    if login_response.status_code == 200:
        print("[SUCCESS] Admin authenticated")
        admin_token = login_response.json().get("access_token")
        admin_cookies = login_response.cookies
        admin_headers = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        }
        print(f"[INFO] Got admin token: {admin_token[:20]}...")
    else:
        print(f"[ERROR] Authentication failed: {login_response.status_code}")
        print(f"Response: {login_response.text}")
        admin_headers = {"Content-Type": "application/json"}
        admin_cookies = None
except Exception as e:
    print(f"[ERROR] Authentication error: {e}")
    admin_headers = {"Content-Type": "application/json"}
    admin_cookies = None

# ============================================================================
# STEP 2: DEEP JSON NESTING ATTACK (STACK OVERFLOW)
# ============================================================================
print("\n[STEP 2] Testing deep JSON nesting (Stack Overflow Attack)...")

def create_nested_json(depth):
    """Create deeply nested JSON object"""
    if depth == 0:
        return {"value": "bottom"}
    return {"nested": create_nested_json(depth - 1)}

def create_nested_array(depth):
    """Create deeply nested array"""
    if depth == 0:
        return ["bottom"]
    return [create_nested_array(depth - 1)]

# Test with increasing depths
depths_to_test = [100, 500, 1000, 5000, 10000]

for depth in depths_to_test:
    print(f"\n  Testing depth: {depth}")

    # Test 1: Nested object in blog post creation
    test_name = f"Deep nested object (depth={depth}) in blog post"
    try:
        nested = create_nested_json(depth)
        response = requests.post(
            f"{API_URL}/admin/blog/posts",
            json={
                "title": "Test Post",
                "content": "Test",
                "slug": "test-deep-nested",
                "metadata": nested  # Deep nesting here
            },
            headers=admin_headers,
            cookies=admin_cookies,
            timeout=10
        )

        if response.status_code == 500:
            log_vuln(
                "CRITICAL",
                f"{API_URL}/admin/blog/posts",
                "Stack Overflow - Deep JSON Nesting",
                f"Server crashed with {depth}-level nested JSON object",
                f"{depth}-level nested object"
            )
            test_result(test_name, False)
        else:
            test_result(test_name, True)

    except requests.exceptions.ConnectionError:
        log_vuln(
            "CRITICAL",
            f"{API_URL}/admin/blog/posts",
            "Stack Overflow - Deep JSON Nesting",
            f"Server crashed/disconnected with {depth}-level nested JSON",
            f"{depth}-level nested object"
        )
        test_result(test_name, False)
        print(f"[WARNING] Server may have crashed! Waiting 5 seconds...")
        time.sleep(5)
    except requests.exceptions.Timeout:
        log_vuln(
            "HIGH",
            f"{API_URL}/admin/blog/posts",
            "Resource Exhaustion",
            f"Request timeout with {depth}-level nested JSON",
            f"{depth}-level nested object"
        )
        test_result(test_name, False)
    except RecursionError:
        print(f"[INFO] RecursionError creating payload at depth {depth} - skipping")
        break
    except Exception as e:
        print(f"[ERROR] {e}")
        test_result(test_name, False)

# ============================================================================
# STEP 3: CIRCULAR REFERENCE ATTACK
# ============================================================================
print("\n[STEP 3] Testing circular reference detection...")

# Try to send circular JSON (will fail in JSON encoding, but test server handling)
test_name = "Circular reference in JSON"
try:
    # Create a string that looks like circular reference
    circular_json = '{"a": {"b": {"c": {"ref": "#/a"}}}}'
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        data=circular_json,
        headers=admin_headers,
        cookies=admin_cookies,
        timeout=5
    )
    test_result(test_name, True)
except Exception as e:
    print(f"[ERROR] {e}")
    test_result(test_name, False)

# ============================================================================
# STEP 4: EXTREMELY LARGE PAYLOADS (Beyond 2MB)
# ============================================================================
print("\n[STEP 4] Testing extremely large payloads...")

large_sizes = [
    (5 * 1024 * 1024, "5MB"),      # 5MB
    (10 * 1024 * 1024, "10MB"),    # 10MB
    (50 * 1024 * 1024, "50MB"),    # 50MB
]

for size, label in large_sizes:
    test_name = f"Large payload - {label}"
    print(f"\n  Testing {label} payload...")

    try:
        large_content = "A" * size
        response = requests.post(
            f"{API_URL}/admin/blog/posts",
            json={
                "title": "Large Post",
                "content": large_content,
                "slug": "test-large"
            },
            headers=admin_headers,
            cookies=admin_cookies,
            timeout=30
        )

        if response.status_code == 500:
            log_vuln(
                "HIGH",
                f"{API_URL}/admin/blog/posts",
                "Buffer Overflow",
                f"Server error with {label} payload",
                label
            )
            test_result(test_name, False)
        elif response.status_code == 413:
            print(f"[INFO] Server properly rejects {label} payload (413 Payload Too Large)")
            test_result(test_name, True)
        else:
            test_result(test_name, True)

    except requests.exceptions.ConnectionError:
        log_vuln(
            "CRITICAL",
            f"{API_URL}/admin/blog/posts",
            "Server Crash",
            f"Server crashed with {label} payload",
            label
        )
        test_result(test_name, False)
        print(f"[WARNING] Server may have crashed! Waiting 5 seconds...")
        time.sleep(5)
    except requests.exceptions.Timeout:
        log_vuln(
            "HIGH",
            f"{API_URL}/admin/blog/posts",
            "Resource Exhaustion",
            f"Request timeout with {label} payload",
            label
        )
        test_result(test_name, False)
    except MemoryError:
        print(f"[ERROR] Client ran out of memory creating {label} payload")
        test_result(test_name, False)
        break
    except Exception as e:
        print(f"[ERROR] {e}")
        test_result(test_name, False)

# ============================================================================
# STEP 5: MALFORMED JSON ATTACKS
# ============================================================================
print("\n[STEP 5] Testing malformed JSON handling...")

malformed_jsons = [
    ('{"key": "value"' * 10000, "Unclosed braces (10000x)"),
    ('{"key": ' + '"value",' * 10000, "Unclosed object with many keys"),
    ('[' * 10000 + ']' * 10000, "Deeply nested empty arrays"),
    ('{"a":' * 5000 + '1' + '}' * 5000, "5000-level nested object"),
]

for payload, description in malformed_jsons:
    test_name = f"Malformed JSON: {description}"
    print(f"\n  Testing: {description}")

    try:
        response = requests.post(
            f"{API_URL}/admin/blog/posts",
            data=payload,
            headers=admin_headers,
            cookies=admin_cookies,
            timeout=10
        )

        if response.status_code == 500:
            log_vuln(
                "HIGH",
                f"{API_URL}/admin/blog/posts",
                "JSON Parser Crash",
                f"Server error with malformed JSON: {description}",
                description
            )
            test_result(test_name, False)
        else:
            test_result(test_name, True)

    except requests.exceptions.ConnectionError:
        log_vuln(
            "CRITICAL",
            f"{API_URL}/admin/blog/posts",
            "Server Crash",
            f"Server crashed with malformed JSON: {description}",
            description
        )
        test_result(test_name, False)
    except Exception as e:
        print(f"[ERROR] {e}")
        test_result(test_name, False)

# ============================================================================
# STEP 6: TEST ALL ADMIN ENDPOINTS WITH INJECTION
# ============================================================================
print("\n[STEP 6] Testing all admin endpoints with aggressive payloads...")

admin_endpoints = [
    # Blog admin
    ("POST", f"{API_URL}/admin/blog/posts", {"title": "' OR '1'='1", "content": "test", "slug": "test"}),
    ("PUT", f"{API_URL}/admin/blog/posts/1", {"title": "'; DROP TABLE posts--", "content": "test"}),
    ("POST", f"{API_URL}/admin/blog/categories", {"name": "' UNION SELECT NULL--", "slug": "test"}),
    ("POST", f"{API_URL}/admin/blog/tags", {"name": "' OR 1=1--", "slug": "test"}),

    # Bulk operations
    ("POST", f"{API_URL}/admin/blog/posts/bulk-update", {
        "post_ids": ["' OR '1'='1"],
        "published": True
    }),
]

for method, endpoint, payload in admin_endpoints:
    test_name = f"{method} {endpoint}"
    print(f"\n  Testing: {test_name}")

    try:
        if method == "POST":
            response = requests.post(endpoint, json=payload, headers=admin_headers, cookies=admin_cookies, timeout=5)
        elif method == "PUT":
            response = requests.put(endpoint, json=payload, headers=admin_headers, cookies=admin_cookies, timeout=5)
        elif method == "DELETE":
            response = requests.delete(endpoint, headers=admin_headers, cookies=admin_cookies, timeout=5)
        else:
            response = requests.get(endpoint, headers=admin_headers, cookies=admin_cookies, timeout=5)

        # Check for SQL errors
        if any(error in response.text.lower() for error in ['sql', 'syntax error', 'postgresql', 'database']):
            log_vuln(
                "HIGH",
                endpoint,
                "SQL Injection",
                f"SQL error in {method} request",
                str(payload)
            )
            test_result(test_name, False)
        else:
            test_result(test_name, True)

    except Exception as e:
        print(f"[ERROR] {e}")
        test_result(test_name, False)

# ============================================================================
# STEP 7: TEST NEWSLETTER WITH EXTREME CASES
# ============================================================================
print("\n[STEP 7] Testing newsletter with extreme cases...")

newsletter_tests = [
    # Very long email
    ("A" * 10000 + "@example.com", "10000 char email"),
    # Email with SQL injection
    ("admin@example.com'; DROP TABLE newsletter_subscribers--", "SQL injection in email"),
    # Unicode/special chars
    ("test\x00@example.com", "Null byte in email"),
    ("test\r\n@example.com", "CRLF in email"),
]

for email, description in newsletter_tests:
    test_name = f"Newsletter: {description}"
    print(f"\n  Testing: {description}")

    try:
        response = requests.post(
            f"{API_URL}/newsletter/subscribe",
            json={"email": email},
            timeout=5
        )

        if response.status_code == 500:
            log_vuln(
                "MEDIUM",
                f"{API_URL}/newsletter/subscribe",
                "Input Validation Error",
                f"Server error with {description}",
                email[:100]
            )
            test_result(test_name, False)
        else:
            test_result(test_name, True)

    except Exception as e:
        print(f"[ERROR] {e}")
        test_result(test_name, False)

# ============================================================================
# STEP 8: STRESS TEST WITH RAPID REQUESTS
# ============================================================================
print("\n[STEP 8] Stress testing with rapid requests...")

test_name = "Rapid fire requests (100 requests in quick succession)"
print(f"\n  Testing: {test_name}")

try:
    errors = 0
    for i in range(100):
        response = requests.get(f"{API_URL}/blog/posts", timeout=2)
        if response.status_code >= 500:
            errors += 1

    if errors > 10:
        log_vuln(
            "MEDIUM",
            f"{API_URL}/blog/posts",
            "Rate Limiting / Resource Exhaustion",
            f"{errors} server errors out of 100 rapid requests",
            "100 rapid GET requests"
        )
        test_result(test_name, False)
    else:
        print(f"[INFO] {errors} errors out of 100 requests")
        test_result(test_name, True)

except Exception as e:
    print(f"[ERROR] {e}")
    test_result(test_name, False)

# ============================================================================
# GENERATE REPORT
# ============================================================================
print("\n" + "="*80)
print("AGGRESSIVE SECURITY TEST COMPLETED")
print("="*80)
print(f"Total Tests: {test_count}")
print(f"Vulnerabilities Found: {len(vulnerabilities)}")

if vulnerabilities:
    print("\n" + "="*80)
    print("VULNERABILITIES SUMMARY")
    print("="*80)

    critical = [v for v in vulnerabilities if v['severity'] == 'CRITICAL']
    high = [v for v in vulnerabilities if v['severity'] == 'HIGH']
    medium = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']

    print(f"\nCRITICAL: {len(critical)}")
    for v in critical:
        print(f"  - {v['attack_type']} at {v['endpoint']}")
        print(f"    {v['details']}")

    print(f"\nHIGH: {len(high)}")
    for v in high:
        print(f"  - {v['attack_type']} at {v['endpoint']}")
        print(f"    {v['details']}")

    print(f"\nMEDIUM: {len(medium)}")
    for v in medium:
        print(f"  - {v['attack_type']} at {v['endpoint']}")
        print(f"    {v['details']}")

    # Save to file
    report_file = f"aggressive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({
            "test_count": test_count,
            "vulnerabilities": vulnerabilities,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)

    print(f"\n[SAVED] Detailed report: {report_file}")

    sys.exit(1)  # Exit with error code if vulnerabilities found
else:
    print("\n[SUCCESS] No vulnerabilities found!")
    sys.exit(0)
