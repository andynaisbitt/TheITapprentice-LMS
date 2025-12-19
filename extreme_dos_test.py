#!/usr/bin/env python3
"""
EXTREME DoS AND OVERSIZED PAYLOAD TESTING
This will find the oversized payload vulnerabilities from last session
"""

import requests
import json
import sys
import time
from datetime import datetime

BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"
AUTH_URL = f"{BASE_URL}/auth"

vulnerabilities = []
test_count = 0

def log_vuln(severity, endpoint, attack_type, details, payload_size=""):
    vuln = {
        "severity": severity,
        "endpoint": endpoint,
        "attack_type": attack_type,
        "details": details,
        "payload_size": payload_size,
        "timestamp": datetime.now().isoformat()
    }
    vulnerabilities.append(vuln)
    print(f"\n{'='*80}")
    print(f"[VULNERABILITY] {severity} - {attack_type}")
    print(f"Endpoint: {endpoint}")
    print(f"Details: {details}")
    if payload_size:
        print(f"Payload Size: {payload_size}")
    print(f"{'='*80}\n")

def test(name):
    global test_count
    test_count += 1
    print(f"[Test #{test_count}] {name}", end=" ... ")

print("="*80)
print("EXTREME DoS AND OVERSIZED PAYLOAD TESTING")
print("Finding the memory exhaustion vulnerabilities")
print("="*80)

# Authenticate
print("\n[AUTH] Authenticating as admin...")
try:
    login = requests.post(f"{AUTH_URL}/login",
        data={"username": "admin@blogcms.local", "password": "AdminBlogCMS2025!"},
        timeout=5)
    token = login.json().get("access_token")
    cookies = login.cookies
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print("[SUCCESS] Authenticated")
except Exception as e:
    print(f"[ERROR] {e}")
    headers = {"Content-Type": "application/json"}
    cookies = None

# ============================================================================
# TEST 1: MASSIVE JSON PAYLOAD (100MB+)
# ============================================================================
print("\n[SECTION 1] MASSIVE JSON PAYLOADS (DoS)")
print("-" * 80)

# Test 1.1: 50MB JSON string
test("50MB JSON string in title field")
try:
    huge_title = "A" * (50 * 1024 * 1024)  # 50MB
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": huge_title, "content": "test", "slug": "test"},
        headers=headers,
        cookies=cookies,
        timeout=30
    )

    if response.status_code == 413:
        print("PASS (413 Payload Too Large)")
    elif response.status_code == 500:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - Memory Exhaustion",
                 "Server crashed with 50MB title field", "50MB")
        print("FAIL - Server Error 500")
    elif response.status_code == 200:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - No Size Limit",
                 "Server accepted 50MB title field", "50MB")
        print("FAIL - Accepted 50MB payload!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
             "DoS - Server Crash",
             "Server crashed/disconnected with 50MB payload", "50MB")
    print("FAIL - Connection lost (server crashed?)")
    time.sleep(5)
except requests.exceptions.Timeout:
    log_vuln("HIGH", f"{API_URL}/admin/blog/posts",
             "DoS - Resource Exhaustion",
             "Request timeout with 50MB payload", "50MB")
    print("FAIL - Timeout")
except MemoryError:
    print("SKIP - Client out of memory")
except Exception as e:
    print(f"ERROR - {e}")

# Test 1.2: 100MB JSON string
test("100MB JSON string in content field")
try:
    huge_content = "B" * (100 * 1024 * 1024)  # 100MB
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": "Test", "content": huge_content, "slug": "test2"},
        headers=headers,
        cookies=cookies,
        timeout=30
    )

    if response.status_code == 413:
        print("PASS (413 Payload Too Large)")
    elif response.status_code == 500:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - Memory Exhaustion",
                 "Server crashed with 100MB content field", "100MB")
        print("FAIL - Server Error 500")
    elif response.status_code == 200:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - No Size Limit",
                 "Server accepted 100MB content field", "100MB")
        print("FAIL - Accepted!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
             "DoS - Server Crash",
             "Server disconnected with 100MB payload", "100MB")
    print("FAIL - Connection lost!")
    time.sleep(5)
except requests.exceptions.Timeout:
    log_vuln("HIGH", f"{API_URL}/admin/blog/posts",
             "DoS - Resource Exhaustion",
             "Timeout with 100MB payload", "100MB")
    print("FAIL - Timeout")
except MemoryError:
    print("SKIP - Client out of memory")
except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# TEST 2: ARRAY OVERFLOW ATTACKS
# ============================================================================
print("\n[SECTION 2] ARRAY OVERFLOW ATTACKS")
print("-" * 80)

# Test 2.1: Huge array of items
test("Array with 1 million integers")
try:
    huge_array = list(range(1000000))  # 1 million integers
    response = requests.post(
        f"{API_URL}/admin/blog/posts/bulk-update",
        json={"post_ids": huge_array, "published": True},
        headers=headers,
        cookies=cookies,
        timeout=30
    )

    if response.status_code == 413 or response.status_code == 400:
        print("PASS (Rejected)")
    elif response.status_code == 500:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts/bulk-update",
                 "DoS - Array Overflow",
                 "Server crashed with 1M element array", "1M elements")
        print("FAIL - Server Error")
    elif response.status_code == 200:
        log_vuln("HIGH", f"{API_URL}/admin/blog/posts/bulk-update",
                 "DoS - No Array Size Limit",
                 "Server processed 1M element array", "1M elements")
        print("FAIL - Accepted!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts/bulk-update",
             "DoS - Server Crash",
             "Server crashed with 1M element array", "1M elements")
    print("FAIL - Connection lost!")
    time.sleep(5)
except Exception as e:
    print(f"ERROR - {e}")

# Test 2.2: Array of huge strings
test("Array with 10,000 huge strings")
try:
    huge_strings = ["X" * 100000 for _ in range(10000)]  # 10k strings of 100KB each = ~1GB
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": "Test", "content": "Test", "slug": "test3", "tags": huge_strings},
        headers=headers,
        cookies=cookies,
        timeout=30
    )

    if response.status_code == 413 or response.status_code == 400:
        print("PASS (Rejected)")
    elif response.status_code == 500:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - Array Memory Exhaustion",
                 "Server crashed with array of huge strings", "~1GB")
        print("FAIL - Server Error")
    elif response.status_code == 200:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - No Array Content Limit",
                 "Server accepted ~1GB array payload", "~1GB")
        print("FAIL - Accepted!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
             "DoS - Server Crash",
             "Server crashed with huge string array", "~1GB")
    print("FAIL - Connection lost!")
    time.sleep(5)
except MemoryError:
    print("SKIP - Client out of memory")
except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# TEST 3: DEEPLY NESTED ARRAYS (not just objects)
# ============================================================================
print("\n[SECTION 3] DEEPLY NESTED ARRAY ATTACKS")
print("-" * 80)

def create_nested_array_payload(depth):
    """Create deeply nested array structure"""
    result = {"value": "bottom"}
    for i in range(depth):
        result = {"array": [result]}
    return result

# Test 3.1: 10,000 level nested arrays
test("10,000 level nested arrays")
try:
    nested = create_nested_array_payload(10000)
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": "Test", "content": "Test", "slug": "test4", "metadata": nested},
        headers=headers,
        cookies=cookies,
        timeout=30
    )

    if response.status_code == 400:
        print("PASS (Rejected)")
    elif response.status_code == 500:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "Stack Overflow - Nested Arrays",
                 "Server crashed with 10,000-level nested arrays", "10k levels")
        print("FAIL - Server Error (STACK OVERFLOW?)")
    elif response.status_code == 200:
        log_vuln("HIGH", f"{API_URL}/admin/blog/posts",
                 "No Nesting Limit - Arrays",
                 "Server processed 10,000-level nested arrays", "10k levels")
        print("FAIL - Accepted!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
             "Stack Overflow - Server Crash",
             "Server crashed with nested arrays (likely stack overflow)", "10k levels")
    print("FAIL - Connection lost! (STACK OVERFLOW)")
    time.sleep(5)
except RecursionError:
    print("SKIP - Client recursion limit")
except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# TEST 4: REQUEST BODY SIZE ATTACKS
# ============================================================================
print("\n[SECTION 4] REQUEST BODY SIZE LIMITS")
print("-" * 80)

# Test 4.1: Send raw 200MB request body
test("200MB raw request body")
try:
    # Create 200MB of data
    payload_data = {"data": "C" * (200 * 1024 * 1024)}

    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json=payload_data,
        headers=headers,
        cookies=cookies,
        timeout=60
    )

    if response.status_code == 413:
        print("PASS (413 Payload Too Large)")
    elif response.status_code == 500:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - Request Body Size",
                 "Server crashed with 200MB request body", "200MB")
        print("FAIL - Server Error")
    elif response.status_code == 200:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "DoS - No Request Size Limit",
                 "Server accepted 200MB request body", "200MB")
        print("FAIL - Accepted!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
             "DoS - Server Crash",
             "Server crashed with 200MB request", "200MB")
    print("FAIL - Connection lost!")
    time.sleep(5)
except MemoryError:
    print("SKIP - Client out of memory")
except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# TEST 5: MALFORMED JSON PARSER CRASHES
# ============================================================================
print("\n[SECTION 5] MALFORMED JSON ATTACKS (Parser Crashes)")
print("-" * 80)

malformed_payloads = [
    ('{"key":' * 100000, "100,000 unclosed braces"),
    ('[' * 100000 + ']' * 100000, "100,000 level array nesting"),
    ('{"a":' * 50000 + '1' + '}' * 50000, "50,000 level object nesting"),
    ('{"key":"' + 'A' * 10000000 + '"}', "10MB string value"),
    ('[' + '1,' * 1000000 + '1]', "1M element flat array"),
]

for payload, desc in malformed_payloads:
    test(f"Malformed JSON: {desc}")
    try:
        response = requests.post(
            f"{API_URL}/admin/blog/posts",
            data=payload,
            headers=headers,
            cookies=cookies,
            timeout=15
        )

        if response.status_code == 400 or response.status_code == 422:
            print("PASS (Rejected)")
        elif response.status_code == 500:
            log_vuln("HIGH", f"{API_URL}/admin/blog/posts",
                     "JSON Parser Crash",
                     f"Server error with: {desc}", desc)
            print("FAIL - Server Error")
        else:
            print(f"Status: {response.status_code}")

    except requests.exceptions.ConnectionError:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "JSON Parser Crash - Server Down",
                 f"Server crashed with: {desc}", desc)
        print("FAIL - Connection lost!")
        time.sleep(5)
    except MemoryError:
        print("SKIP - Client out of memory")
    except Exception as e:
        print(f"ERROR - {e}")

# ============================================================================
# TEST 6: NEWSLETTER ENDPOINT DoS
# ============================================================================
print("\n[SECTION 6] NEWSLETTER ENDPOINT DoS")
print("-" * 80)

# Test 6.1: Massive email field
test("Newsletter with 10MB email field")
try:
    huge_email = "A" * (10 * 1024 * 1024) + "@test.com"
    response = requests.post(
        f"{API_URL}/newsletter/subscribe",
        json={"email": huge_email},
        timeout=15
    )

    if response.status_code == 400 or response.status_code == 422:
        print("PASS (Rejected)")
    elif response.status_code == 500:
        log_vuln("HIGH", f"{API_URL}/newsletter/subscribe",
                 "DoS - Email Field Size",
                 "Server crashed with 10MB email", "10MB")
        print("FAIL - Server Error")
    elif response.status_code == 200:
        log_vuln("MEDIUM", f"{API_URL}/newsletter/subscribe",
                 "No Email Size Limit",
                 "Server accepted 10MB email", "10MB")
        print("FAIL - Accepted!")
    else:
        print(f"Status: {response.status_code}")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", f"{API_URL}/newsletter/subscribe",
             "DoS - Server Crash",
             "Server crashed with huge email", "10MB")
    print("FAIL - Connection lost!")
except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# TEST 7: UNICODE/ENCODING ATTACKS
# ============================================================================
print("\n[SECTION 7] UNICODE AND ENCODING ATTACKS")
print("-" * 80)

# Test 7.1: Unicode payload (4-byte characters)
test("10,000 4-byte Unicode characters")
try:
    # Emoji/4-byte UTF-8 characters
    unicode_payload = "😀" * 10000
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": unicode_payload, "content": "test", "slug": "unicode-test"},
        headers=headers,
        cookies=cookies,
        timeout=10
    )

    if response.status_code in [200, 201]:
        print("PASS (Handled)")
    elif response.status_code == 500:
        log_vuln("MEDIUM", f"{API_URL}/admin/blog/posts",
                 "Unicode Handling Error",
                 "Server error with 4-byte Unicode", "10k emojis")
        print("FAIL - Server Error")
    else:
        print(f"Status: {response.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# Test 7.2: Mixed encoding attack
test("Mixed encoding (UTF-8 + Latin1 + Unicode)")
try:
    mixed = "Test\x00\xFF\xFE" + "😀" * 1000 + "\r\n\t" * 100
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": mixed, "content": "test", "slug": "mixed-test"},
        headers=headers,
        cookies=cookies,
        timeout=10
    )

    if response.status_code in [200, 201, 400, 422]:
        print("PASS (Handled)")
    elif response.status_code == 500:
        log_vuln("MEDIUM", f"{API_URL}/admin/blog/posts",
                 "Encoding Error",
                 "Server error with mixed encoding", "Mixed")
        print("FAIL - Server Error")
    else:
        print(f"Status: {response.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# TEST 8: RAPID FIRE DoS (Rate Limiting)
# ============================================================================
print("\n[SECTION 8] RAPID FIRE DoS (Rate Limiting Test)")
print("-" * 80)

test("1000 rapid requests to newsletter subscribe")
try:
    errors = 0
    timeouts = 0

    for i in range(1000):
        try:
            response = requests.post(
                f"{API_URL}/newsletter/subscribe",
                json={"email": f"test{i}@example.com"},
                timeout=1
            )
            if response.status_code >= 500:
                errors += 1
        except requests.exceptions.Timeout:
            timeouts += 1
        except:
            pass

    if errors > 100:
        log_vuln("HIGH", f"{API_URL}/newsletter/subscribe",
                 "DoS - No Rate Limiting",
                 f"{errors} server errors from 1000 rapid requests", "1000 requests")
        print(f"FAIL - {errors} errors")
    elif timeouts > 100:
        log_vuln("MEDIUM", f"{API_URL}/newsletter/subscribe",
                 "DoS - Resource Exhaustion",
                 f"{timeouts} timeouts from 1000 rapid requests", "1000 requests")
        print(f"WARN - {timeouts} timeouts")
    else:
        print(f"PASS ({errors} errors, {timeouts} timeouts)")

except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# RESULTS
# ============================================================================
print("\n" + "="*80)
print("EXTREME DoS TESTING COMPLETED")
print("="*80)
print(f"Total Tests: {test_count}")
print(f"Vulnerabilities Found: {len(vulnerabilities)}")

if vulnerabilities:
    print("\n" + "="*80)
    print("VULNERABILITIES FOUND")
    print("="*80)

    critical = [v for v in vulnerabilities if v['severity'] == 'CRITICAL']
    high = [v for v in vulnerabilities if v['severity'] == 'HIGH']
    medium = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']

    if critical:
        print(f"\nCRITICAL ({len(critical)}):")
        for v in critical:
            print(f"  [{v['attack_type']}] {v['details']}")
            print(f"      Endpoint: {v['endpoint']}")
            print(f"      Payload: {v['payload_size']}")

    if high:
        print(f"\nHIGH ({len(high)}):")
        for v in high:
            print(f"  [{v['attack_type']}] {v['details']}")
            print(f"      Endpoint: {v['endpoint']}")
            print(f"      Payload: {v['payload_size']}")

    if medium:
        print(f"\nMEDIUM ({len(medium)}):")
        for v in medium:
            print(f"  [{v['attack_type']}] {v['details']}")
            print(f"      Endpoint: {v['endpoint']}")

    # Save report
    report_file = f"dos_vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({
            "test_count": test_count,
            "vulnerabilities": vulnerabilities,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)

    print(f"\n[SAVED] {report_file}")
    sys.exit(1)
else:
    print("\n[SUCCESS] No DoS vulnerabilities found")
    sys.exit(0)
