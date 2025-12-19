#!/usr/bin/env python3
"""
CSRF TOKEN VALIDATION & DEEP SQL INJECTION TESTING
Test EVERY field for SQL injection and CSRF bypass
"""

import requests
import json
import sys
from datetime import datetime

BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"
AUTH_URL = f"{BASE_URL}/auth"

vulnerabilities = []
test_count = 0

def log_vuln(severity, endpoint, attack_type, details):
    vuln = {
        "severity": severity,
        "endpoint": endpoint,
        "attack_type": attack_type,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }
    vulnerabilities.append(vuln)
    print(f"\n[VULN-{severity}] {attack_type}")
    print(f"  Endpoint: {endpoint}")
    print(f"  Details: {details}\n")

def test(name):
    global test_count
    test_count += 1
    print(f"[{test_count}] {name[:70]}", end=" ... ")

print("="*80)
print("CSRF VALIDATION & DEEP SQL INJECTION TESTING")
print("="*80)

# ============================================================================
# SECTION 1: CSRF TOKEN VALIDATION
# ============================================================================
print("\n[SECTION 1] CSRF TOKEN BYPASS ATTEMPTS")
print("-" * 80)

# Test 1.1: Login and get tokens
test("Getting valid session with CSRF token")
try:
    login_response = requests.post(
        f"{AUTH_URL}/login",
        data={"username": "admin@blogcms.local", "password": "AdminBlogCMS2025!"}
    )

    if login_response.status_code == 200:
        data = login_response.json()
        valid_token = data.get("access_token")
        csrf_token = data.get("csrf_token")
        cookies = login_response.cookies
        print(f"PASS (Got CSRF: {csrf_token[:20] if csrf_token else 'None'}...)")
    else:
        print(f"FAIL - Status {login_response.status_code}")
        valid_token = None
        csrf_token = None
        cookies = None
except Exception as e:
    print(f"ERROR - {e}")
    valid_token = None
    csrf_token = None
    cookies = None

# Test 1.2: Try request WITHOUT CSRF token
test("POST request without CSRF token")
try:
    headers_no_csrf = {"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"}
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": "Test", "content": "Test", "slug": "csrf-test-1"},
        headers=headers_no_csrf,
        # No cookies = no CSRF token
        timeout=5
    )

    if response.status_code == 200 or response.status_code == 201:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "CSRF - No Token Required",
                 "POST request succeeded without CSRF token")
        print("FAIL - Request succeeded without CSRF!")
    elif response.status_code == 403:
        print("PASS (403 Forbidden - CSRF required)")
    else:
        print(f"Status: {response.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# Test 1.3: Try with INVALID CSRF token
test("POST request with invalid CSRF token")
try:
    headers_bad_csrf = {"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"}
    cookies_bad = cookies.copy() if cookies else {}
    cookies_bad.set('csrf_token', 'INVALID_TOKEN_123456')

    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": "Test", "content": "Test", "slug": "csrf-test-2"},
        headers=headers_bad_csrf,
        cookies=cookies_bad,
        timeout=5
    )

    if response.status_code == 200 or response.status_code == 201:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                 "CSRF - Invalid Token Accepted",
                 "POST request succeeded with invalid CSRF token")
        print("FAIL - Accepted invalid CSRF token!")
    elif response.status_code == 403:
        print("PASS (403 Forbidden - Invalid CSRF rejected)")
    else:
        print(f"Status: {response.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# Test 1.4: Try request with another user's CSRF token
test("POST request with CSRF token from different session")
try:
    # Login as different user (if exists) or just use a fake token
    fake_csrf_cookies = cookies.copy() if cookies else {}
    fake_csrf_cookies.set('csrf_token', 'x' * 43)  # Different token

    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        json={"title": "Test", "content": "Test", "slug": "csrf-test-3"},
        headers={"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"},
        cookies=fake_csrf_cookies,
        timeout=5
    )

    if response.status_code == 200 or response.status_code == 201:
        log_vuln("HIGH", f"{API_URL}/admin/blog/posts",
                 "CSRF - Session Token Mismatch",
                 "POST request succeeded with CSRF from different session")
        print("FAIL - Accepted different session's CSRF!")
    elif response.status_code == 403:
        print("PASS (403 Forbidden - CSRF mismatch detected)")
    else:
        print(f"Status: {response.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# Test 1.5: Test CSRF on state-changing GET requests
test("GET request for state change (password reset)")
try:
    # Some apps mistakenly allow state changes via GET
    response = requests.get(
        f"{AUTH_URL}/change-password?current_password=test&new_password=hacked",
        headers={"Authorization": f"Bearer {valid_token}"},
        timeout=5
    )

    if response.status_code == 200:
        log_vuln("HIGH", f"{AUTH_URL}/change-password",
                 "CSRF - GET Request State Change",
                 "State-changing operation allowed via GET request")
        print("FAIL - GET request can change state!")
    elif response.status_code == 405:
        print("PASS (405 Method Not Allowed)")
    else:
        print(f"Status: {response.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# SECTION 2: DEEP SQL INJECTION - EVERY FIELD
# ============================================================================
print("\n[SECTION 2] DEEP SQL INJECTION - EVERY FIELD")
print("-" * 80)

# Aggressive SQL payloads
sql_payloads = [
    # Time-based (most reliable for blind injection)
    "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",

    # Boolean-based
    "' AND '1'='1' AND '1'='1",
    "' AND '1'='2' AND '1'='1",

    # UNION-based
    "' UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
    "' UNION SELECT username,password,email,NULL FROM users--",

    # Stacked queries
    "'; UPDATE users SET password='hacked' WHERE id=1--",
    "'; DELETE FROM users WHERE 1=1--",
    "'; INSERT INTO users (username,email) VALUES ('hacker','hacked@evil.com')--",

    # Error-based
    "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--",

    # Second-order
    "admin'--",
]

# Test blog post creation - EVERY field
fields_to_test = {
    "title": "Blog post title",
    "content": "Blog post content",
    "slug": "Blog post slug",
    "excerpt": "Blog post excerpt",
    "meta_title": "SEO meta title",
    "meta_description": "SEO meta description",
    "canonical_url": "Canonical URL",
}

for field_name, field_desc in fields_to_test.items():
    for i, payload in enumerate(sql_payloads[:5]):  # Test first 5 payloads per field
        test(f"SQL in {field_desc}: {payload[:30]}")

        try:
            post_data = {
                "title": "Test Title",
                "content": "Test Content",
                "slug": f"test-{field_name}-{i}"
            }
            post_data[field_name] = payload

            start_time = requests.get(f"{BASE_URL}/health").elapsed.total_seconds()

            response = requests.post(
                f"{API_URL}/admin/blog/posts",
                json=post_data,
                headers={"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"},
                cookies=cookies,
                timeout=10
            )

            # Check for SQL errors in response
            response_text = response.text.lower()
            if any(err in response_text for err in ['sql', 'syntax', 'postgresql', 'sqlalchemy', 'database']):
                log_vuln("HIGH", f"{API_URL}/admin/blog/posts",
                         f"SQL Injection - {field_desc}",
                         f"SQL error leaked in response for field '{field_name}'")
                print(f"FAIL - SQL error leaked!")

            # Check for time delay (time-based injection)
            elif response.elapsed.total_seconds() > 4:
                log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                         f"SQL Injection - Time-based in {field_desc}",
                         f"Query took {response.elapsed.total_seconds()}s - likely time-based SQL injection")
                print(f"FAIL - Time delay detected ({response.elapsed.total_seconds()}s)")

            else:
                print("PASS")

        except requests.exceptions.Timeout:
            log_vuln("CRITICAL", f"{API_URL}/admin/blog/posts",
                     f"SQL Injection - Timeout in {field_desc}",
                     f"Request timeout - possible time-based SQL injection in '{field_name}'")
            print("FAIL - Timeout (SQL injection?)")

        except Exception as e:
            print(f"ERROR - {e}")

# Test newsletter - email field
test("SQL injection in newsletter email field")
for payload in sql_payloads[:3]:
    try:
        response = requests.post(
            f"{API_URL}/newsletter/subscribe",
            json={"email": payload},
            timeout=10
        )

        if any(err in response.text.lower() for err in ['sql', 'syntax', 'postgresql', 'integrity', 'unique constraint']):
            log_vuln("HIGH", f"{API_URL}/newsletter/subscribe",
                     "SQL Injection - Newsletter Email",
                     f"SQL error in newsletter email field")
            break

        if response.elapsed.total_seconds() > 4:
            log_vuln("CRITICAL", f"{API_URL}/newsletter/subscribe",
                     "SQL Injection - Time-based in Newsletter",
                     f"Time-based SQL injection in newsletter email")
            break

    except requests.exceptions.Timeout:
        log_vuln("CRITICAL", f"{API_URL}/newsletter/subscribe",
                 "SQL Injection - Newsletter Timeout",
                 "Time-based SQL injection in newsletter")
        break
    except Exception as e:
        pass

print("Done newsletter SQL tests")

# Test category creation - name and slug
test("SQL injection in category name")
for payload in sql_payloads[:3]:
    try:
        response = requests.post(
            f"{API_URL}/admin/blog/categories",
            json={"name": payload, "slug": "test-cat"},
            headers={"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"},
            cookies=cookies,
            timeout=10
        )

        if any(err in response.text.lower() for err in ['sql', 'syntax', 'postgresql']):
            log_vuln("HIGH", f"{API_URL}/admin/blog/categories",
                     "SQL Injection - Category Name",
                     "SQL error in category name field")
            break
    except requests.exceptions.Timeout:
        log_vuln("CRITICAL", f"{API_URL}/admin/blog/categories",
                 "SQL Injection - Category Timeout",
                 "Time-based SQL injection in category")
        break
    except Exception as e:
        pass

print("Done category SQL tests")

# Test query parameters
test("SQL injection in search query parameter")
for payload in sql_payloads[:3]:
    try:
        response = requests.get(
            f"{API_URL}/blog/posts",
            params={"search": payload},
            timeout=10
        )

        if any(err in response.text.lower() for err in ['sql', 'syntax', 'postgresql']):
            log_vuln("HIGH", f"{API_URL}/blog/posts?search=",
                     "SQL Injection - Search Parameter",
                     "SQL error in search query parameter")
            break

        if response.elapsed.total_seconds() > 4:
            log_vuln("CRITICAL", f"{API_URL}/blog/posts?search=",
                     "SQL Injection - Time-based in Search",
                     "Time-based SQL injection in search parameter")
            break
    except requests.exceptions.Timeout:
        log_vuln("CRITICAL", f"{API_URL}/blog/posts?search=",
                 "SQL Injection - Search Timeout",
                 "Time-based SQL injection in search")
        break
    except Exception as e:
        pass

print("Done search SQL tests")

# ============================================================================
# SECTION 3: SECOND-ORDER SQL INJECTION
# ============================================================================
print("\n[SECTION 3] SECOND-ORDER SQL INJECTION")
print("-" * 80)

test("Second-order SQL injection via stored data")
try:
    # Step 1: Store malicious payload
    response1 = requests.post(
        f"{API_URL}/admin/blog/categories",
        json={"name": "Normal'; DROP TABLE posts--", "slug": "second-order-test"},
        headers={"Authorization": f"Bearer {valid_token}", "Content-Type": "application/json"},
        cookies=cookies,
        timeout=5
    )

    if response1.status_code in [200, 201]:
        cat_id = response1.json().get('id')

        # Step 2: Use the stored data (triggers second-order injection)
        response2 = requests.get(
            f"{API_URL}/blog/posts",
            params={"category_id": cat_id},
            timeout=5
        )

        if any(err in response2.text.lower() for err in ['sql', 'syntax', 'drop table']):
            log_vuln("CRITICAL", f"{API_URL}/blog/posts",
                     "Second-Order SQL Injection",
                     "SQL injection triggered when using stored category data")
            print("FAIL - Second-order SQL injection!")
        else:
            print("PASS")
    else:
        print(f"Status: {response1.status_code}")

except Exception as e:
    print(f"ERROR - {e}")

# ============================================================================
# RESULTS
# ============================================================================
print("\n" + "="*80)
print("CSRF & SQL INJECTION TESTING COMPLETED")
print("="*80)
print(f"Total Tests: {test_count}")
print(f"Vulnerabilities Found: {len(vulnerabilities)}")

if vulnerabilities:
    print("\nVULNERABILITIES:")

    critical = [v for v in vulnerabilities if v['severity'] == 'CRITICAL']
    high = [v for v in vulnerabilities if v['severity'] == 'HIGH']

    if critical:
        print(f"\nCRITICAL ({len(critical)}):")
        for v in critical:
            print(f"  [{v['attack_type']}] {v['details']}")
            print(f"      {v['endpoint']}")

    if high:
        print(f"\nHIGH ({len(high)}):")
        for v in high:
            print(f"  [{v['attack_type']}] {v['details']}")
            print(f"      {v['endpoint']}")

    # Save report
    report_file = f"csrf_sql_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({
            "test_count": test_count,
            "vulnerabilities": vulnerabilities,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)

    print(f"\n[SAVED] {report_file}")
    sys.exit(1)
else:
    print("\n[SUCCESS] No CSRF or SQL injection vulnerabilities")
    sys.exit(0)
