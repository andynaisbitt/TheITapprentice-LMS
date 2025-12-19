#!/usr/bin/env python3
"""Quick security test to verify setup and find immediate issues"""

import requests
import json

BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"

# Basic SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

print("="*80)
print("QUICK SECURITY TEST - BlogCMS")
print("="*80)

# Test 1: Health check
print("\n[1] Testing server health...")
try:
    response = requests.get(f"{BASE_URL}/health", timeout=5)
    print(f"    Status: {response.status_code}")
    print(f"    Response: {response.json()}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 2: SQL Injection in blog search
print("\n[2] Testing SQL injection in /blog/posts?search=...")
for payload in SQL_PAYLOADS:
    print(f"\n    Payload: {payload[:50]}")
    try:
        response = requests.get(
            f"{API_URL}/blog/posts",
            params={"search": payload},
            timeout=6
        )
        print(f"    Status: {response.status_code}")

        # Check for SQL errors
        if any(error in response.text.lower() for error in ['sql', 'syntax', 'postgresql', 'database error']):
            print(f"    [VULNERABILITY] SQL error detected in response!")
            print(f"    Response snippet: {response.text[:200]}")
        else:
            print(f"    [SAFE] No SQL errors detected")

    except requests.exceptions.Timeout:
        print(f"    [VULNERABILITY] Request timed out - possible time-based SQL injection")
    except Exception as e:
        print(f"    ERROR: {e}")

# Test 3: SQL Injection in newsletter subscribe
print("\n[3] Testing SQL injection in newsletter subscribe...")
for payload in SQL_PAYLOADS[:2]:  # Just 2 payloads
    print(f"\n    Payload: {payload[:50]}")
    try:
        response = requests.post(
            f"{API_URL}/newsletter/subscribe",
            json={"email": payload},
            timeout=5
        )
        print(f"    Status: {response.status_code}")

        if any(error in response.text.lower() for error in ['sql', 'syntax', 'postgresql', 'integrity']):
            print(f"    [VULNERABILITY] SQL error detected!")
            print(f"    Response: {response.text[:200]}")
        else:
            print(f"    [SAFE] No SQL errors detected")

    except Exception as e:
        print(f"    ERROR: {e}")

# Test 4: Buffer overflow with large payload
print("\n[4] Testing buffer overflow with large payload...")
large_payload = 'A' * 100000  # 100KB
try:
    response = requests.get(
        f"{API_URL}/blog/posts",
        params={"search": large_payload},
        timeout=10
    )
    print(f"    Status: {response.status_code}")
    if response.status_code == 500:
        print(f"    [VULNERABILITY] Server error 500 with large payload!")
    else:
        print(f"    [SAFE] Server handled large payload")
except requests.exceptions.ConnectionError:
    print(f"    [CRITICAL] Connection error - server may have crashed!")
except requests.exceptions.Timeout:
    print(f"    [WARNING] Request timeout with large payload")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 5: XSS in search
print("\n[5] Testing XSS in blog search...")
xss_payload = "<script>alert('XSS')</script>"
try:
    response = requests.get(
        f"{API_URL}/blog/posts",
        params={"search": xss_payload},
        timeout=5
    )
    print(f"    Payload: {xss_payload}")
    print(f"    Status: {response.status_code}")

    if xss_payload in response.text:
        print(f"    [VULNERABILITY] XSS payload reflected without encoding!")
    else:
        print(f"    [SAFE] Payload not reflected or properly encoded")

except Exception as e:
    print(f"    ERROR: {e}")

print("\n" + "="*80)
print("QUICK TEST COMPLETED")
print("="*80)
