#!/usr/bin/env python3
"""
File Upload Attack Tests - Target media upload endpoints
Tests for: Decompression bombs, malicious images, stack overflow in PIL
"""

import requests
import io
from PIL import Image
import sys

BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"
AUTH_URL = f"{BASE_URL}/auth"

vulnerabilities = []

def log_vuln(severity, details):
    print(f"\n{'='*80}")
    print(f"[VULNERABILITY] {severity}")
    print(f"{details}")
    print(f"{'='*80}\n")
    vulnerabilities.append({"severity": severity, "details": details})

print("="*80)
print("FILE UPLOAD ATTACK TESTS")
print("="*80)

# Authenticate
print("\n[1] Authenticating...")
login_response = requests.post(
    f"{AUTH_URL}/login",
    data={"username": "admin@blogcms.local", "password": "AdminBlogCMS2025!"}
)

if login_response.status_code != 200:
    print("[ERROR] Authentication failed")
    sys.exit(1)

token = login_response.json().get("access_token")
cookies = login_response.cookies
headers = {"Authorization": f"Bearer {token}"}
print("[SUCCESS] Authenticated")

# ============================================================================
# TEST 1: DECOMPRESSION BOMB (Image Bomb)
# ============================================================================
print("\n[2] Testing decompression bomb...")

# Create a decompression bomb: small file that decompresses to huge size
# 1000x1000 white image compresses to ~8KB but uses ~3MB in memory
try:
    # Create tiny image that claims huge dimensions
    img = Image.new('RGB', (10000, 10000), color='white')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG', compress_level=9)
    img_bytes.seek(0)

    files = {'file': ('bomb.png', img_bytes, 'image/png')}
    response = requests.post(
        f"{API_URL}/admin/blog/media/upload",
        files=files,
        headers=headers,
        cookies=cookies,
        timeout=10
    )

    print(f"    Status: {response.status_code}")
    if response.status_code == 500:
        log_vuln("HIGH", "Server crashed with decompression bomb (10000x10000 image)")
    elif response.status_code == 200:
        log_vuln("MEDIUM", "Server accepted decompression bomb - could cause memory exhaustion")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", "Server crashed/disconnected with decompression bomb")
except requests.exceptions.Timeout:
    log_vuln("HIGH", "Request timeout with decompression bomb - possible resource exhaustion")
except Exception as e:
    print(f"    Error: {e}")

# ============================================================================
# TEST 2: EXTREME DIMENSIONS (Pixel Bomb)
# ============================================================================
print("\n[3] Testing extreme dimensions...")

try:
    # Create image with extreme aspect ratio: 1 x 1000000 pixels
    img = Image.new('RGB', (1, 100000), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)

    files = {'file': ('extreme.png', img_bytes, 'image/png')}
    response = requests.post(
        f"{API_URL}/admin/blog/media/upload",
        files=files,
        headers=headers,
        cookies=cookies,
        timeout=10
    )

    print(f"    Status: {response.status_code}")
    if response.status_code == 500:
        log_vuln("HIGH", "Server error with extreme dimensions (1x100000)")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", "Server crashed with extreme dimensions")
except Exception as e:
    print(f"    Error: {e}")

# ============================================================================
# TEST 3: FILE SIZE EXCEEDING LIMIT
# ============================================================================
print("\n[4] Testing oversized file (20MB)...")

try:
    # Create 20MB file (exceeds 10MB limit)
    large_data = b'A' * (20 * 1024 * 1024)
    files = {'file': ('large.jpg', large_data, 'image/jpeg')}

    response = requests.post(
        f"{API_URL}/admin/blog/media/upload",
        files=files,
        headers=headers,
        cookies=cookies,
        timeout=30
    )

    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        log_vuln("CRITICAL", "Server accepted 20MB file (exceeds 10MB limit)")
    elif response.status_code == 400:
        print("    [SAFE] Server rejected oversized file")

except requests.exceptions.ConnectionError:
    log_vuln("CRITICAL", "Server crashed with 20MB upload")
except Exception as e:
    print(f"    Error: {e}")

# ============================================================================
# TEST 4: MALICIOUS SVG WITH DEEP NESTING
# ============================================================================
print("\n[5] Testing deeply nested SVG (stack overflow potential)...")

def create_nested_svg(depth):
    """Create deeply nested SVG"""
    svg = '<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg">\n'
    for i in range(depth):
        svg += f'  <g id="group{i}">\n'
    svg += '    <rect width="100" height="100" />\n'
    for i in range(depth):
        svg += '  </g>\n'
    svg += '</svg>'
    return svg

depths = [1000, 5000, 10000]

for depth in depths:
    try:
        svg_content = create_nested_svg(depth)
        svg_bytes = svg_content.encode('utf-8')

        files = {'file': (f'nested{depth}.svg', io.BytesIO(svg_bytes), 'image/svg+xml')}
        response = requests.post(
            f"{API_URL}/admin/blog/media/upload",
            files=files,
            headers=headers,
            cookies=cookies,
            timeout=15
        )

        print(f"    Depth {depth}: Status {response.status_code}")
        if response.status_code == 500:
            log_vuln("CRITICAL", f"Server crashed with {depth}-level nested SVG (stack overflow)")

    except requests.exceptions.ConnectionError:
        log_vuln("CRITICAL", f"Server crashed with {depth}-level nested SVG")
        break
    except requests.exceptions.Timeout:
        log_vuln("HIGH", f"Timeout with {depth}-level nested SVG")
    except Exception as e:
        print(f"    Error at depth {depth}: {e}")

# ============================================================================
# TEST 5: MALFORMED IMAGE FILE
# ============================================================================
print("\n[6] Testing malformed image file...")

try:
    # Create fake PNG header with corrupted data
    malformed = b'\x89PNG\r\n\x1a\n' + b'\x00' * 1000 + b'CORRUPTED_DATA' * 1000

    files = {'file': ('malformed.png', io.BytesIO(malformed), 'image/png')}
    response = requests.post(
        f"{API_URL}/admin/blog/media/upload",
        files=files,
        headers=headers,
        cookies=cookies,
        timeout=10
    )

    print(f"    Status: {response.status_code}")
    if response.status_code == 500:
        log_vuln("HIGH", "Server error with malformed PNG")
    elif response.status_code == 400:
        print("    [SAFE] Server rejected malformed image")

except Exception as e:
    print(f"    Error: {e}")

# ============================================================================
# TEST 6: PATH TRAVERSAL IN FILENAME
# ============================================================================
print("\n[7] Testing path traversal in filename...")

traversal_filenames = [
    "../../../etc/passwd.png",
    "..\\..\\..\\windows\\system32\\config\\sam.png",
    "../../../../../../../../etc/shadow.png",
]

for filename in traversal_filenames:
    try:
        # Create small valid image
        img = Image.new('RGB', (10, 10), color='blue')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)

        files = {'file': (filename, img_bytes, 'image/png')}
        response = requests.post(
            f"{API_URL}/admin/blog/media/upload",
            files=files,
            headers=headers,
            cookies=cookies,
            timeout=5
        )

        print(f"    Filename: {filename[:50]}")
        print(f"    Status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            if '../' in data.get('url', '') or '..' in data.get('filename', ''):
                log_vuln("CRITICAL", f"Path traversal successful with filename: {filename}")
            else:
                print(f"    [SAFE] Filename sanitized to: {data.get('filename', 'unknown')}")

    except Exception as e:
        print(f"    Error: {e}")

# ============================================================================
# TEST 7: NULL BYTE INJECTION
# ============================================================================
print("\n[8] Testing null byte injection in filename...")

try:
    img = Image.new('RGB', (10, 10))
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)

    # Null byte could truncate filename and bypass validation
    files = {'file': ('malicious.exe\x00.png', img_bytes, 'image/png')}
    response = requests.post(
        f"{API_URL}/admin/blog/media/upload",
        files=files,
        headers=headers,
        cookies=cookies,
        timeout=5
    )

    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        if '\x00' in data.get('filename', ''):
            log_vuln("HIGH", "Null byte not sanitized in filename")
        else:
            print(f"    [SAFE] Filename: {data.get('filename')}")

except Exception as e:
    print(f"    Error: {e}")

# ============================================================================
# TEST 8: HUGE FILE (100MB) - Memory Exhaustion
# ============================================================================
print("\n[9] Testing 100MB file (memory exhaustion)...")

try:
    # Don't actually create 100MB in memory, just simulate header
    # Send chunked upload to test server handling
    print("    [SKIPPED] - Would require 100MB memory")

except Exception as e:
    print(f"    Error: {e}")

# ============================================================================
# RESULTS
# ============================================================================
print("\n" + "="*80)
print("FILE UPLOAD ATTACK TESTS COMPLETED")
print("="*80)
print(f"Vulnerabilities Found: {len(vulnerabilities)}")

if vulnerabilities:
    print("\nVULNERABILITIES:")
    for v in vulnerabilities:
        print(f"\n[{v['severity']}] {v['details']}")
    sys.exit(1)
else:
    print("\n[SUCCESS] No vulnerabilities found in file upload!")
    sys.exit(0)
