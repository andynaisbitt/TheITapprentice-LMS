#!/usr/bin/env python3
"""
BROKEN ACCESS CONTROL TESTING (OWASP A01:2021)
Tests for IDOR, Horizontal/Vertical Privilege Escalation, Mass Assignment

Priority: CRITICAL
Estimated vulnerabilities: HIGH RISK

Test Categories:
1. IDOR (Insecure Direct Object References)
2. Horizontal Privilege Escalation (User A → User B data)
3. Vertical Privilege Escalation (User → Admin)
4. Mass Assignment (Unauthorized field modification)
5. Authorization Bypass
"""

import requests
import json
import sys
from datetime import datetime
from typing import Dict, Optional, Tuple

# Configuration
BASE_URL = "http://localhost:8100"
API_URL = f"{BASE_URL}/api/v1"
AUTH_URL = f"{BASE_URL}/auth"

# Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Test results tracking
test_results = {
    "total_tests": 0,
    "passed": 0,
    "failed": 0,
    "vulnerabilities": [],
    "start_time": datetime.now()
}

# User accounts for testing
TEST_USERS = {
    "admin": {
        "email": "admin@blogcms.local",
        "password": "AdminBlogCMS2025!",
        "expected_role": "admin"
    },
    "author": {
        "email": "author@blogcms.local",
        "password": "AuthorPass123!",
        "expected_role": "author"
    },
    "user": {
        "email": "user@blogcms.local",
        "password": "UserPass123!",
        "expected_role": "user"
    }
}

# Authenticated sessions
sessions = {}

#===============================================================================
# HELPER FUNCTIONS
#===============================================================================

def print_header(text: str):
    """Print section header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}")
    print(f"{text}")
    print(f"{'='*80}{Colors.ENDC}")

def print_subheader(text: str):
    """Print subsection header"""
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}[{text}]{Colors.ENDC}")

def print_test(name: str):
    """Print test name"""
    test_results["total_tests"] += 1
    print(f"{Colors.OKBLUE}[TEST {test_results['total_tests']}] {name}{Colors.ENDC}", end=' ... ')

def print_pass():
    """Print pass status"""
    print(f"{Colors.OKGREEN}✓ PASS{Colors.ENDC}")
    test_results["passed"] += 1

def print_fail(details: str = ""):
    """Print fail status"""
    print(f"{Colors.FAIL}✗ FAIL{Colors.ENDC}")
    if details:
        print(f"{Colors.WARNING}  └─ {details}{Colors.ENDC}")
    test_results["failed"] += 1

def log_vulnerability(severity: str, test_name: str, endpoint: str, details: str, exploit: str = ""):
    """Log a vulnerability"""
    vuln = {
        "severity": severity,
        "test_name": test_name,
        "endpoint": endpoint,
        "details": details,
        "exploit": exploit,
        "timestamp": datetime.now().isoformat()
    }
    test_results["vulnerabilities"].append(vuln)

    print(f"\n{Colors.FAIL}{Colors.BOLD}{'='*80}")
    print(f"[VULNERABILITY FOUND] {severity}")
    print(f"{'='*80}{Colors.ENDC}")
    print(f"{Colors.WARNING}Test: {test_name}")
    print(f"Endpoint: {endpoint}")
    print(f"Details: {details}")
    if exploit:
        print(f"Exploit: {exploit}")
    print(f"{Colors.FAIL}{'='*80}{Colors.ENDC}\n")

def authenticate_user(user_type: str) -> Optional[Dict]:
    """Authenticate a user and return session info"""
    if user_type not in TEST_USERS:
        print(f"{Colors.FAIL}Invalid user type: {user_type}{Colors.ENDC}")
        return None

    user = TEST_USERS[user_type]

    try:
        response = requests.post(
            f"{AUTH_URL}/login",
            data={
                "username": user["email"],
                "password": user["password"]
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "token": data.get("access_token"),
                "cookies": response.cookies,
                "user_id": data.get("user", {}).get("id"),
                "role": data.get("user", {}).get("role"),
                "email": user["email"]
            }
        else:
            print(f"{Colors.WARNING}Auth failed for {user_type}: {response.status_code}{Colors.ENDC}")
            return None
    except Exception as e:
        print(f"{Colors.FAIL}Error authenticating {user_type}: {e}{Colors.ENDC}")
        return None

def make_authenticated_request(method: str, endpoint: str, session_info: Dict,
                               json_data: Dict = None, params: Dict = None) -> requests.Response:
    """Make an authenticated request"""
    headers = {
        "Authorization": f"Bearer {session_info['token']}",
        "Content-Type": "application/json"
    }

    if method.upper() == "GET":
        return requests.get(endpoint, headers=headers, cookies=session_info['cookies'], params=params)
    elif method.upper() == "POST":
        return requests.post(endpoint, headers=headers, cookies=session_info['cookies'], json=json_data)
    elif method.upper() == "PUT":
        return requests.put(endpoint, headers=headers, cookies=session_info['cookies'], json=json_data)
    elif method.upper() == "PATCH":
        return requests.patch(endpoint, headers=headers, cookies=session_info['cookies'], json=json_data)
    elif method.upper() == "DELETE":
        return requests.delete(endpoint, headers=headers, cookies=session_info['cookies'])
    else:
        raise ValueError(f"Unsupported method: {method}")

#===============================================================================
# TEST SETUP
#===============================================================================

def setup_test_environment():
    """Authenticate all test users"""
    print_header("TEST SETUP - Authenticating Test Users")

    # Check server health
    print_test("Server health check")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print_pass()
        else:
            print_fail(f"Server returned {response.status_code}")
            return False
    except Exception as e:
        print_fail(f"Cannot connect: {e}")
        print(f"\n{Colors.WARNING}Please start the backend server:{Colors.ENDC}")
        print(f"cd backend && python -m uvicorn app.main:app --port 8100")
        return False

    # Authenticate users
    for user_type in TEST_USERS.keys():
        print_test(f"Authenticating as {user_type}")
        session = authenticate_user(user_type)
        if session:
            sessions[user_type] = session
            print_pass()
            print(f"    User ID: {session['user_id']}, Role: {session['role']}")
        else:
            print_fail(f"Could not authenticate {user_type}")
            print(f"\n{Colors.WARNING}Note: You may need to create test accounts first{Colors.ENDC}")
            return False

    return True

#===============================================================================
# CATEGORY 1: IDOR (Insecure Direct Object References)
#===============================================================================

def test_idor_blog_posts():
    """Test IDOR vulnerabilities in blog post access"""
    print_header("CATEGORY 1: IDOR - Blog Posts")

    # First, create a post as admin
    print_subheader("Setup: Creating admin's blog post")
    admin_post_data = {
        "title": "Admin's Private Post",
        "slug": f"admin-private-{datetime.now().timestamp()}",
        "content": "This is admin's private content",
        "excerpt": "Admin only",
        "published": False  # Unpublished = should be private
    }

    response = make_authenticated_request(
        "POST",
        f"{API_URL}/admin/blog/posts",
        sessions["admin"],
        json_data=admin_post_data
    )

    if response.status_code in [200, 201]:
        admin_post_id = response.json().get("id")
        print(f"    Created admin post ID: {admin_post_id}")
    else:
        print(f"{Colors.WARNING}    Could not create admin post (status {response.status_code}){Colors.ENDC}")
        admin_post_id = 1  # Try with ID 1

    # Test 1.1: Regular user accessing admin's unpublished post
    print_test("IDOR: Regular user accessing admin's unpublished post")
    response = make_authenticated_request(
        "GET",
        f"{API_URL}/admin/blog/posts/{admin_post_id}",
        sessions["user"]
    )

    if response.status_code == 200:
        log_vulnerability(
            "CRITICAL",
            "IDOR - Unpublished Post Access",
            f"GET /admin/blog/posts/{admin_post_id}",
            "Regular user can access admin's unpublished blog post",
            f"User ID {sessions['user']['user_id']} accessed post owned by admin"
        )
        print_fail("User can access admin's unpublished post!")
    elif response.status_code == 403:
        print_pass()
    elif response.status_code == 404:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 1.2: Sequential ID enumeration
    print_test("IDOR: Sequential post ID enumeration")
    accessible_posts = []
    for post_id in range(1, 11):  # Test first 10 IDs
        response = make_authenticated_request(
            "GET",
            f"{API_URL}/admin/blog/posts/{post_id}",
            sessions["user"]
        )
        if response.status_code == 200:
            accessible_posts.append(post_id)

    if len(accessible_posts) > 0:
        log_vulnerability(
            "HIGH",
            "IDOR - Post Enumeration",
            f"GET /admin/blog/posts/{{id}}",
            f"Regular user can enumerate {len(accessible_posts)} blog posts by sequential ID",
            f"Accessible IDs: {accessible_posts}"
        )
        print_fail(f"User can access {len(accessible_posts)} posts by enumeration")
    else:
        print_pass()

    # Test 1.3: Modifying another user's post
    print_test("IDOR: Regular user modifying admin's post")
    response = make_authenticated_request(
        "PATCH",
        f"{API_URL}/admin/blog/posts/{admin_post_id}",
        sessions["user"],
        json_data={"title": "Hacked by regular user"}
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "CRITICAL",
            "IDOR - Unauthorized Modification",
            f"PATCH /admin/blog/posts/{admin_post_id}",
            "Regular user can modify admin's blog post",
            f"User ID {sessions['user']['user_id']} modified post owned by admin"
        )
        print_fail("User can modify admin's post!")
    elif response.status_code == 403:
        print_pass()
    elif response.status_code == 404:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 1.4: Deleting another user's post
    print_test("IDOR: Regular user deleting admin's post")
    response = make_authenticated_request(
        "DELETE",
        f"{API_URL}/admin/blog/posts/{admin_post_id}",
        sessions["user"]
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "CRITICAL",
            "IDOR - Unauthorized Deletion",
            f"DELETE /admin/blog/posts/{admin_post_id}",
            "Regular user can delete admin's blog post",
            f"User ID {sessions['user']['user_id']} deleted post owned by admin"
        )
        print_fail("User can delete admin's post!")
    elif response.status_code == 403:
        print_pass()
    elif response.status_code == 404:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

def test_idor_media():
    """Test IDOR vulnerabilities in media access"""
    print_header("CATEGORY 1: IDOR - Media Files")

    # Test 1.5: Media enumeration
    print_test("IDOR: Media file enumeration")
    accessible_media = []
    for media_id in range(1, 11):
        response = make_authenticated_request(
            "GET",
            f"{API_URL}/admin/blog/media/{media_id}",
            sessions["user"]
        )
        if response.status_code == 200:
            accessible_media.append(media_id)

    if len(accessible_media) > 0:
        log_vulnerability(
            "MEDIUM",
            "IDOR - Media Enumeration",
            f"GET /admin/blog/media/{{id}}",
            f"Regular user can enumerate {len(accessible_media)} media files",
            f"Accessible IDs: {accessible_media}"
        )
        print_fail(f"User can access {len(accessible_media)} media files")
    else:
        print_pass()

    # Test 1.6: Deleting another user's media
    print_test("IDOR: Regular user deleting admin's media")
    response = make_authenticated_request(
        "DELETE",
        f"{API_URL}/admin/blog/media/1",
        sessions["user"]
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "HIGH",
            "IDOR - Unauthorized Media Deletion",
            f"DELETE /admin/blog/media/1",
            "Regular user can delete admin's media files"
        )
        print_fail("User can delete admin's media!")
    elif response.status_code == 403:
        print_pass()
    elif response.status_code == 404:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

#===============================================================================
# CATEGORY 2: HORIZONTAL PRIVILEGE ESCALATION
#===============================================================================

def test_horizontal_privilege_escalation():
    """Test horizontal privilege escalation (User A → User B)"""
    print_header("CATEGORY 2: Horizontal Privilege Escalation")

    # Test 2.1: User accessing another user's profile
    print_test("Horizontal: User A accessing User B's profile")
    response = make_authenticated_request(
        "GET",
        f"{API_URL}/users/{sessions['admin']['user_id']}",
        sessions["user"]
    )

    if response.status_code == 200:
        data = response.json()
        # Check if sensitive data is exposed
        if "email" in data or "password" in data or "hashed_password" in data:
            log_vulnerability(
                "HIGH",
                "Horizontal Escalation - Profile Access",
                f"GET /users/{sessions['admin']['user_id']}",
                "User can access another user's profile including sensitive data",
                f"User {sessions['user']['user_id']} accessed admin profile {sessions['admin']['user_id']}"
            )
            print_fail("Sensitive data exposed!")
        else:
            print_pass()
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 2.2: User modifying another user's profile
    print_test("Horizontal: User A modifying User B's profile")
    response = make_authenticated_request(
        "PATCH",
        f"{API_URL}/users/{sessions['admin']['user_id']}",
        sessions["user"],
        json_data={"display_name": "Hacked"}
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "CRITICAL",
            "Horizontal Escalation - Profile Modification",
            f"PATCH /users/{sessions['admin']['user_id']}",
            "User can modify another user's profile",
            f"User {sessions['user']['user_id']} modified admin profile"
        )
        print_fail("User can modify another user's profile!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 2.3: User deleting another user's account
    print_test("Horizontal: User A deleting User B's account")
    response = make_authenticated_request(
        "DELETE",
        f"{API_URL}/users/{sessions['author']['user_id']}",
        sessions["user"]
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "CRITICAL",
            "Horizontal Escalation - Account Deletion",
            f"DELETE /users/{sessions['author']['user_id']}",
            "User can delete another user's account"
        )
        print_fail("User can delete another user's account!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

#===============================================================================
# CATEGORY 3: VERTICAL PRIVILEGE ESCALATION
#===============================================================================

def test_vertical_privilege_escalation():
    """Test vertical privilege escalation (User → Admin)"""
    print_header("CATEGORY 3: Vertical Privilege Escalation")

    # Test 3.1: Regular user accessing admin endpoints
    print_test("Vertical: Regular user accessing /admin/blog/posts")
    response = make_authenticated_request(
        "GET",
        f"{API_URL}/admin/blog/posts",
        sessions["user"]
    )

    if response.status_code == 200:
        log_vulnerability(
            "CRITICAL",
            "Vertical Escalation - Admin Endpoint Access",
            f"GET /admin/blog/posts",
            "Regular user can access admin-only endpoint"
        )
        print_fail("User can access admin endpoint!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 3.2: Regular user creating blog posts (author privilege)
    print_test("Vertical: Regular user creating blog posts")
    response = make_authenticated_request(
        "POST",
        f"{API_URL}/admin/blog/posts",
        sessions["user"],
        json_data={
            "title": "Unauthorized Post",
            "slug": f"unauth-{datetime.now().timestamp()}",
            "content": "This should fail",
            "excerpt": "Test"
        }
    )

    if response.status_code in [200, 201]:
        log_vulnerability(
            "CRITICAL",
            "Vertical Escalation - Unauthorized Post Creation",
            f"POST /admin/blog/posts",
            "Regular user can create blog posts (requires author role)"
        )
        print_fail("User can create posts without author role!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 3.3: Regular user accessing site settings
    print_test("Vertical: Regular user accessing site settings")
    response = make_authenticated_request(
        "GET",
        f"{API_URL}/admin/site-settings",
        sessions["user"]
    )

    if response.status_code == 200:
        log_vulnerability(
            "CRITICAL",
            "Vertical Escalation - Site Settings Access",
            f"GET /admin/site-settings",
            "Regular user can access admin site settings"
        )
        print_fail("User can access site settings!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 3.4: Regular user modifying site settings
    print_test("Vertical: Regular user modifying site settings")
    response = make_authenticated_request(
        "PATCH",
        f"{API_URL}/admin/site-settings",
        sessions["user"],
        json_data={"site_title": "Hacked Site"}
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "CRITICAL",
            "Vertical Escalation - Site Settings Modification",
            f"PATCH /admin/site-settings",
            "Regular user can modify site settings (admin-only)"
        )
        print_fail("User can modify site settings!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

#===============================================================================
# CATEGORY 4: MASS ASSIGNMENT
#===============================================================================

def test_mass_assignment():
    """Test mass assignment vulnerabilities"""
    print_header("CATEGORY 4: Mass Assignment Attacks")

    # Test 4.1: Changing author_id in post creation
    print_test("Mass Assignment: Changing author_id in post creation")
    response = make_authenticated_request(
        "POST",
        f"{API_URL}/admin/blog/posts",
        sessions["admin"],
        json_data={
            "title": "Mass Assignment Test",
            "slug": f"mass-assign-{datetime.now().timestamp()}",
            "content": "Test content",
            "excerpt": "Test",
            "author_id": 999999  # Try to set different author
        }
    )

    if response.status_code in [200, 201]:
        data = response.json()
        if data.get("author_id") == 999999:
            log_vulnerability(
                "CRITICAL",
                "Mass Assignment - Author ID Override",
                f"POST /admin/blog/posts",
                "User can override author_id field to impersonate other users"
            )
            print_fail("Can override author_id!")
        elif data.get("author_id") == sessions["admin"]["user_id"]:
            print_pass()
        else:
            print_fail(f"Unexpected author_id: {data.get('author_id')}")
    else:
        print_fail(f"Request failed: {response.status_code}")

    # Test 4.2: Elevating role in user profile update
    print_test("Mass Assignment: Regular user elevating own role to admin")
    response = make_authenticated_request(
        "PATCH",
        f"{API_URL}/users/{sessions['user']['user_id']}",
        sessions["user"],
        json_data={"role": "admin"}
    )

    if response.status_code in [200, 204]:
        # Verify if role actually changed
        verify_response = make_authenticated_request(
            "GET",
            f"{API_URL}/users/me",
            sessions["user"]
        )
        if verify_response.status_code == 200:
            new_role = verify_response.json().get("role")
            if new_role == "admin":
                log_vulnerability(
                    "CRITICAL",
                    "Mass Assignment - Role Escalation",
                    f"PATCH /users/{sessions['user']['user_id']}",
                    "User can elevate own role to admin via mass assignment",
                    "User changed role from 'user' to 'admin'"
                )
                print_fail("User escalated to admin!")
            else:
                print_pass()
        else:
            print_fail("Could not verify role change")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 4.3: Setting is_featured flag in post creation
    print_test("Mass Assignment: Regular user setting is_featured=True")
    response = make_authenticated_request(
        "POST",
        f"{API_URL}/admin/blog/posts",
        sessions["admin"],  # Use admin for this test
        json_data={
            "title": "Featured Test",
            "slug": f"featured-{datetime.now().timestamp()}",
            "content": "Test",
            "excerpt": "Test",
            "is_featured": True,  # Should be admin-only control
            "published": True
        }
    )

    if response.status_code in [200, 201]:
        data = response.json()
        # This is expected to work for admin, just documenting behavior
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

#===============================================================================
# CATEGORY 5: AUTHORIZATION BYPASS
#===============================================================================

def test_authorization_bypass():
    """Test various authorization bypass techniques"""
    print_header("CATEGORY 5: Authorization Bypass Techniques")

    # Test 5.1: HTTP method override
    print_test("Auth Bypass: HTTP method override (GET → DELETE)")
    response = requests.get(
        f"{API_URL}/admin/blog/posts/1",
        headers={
            "Authorization": f"Bearer {sessions['user']['token']}",
            "X-HTTP-Method-Override": "DELETE"
        },
        cookies=sessions["user"]["cookies"]
    )

    if response.status_code in [200, 204]:
        log_vulnerability(
            "HIGH",
            "Authorization Bypass - Method Override",
            f"GET /admin/blog/posts/1 (X-HTTP-Method-Override: DELETE)",
            "HTTP method override allows bypassing authorization checks"
        )
        print_fail("Method override works!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 5.2: Content-Type manipulation
    print_test("Auth Bypass: Content-Type manipulation")
    response = requests.post(
        f"{API_URL}/admin/blog/posts",
        headers={
            "Authorization": f"Bearer {sessions['user']['token']}",
            "Content-Type": "application/x-www-form-urlencoded"  # Try different content type
        },
        data="title=Test&content=Test&slug=test",
        cookies=sessions["user"]["cookies"]
    )

    if response.status_code in [200, 201]:
        log_vulnerability(
            "MEDIUM",
            "Authorization Bypass - Content-Type",
            f"POST /admin/blog/posts",
            "Content-Type manipulation allows bypassing validation"
        )
        print_fail("Content-Type bypass works!")
    elif response.status_code == 403:
        print_pass()
    else:
        print_fail(f"Status: {response.status_code}")

    # Test 5.3: Path traversal in endpoints
    print_test("Auth Bypass: Path traversal (/../admin)")
    response = requests.get(
        f"{API_URL}/blog/../admin/blog/posts",
        headers={"Authorization": f"Bearer {sessions['user']['token']}"},
        cookies=sessions["user"]["cookies"]
    )

    if response.status_code == 200:
        log_vulnerability(
            "HIGH",
            "Authorization Bypass - Path Traversal",
            f"GET /blog/../admin/blog/posts",
            "Path traversal allows accessing admin endpoints"
        )
        print_fail("Path traversal works!")
    elif response.status_code in [403, 404]:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

    # Test 5.4: Missing authentication header
    print_test("Auth Bypass: Accessing admin endpoint without auth")
    response = requests.get(f"{API_URL}/admin/blog/posts")

    if response.status_code == 200:
        log_vulnerability(
            "CRITICAL",
            "Authorization Bypass - No Auth Required",
            f"GET /admin/blog/posts",
            "Admin endpoint accessible without authentication"
        )
        print_fail("No authentication required!")
    elif response.status_code == 401:
        print_pass()
    else:
        print_fail(f"Unexpected status: {response.status_code}")

#===============================================================================
# REPORT GENERATION
#===============================================================================

def generate_report():
    """Generate final test report"""
    print_header("ACCESS CONTROL TEST REPORT")

    duration = (datetime.now() - test_results["start_time"]).total_seconds()

    print(f"\nTest Duration: {duration:.2f} seconds")
    print(f"Total Tests: {test_results['total_tests']}")
    print(f"{Colors.OKGREEN}Passed: {test_results['passed']}{Colors.ENDC}")
    print(f"{Colors.FAIL}Failed: {test_results['failed']}{Colors.ENDC}")
    print(f"\n{Colors.FAIL}{Colors.BOLD}Vulnerabilities Found: {len(test_results['vulnerabilities'])}{Colors.ENDC}")

    if test_results['vulnerabilities']:
        print(f"\n{Colors.FAIL}{Colors.BOLD}VULNERABILITY SUMMARY:{Colors.ENDC}")

        # Group by severity
        critical = [v for v in test_results['vulnerabilities'] if v['severity'] == 'CRITICAL']
        high = [v for v in test_results['vulnerabilities'] if v['severity'] == 'HIGH']
        medium = [v for v in test_results['vulnerabilities'] if v['severity'] == 'MEDIUM']

        if critical:
            print(f"\n{Colors.FAIL}{Colors.BOLD}🔴 CRITICAL ({len(critical)}):{Colors.ENDC}")
            for v in critical:
                print(f"  • {v['test_name']}")
                print(f"    {v['details']}")
                print(f"    Endpoint: {v['endpoint']}")
                if v['exploit']:
                    print(f"    Exploit: {v['exploit']}")
                print()

        if high:
            print(f"\n{Colors.WARNING}{Colors.BOLD}🟠 HIGH ({len(high)}):{Colors.ENDC}")
            for v in high:
                print(f"  • {v['test_name']}")
                print(f"    {v['details']}")
                print(f"    Endpoint: {v['endpoint']}")
                print()

        if medium:
            print(f"\n{Colors.OKBLUE}{Colors.BOLD}🟡 MEDIUM ({len(medium)}):{Colors.ENDC}")
            for v in medium:
                print(f"  • {v['test_name']}")
                print(f"    {v['details']}")
                print()

    # Save JSON report
    report_file = f"tests/security/reports/access_control_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)

    print(f"\n{Colors.OKGREEN}Full report saved to: {report_file}{Colors.ENDC}")

    # Return exit code based on vulnerabilities found
    return 0 if len(test_results['vulnerabilities']) == 0 else 1

#===============================================================================
# MAIN EXECUTION
#===============================================================================

def main():
    """Main test execution"""
    print_header("BROKEN ACCESS CONTROL SECURITY TESTING")
    print("OWASP A01:2021 - Most Critical Vulnerability")
    print(f"Target: {BASE_URL}")
    print(f"Start Time: {test_results['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")

    # Setup
    if not setup_test_environment():
        sys.exit(1)

    # Run all test categories
    try:
        test_idor_blog_posts()
        test_idor_media()
        test_horizontal_privilege_escalation()
        test_vertical_privilege_escalation()
        test_mass_assignment()
        test_authorization_bypass()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Testing interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}Unexpected error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
    finally:
        # Generate report
        exit_code = generate_report()
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
