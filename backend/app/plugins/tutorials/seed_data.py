# backend/app/plugins/tutorials/seed_data.py
"""
Tutorial Seed Data Script
Creates sample tutorials with steps for testing and demonstration
Run with: python -m app.plugins.tutorials.seed_data
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.plugins.tutorials.models import Tutorial, TutorialStep, TutorialCategory
from app.users.models import User, UserRole
from app.auth.email_verification import EmailVerification  # Import to avoid relationship errors

def create_categories(db: Session):
    """Create tutorial categories - IT-focused for beginners"""
    categories = [
        {
            "name": "IT Fundamentals",
            "slug": "it-fundamentals",
            "description": "Core concepts every IT professional should know",
            "icon": "🖥️",
            "color": "#3B82F6",
            "display_order": 1
        },
        {
            "name": "Programming",
            "slug": "programming",
            "description": "Learn coding and scripting fundamentals",
            "icon": "💻",
            "color": "#10B981",
            "display_order": 2
        },
        {
            "name": "Hardware & Networking",
            "slug": "hardware-networking",
            "description": "Understand computer hardware and network basics",
            "icon": "🔌",
            "color": "#F59E0B",
            "display_order": 3
        },
        {
            "name": "IT Support",
            "slug": "it-support",
            "description": "Help desk skills and customer service",
            "icon": "🎧",
            "color": "#8B5CF6",
            "display_order": 4
        },
    ]

    created_categories = {}
    for cat_data in categories:
        existing = db.query(TutorialCategory).filter(
            TutorialCategory.slug == cat_data["slug"]
        ).first()

        if existing:
            # Update existing category
            for key, value in cat_data.items():
                setattr(existing, key, value)
            created_categories[cat_data["slug"]] = existing
            print(f"[UPDATE] Updated category: {cat_data['name']}")
        else:
            category = TutorialCategory(**cat_data)
            db.add(category)
            db.flush()
            created_categories[cat_data["slug"]] = category
            print(f"[OK] Created category: {cat_data['name']}")

    db.commit()
    return created_categories


def create_tutorials(db: Session, categories: dict, admin_user: User):
    """Create sample tutorials - IT-focused for beginners"""

    tutorials_data = [
        {
            "title": "Understanding Computers: A Beginner's Guide",
            "slug": "understanding-computers-beginners-guide",
            "description": "Learn the fundamental concepts of how computers work, from hardware components to basic operations",
            "difficulty": "beginner",
            "estimated_time_minutes": 30,
            "category": "it-fundamentals",
            "thumbnail_url": None,
            "xp_reward": 75,
            "related_skills": ["hardware-support", "problem-solving"],
            "is_published": True,
            "is_featured": True,
            "steps": [
                {
                    "step_order": 1,
                    "title": "What is a Computer?",
                    "content": """
# What is a Computer?

A computer is an electronic device that processes data according to instructions. At its core, every computer follows a simple cycle:

## The Input-Process-Output Cycle

1. **Input** - Data goes in (keyboard, mouse, microphone)
2. **Process** - The CPU works with the data
3. **Output** - Results come out (screen, speakers, printer)

## Real-World Example

When you type a document:
- **Input**: Your keystrokes on the keyboard
- **Process**: The CPU handles each letter, the word processor formats it
- **Output**: You see the text appear on your screen

This simple concept is the foundation of everything computers do!
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Think of a computer like a very fast calculator", "Every action follows the Input-Process-Output cycle"]
                },
                {
                    "step_order": 2,
                    "title": "Hardware Components",
                    "content": """
# Essential Hardware Components

Every computer has these key parts:

## The Brain: CPU (Central Processing Unit)
- Executes instructions
- Measured in GHz (speed)
- Examples: Intel Core i5, AMD Ryzen 5

## Short-Term Memory: RAM (Random Access Memory)
- Stores data the CPU is actively using
- **Volatile** - loses data when powered off
- More RAM = more programs running smoothly
- Typical: 8GB, 16GB, 32GB

## Long-Term Storage
- **HDD (Hard Disk Drive)** - Spinning disks, cheaper, slower
- **SSD (Solid State Drive)** - No moving parts, faster, more reliable

## The Hub: Motherboard
- Connects all components together
- Contains slots for RAM, CPU, and expansion cards

## Power Supply Unit (PSU)
- Converts AC power to DC for components
- Measured in watts (W)
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["RAM is like your desk - more space means more projects open at once", "SSDs are faster but HDDs offer more storage per dollar"]
                },
                {
                    "step_order": 3,
                    "title": "Operating Systems",
                    "content": """
# Operating Systems (OS)

The operating system is software that manages your computer's hardware and software resources.

## The Big Three

### Windows
- Most common in business environments
- Made by Microsoft
- Versions: Windows 10, Windows 11

### macOS
- Made by Apple, runs on Mac computers
- Known for creative work and design
- Versions: Ventura, Sonoma, Sequoia

### Linux
- Free and open-source
- Popular with servers and developers
- Distributions: Ubuntu, Fedora, CentOS

## What Does an OS Do?

1. **Manages hardware** - Controls CPU, RAM, storage
2. **Runs applications** - Word processors, browsers, games
3. **Provides a user interface** - Desktop, Start menu, icons
4. **Handles files** - Create, move, delete files and folders
5. **Security** - User accounts, permissions, updates
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Most IT jobs require Windows knowledge", "Linux is essential for server administration"]
                },
                {
                    "step_order": 4,
                    "title": "Files and Folders",
                    "content": """
# Managing Files and Folders

Understanding file management is a core IT skill.

## File Structure

```
C:\\ (or /)
├── Users
│   └── YourName
│       ├── Documents
│       ├── Downloads
│       ├── Desktop
│       └── Pictures
├── Program Files
└── Windows (or System)
```

## Common File Extensions

| Extension | Type | Opens With |
|-----------|------|------------|
| .docx | Word Document | Microsoft Word |
| .xlsx | Spreadsheet | Microsoft Excel |
| .pdf | Portable Document | Adobe Reader |
| .exe | Program | Windows |
| .zip | Compressed Archive | WinZip, 7-Zip |
| .jpg, .png | Image | Photo viewer |

## Best Practices

- Use descriptive file names: `Invoice_2024_January.pdf`
- Organize files into folders by project or date
- Back up important files regularly
- Don't delete files in System folders!
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Never modify or delete files in C:\\Windows", "Create a consistent folder structure for your work"]
                },
                {
                    "step_order": 5,
                    "title": "Basic Troubleshooting",
                    "content": """
# The IT Troubleshooting Mindset

Before calling IT support, try these basic steps. Most issues can be resolved quickly!

## The Universal Fix: Restart

"Have you tried turning it off and on again?" is famous for a reason - it works!

**Why restarting helps:**
- Clears temporary memory
- Stops runaway processes
- Resets network connections
- Applies pending updates

## The Troubleshooting Checklist

### 1. Define the Problem
- What exactly isn't working?
- When did it start?
- What changed recently?

### 2. Check the Basics
- Is it plugged in?
- Is it turned on?
- Are cables connected properly?
- Is there an internet connection?

### 3. Try Simple Fixes
- Restart the application
- Restart the computer
- Check for updates
- Clear browser cache

### 4. Google the Error
- Copy the exact error message
- Add your OS and software version
- Look for official documentation first

### 5. Document and Escalate
- Write down what you tried
- Note any error messages
- Contact IT support with this information
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Always try restarting before escalating", "Write down error messages exactly as they appear"]
                },
            ]
        },
        {
            "title": "Your First Day in IT: Help Desk Essentials",
            "slug": "first-day-it-help-desk-essentials",
            "description": "Learn what to expect in an IT support role and master the essential skills for helping users",
            "difficulty": "beginner",
            "estimated_time_minutes": 45,
            "category": "it-support",
            "thumbnail_url": None,
            "xp_reward": 100,
            "related_skills": ["hardware-support", "communication"],
            "is_published": True,
            "is_featured": True,
            "steps": [
                {
                    "step_order": 1,
                    "title": "What is IT Support?",
                    "content": """
# Welcome to IT Support!

IT Support (also called Help Desk or Service Desk) is the front line of technology assistance in an organization.

## Your Role

As an IT Support professional, you will:
- Answer phone calls, emails, and chat requests from users
- Troubleshoot hardware and software problems
- Create and manage user accounts
- Install and configure software
- Escalate complex issues to specialized teams

## Common Job Titles

- Help Desk Technician
- IT Support Specialist
- Desktop Support Technician
- Service Desk Analyst
- Technical Support Representative

## The Tier System

Most IT departments use tiers:

| Tier | Role | Handles |
|------|------|---------|
| Tier 1 | Help Desk | Password resets, basic issues |
| Tier 2 | Desktop Support | Hardware, complex software |
| Tier 3 | System Admins | Servers, networks, specialized |

**You'll likely start at Tier 1** - and that's where you learn the most!
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Tier 1 is about learning and building experience", "Every senior IT person started at the help desk"]
                },
                {
                    "step_order": 2,
                    "title": "The Ticketing System",
                    "content": """
# Working with Tickets

A ticket is a record of a user's request or issue. Ticketing systems are essential for IT operations.

## Popular Ticketing Systems

- ServiceNow
- Jira Service Management
- Zendesk
- Freshdesk
- ConnectWise

## Anatomy of a Good Ticket

### Essential Information
- **Requester**: Who reported the issue
- **Category**: Hardware, Software, Network, etc.
- **Priority**: Low, Medium, High, Critical
- **Description**: What's the problem?
- **Status**: New, In Progress, Pending, Resolved

### The Ticket Lifecycle

```
New → Assigned → In Progress → Pending → Resolved → Closed
```

## Best Practices

1. **Document everything** - Future you will thank present you
2. **Update the ticket** - Users appreciate knowing you're working on it
3. **Set realistic expectations** - Don't promise what you can't deliver
4. **Close with resolution notes** - What fixed it? How can it be prevented?
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Good documentation helps the whole team", "Always update ticket status when you make progress"]
                },
                {
                    "step_order": 3,
                    "title": "Common Issues You'll See",
                    "content": """
# The Top 10 Help Desk Issues

These issues make up 80% of help desk calls. Master these, and you'll handle most tickets!

## 1. Password Resets
- Most common ticket by far
- Use your organization's reset process
- Verify user identity before resetting

## 2. Slow Computer
- Check for updates running
- Look at startup programs
- Check disk space and RAM usage

## 3. Cannot Connect to Network
- Check physical cables
- Verify WiFi is connected
- Restart network adapter

## 4. Printer Issues
- "Have you tried turning it off and on again?"
- Check paper, toner, and connections
- Clear print queue

## 5. Software Won't Open
- Restart the application
- Restart the computer
- Check for updates

## 6. Email Problems
- Verify internet connection
- Check mailbox storage
- Confirm correct password

## 7. Missing Files
- Check Recycle Bin
- Look in recent files
- Search by file name

## 8. Computer Won't Turn On
- Check power cable
- Try a different outlet
- Look for power indicator lights

## 9. Blue Screen of Death
- Note the error code
- Restart and see if it repeats
- Check recent hardware/software changes

## 10. "It's Not Working"
- Ask clarifying questions!
- What exactly isn't working?
- When did it start?
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Password resets are #1 - get very good at them", "Always ask users to describe the exact problem"]
                },
                {
                    "step_order": 4,
                    "title": "Professional Communication",
                    "content": """
# Communicating Like a Pro

Technical skills are only half the job. How you communicate matters just as much.

## The Golden Rules

1. **Be patient** - Not everyone is tech-savvy
2. **Avoid jargon** - Say "restart" not "reboot the kernel"
3. **Listen first** - Let users explain fully before jumping in
4. **Confirm understanding** - "So the issue is that..."

## Good vs Bad Responses

### Bad Response
> "Just clear your cache."

### Good Response
> "I can help you with that! Let me walk you through clearing your browser's temporary files. First, click on the three dots in the top right corner..."

## Writing Great Ticket Responses

**Structure your replies:**
1. Acknowledge the issue
2. Explain what you're doing/did
3. Provide next steps
4. Offer additional help

**Example:**
```
Hi Sarah,

Thank you for reporting the printer issue.

I've restarted the print spooler service which was causing the queue to get stuck. Your documents should now print successfully.

If you continue to experience issues, please reply to this ticket and I'll investigate further.

Best regards,
[Your Name]
```
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Users remember how you made them feel, not just the solution", "Written communication should be clear and professional"]
                },
                {
                    "step_order": 5,
                    "title": "When to Escalate",
                    "content": """
# Knowing When to Escalate

Escalation isn't failure - it's knowing your limits and working efficiently.

## When to Escalate

### Escalate When:
- The issue requires admin access you don't have
- You've tried all troubleshooting steps without success
- The issue affects multiple users or critical systems
- It involves security concerns
- The user requests a manager

### Don't Escalate When:
- You haven't tried basic troubleshooting
- You can find the answer with a quick search
- It's a common issue you should learn to handle

## How to Escalate Properly

### Before Escalating
1. Document all steps you've tried
2. Gather relevant error messages and screenshots
3. Note user information and contact details
4. Categorize the priority level

### The Escalation Note Template

```
Issue: [Brief description]
User: [Name and contact]
Reported: [Date/time]
Priority: [Low/Medium/High/Critical]

Steps Taken:
1. Restarted the application
2. Cleared cache
3. Reinstalled software
4. [etc.]

Current Status: [What's happening now]

Additional Notes: [Any relevant context]
```

## Remember

- Escalating with good documentation helps the next tier
- Follow up to learn what solved the issue
- Every escalation is a learning opportunity
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Good escalation notes save everyone time", "Ask the next tier what solved it - that's how you learn"]
                },
            ]
        },
        {
            "title": "Python for Beginners",
            "slug": "python-for-beginners",
            "description": "Learn Python programming from scratch - a great first programming language for IT professionals",
            "difficulty": "beginner",
            "estimated_time_minutes": 60,
            "category": "programming",
            "thumbnail_url": None,
            "xp_reward": 150,
            "related_skills": ["programming", "automation"],
            "is_published": True,
            "is_featured": False,
            "steps": [
                {
                    "step_order": 1,
                    "title": "Why Python for IT?",
                    "content": """
# Why Learn Python?

Python is one of the best first programming languages, especially for IT professionals.

## Python is Used For

- **Automation** - Automate repetitive tasks
- **System Administration** - Manage servers and networks
- **Data Analysis** - Process logs and reports
- **Security** - Build security tools
- **Web Development** - Build internal tools

## Why Python is Great for Beginners

1. **Readable syntax** - Looks almost like English
2. **Large community** - Lots of help available
3. **Versatile** - Used everywhere in IT
4. **Instant feedback** - See results immediately
                    """,
                    "code_example": """# This is a comment - Python ignores it
print("Hello, World!")

# Python is readable
name = "IT Apprentice"
print(f"Welcome, {name}!")""",
                    "code_language": "python",
                    "hints": ["Python is the #1 language for automation in IT", "You can run Python interactively to test ideas"]
                },
                {
                    "step_order": 2,
                    "title": "Variables and Data Types",
                    "content": """
# Variables in Python

A variable is a name that stores a value. Think of it as a labeled box.

## Common Data Types

| Type | Description | Example |
|------|-------------|---------|
| `str` | Text | `"Hello"` |
| `int` | Whole numbers | `42` |
| `float` | Decimal numbers | `3.14` |
| `bool` | True/False | `True` |
| `list` | Collection | `[1, 2, 3]` |
| `dict` | Key-value pairs | `{"name": "John"}` |

## Creating Variables

No special keyword needed - just assign!
                    """,
                    "code_example": """# Text (strings)
username = "admin"
password = "secret123"

# Numbers
port = 22
timeout = 30.5

# Boolean (true/false)
is_connected = True
has_error = False

# Lists (collections)
servers = ["web01", "web02", "db01"]

# Dictionaries (key-value)
user = {
    "name": "John",
    "role": "admin",
    "active": True
}

# Check the type of a variable
print(type(username))  # <class 'str'>
print(type(port))      # <class 'int'>""",
                    "code_language": "python",
                    "hints": ["Python figures out the type automatically", "Use descriptive variable names like 'server_count' not 'sc'"]
                },
                {
                    "step_order": 3,
                    "title": "Control Flow",
                    "content": """
# Making Decisions and Repeating Actions

Control flow lets your program make decisions and repeat actions.

## If Statements

Check conditions and take action:

```python
if condition:
    # do this
elif other_condition:
    # do this instead
else:
    # if nothing else matched
```

## Loops

Repeat actions:

- `for` - When you know how many times
- `while` - Until a condition is false
                    """,
                    "code_example": """# If statement example
status = "running"

if status == "running":
    print("Server is healthy")
elif status == "stopped":
    print("Starting server...")
else:
    print("Unknown status!")

# For loop - iterate over a list
servers = ["web01", "web02", "web03"]
for server in servers:
    print(f"Checking {server}...")

# For loop with range
for i in range(5):
    print(f"Attempt {i + 1}")

# While loop
attempts = 0
max_attempts = 3

while attempts < max_attempts:
    print(f"Trying... (attempt {attempts + 1})")
    attempts += 1
    # In real code, you'd check if it succeeded""",
                    "code_language": "python",
                    "hints": ["Indentation matters in Python - use 4 spaces", "range(5) gives you 0, 1, 2, 3, 4"]
                },
                {
                    "step_order": 4,
                    "title": "Functions",
                    "content": """
# Reusable Code with Functions

Functions let you write code once and use it many times.

## Defining a Function

```python
def function_name(parameters):
    # code here
    return result
```

## Why Use Functions?

- **Reusability** - Write once, use everywhere
- **Organization** - Break big problems into small pieces
- **Testing** - Easy to test individual functions
                    """,
                    "code_example": """# Define a function
def ping_server(hostname):
    \"\"\"Check if a server is responding\"\"\"
    print(f"Pinging {hostname}...")
    # Simulate a ping (real code would use subprocess)
    return True

# Call the function
result = ping_server("web01.company.com")
print(f"Server responding: {result}")

# Function with multiple parameters
def create_user(username, role="user", active=True):
    \"\"\"Create a new user account\"\"\"
    return {
        "username": username,
        "role": role,
        "active": active
    }

# Call with different arguments
admin = create_user("john", role="admin")
guest = create_user("visitor", active=False)

print(admin)  # {'username': 'john', 'role': 'admin', 'active': True}""",
                    "code_language": "python",
                    "hints": ["Give functions descriptive names like 'check_connection' not 'cc'", "Default parameters make functions flexible"]
                },
                {
                    "step_order": 5,
                    "title": "Real IT Examples",
                    "content": """
# Python in Action for IT

Let's see some practical IT examples you might actually use.

## Example 1: Check Disk Space

```python
import shutil

def check_disk_space(path="/"):
    total, used, free = shutil.disk_usage(path)
    free_gb = free // (1024 ** 3)

    if free_gb < 10:
        return f"WARNING: Only {free_gb}GB free!"
    return f"OK: {free_gb}GB free"

print(check_disk_space())
```

## Example 2: Parse a Log File

```python
def find_errors(log_file):
    errors = []
    with open(log_file, 'r') as f:
        for line in f:
            if 'ERROR' in line:
                errors.append(line.strip())
    return errors
```

## Example 3: Simple Server Health Check

This shows how Python makes IT tasks easier!
                    """,
                    "code_example": """import os
from datetime import datetime

def health_check():
    \"\"\"Simple system health check\"\"\"
    report = []
    report.append(f"Health Check - {datetime.now()}")
    report.append("-" * 40)

    # Check Python version
    import sys
    report.append(f"Python Version: {sys.version_info.major}.{sys.version_info.minor}")

    # Check current directory
    report.append(f"Working Directory: {os.getcwd()}")

    # Check environment
    user = os.environ.get('USERNAME', os.environ.get('USER', 'unknown'))
    report.append(f"Current User: {user}")

    return "\\n".join(report)

# Run the health check
print(health_check())""",
                    "code_language": "python",
                    "hints": ["Start with simple scripts and build up", "Python's standard library has many useful modules for IT work"]
                },
            ]
        },
        {
            "title": "Introduction to Networking",
            "slug": "introduction-to-networking",
            "description": "Understand how computers communicate - essential knowledge for any IT professional",
            "difficulty": "beginner",
            "estimated_time_minutes": 45,
            "category": "hardware-networking",
            "thumbnail_url": None,
            "xp_reward": 100,
            "related_skills": ["networking", "problem-solving"],
            "is_published": True,
            "is_featured": True,
            "steps": [
                {
                    "step_order": 1,
                    "title": "What is a Network?",
                    "content": """
# Networks: Connecting Computers

A network is simply two or more devices connected to share resources and communicate.

## Types of Networks

### LAN (Local Area Network)
- Covers a small area (home, office, building)
- Fast speeds
- You control it

### WAN (Wide Area Network)
- Covers large areas (cities, countries)
- The internet is the biggest WAN
- Slower than LAN, connects LANs together

### WLAN (Wireless LAN)
- A LAN using Wi-Fi instead of cables
- Convenient but slightly slower

## What Networks Let You Do

- Share files between computers
- Share printers and devices
- Access the internet
- Communicate (email, chat, video)
- Access centralized applications
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Your home network is a LAN", "The internet connects millions of LANs together"]
                },
                {
                    "step_order": 2,
                    "title": "IP Addresses",
                    "content": """
# IP Addresses: The Phone Numbers of Networking

Every device on a network needs a unique address. That's the IP address.

## IPv4 Addresses

The most common format: `192.168.1.100`

- Four numbers (0-255) separated by dots
- Total possible: ~4.3 billion addresses

## Private vs Public IPs

### Private IP Addresses
Used inside your network (not routable on internet):
- `10.0.0.0` to `10.255.255.255`
- `172.16.0.0` to `172.31.255.255`
- `192.168.0.0` to `192.168.255.255`

### Public IP Addresses
Used on the internet:
- Your router has one
- Websites have them (e.g., `142.250.185.46` is Google)

## Special Addresses

| Address | Purpose |
|---------|---------|
| `127.0.0.1` | Localhost (your own computer) |
| `0.0.0.0` | All interfaces |
| `255.255.255.255` | Broadcast |

## DHCP: Automatic IP Assignment

Most networks use DHCP to automatically assign IP addresses.
- Your router usually runs DHCP
- Devices request an IP when they connect
- No manual configuration needed
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Private IPs are reused by millions of networks safely", "127.0.0.1 always means 'this computer'"]
                },
                {
                    "step_order": 3,
                    "title": "DNS: The Internet's Phone Book",
                    "content": """
# DNS: Domain Name System

Humans remember names. Computers use numbers. DNS translates between them.

## How DNS Works

When you type `www.google.com`:

1. Your computer asks a DNS server
2. DNS server looks up the domain
3. Returns the IP address (e.g., `142.250.185.46`)
4. Your browser connects to that IP

## The DNS Hierarchy

```
. (root)
├── com
│   ├── google
│   ├── amazon
│   └── ...
├── org
├── net
└── uk
    ├── co
    │   └── bbc
    └── ...
```

## Common DNS Record Types

| Type | Purpose | Example |
|------|---------|---------|
| A | Maps name to IPv4 | `example.com → 93.184.216.34` |
| AAAA | Maps name to IPv6 | `example.com → 2606:2800:220:1:...` |
| CNAME | Alias for another name | `www → example.com` |
| MX | Email server | `example.com → mail.example.com` |

## Troubleshooting DNS

Common command:
```
nslookup google.com
```
This tells you what IP address Google resolves to.
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["DNS is often called 'the phonebook of the internet'", "DNS problems cause 'cannot find server' errors"]
                },
                {
                    "step_order": 4,
                    "title": "Network Hardware",
                    "content": """
# Network Devices

Different devices serve different purposes in a network.

## Router
- Connects different networks (like your LAN to the internet)
- Assigns IP addresses (via DHCP)
- Has firewall features
- Your home "router" is usually router + switch + wireless access point combined

## Switch
- Connects devices within a network
- Sends data only to the intended device
- Has multiple ports (8, 16, 24, 48)
- Smarter than a hub

## Access Point (AP)
- Creates a wireless network
- Connects to a switch via ethernet
- Extends network coverage

## Modem
- Connects to your ISP
- Converts signals (cable/DSL/fiber to ethernet)
- Often combined with router for home use

## Cables

| Type | Speed | Use Case |
|------|-------|----------|
| Cat5e | Up to 1 Gbps | Basic networking |
| Cat6 | Up to 10 Gbps | Modern offices |
| Cat6a | 10 Gbps (longer) | Enterprise |
| Fiber | 100+ Gbps | Data centers, ISPs |
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Home 'routers' are actually 3 devices in 1", "Most office computers use Cat5e or Cat6 cables"]
                },
                {
                    "step_order": 5,
                    "title": "Troubleshooting Network Issues",
                    "content": """
# Network Troubleshooting Basics

These commands help diagnose network problems.

## The Essential Commands

### ping - Test connectivity
```
ping google.com
```
- Sends test packets and measures response time
- If it fails, there's a connectivity problem

### ipconfig (Windows) / ifconfig (Mac/Linux)
```
ipconfig
```
- Shows your IP address and network configuration
- Use `ipconfig /all` for detailed info

### nslookup - Test DNS
```
nslookup google.com
```
- Checks if DNS is resolving names correctly

### tracert (Windows) / traceroute (Mac/Linux)
```
tracert google.com
```
- Shows the path packets take to reach a destination
- Helps identify where problems occur

## Quick Troubleshooting Steps

1. **Check physical connection**
   - Is the cable plugged in?
   - Is Wi-Fi connected?

2. **Get your IP address**
   - Run `ipconfig` or check network settings
   - No IP? DHCP might be the issue

3. **Ping your gateway (router)**
   - Find gateway IP in ipconfig output
   - If ping fails, local network issue

4. **Ping an internet IP**
   - Try `ping 8.8.8.8` (Google's DNS)
   - If fails, internet connection issue

5. **Ping a domain name**
   - Try `ping google.com`
   - If IP works but name doesn't, DNS issue
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Always start with physical checks - cables come loose!", "8.8.8.8 is Google's DNS - good for testing internet"]
                },
            ]
        },
    ]

    for tutorial_data in tutorials_data:
        # Check if tutorial already exists
        existing = db.query(Tutorial).filter(
            Tutorial.slug == tutorial_data["slug"]
        ).first()

        if existing:
            print(f"- Tutorial already exists: {tutorial_data['title']}")
            continue

        # Get category
        category_slug = tutorial_data.pop("category")
        category = categories.get(category_slug)

        # Create tutorial
        steps_data = tutorial_data.pop("steps")
        tutorial = Tutorial(
            author_id=admin_user.id,
            category_id=category.id if category else None,
            **tutorial_data
        )
        db.add(tutorial)
        db.flush()

        # Create steps
        for step_data in steps_data:
            step = TutorialStep(
                tutorial_id=tutorial.id,
                **step_data
            )
            db.add(step)

        db.commit()
        print(f"[OK] Created tutorial: {tutorial.title} ({len(steps_data)} steps)")


def main():
    """Main seed function"""
    db = SessionLocal()

    try:
        # Get admin user
        admin_user = db.query(User).filter(User.role == UserRole.ADMIN).first()

        if not admin_user:
            print("[ERROR] No admin user found. Please create an admin user first.")
            return

        print(f"Using admin user: {admin_user.email}\n")

        # Create categories
        print("Creating categories...")
        categories = create_categories(db)
        print(f"\n[OK] Created/updated {len(categories)} categories\n")

        # Create tutorials
        print("Creating tutorials...")
        create_tutorials(db, categories, admin_user)

        print("\n[OK] Seed data created successfully!")

    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
