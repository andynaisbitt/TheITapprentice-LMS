"""
Comprehensive Seed Data for Courses Plugin
Creates full IT courses with 10 modules each for TheITApprentice.
Written in UK English style.

Run with: python -m app.plugins.courses.seed_data_comprehensive
"""
from sqlalchemy.orm import Session
from typing import List

# Import User models first to resolve relationships
from app.users.models import User, UserRole
from app.auth.email_verification import EmailVerification

from app.plugins.courses.models import Course, CourseModule, ModuleSection
from app.plugins.courses.schemas import CourseModuleCreate, ModuleSectionCreate


def cleanup_existing_courses(db: Session, course_ids: List[str]):
    """Remove existing courses before re-seeding."""
    for course_id in course_ids:
        existing = db.query(Course).filter(Course.id == course_id).first()
        if existing:
            for module in existing.modules:
                db.query(ModuleSection).filter(ModuleSection.module_id == module.id).delete()
            db.query(CourseModule).filter(CourseModule.course_id == course_id).delete()
            db.delete(existing)
            db.commit()
            print(f"Cleaned up existing course: {course_id}")


def create_it_support_course(db: Session, instructor_id: int) -> Course:
    """Create IT Support Fundamentals course with 10 modules."""
    from app.plugins.courses.crud import create_module, create_section

    course_data = {
        "id": "it-support-fundamentals",
        "title": "IT Support Fundamentals",
        "description": "Start your IT career with essential help desk and support skills. This comprehensive course covers everything from troubleshooting methodology to professional communication, preparing you for real-world IT support roles.",
        "short_description": "Master the essentials of IT support and help desk operations",
        "level": "beginner",
        "category": "IT Support",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 20,
        "related_skills": ["troubleshooting", "customer-service", "ticketing", "hardware", "software"],
        "xp_reward": 1000,
        "requirements": [
            "No prior IT experience required",
            "Basic computer skills (mouse, keyboard, web browser)",
            "Willingness to help others solve problems",
            "Access to a computer for practical exercises"
        ],
        "objectives": [
            "Understand the role of IT support in organisations",
            "Apply systematic troubleshooting methodology",
            "Diagnose common hardware and software issues",
            "Provide professional customer service",
            "Use ticketing systems effectively",
            "Document solutions for knowledge bases"
        ],
    }

    course = Course(
        id=course_data["id"],
        title=course_data["title"],
        description=course_data["description"],
        short_description=course_data.get("short_description"),
        level="beginner",
        status="published",
        category=course_data.get("category"),
        instructor_id=course_data["instructor_id"],
        is_premium=False,
        price=0.0,
        estimated_hours=course_data.get("estimated_hours", 0),
        related_skills=course_data.get("related_skills", []),
        xp_reward=course_data.get("xp_reward", 0),
        requirements=course_data.get("requirements", []),
        objectives=course_data.get("objectives", []),
    )
    db.add(course)
    db.commit()
    db.refresh(course)

    # Module 1: The IT Support Role
    mod1 = create_module(db, CourseModuleCreate(
        id="its-m1",
        title="The IT Support Role",
        description="Understand what IT support professionals do and where they fit in organisations",
        order_index=0,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m1-s1",
        title="What is IT Support?",
        order_index=0,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b1", "type": "heading", "content": {"text": "Welcome to IT Support", "level": 1}},
            {"id": "b2", "type": "text", "content": {"text": "IT support is the backbone of every organisation's technology operations. As an IT support technician, you're the first line of defence when technology fails. Your role is crucial in keeping businesses running smoothly and employees productive.\n\nIn this course, you'll learn everything needed to start your career in IT support, from basic troubleshooting to professional communication skills.", "markdown": True}},
            {"id": "b3", "type": "callout", "content": {"type": "info", "title": "Career Opportunity", "message": "IT Support roles are in high demand across the UK. Entry-level positions often lead to specialised careers in networking, security, or system administration."}},
            {"id": "b4", "type": "text", "content": {"text": "### Key Responsibilities\n\n- Responding to help desk tickets and phone calls\n- Troubleshooting hardware and software issues\n- Setting up new user accounts and equipment\n- Documenting solutions for future reference\n- Escalating complex issues to senior technicians\n- Maintaining IT asset inventories", "markdown": True}}
        ]
    ), mod1.id)

    create_section(db, ModuleSectionCreate(
        id="its-m1-s2",
        title="IT Support Tiers",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b5", "type": "heading", "content": {"text": "Understanding Support Tiers", "level": 2}},
            {"id": "b6", "type": "text", "content": {"text": "IT support is typically organised into tiers, each handling different levels of complexity. Understanding this structure helps you know when to solve issues yourself and when to escalate.", "markdown": True}},
            {"id": "b7", "type": "text", "content": {"text": "### The Three-Tier Model\n\n**Tier 1 (Help Desk)**\n- First point of contact for users\n- Handles password resets, basic troubleshooting\n- Logs all tickets and initial diagnostics\n- Resolves 60-70% of issues\n\n**Tier 2 (Technical Support)**\n- More experienced technicians\n- Handles complex software and hardware issues\n- Performs system configurations\n- May require remote access to user machines\n\n**Tier 3 (Expert/Engineering)**\n- Specialists and system administrators\n- Handles infrastructure-level problems\n- Develops solutions for recurring issues\n- Works with vendors on product issues", "markdown": True}},
            {"id": "b8", "type": "callout", "content": {"type": "tip", "title": "Starting Out", "message": "Most IT careers begin at Tier 1. It's an excellent way to learn the breadth of IT issues whilst developing your troubleshooting skills."}}
        ]
    ), mod1.id)

    create_section(db, ModuleSectionCreate(
        id="its-m1-s3",
        title="Module 1 Quiz",
        order_index=2,
        duration="10 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b9", "type": "heading", "content": {"text": "Check Your Understanding", "level": 2}},
            {"id": "b10", "type": "quiz", "content": {
                "questions": [
                    {"id": "q1", "question": "Which tier of IT support typically handles password resets?", "type": "multiple_choice", "options": ["Tier 1 (Help Desk)", "Tier 2 (Technical Support)", "Tier 3 (Expert/Engineering)", "External Vendor"], "correct_answer": "Tier 1 (Help Desk)", "explanation": "Tier 1 handles common, straightforward issues like password resets, allowing higher tiers to focus on complex problems."},
                    {"id": "q2", "question": "True or False: IT support technicians should document their solutions.", "type": "true_false", "correct_answer": "true", "explanation": "Documentation is essential! It helps other technicians solve similar issues and builds your organisation's knowledge base."},
                    {"id": "q3", "question": "What percentage of issues does Tier 1 typically resolve?", "type": "multiple_choice", "options": ["20-30%", "40-50%", "60-70%", "90-100%"], "correct_answer": "60-70%", "explanation": "A well-functioning Tier 1 resolves the majority of issues, filtering only complex problems to higher tiers."}
                ],
                "passing_score": 70
            }}
        ]
    ), mod1.id)

    # Module 2: Hardware Fundamentals
    mod2 = create_module(db, CourseModuleCreate(
        id="its-m2",
        title="Hardware Fundamentals",
        description="Learn about computer components and how they work together",
        order_index=1,
        duration="60 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m2-s1",
        title="Inside a Computer",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b11", "type": "heading", "content": {"text": "Computer Components", "level": 1}},
            {"id": "b12", "type": "text", "content": {"text": "To troubleshoot hardware effectively, you need to understand what's inside a computer and how each component contributes to the system's operation.", "markdown": True}},
            {"id": "b13", "type": "text", "content": {"text": "### Core Components\n\n**CPU (Central Processing Unit)**\nThe brain of the computer. Executes instructions and performs calculations. Common manufacturers: Intel and AMD.\n\n**RAM (Random Access Memory)**\nTemporary storage for active programs and data. More RAM allows more programs to run simultaneously. Typical sizes: 8GB, 16GB, 32GB.\n\n**Storage (HDD/SSD)**\n- **HDD (Hard Disk Drive)**: Mechanical, slower, cheaper, higher capacity\n- **SSD (Solid State Drive)**: No moving parts, faster, more reliable, pricier\n\n**Motherboard**\nThe main circuit board connecting all components. Contains slots for CPU, RAM, and expansion cards.\n\n**Power Supply Unit (PSU)**\nConverts mains electricity to voltages the computer needs. Measured in watts (e.g., 500W, 750W).\n\n**Graphics Card (GPU)**\nProcesses visual output. Essential for gaming and design work; basic tasks use integrated graphics.", "markdown": True}},
            {"id": "b14", "type": "callout", "content": {"type": "warning", "title": "Safety First", "message": "Always discharge static electricity before handling components. Touch a metal surface or wear an anti-static wrist strap to prevent damage."}}
        ]
    ), mod2.id)

    create_section(db, ModuleSectionCreate(
        id="its-m2-s2",
        title="Peripherals and Connectors",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b15", "type": "heading", "content": {"text": "Ports, Cables, and Peripherals", "level": 2}},
            {"id": "b16", "type": "text", "content": {"text": "### Common Port Types\n\n| Port | Purpose | Notes |\n|------|---------|-------|\n| USB-A | General peripherals | Most common, rectangular |\n| USB-C | Modern devices | Reversible, supports video |\n| HDMI | Video output | TVs, monitors |\n| DisplayPort | Video output | Higher refresh rates |\n| Ethernet (RJ-45) | Network connection | Wired internet |\n| 3.5mm Audio | Headphones/speakers | Universal audio |\n| VGA | Legacy video | Blue connector, older monitors |", "markdown": True}},
            {"id": "b17", "type": "text", "content": {"text": "### Peripheral Devices\n\n**Input Devices**: Keyboard, mouse, scanner, webcam, microphone\n\n**Output Devices**: Monitor, printer, speakers, headphones\n\n**Storage Devices**: USB drives, external hard drives, SD cards", "markdown": True}},
            {"id": "b18", "type": "callout", "content": {"type": "tip", "title": "Troubleshooting Tip", "message": "When a peripheral doesn't work, always check the physical connection first. A loose cable is the cause of many 'broken' devices."}}
        ]
    ), mod2.id)

    create_section(db, ModuleSectionCreate(
        id="its-m2-s3",
        title="Module 2 Quiz",
        order_index=2,
        duration="10 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b19", "type": "quiz", "content": {
                "questions": [
                    {"id": "q4", "question": "Which component is considered the 'brain' of the computer?", "type": "multiple_choice", "options": ["RAM", "CPU", "SSD", "PSU"], "correct_answer": "CPU", "explanation": "The CPU (Central Processing Unit) executes all instructions and is often called the computer's brain."},
                    {"id": "q5", "question": "What is the main advantage of an SSD over an HDD?", "type": "multiple_choice", "options": ["Larger storage capacity", "Faster read/write speeds", "Lower cost per gigabyte", "Mechanical reliability"], "correct_answer": "Faster read/write speeds", "explanation": "SSDs have no moving parts, allowing much faster data access compared to mechanical HDDs."},
                    {"id": "q6", "question": "Which port type is reversible?", "type": "multiple_choice", "options": ["USB-A", "USB-C", "HDMI", "VGA"], "correct_answer": "USB-C", "explanation": "USB-C connectors can be plugged in either way up, unlike USB-A which only fits one way."}
                ],
                "passing_score": 70
            }}
        ]
    ), mod2.id)

    # Module 3: Troubleshooting Methodology
    mod3 = create_module(db, CourseModuleCreate(
        id="its-m3",
        title="Troubleshooting Methodology",
        description="Learn systematic approaches to diagnosing and solving IT problems",
        order_index=2,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m3-s1",
        title="The 6-Step Process",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b20", "type": "heading", "content": {"text": "Systematic Troubleshooting", "level": 1}},
            {"id": "b21", "type": "text", "content": {"text": "Good troubleshooting is like detective work. You gather clues, form theories, and test them until you find the solution. Following a systematic approach saves time and ensures you don't miss anything.", "markdown": True}},
            {"id": "b22", "type": "text", "content": {"text": "### The 6-Step Troubleshooting Method\n\n**1. Identify the Problem**\n- Ask the user what happened\n- Gather error messages and symptoms\n- Determine when the issue started\n- Ask: 'What changed recently?'\n\n**2. Establish a Theory**\n- Consider likely causes based on symptoms\n- Start with the most probable\n- Don't overlook simple explanations\n\n**3. Test the Theory**\n- Try your proposed solution\n- If it works, proceed to step 4\n- If not, return to step 2 with a new theory\n\n**4. Create an Action Plan**\n- Plan the full fix if your theory is correct\n- Consider impact on users\n- Prepare rollback steps if needed\n\n**5. Implement the Solution**\n- Apply the fix carefully\n- Verify the problem is resolved\n- Test related functionality\n\n**6. Document Everything**\n- Record the problem, cause, and solution\n- Update the knowledge base\n- Note any preventive measures", "markdown": True}},
            {"id": "b23", "type": "callout", "content": {"type": "tip", "title": "Pro Tip", "message": "Always ask 'What changed recently?' - Many issues occur right after updates, new software installations, or configuration changes."}}
        ]
    ), mod3.id)

    create_section(db, ModuleSectionCreate(
        id="its-m3-s2",
        title="Common Quick Fixes",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b24", "type": "heading", "content": {"text": "The Simple Solutions", "level": 2}},
            {"id": "b25", "type": "text", "content": {"text": "Before diving into complex troubleshooting, try these quick fixes that resolve a surprising number of issues:", "markdown": True}},
            {"id": "b26", "type": "text", "content": {"text": "### The Power of Restarting\n\n**'Have you tried turning it off and on again?'**\n\nThis isn't a joke - restarting genuinely fixes many problems by:\n- Clearing temporary memory issues\n- Resetting stuck processes\n- Applying pending updates\n- Refreshing network connections\n\n### The Quick Fix Checklist\n\n1. **Restart the application**\n2. **Restart the computer**\n3. **Check cable connections**\n4. **Check Wi-Fi/network connection**\n5. **Clear browser cache (for web issues)**\n6. **Check for available updates**\n7. **Try a different browser/application**\n8. **Log out and log back in**", "markdown": True}},
            {"id": "b27", "type": "callout", "content": {"type": "info", "title": "Statistics", "message": "Studies suggest that up to 90% of desktop issues can be resolved with a simple restart. Always try this first!"}}
        ]
    ), mod3.id)

    # Module 4: Common Hardware Issues
    mod4 = create_module(db, CourseModuleCreate(
        id="its-m4",
        title="Common Hardware Issues",
        description="Diagnose and resolve typical hardware problems",
        order_index=3,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m4-s1",
        title="Display Problems",
        order_index=0,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b28", "type": "heading", "content": {"text": "Monitor and Display Issues", "level": 1}},
            {"id": "b29", "type": "text", "content": {"text": "### No Display / Black Screen\n\n**Check these first:**\n- Is the monitor powered on? (Look for power LED)\n- Is the correct input source selected?\n- Are all cables securely connected?\n- Try a different cable or port\n\n**If still no display:**\n- Connect to a different monitor to isolate the issue\n- Check if the computer is actually running (listen for fans, check HDD light)\n- Try reseating the RAM and graphics card\n\n### Flickering or Artifacts\n\n**Possible causes:**\n- Loose cable connection\n- Failing graphics card\n- Incorrect refresh rate setting\n- Driver issues\n- Overheating GPU\n\n**Solutions:**\n- Secure all connections\n- Update graphics drivers\n- Check GPU temperatures\n- Test with a different monitor", "markdown": True}}
        ]
    ), mod4.id)

    create_section(db, ModuleSectionCreate(
        id="its-m4-s2",
        title="Performance Issues",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b30", "type": "heading", "content": {"text": "Slow Computer Troubleshooting", "level": 2}},
            {"id": "b31", "type": "text", "content": {"text": "A slow computer is one of the most common complaints. Here's how to diagnose and fix performance issues:", "markdown": True}},
            {"id": "b32", "type": "text", "content": {"text": "### Check Resource Usage\n\nOpen Task Manager (Ctrl+Shift+Esc) and check:\n\n**High CPU Usage**\n- Identify which process is using CPU\n- Could be malware, Windows updates, or a runaway application\n- End unresponsive processes\n\n**High Memory (RAM) Usage**\n- Too many applications open\n- Memory leak in an application\n- Consider adding more RAM if consistently high\n\n**High Disk Usage**\n- Often seen with HDDs, especially during Windows updates\n- Check for indexing or antivirus scans\n- Consider upgrading to SSD\n\n### Other Causes\n\n- **Startup programs**: Disable unnecessary startup items\n- **Malware**: Run antivirus scan\n- **Fragmented HDD**: Run defragmentation (not needed for SSDs)\n- **Insufficient storage**: Free up disk space (need at least 10-15% free)\n- **Thermal throttling**: Clean dust from fans and vents", "markdown": True}},
            {"id": "b33", "type": "callout", "content": {"type": "tip", "title": "Quick Win", "message": "An SSD upgrade is often the single most impactful performance improvement for older computers."}}
        ]
    ), mod4.id)

    # Module 5: Common Software Issues
    mod5 = create_module(db, CourseModuleCreate(
        id="its-m5",
        title="Common Software Issues",
        description="Troubleshoot operating system and application problems",
        order_index=4,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m5-s1",
        title="Application Crashes",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b34", "type": "heading", "content": {"text": "When Applications Stop Working", "level": 1}},
            {"id": "b35", "type": "text", "content": {"text": "Applications can crash, freeze, or behave unexpectedly for various reasons. Here's how to approach these issues:", "markdown": True}},
            {"id": "b36", "type": "text", "content": {"text": "### Application Freezes\n\n**Immediate steps:**\n1. Wait 30-60 seconds - it might recover\n2. Check if just the UI is frozen (try minimising)\n3. Use Task Manager to end the task if unresponsive\n\n**Investigate:**\n- Check Event Viewer for error logs\n- Look for patterns (time of day, specific action)\n- Check if the issue occurs in Safe Mode\n\n### Application Won't Start\n\n**Common causes and fixes:**\n- **Missing dependencies**: Reinstall the application\n- **Corrupted files**: Repair or reinstall\n- **Compatibility issues**: Run in compatibility mode\n- **Antivirus blocking**: Check quarantine, add exception\n- **Insufficient permissions**: Run as administrator\n\n### Blue Screen of Death (BSOD)\n\nA BSOD indicates a critical system error:\n1. Note the error code (e.g., DRIVER_IRQL_NOT_LESS_OR_EQUAL)\n2. Search for the specific error code\n3. Common causes: driver issues, hardware failure, Windows updates\n4. Boot into Safe Mode to troubleshoot", "markdown": True}},
            {"id": "b37", "type": "callout", "content": {"type": "warning", "title": "Data Loss Risk", "message": "When dealing with frequent crashes, ensure the user's data is backed up before attempting repairs."}}
        ]
    ), mod5.id)

    create_section(db, ModuleSectionCreate(
        id="its-m5-s2",
        title="Windows Update Issues",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b38", "type": "heading", "content": {"text": "Managing Windows Updates", "level": 2}},
            {"id": "b39", "type": "text", "content": {"text": "Windows Update problems are extremely common. Here's how to handle them:", "markdown": True}},
            {"id": "b40", "type": "text", "content": {"text": "### Update Stuck or Failed\n\n**First steps:**\n1. Wait - large updates can take hours\n2. Restart the computer and try again\n3. Run Windows Update Troubleshooter\n\n**If that doesn't work:**\n- Clear the Software Distribution folder\n- Use DISM and SFC commands to repair system files\n- Download update manually from Microsoft Catalog\n\n### Commands for Repair\n\n```\nsfc /scannow\nDISM /Online /Cleanup-Image /RestoreHealth\n```\n\n### Update Causing Problems\n\nIf an update breaks something:\n1. Go to Settings > Update & Security > View update history\n2. Click 'Uninstall updates'\n3. Remove the problematic update\n4. Pause updates temporarily\n5. Report the issue to Microsoft", "markdown": True}}
        ]
    ), mod5.id)

    # Module 6: Printer Troubleshooting
    mod6 = create_module(db, CourseModuleCreate(
        id="its-m6",
        title="Printer Troubleshooting",
        description="Solve common printing problems",
        order_index=5,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m6-s1",
        title="Print Problems",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b41", "type": "heading", "content": {"text": "Common Printing Issues", "level": 1}},
            {"id": "b42", "type": "text", "content": {"text": "Printers are notoriously temperamental. Here's how to tackle the most common issues:", "markdown": True}},
            {"id": "b43", "type": "text", "content": {"text": "### Print Job Won't Start\n\n**Check the basics:**\n- Is the printer powered on and online?\n- Is the correct printer selected?\n- Is there a paper jam or error light?\n- Is the printer connected (USB/network)?\n\n**Clear the print queue:**\n1. Open Services (services.msc)\n2. Stop 'Print Spooler' service\n3. Delete files from C:\\Windows\\System32\\spool\\PRINTERS\n4. Start 'Print Spooler' service\n5. Try printing again\n\n### Poor Print Quality\n\n**Inkjet printers:**\n- Run print head cleaning utility\n- Check ink levels\n- Use correct paper type setting\n- Align print heads\n\n**Laser printers:**\n- Check toner levels\n- Clean the drum unit\n- Check for toner leaks\n- Print test page\n\n### Paper Jams\n\n1. Turn off the printer\n2. Remove paper tray\n3. Gently pull jammed paper in the direction of paper path\n4. Check for torn pieces left inside\n5. Fan paper stack before reloading", "markdown": True}},
            {"id": "b44", "type": "callout", "content": {"type": "tip", "title": "Network Printers", "message": "For network printer issues, check if other users can print. If no one can, the problem is with the printer. If only one user can't, the problem is with their computer."}}
        ]
    ), mod6.id)

    # Module 7: Help Desk and Ticketing
    mod7 = create_module(db, CourseModuleCreate(
        id="its-m7",
        title="Help Desk and Ticketing",
        description="Master ticketing systems and help desk workflows",
        order_index=6,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m7-s1",
        title="Ticket Lifecycle",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b45", "type": "heading", "content": {"text": "The Ticket Lifecycle", "level": 1}},
            {"id": "b46", "type": "text", "content": {"text": "Every IT support request follows a lifecycle from creation to resolution. Understanding this workflow helps you provide consistent, professional service.", "markdown": True}},
            {"id": "b47", "type": "text", "content": {"text": "### Ticket Stages\n\n**1. New**\nUser submits a request via email, phone, or portal. System creates a ticket with unique ID.\n\n**2. Assigned**\nTicket is routed to the appropriate technician or queue based on category, priority, or skills.\n\n**3. In Progress**\nTechnician is actively working on the issue. User should be kept informed.\n\n**4. Pending/On Hold**\nWaiting for:\n- User response or information\n- Parts or equipment to arrive\n- Third-party vendor action\n- Scheduled maintenance window\n\n**5. Resolved**\nIssue has been fixed. Technician documents the solution.\n\n**6. Closed**\nUser confirms resolution (or auto-closes after timeout). Ticket archived for reporting.", "markdown": True}},
            {"id": "b48", "type": "text", "content": {"text": "### Best Practices\n\n- Acknowledge every ticket promptly\n- Set realistic expectations for resolution\n- Update the ticket with every action taken\n- Communicate proactively with the user\n- Document the solution clearly for future reference\n- Categorise tickets correctly for reporting", "markdown": True}}
        ]
    ), mod7.id)

    create_section(db, ModuleSectionCreate(
        id="its-m7-s2",
        title="Priority and SLAs",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b49", "type": "heading", "content": {"text": "Understanding Priority Levels", "level": 2}},
            {"id": "b50", "type": "text", "content": {"text": "### Priority Matrix\n\n| Priority | Impact | Response Time | Example |\n|----------|--------|---------------|----------|\n| Critical | Entire business | 15 minutes | Server down, security breach |\n| High | Department | 1 hour | Email system issues |\n| Medium | Multiple users | 4 hours | Printer not working |\n| Low | Single user | 1 business day | Password reset |\n\n### Service Level Agreements (SLAs)\n\nSLAs are formal agreements defining:\n- Response time (how quickly you acknowledge)\n- Resolution time (how quickly you fix it)\n- Escalation procedures\n- Communication requirements\n\n**Why SLAs Matter:**\n- Set clear expectations with users\n- Help prioritise workload\n- Measure IT performance\n- Identify areas for improvement", "markdown": True}},
            {"id": "b51", "type": "callout", "content": {"type": "warning", "title": "SLA Breaches", "message": "Approaching SLA breach? Escalate early! It's better to ask for help than to miss your target."}}
        ]
    ), mod7.id)

    # Module 8: Communication Skills
    mod8 = create_module(db, CourseModuleCreate(
        id="its-m8",
        title="Professional Communication",
        description="Develop essential communication skills for IT support",
        order_index=7,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m8-s1",
        title="Talking to Users",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b52", "type": "heading", "content": {"text": "Effective User Communication", "level": 1}},
            {"id": "b53", "type": "text", "content": {"text": "Technical skills alone won't make you successful in IT support. How you communicate with users is equally important.", "markdown": True}},
            {"id": "b54", "type": "text", "content": {"text": "### The Golden Rules\n\n**1. Avoid Technical Jargon**\nSay: 'The file that stores your settings got corrupted'\nNot: 'Your registry hive is corrupted'\n\n**2. Listen Actively**\n- Let users finish explaining\n- Take notes\n- Repeat back to confirm understanding\n- Ask clarifying questions\n\n**3. Show Empathy**\n- Acknowledge their frustration\n- Avoid blame\n- Focus on solutions\n\n**4. Set Expectations**\n- Be honest about timeframes\n- Explain what you're doing\n- Keep them informed of progress\n\n**5. Stay Professional**\n- Remain calm under pressure\n- Never argue with users\n- Admit when you don't know (then find out)", "markdown": True}},
            {"id": "b55", "type": "callout", "content": {"type": "tip", "title": "The Curse of Knowledge", "message": "What seems obvious to you isn't obvious to users. What you consider 'basic' might be completely foreign to them. Adjust your language accordingly."}}
        ]
    ), mod8.id)

    create_section(db, ModuleSectionCreate(
        id="its-m8-s2",
        title="Difficult Situations",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b56", "type": "heading", "content": {"text": "Handling Difficult Users", "level": 2}},
            {"id": "b57", "type": "text", "content": {"text": "Sometimes you'll encounter frustrated, angry, or demanding users. Here's how to handle these situations:", "markdown": True}},
            {"id": "b58", "type": "text", "content": {"text": "### The LEAD Method\n\n**L - Listen**\nLet them vent without interruption. Often, they just need to be heard.\n\n**E - Empathise**\n'I understand how frustrating this must be, especially with your deadline.'\n\n**A - Apologise**\nApologise for the inconvenience, not necessarily for fault.\n'I'm sorry you're experiencing this issue.'\n\n**D - Diagnose/Deliver**\nMove to solving the problem.\n'Let me take a look at what's happening and get this sorted for you.'\n\n### Things to Avoid\n\n- Matching their emotional level\n- Taking complaints personally\n- Making promises you can't keep\n- Blaming colleagues or other departments\n- Being defensive\n\n### When to Escalate\n\nEscalate to your manager if:\n- User becomes abusive or threatening\n- They demand to speak to a supervisor\n- You've done everything you can but they're not satisfied\n- The situation is affecting other work", "markdown": True}}
        ]
    ), mod8.id)

    # Module 9: Remote Support Tools
    mod9 = create_module(db, CourseModuleCreate(
        id="its-m9",
        title="Remote Support Tools",
        description="Learn to support users remotely",
        order_index=8,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m9-s1",
        title="Remote Desktop Tools",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b59", "type": "heading", "content": {"text": "Supporting Users Remotely", "level": 1}},
            {"id": "b60", "type": "text", "content": {"text": "Remote support tools let you view and control a user's computer from your desk. This is essential for distributed workforces and faster resolution times.", "markdown": True}},
            {"id": "b61", "type": "text", "content": {"text": "### Common Remote Support Tools\n\n**Built into Windows:**\n- Remote Desktop Connection (RDP)\n- Quick Assist (Windows 10/11)\n- Remote Assistance (legacy)\n\n**Third-party tools:**\n- TeamViewer\n- AnyDesk\n- ConnectWise Control\n- Datto Remote Support\n- Splashtop\n\n### Best Practices\n\n1. **Always get permission** before connecting\n2. **Explain what you're doing** as you do it\n3. **Don't snoop** - only access what's necessary\n4. **Disconnect properly** when finished\n5. **Document the session** in your ticket\n\n### Security Considerations\n\n- Use encrypted connections\n- Require user consent for each session\n- Log all remote sessions\n- Use unique session codes (not permanent passwords)\n- Disconnect immediately when done", "markdown": True}},
            {"id": "b62", "type": "callout", "content": {"type": "warning", "title": "Privacy Warning", "message": "Users may have personal information visible on screen. Be professional and discreet. Never mention what you see beyond the scope of the support issue."}}
        ]
    ), mod9.id)

    # Module 10: Documentation and Knowledge Base
    mod10 = create_module(db, CourseModuleCreate(
        id="its-m10",
        title="Documentation Best Practices",
        description="Create effective documentation and maintain knowledge bases",
        order_index=9,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="its-m10-s1",
        title="Writing Documentation",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b63", "type": "heading", "content": {"text": "The Art of IT Documentation", "level": 1}},
            {"id": "b64", "type": "text", "content": {"text": "Good documentation is the backbone of efficient IT support. It saves time, ensures consistency, and helps new team members get up to speed quickly.", "markdown": True}},
            {"id": "b65", "type": "text", "content": {"text": "### Types of Documentation\n\n**Ticket Notes**\n- What the user reported\n- Steps taken to diagnose\n- Solution applied\n- Follow-up actions needed\n\n**Knowledge Base Articles**\n- How-to guides for common issues\n- Step-by-step procedures\n- FAQs for users\n- Technical reference documents\n\n**System Documentation**\n- Network diagrams\n- Server configurations\n- Software inventories\n- Disaster recovery procedures\n\n### Writing Effective KB Articles\n\n1. **Clear title** - Users should know if it's relevant\n2. **Problem statement** - What issue does this solve?\n3. **Step-by-step instructions** - Numbered, specific\n4. **Screenshots** - Where helpful\n5. **Expected outcome** - What should happen\n6. **Related articles** - Links to connected topics", "markdown": True}},
            {"id": "b66", "type": "callout", "content": {"type": "tip", "title": "The 5-Minute Rule", "message": "If you spend more than 5 minutes solving a problem that isn't already documented, document it. Your future self (and colleagues) will thank you."}}
        ]
    ), mod10.id)

    create_section(db, ModuleSectionCreate(
        id="its-m10-s2",
        title="Final Assessment",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "b67", "type": "heading", "content": {"text": "Course Final Assessment", "level": 1}},
            {"id": "b68", "type": "text", "content": {"text": "Congratulations on completing IT Support Fundamentals! Take this final assessment to test your knowledge.", "markdown": True}},
            {"id": "b69", "type": "quiz", "content": {
                "questions": [
                    {"id": "fq1", "question": "A user reports their computer is running slowly. What should you check first in Task Manager?", "type": "multiple_choice", "options": ["Startup tab", "Performance tab (CPU/Memory/Disk usage)", "App history tab", "Users tab"], "correct_answer": "Performance tab (CPU/Memory/Disk usage)", "explanation": "The Performance tab shows real-time resource usage, helping identify bottlenecks."},
                    {"id": "fq2", "question": "What is the first step in the 6-step troubleshooting method?", "type": "multiple_choice", "options": ["Establish a theory", "Test the theory", "Identify the problem", "Document everything"], "correct_answer": "Identify the problem", "explanation": "You must understand the problem before you can form theories about its cause."},
                    {"id": "fq3", "question": "True or False: You should always restart the Print Spooler service before checking if the printer is powered on.", "type": "true_false", "correct_answer": "false", "explanation": "Always check the basics first - power, connections, and obvious issues before technical solutions."},
                    {"id": "fq4", "question": "A Critical priority ticket should typically be responded to within:", "type": "multiple_choice", "options": ["15 minutes", "1 hour", "4 hours", "1 business day"], "correct_answer": "15 minutes", "explanation": "Critical issues affect the entire business and require immediate response."},
                    {"id": "fq5", "question": "When using remote support tools, you should:", "type": "multiple_select", "options": ["Always get user permission first", "Document the session", "Explore personal files if you have time", "Disconnect when finished"], "correct_answer": ["Always get user permission first", "Document the session", "Disconnect when finished"], "explanation": "Never access anything beyond what's necessary for the support issue - this is a privacy and professional boundary."}
                ],
                "passing_score": 70
            }}
        ]
    ), mod10.id)

    print(f"Created course: {course.title} with 10 modules")
    return course


def create_networking_course(db: Session, instructor_id: int) -> Course:
    """Create Networking Essentials course with 10 modules."""
    from app.plugins.courses.crud import create_module, create_section

    course_data = {
        "id": "networking-essentials",
        "title": "Networking Essentials",
        "description": "Build a solid foundation in computer networking. Learn how networks work, from home routers to enterprise infrastructure. Essential knowledge for any IT career path.",
        "short_description": "Understand how computer networks function and connect the digital world",
        "level": "beginner",
        "category": "Networking",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 25,
        "related_skills": ["networking", "tcp-ip", "subnetting", "troubleshooting", "infrastructure"],
        "xp_reward": 1200,
        "requirements": [
            "Basic computer literacy",
            "Understanding of IT Support fundamentals helpful but not required",
            "Access to a computer with internet connection"
        ],
        "objectives": [
            "Understand the OSI and TCP/IP networking models",
            "Configure IP addresses and subnet masks",
            "Identify common network devices and their functions",
            "Troubleshoot basic connectivity issues",
            "Explain how the internet works",
            "Set up and secure a home network"
        ],
    }

    course = Course(
        id=course_data["id"],
        title=course_data["title"],
        description=course_data["description"],
        short_description=course_data.get("short_description"),
        level="beginner",
        status="published",
        category=course_data.get("category"),
        instructor_id=course_data["instructor_id"],
        is_premium=False,
        price=0.0,
        estimated_hours=course_data.get("estimated_hours", 0),
        related_skills=course_data.get("related_skills", []),
        xp_reward=course_data.get("xp_reward", 0),
        requirements=course_data.get("requirements", []),
        objectives=course_data.get("objectives", []),
    )
    db.add(course)
    db.commit()
    db.refresh(course)

    # Module 1: Introduction to Networking
    mod1 = create_module(db, CourseModuleCreate(
        id="net-m1",
        title="Introduction to Networking",
        description="Discover what networks are and why they matter",
        order_index=0,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m1-s1",
        title="What is a Network?",
        order_index=0,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n1", "type": "heading", "content": {"text": "Welcome to Networking", "level": 1}},
            {"id": "n2", "type": "text", "content": {"text": "A computer network is simply two or more devices connected together to share resources and communicate. From the Wi-Fi in your home to the global internet, networks are the invisible infrastructure that connects our digital world.\n\nIn this course, you'll learn the fundamental concepts that underpin all computer networks, from the smallest home setup to enterprise data centres.", "markdown": True}},
            {"id": "n3", "type": "callout", "content": {"type": "info", "title": "Networks Are Everywhere", "message": "Every time you send an email, stream a video, or browse a website, you're using multiple networks working together seamlessly."}},
            {"id": "n4", "type": "text", "content": {"text": "### Types of Networks\n\n**LAN (Local Area Network)**\nCovers a small geographical area like a home, office, or building. High speed, low latency.\n\n**WAN (Wide Area Network)**\nSpans large geographical distances. The internet is the largest WAN. Slower than LANs.\n\n**WLAN (Wireless LAN)**\nA LAN that uses Wi-Fi instead of cables.\n\n**MAN (Metropolitan Area Network)**\nCovers a city or campus. Larger than LAN, smaller than WAN.", "markdown": True}}
        ]
    ), mod1.id)

    create_section(db, ModuleSectionCreate(
        id="net-m1-s2",
        title="Network Components",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n5", "type": "heading", "content": {"text": "Essential Network Devices", "level": 2}},
            {"id": "n6", "type": "text", "content": {"text": "### Common Network Devices\n\n**Router**\nConnects different networks together. Your home router connects your LAN to the internet (WAN). Makes routing decisions based on IP addresses.\n\n**Switch**\nConnects devices within the same network. Uses MAC addresses to forward traffic to the correct device. More efficient than a hub.\n\n**Access Point (AP)**\nProvides wireless connectivity. Bridges wireless devices to the wired network.\n\n**Modem**\nConverts signals between your ISP and your network. 'Modulates' and 'demodulates' signals.\n\n**Firewall**\nFilters network traffic based on security rules. Protects networks from unauthorised access.", "markdown": True}},
            {"id": "n7", "type": "text", "content": {"text": "### Home Network vs Enterprise\n\n| Component | Home | Enterprise |\n|-----------|------|------------|\n| Router | Combined device (router/switch/AP/modem) | Dedicated routing appliance |\n| Switch | Built into router | Managed switches (24-48 ports) |\n| Wi-Fi | Single access point | Multiple APs with controllers |\n| Firewall | Basic NAT firewall | Dedicated next-gen firewall |\n| Management | Web interface | Central management console |", "markdown": True}},
            {"id": "n8", "type": "callout", "content": {"type": "tip", "title": "Home Routers", "message": "Your typical home 'router' is actually 4-5 devices in one: router, switch, wireless access point, modem, and firewall."}}
        ]
    ), mod1.id)

    # Module 2: The OSI Model
    mod2 = create_module(db, CourseModuleCreate(
        id="net-m2",
        title="The OSI Model",
        description="Understand the seven-layer networking reference model",
        order_index=1,
        duration="60 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m2-s1",
        title="Understanding the OSI Model",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n9", "type": "heading", "content": {"text": "The Seven Layers of Networking", "level": 1}},
            {"id": "n10", "type": "text", "content": {"text": "The OSI (Open Systems Interconnection) model is a conceptual framework that describes how data moves through a network. Understanding this model helps you troubleshoot issues and communicate with other IT professionals.", "markdown": True}},
            {"id": "n11", "type": "text", "content": {"text": "### The Seven Layers (Top to Bottom)\n\n**Layer 7 - Application**\nWhat users interact with. HTTP, HTTPS, FTP, SMTP, DNS.\nExample: Your web browser.\n\n**Layer 6 - Presentation**\nData formatting and encryption. SSL/TLS, JPEG, ASCII.\nTranslates data between application and network formats.\n\n**Layer 5 - Session**\nManages connections between applications.\nEstablishes, maintains, and terminates sessions.\n\n**Layer 4 - Transport**\nEnd-to-end data delivery. TCP (reliable) and UDP (fast).\nHandles segmentation and reassembly.\n\n**Layer 3 - Network**\nRouting between networks. IP addresses, routers.\nDetermines the best path for data.\n\n**Layer 2 - Data Link**\nNode-to-node data transfer. MAC addresses, switches.\nFrames data for transmission.\n\n**Layer 1 - Physical**\nActual transmission of bits. Cables, connectors, signals.\nThe hardware layer.", "markdown": True}},
            {"id": "n12", "type": "callout", "content": {"type": "tip", "title": "Memory Trick", "message": "Remember the layers with: 'All People Seem To Need Data Processing' (from Layer 7 down) or 'Please Do Not Throw Sausage Pizza Away' (from Layer 1 up)."}}
        ]
    ), mod2.id)

    create_section(db, ModuleSectionCreate(
        id="net-m2-s2",
        title="OSI in Practice",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n13", "type": "heading", "content": {"text": "Troubleshooting with the OSI Model", "level": 2}},
            {"id": "n14", "type": "text", "content": {"text": "When troubleshooting network issues, work through the layers systematically:\n\n### Bottom-Up Approach (Recommended)\n\n**1. Physical (Layer 1)**\n- Is the cable plugged in?\n- Is there link light?\n- Is the device powered on?\n\n**2. Data Link (Layer 2)**\n- Can you see MAC addresses?\n- Is the switch functioning?\n- Are VLANs configured correctly?\n\n**3. Network (Layer 3)**\n- Is the IP address correct?\n- Can you ping the gateway?\n- Is routing working?\n\n**4. Transport (Layer 4)**\n- Is the port open?\n- Is the service listening?\n- Are firewall rules blocking?\n\n**5-7. Upper Layers**\n- Is the application configured correctly?\n- Are credentials valid?\n- Is encryption working?", "markdown": True}},
            {"id": "n15", "type": "callout", "content": {"type": "info", "title": "Real-World Usage", "message": "In daily IT work, you'll often hear 'Is this a Layer 2 or Layer 3 issue?' meaning is the problem with local switching (MAC/VLAN) or routing (IP)."}}
        ]
    ), mod2.id)

    # Module 3: IP Addressing
    mod3 = create_module(db, CourseModuleCreate(
        id="net-m3",
        title="IP Addressing",
        description="Learn how devices are identified on networks",
        order_index=2,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m3-s1",
        title="IPv4 Fundamentals",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n16", "type": "heading", "content": {"text": "Understanding IP Addresses", "level": 1}},
            {"id": "n17", "type": "text", "content": {"text": "An IP address is a unique identifier for a device on a network. Think of it like a postal address for your computer.", "markdown": True}},
            {"id": "n18", "type": "text", "content": {"text": "### IPv4 Address Format\n\nAn IPv4 address consists of four numbers (octets) separated by dots:\n\n`192.168.1.100`\n\nEach octet ranges from 0 to 255.\n\n### Public vs Private Addresses\n\n**Public IP Addresses**\n- Unique across the entire internet\n- Assigned by your ISP\n- Used to communicate with the outside world\n\n**Private IP Addresses**\n- Only unique within your local network\n- Free to use\n- Cannot be routed on the internet\n\n**Private Address Ranges:**\n- `10.0.0.0` to `10.255.255.255` (Class A)\n- `172.16.0.0` to `172.31.255.255` (Class B)\n- `192.168.0.0` to `192.168.255.255` (Class C)", "markdown": True}},
            {"id": "n19", "type": "callout", "content": {"type": "tip", "title": "Common Addresses", "message": "Your home router typically uses 192.168.0.1 or 192.168.1.1. Devices get addresses like 192.168.1.100, 192.168.1.101, etc."}}
        ]
    ), mod3.id)

    create_section(db, ModuleSectionCreate(
        id="net-m3-s2",
        title="Subnet Masks",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n20", "type": "heading", "content": {"text": "What is a Subnet Mask?", "level": 2}},
            {"id": "n21", "type": "text", "content": {"text": "A subnet mask defines which part of an IP address identifies the network and which part identifies the device (host).", "markdown": True}},
            {"id": "n22", "type": "text", "content": {"text": "### Common Subnet Masks\n\n| Mask | CIDR | Hosts | Use Case |\n|------|------|-------|----------|\n| 255.255.255.0 | /24 | 254 | Home/small office |\n| 255.255.255.128 | /25 | 126 | Small department |\n| 255.255.0.0 | /16 | 65,534 | Large organisation |\n| 255.0.0.0 | /8 | 16 million | Massive network |\n\n### How It Works\n\nFor IP: `192.168.1.100` with mask `255.255.255.0`\n\n- Network portion: `192.168.1` (where the mask is 255)\n- Host portion: `100` (where the mask is 0)\n\nDevices can communicate directly if they share the same network portion. Otherwise, traffic must go through a router.", "markdown": True}},
            {"id": "n23", "type": "callout", "content": {"type": "info", "title": "CIDR Notation", "message": "/24 means the first 24 bits are the network portion. It's a shorter way to write 255.255.255.0."}}
        ]
    ), mod3.id)

    # Module 4: TCP/IP Model
    mod4 = create_module(db, CourseModuleCreate(
        id="net-m4",
        title="TCP/IP Model and Protocols",
        description="Learn the practical networking model used on the internet",
        order_index=3,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m4-s1",
        title="TCP vs UDP",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n24", "type": "heading", "content": {"text": "Transport Layer Protocols", "level": 1}},
            {"id": "n25", "type": "text", "content": {"text": "The Transport layer uses two main protocols, each with different strengths:", "markdown": True}},
            {"id": "n26", "type": "text", "content": {"text": "### TCP (Transmission Control Protocol)\n\n**Characteristics:**\n- Connection-oriented (handshake required)\n- Reliable delivery guaranteed\n- Data arrives in order\n- Error checking and retransmission\n- Slower due to overhead\n\n**Used for:**\n- Web browsing (HTTP/HTTPS)\n- Email (SMTP, IMAP)\n- File transfers (FTP)\n- Any application where data integrity matters\n\n### UDP (User Datagram Protocol)\n\n**Characteristics:**\n- Connectionless (no handshake)\n- No guarantee of delivery\n- Data may arrive out of order\n- Minimal overhead\n- Very fast\n\n**Used for:**\n- Video streaming\n- Online gaming\n- Voice over IP (VoIP)\n- DNS queries\n- Any application where speed matters more than reliability", "markdown": True}},
            {"id": "n27", "type": "callout", "content": {"type": "tip", "title": "Analogy", "message": "TCP is like sending a recorded letter - you know it arrived. UDP is like shouting across a room - faster, but no guarantee they heard you."}}
        ]
    ), mod4.id)

    # Module 5: Common Ports and Protocols
    mod5 = create_module(db, CourseModuleCreate(
        id="net-m5",
        title="Common Ports and Protocols",
        description="Learn the standard ports used by network services",
        order_index=4,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m5-s1",
        title="Essential Port Numbers",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n28", "type": "heading", "content": {"text": "Ports and Services", "level": 1}},
            {"id": "n29", "type": "text", "content": {"text": "Ports are like doors on a computer. Each service uses a specific port number so the system knows where to send incoming traffic.", "markdown": True}},
            {"id": "n30", "type": "text", "content": {"text": "### Must-Know Port Numbers\n\n| Port | Protocol | Service |\n|------|----------|----------|\n| 20, 21 | TCP | FTP (file transfer) |\n| 22 | TCP | SSH (secure shell) |\n| 23 | TCP | Telnet (insecure) |\n| 25 | TCP | SMTP (email sending) |\n| 53 | TCP/UDP | DNS |\n| 67, 68 | UDP | DHCP |\n| 80 | TCP | HTTP (web) |\n| 110 | TCP | POP3 (email) |\n| 143 | TCP | IMAP (email) |\n| 443 | TCP | HTTPS (secure web) |\n| 445 | TCP | SMB (file sharing) |\n| 3389 | TCP | RDP (remote desktop) |\n\n### Port Ranges\n\n- **0-1023**: Well-known ports (require admin rights)\n- **1024-49151**: Registered ports (applications)\n- **49152-65535**: Dynamic/ephemeral ports (temporary)", "markdown": True}},
            {"id": "n31", "type": "callout", "content": {"type": "warning", "title": "Security Note", "message": "Ports 23 (Telnet) and 21 (FTP) send data unencrypted. Use SSH (22) and SFTP instead in production environments."}}
        ]
    ), mod5.id)

    # Module 6: DNS
    mod6 = create_module(db, CourseModuleCreate(
        id="net-m6",
        title="DNS - Domain Name System",
        description="Understand how domain names translate to IP addresses",
        order_index=5,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m6-s1",
        title="How DNS Works",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n32", "type": "heading", "content": {"text": "The Phone Book of the Internet", "level": 1}},
            {"id": "n33", "type": "text", "content": {"text": "DNS (Domain Name System) translates human-readable domain names like `google.com` into IP addresses like `142.250.180.14`. Without DNS, you'd need to remember IP addresses for every website.", "markdown": True}},
            {"id": "n34", "type": "text", "content": {"text": "### DNS Lookup Process\n\n1. **Browser Cache** - Check if we've looked this up recently\n2. **OS Cache** - Check the local computer's cache\n3. **Hosts File** - Check local overrides\n4. **Recursive Resolver** - Ask your ISP's DNS server\n5. **Root Servers** - If resolver doesn't know, ask root\n6. **TLD Servers** - Root points to .com, .org, etc.\n7. **Authoritative Server** - Finally gets the answer\n8. **Response** - IP address returned and cached\n\n### DNS Record Types\n\n- **A Record**: Maps domain to IPv4 address\n- **AAAA Record**: Maps domain to IPv6 address\n- **CNAME**: Alias pointing to another domain\n- **MX Record**: Mail server for the domain\n- **TXT Record**: Text information (often for verification)", "markdown": True}},
            {"id": "n35", "type": "callout", "content": {"type": "tip", "title": "Testing DNS", "message": "Use `nslookup domain.com` or `dig domain.com` to query DNS records manually."}}
        ]
    ), mod6.id)

    # Module 7: DHCP
    mod7 = create_module(db, CourseModuleCreate(
        id="net-m7",
        title="DHCP - Dynamic Configuration",
        description="Learn how devices automatically receive network settings",
        order_index=6,
        duration="35 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m7-s1",
        title="DHCP Explained",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n36", "type": "heading", "content": {"text": "Automatic IP Assignment", "level": 1}},
            {"id": "n37", "type": "text", "content": {"text": "DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses and other network settings to devices. Without DHCP, you'd need to manually configure every device.", "markdown": True}},
            {"id": "n38", "type": "text", "content": {"text": "### The DORA Process\n\n**D - Discover**\nClient broadcasts: 'Is there a DHCP server out there?'\n\n**O - Offer**\nServer responds: 'Yes! Here's an IP address you can use.'\n\n**R - Request**\nClient replies: 'Thanks, I'll take that one please.'\n\n**A - Acknowledge**\nServer confirms: 'It's yours. Here are your settings.'\n\n### What DHCP Provides\n\n- IP address\n- Subnet mask\n- Default gateway (router)\n- DNS server addresses\n- Lease duration (how long to keep the address)\n- Optional: NTP server, domain name, etc.", "markdown": True}},
            {"id": "n39", "type": "callout", "content": {"type": "info", "title": "DHCP Leases", "message": "IP addresses are 'leased' for a period (often 24 hours). Devices must renew their lease or get a new address."}}
        ]
    ), mod7.id)

    # Module 8: Network Troubleshooting
    mod8 = create_module(db, CourseModuleCreate(
        id="net-m8",
        title="Network Troubleshooting",
        description="Master essential network diagnostic techniques",
        order_index=7,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m8-s1",
        title="Diagnostic Commands",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n40", "type": "heading", "content": {"text": "Essential Network Commands", "level": 1}},
            {"id": "n41", "type": "text", "content": {"text": "These commands are your toolkit for diagnosing network issues:", "markdown": True}},
            {"id": "n42", "type": "text", "content": {"text": "### Windows Commands\n\n**ipconfig**\nView IP configuration. Use `ipconfig /all` for detailed info.\n`ipconfig /release` and `ipconfig /renew` to get new DHCP address.\n\n**ping**\nTest connectivity to a host. `ping 8.8.8.8` tests internet.\n`ping localhost` tests local TCP/IP stack.\n\n**tracert**\nShows the path packets take to reach a destination.\nIdentifies where in the network a problem occurs.\n\n**nslookup**\nQuery DNS servers. `nslookup google.com` to test DNS.\n\n**netstat**\nShows active connections and listening ports.\n`netstat -an` shows all connections with numbers.\n\n### Linux/Mac Equivalents\n\n- `ifconfig` or `ip addr` (instead of ipconfig)\n- `ping` (same)\n- `traceroute` (instead of tracert)\n- `dig` or `nslookup` (for DNS)\n- `netstat` or `ss` (for connections)", "markdown": True}},
            {"id": "n43", "type": "callout", "content": {"type": "tip", "title": "Quick Test", "message": "If you can ping 8.8.8.8 but not google.com, your internet works but DNS is broken."}}
        ]
    ), mod8.id)

    # Module 9: Wireless Networking
    mod9 = create_module(db, CourseModuleCreate(
        id="net-m9",
        title="Wireless Networking",
        description="Understand Wi-Fi standards and configuration",
        order_index=8,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m9-s1",
        title="Wi-Fi Standards",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n44", "type": "heading", "content": {"text": "Understanding Wireless Standards", "level": 1}},
            {"id": "n45", "type": "text", "content": {"text": "Wi-Fi has evolved through multiple generations, each bringing faster speeds and better reliability.", "markdown": True}},
            {"id": "n46", "type": "text", "content": {"text": "### Wi-Fi Generations\n\n| Generation | Standard | Frequency | Max Speed |\n|------------|----------|-----------|------------|\n| Wi-Fi 4 | 802.11n | 2.4/5 GHz | 600 Mbps |\n| Wi-Fi 5 | 802.11ac | 5 GHz | 3.5 Gbps |\n| Wi-Fi 6 | 802.11ax | 2.4/5/6 GHz | 9.6 Gbps |\n| Wi-Fi 6E | 802.11ax | 6 GHz | 9.6 Gbps |\n\n### Frequency Bands\n\n**2.4 GHz**\n- Better range and wall penetration\n- More interference (microwaves, Bluetooth, neighbours)\n- Fewer channels (only 3 non-overlapping)\n- Slower speeds\n\n**5 GHz**\n- Faster speeds\n- Less interference\n- More channels\n- Shorter range, worse through walls", "markdown": True}},
            {"id": "n47", "type": "callout", "content": {"type": "tip", "title": "Channel Selection", "message": "On 2.4 GHz, use channels 1, 6, or 11 only. Other channels overlap and cause interference."}}
        ]
    ), mod9.id)

    create_section(db, ModuleSectionCreate(
        id="net-m9-s2",
        title="Wi-Fi Security",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n48", "type": "heading", "content": {"text": "Securing Wireless Networks", "level": 2}},
            {"id": "n49", "type": "text", "content": {"text": "### Wireless Security Standards\n\n**WEP (Wired Equivalent Privacy)**\nOld and broken. Never use. Can be cracked in minutes.\n\n**WPA (Wi-Fi Protected Access)**\nBetter than WEP but has vulnerabilities. Avoid if possible.\n\n**WPA2**\nCurrent standard. Uses AES encryption. Secure when properly configured.\n\n**WPA3**\nLatest standard. Stronger encryption, protection against brute force.\n\n### Best Practices\n\n- Use WPA2 or WPA3 only\n- Strong password (12+ characters)\n- Change default admin credentials\n- Update router firmware regularly\n- Disable WPS (has vulnerabilities)\n- Consider guest networks for visitors", "markdown": True}},
            {"id": "n50", "type": "callout", "content": {"type": "warning", "title": "Security Alert", "message": "If you see a network using WEP, it's extremely vulnerable. Upgrade to WPA2 immediately."}}
        ]
    ), mod9.id)

    # Module 10: Network Security Basics
    mod10 = create_module(db, CourseModuleCreate(
        id="net-m10",
        title="Network Security Fundamentals",
        description="Learn essential security concepts for network protection",
        order_index=9,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="net-m10-s1",
        title="Firewalls and Security",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n51", "type": "heading", "content": {"text": "Network Security Essentials", "level": 1}},
            {"id": "n52", "type": "text", "content": {"text": "Network security protects your systems and data from unauthorised access, attacks, and data breaches.", "markdown": True}},
            {"id": "n53", "type": "text", "content": {"text": "### Firewall Types\n\n**Packet Filtering**\nBasic firewall. Examines packet headers (IP, port) and allows/blocks based on rules.\n\n**Stateful Inspection**\nTracks connection state. More intelligent than packet filtering.\n\n**Application Layer (Proxy)**\nInspects actual content. Can block specific applications or content types.\n\n**Next-Generation (NGFW)**\nCombines all above plus intrusion prevention, deep packet inspection, and threat intelligence.\n\n### Common Security Measures\n\n- **NAT (Network Address Translation)**: Hides internal IP addresses\n- **VPN (Virtual Private Network)**: Encrypted tunnel for remote access\n- **IDS/IPS**: Intrusion Detection/Prevention Systems\n- **Network Segmentation**: Separating sensitive systems\n- **Access Control Lists (ACLs)**: Rules for allowing/denying traffic", "markdown": True}}
        ]
    ), mod10.id)

    create_section(db, ModuleSectionCreate(
        id="net-m10-s2",
        title="Final Assessment",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "n54", "type": "heading", "content": {"text": "Networking Essentials Assessment", "level": 1}},
            {"id": "n55", "type": "quiz", "content": {
                "questions": [
                    {"id": "nq1", "question": "Which OSI layer handles IP addressing and routing?", "type": "multiple_choice", "options": ["Layer 2 - Data Link", "Layer 3 - Network", "Layer 4 - Transport", "Layer 7 - Application"], "correct_answer": "Layer 3 - Network", "explanation": "The Network layer (Layer 3) handles IP addresses and routing decisions."},
                    {"id": "nq2", "question": "Which protocol provides reliable, ordered delivery?", "type": "multiple_choice", "options": ["UDP", "TCP", "ICMP", "ARP"], "correct_answer": "TCP", "explanation": "TCP (Transmission Control Protocol) guarantees reliable, ordered delivery through acknowledgments and retransmissions."},
                    {"id": "nq3", "question": "What port does HTTPS use by default?", "type": "multiple_choice", "options": ["80", "22", "443", "8080"], "correct_answer": "443", "explanation": "HTTPS uses port 443. HTTP (unencrypted) uses port 80."},
                    {"id": "nq4", "question": "What does DHCP stand for?", "type": "multiple_choice", "options": ["Dynamic Host Configuration Protocol", "Domain Host Control Protocol", "Dynamic Hypertext Configuration Protocol", "Domain Host Configuration Process"], "correct_answer": "Dynamic Host Configuration Protocol", "explanation": "DHCP automatically assigns IP addresses and network configuration to devices."},
                    {"id": "nq5", "question": "Which wireless security standard should you avoid using?", "type": "multiple_choice", "options": ["WPA3", "WPA2", "WEP", "WPA2-Enterprise"], "correct_answer": "WEP", "explanation": "WEP is severely broken and can be cracked within minutes. Always use WPA2 or WPA3."}
                ],
                "passing_score": 70
            }}
        ]
    ), mod10.id)

    print(f"Created course: {course.title} with 10 modules")
    return course


def create_windows_course(db: Session, instructor_id: int) -> Course:
    """Create Windows Basics for IT course with 10 modules."""
    from app.plugins.courses.crud import create_module, create_section

    course_data = {
        "id": "windows-basics-it",
        "title": "Windows for IT Professionals",
        "description": "Master Windows administration for IT support roles. From basic navigation to advanced troubleshooting, learn to configure, maintain, and secure Windows systems in a professional environment.",
        "short_description": "Essential Windows skills for IT support and administration",
        "level": "beginner",
        "category": "Operating Systems",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 22,
        "related_skills": ["windows", "operating-systems", "administration", "troubleshooting", "security"],
        "xp_reward": 1100,
        "requirements": [
            "Access to a Windows 10 or 11 computer",
            "Basic IT Support knowledge helpful",
            "Willingness to explore system settings"
        ],
        "objectives": [
            "Navigate Windows efficiently as an IT professional",
            "Configure system settings and user accounts",
            "Troubleshoot common Windows issues",
            "Use Command Prompt and PowerShell basics",
            "Manage Windows services and processes",
            "Implement basic security configurations"
        ],
    }

    course = Course(
        id=course_data["id"],
        title=course_data["title"],
        description=course_data["description"],
        short_description=course_data.get("short_description"),
        level="beginner",
        status="published",
        category=course_data.get("category"),
        instructor_id=course_data["instructor_id"],
        is_premium=False,
        price=0.0,
        estimated_hours=course_data.get("estimated_hours", 0),
        related_skills=course_data.get("related_skills", []),
        xp_reward=course_data.get("xp_reward", 0),
        requirements=course_data.get("requirements", []),
        objectives=course_data.get("objectives", []),
    )
    db.add(course)
    db.commit()
    db.refresh(course)

    # Module 1: Windows Overview
    mod1 = create_module(db, CourseModuleCreate(
        id="win-m1",
        title="Windows for IT Professionals",
        description="Understand Windows from an IT support perspective",
        order_index=0,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m1-s1",
        title="Windows in the Enterprise",
        order_index=0,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w1", "type": "heading", "content": {"text": "Why Windows Matters in IT", "level": 1}},
            {"id": "w2", "type": "text", "content": {"text": "Microsoft Windows dominates the enterprise desktop market. As an IT professional, you'll spend a significant portion of your time supporting, configuring, and troubleshooting Windows systems.\n\nThis course focuses on Windows 10 and 11, the versions you'll encounter most frequently in business environments.", "markdown": True}},
            {"id": "w3", "type": "text", "content": {"text": "### Windows Editions\n\n**Windows Home**\n- Consumer edition\n- Limited management features\n- No domain join capability\n- Basic security features\n\n**Windows Pro**\n- Business edition\n- Domain join capable\n- BitLocker encryption\n- Remote Desktop host\n- Group Policy support\n\n**Windows Enterprise**\n- Large organisation edition\n- All Pro features plus:\n- Advanced security features\n- Long-term servicing options\n- AppLocker, DirectAccess", "markdown": True}},
            {"id": "w4", "type": "callout", "content": {"type": "info", "title": "Business Standard", "message": "Most businesses use Windows Pro or Enterprise. Home edition lacks critical features like domain joining and BitLocker."}}
        ]
    ), mod1.id)

    create_section(db, ModuleSectionCreate(
        id="win-m1-s2",
        title="Essential Navigation",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w5", "type": "heading", "content": {"text": "Navigating Windows Efficiently", "level": 2}},
            {"id": "w6", "type": "text", "content": {"text": "### Essential Keyboard Shortcuts\n\n| Shortcut | Action |\n|----------|--------|\n| Win + E | Open File Explorer |\n| Win + I | Open Settings |\n| Win + R | Open Run dialog |\n| Win + X | Power User menu |\n| Win + Pause | System Properties |\n| Ctrl + Shift + Esc | Task Manager |\n| Win + L | Lock computer |\n| Alt + Tab | Switch applications |\n| Win + Tab | Task View |\n\n### Quick Access Locations\n\n- `C:\\Windows` - OS files\n- `C:\\Program Files` - 64-bit applications\n- `C:\\Program Files (x86)` - 32-bit applications\n- `C:\\Users\\[username]` - User profile\n- `%AppData%` - User application data", "markdown": True}},
            {"id": "w7", "type": "callout", "content": {"type": "tip", "title": "Power User Menu", "message": "Win + X (or right-click Start) gives quick access to Device Manager, Disk Management, Event Viewer, and more."}}
        ]
    ), mod1.id)

    # Module 2: Control Panel and Settings
    mod2 = create_module(db, CourseModuleCreate(
        id="win-m2",
        title="System Configuration",
        description="Master Control Panel and Settings",
        order_index=1,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m2-s1",
        title="Settings vs Control Panel",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w8", "type": "heading", "content": {"text": "Configuring Windows", "level": 1}},
            {"id": "w9", "type": "text", "content": {"text": "Windows has two configuration interfaces: the modern **Settings** app and the legacy **Control Panel**. IT professionals need to know both.", "markdown": True}},
            {"id": "w10", "type": "text", "content": {"text": "### Settings App (Modern)\n\nAccess: Win + I or Start > Settings\n\n- System (display, notifications, power)\n- Devices (Bluetooth, printers)\n- Network & Internet\n- Personalisation\n- Apps\n- Accounts\n- Time & Language\n- Privacy & Security\n- Windows Update\n\n### Control Panel (Legacy)\n\nAccess: Win + R, type `control`\n\n- More detailed options\n- Some features only here\n- Being phased out gradually\n- Still essential for IT work\n\n**Control Panel exclusives:**\n- Advanced user account settings\n- Credential Manager\n- Administrative Tools\n- Some device configurations", "markdown": True}},
            {"id": "w11", "type": "callout", "content": {"type": "tip", "title": "Quick Access", "message": "Type the setting you need in the Start menu search. Windows will find it whether it's in Settings or Control Panel."}}
        ]
    ), mod2.id)

    create_section(db, ModuleSectionCreate(
        id="win-m2-s2",
        title="Administrative Tools",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w12", "type": "heading", "content": {"text": "Essential Admin Tools", "level": 2}},
            {"id": "w13", "type": "text", "content": {"text": "### Key Administrative Tools\n\n**Computer Management** (compmgmt.msc)\nAll-in-one console for system administration:\n- Disk Management\n- Device Manager\n- Services\n- Event Viewer\n- Local Users and Groups\n\n**Device Manager** (devmgmt.msc)\nManage hardware devices and drivers:\n- View all installed devices\n- Update/rollback drivers\n- Disable problematic devices\n- Check for hardware errors\n\n**Services** (services.msc)\nControl background services:\n- Start/stop services\n- Change startup type\n- View dependencies\n- Troubleshoot service failures\n\n**Event Viewer** (eventvwr.msc)\nView system logs:\n- Application errors\n- Security events\n- System warnings\n- Critical failures", "markdown": True}},
            {"id": "w14", "type": "callout", "content": {"type": "info", "title": "MSC Files", "message": "The .msc files are Microsoft Management Console snap-ins. You can run them directly from Run (Win + R)."}}
        ]
    ), mod2.id)

    # Module 3: User Account Management
    mod3 = create_module(db, CourseModuleCreate(
        id="win-m3",
        title="User Account Management",
        description="Create and manage Windows user accounts",
        order_index=2,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m3-s1",
        title="Local User Accounts",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w15", "type": "heading", "content": {"text": "Managing User Accounts", "level": 1}},
            {"id": "w16", "type": "text", "content": {"text": "User accounts control who can access the computer and what they can do.", "markdown": True}},
            {"id": "w17", "type": "text", "content": {"text": "### Account Types\n\n**Administrator**\n- Full system access\n- Can install software\n- Can change system settings\n- Can manage other accounts\n\n**Standard User**\n- Limited access\n- Can run installed applications\n- Cannot install system-wide software\n- Cannot change system settings\n\n**Guest**\n- Temporary access\n- Very limited permissions\n- Disabled by default\n\n### Creating Local Accounts\n\n**Via Settings:**\n1. Settings > Accounts > Other users\n2. Add someone else to this PC\n3. Choose 'I don't have this person's sign-in info'\n4. Add a user without a Microsoft account\n\n**Via Computer Management:**\n1. Computer Management > Local Users and Groups\n2. Right-click Users > New User\n3. Set username, password, options", "markdown": True}},
            {"id": "w18", "type": "callout", "content": {"type": "warning", "title": "Least Privilege", "message": "Always give users Standard accounts. Only use Administrator when absolutely necessary to reduce security risks."}}
        ]
    ), mod3.id)

    # Module 4: File System and Permissions
    mod4 = create_module(db, CourseModuleCreate(
        id="win-m4",
        title="File System and Permissions",
        description="Understand NTFS and file permissions",
        order_index=3,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m4-s1",
        title="NTFS File System",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w19", "type": "heading", "content": {"text": "Understanding NTFS", "level": 1}},
            {"id": "w20", "type": "text", "content": {"text": "NTFS (New Technology File System) is the standard file system for Windows. Understanding it is essential for IT support.", "markdown": True}},
            {"id": "w21", "type": "text", "content": {"text": "### NTFS Features\n\n- **File permissions** - Control who can access files\n- **Encryption (EFS)** - Encrypt individual files/folders\n- **Compression** - Compress to save space\n- **Disk quotas** - Limit user storage\n- **Shadow copies** - Previous versions of files\n- **Journaling** - Protection against corruption\n\n### NTFS Permissions\n\n| Permission | Allows |\n|------------|--------|\n| Full Control | Everything |\n| Modify | Read, write, delete |\n| Read & Execute | View and run |\n| List Folder Contents | See folder contents |\n| Read | View only |\n| Write | Create/modify |\n\n### Permission Inheritance\n\nBy default, folders inherit permissions from parent folders. You can:\n- Let permissions inherit automatically\n- Break inheritance and set explicit permissions\n- Copy inherited permissions then modify them", "markdown": True}},
            {"id": "w22", "type": "callout", "content": {"type": "tip", "title": "Effective Permissions", "message": "Use the 'Effective Access' tab in Advanced Security settings to see what a user can actually do after all permissions are calculated."}}
        ]
    ), mod4.id)

    # Module 5: Task Manager and Processes
    mod5 = create_module(db, CourseModuleCreate(
        id="win-m5",
        title="Task Manager and Processes",
        description="Monitor and manage system processes",
        order_index=4,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m5-s1",
        title="Using Task Manager",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w23", "type": "heading", "content": {"text": "Task Manager Deep Dive", "level": 1}},
            {"id": "w24", "type": "text", "content": {"text": "Task Manager is your primary tool for monitoring system performance and managing processes. Access it with Ctrl + Shift + Esc.", "markdown": True}},
            {"id": "w25", "type": "text", "content": {"text": "### Task Manager Tabs\n\n**Processes**\nLists all running applications and background processes.\n- CPU, Memory, Disk, Network usage per process\n- End unresponsive tasks\n- Right-click for more options\n\n**Performance**\nReal-time graphs showing:\n- CPU usage and speed\n- Memory usage\n- Disk activity\n- Network throughput\n- GPU usage\n\n**App History**\nResource usage over time for UWP apps.\n\n**Startup**\nPrograms that run at login.\n- Enable/disable startup items\n- See startup impact\n\n**Users**\nWho's logged in and their resource usage.\n\n**Details**\nAdvanced process information.\n- Set process priority\n- Set processor affinity\n- View command line\n\n**Services**\nBackground services status.\n- Start/stop services\n- Quick access to Services console", "markdown": True}},
            {"id": "w26", "type": "callout", "content": {"type": "tip", "title": "More Details", "message": "Click 'More details' at the bottom of Task Manager to see the full interface with all tabs."}}
        ]
    ), mod5.id)

    # Module 6: Command Line Basics
    mod6 = create_module(db, CourseModuleCreate(
        id="win-m6",
        title="Command Line Essentials",
        description="Learn Command Prompt and PowerShell basics",
        order_index=5,
        duration="60 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m6-s1",
        title="Command Prompt",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w27", "type": "heading", "content": {"text": "Command Prompt Essentials", "level": 1}},
            {"id": "w28", "type": "text", "content": {"text": "The Command Prompt (cmd.exe) is a powerful tool for IT professionals. Many tasks are faster or only possible via command line.", "markdown": True}},
            {"id": "w29", "type": "text", "content": {"text": "### Essential Commands\n\n**Navigation:**\n- `cd [path]` - Change directory\n- `dir` - List directory contents\n- `cls` - Clear screen\n- `exit` - Close window\n\n**File Operations:**\n- `copy [source] [dest]` - Copy files\n- `move [source] [dest]` - Move files\n- `del [file]` - Delete files\n- `mkdir [name]` - Create directory\n- `rmdir [name]` - Remove directory\n\n**System Information:**\n- `systeminfo` - Detailed system info\n- `hostname` - Computer name\n- `whoami` - Current user\n- `ver` - Windows version\n\n**Network:**\n- `ipconfig` - IP configuration\n- `ping [host]` - Test connectivity\n- `netstat` - Network connections\n- `nslookup [domain]` - DNS lookup\n\n**Useful Utilities:**\n- `sfc /scannow` - Check system files\n- `chkdsk` - Check disk for errors\n- `shutdown /r /t 0` - Restart immediately", "markdown": True}},
            {"id": "w30", "type": "callout", "content": {"type": "tip", "title": "Run as Administrator", "message": "Right-click Command Prompt and choose 'Run as administrator' for commands that need elevated privileges."}}
        ]
    ), mod6.id)

    create_section(db, ModuleSectionCreate(
        id="win-m6-s2",
        title="PowerShell Introduction",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w31", "type": "heading", "content": {"text": "Getting Started with PowerShell", "level": 2}},
            {"id": "w32", "type": "text", "content": {"text": "PowerShell is a more powerful successor to Command Prompt. It uses cmdlets (command-lets) with a Verb-Noun naming convention.", "markdown": True}},
            {"id": "w33", "type": "text", "content": {"text": "### Basic PowerShell Commands\n\n| Cmdlet | Alias | Purpose |\n|--------|-------|----------|\n| Get-ChildItem | dir, ls | List files |\n| Set-Location | cd | Change directory |\n| Get-Content | cat, type | Read file contents |\n| Get-Process | ps | List processes |\n| Get-Service | - | List services |\n| Stop-Process | kill | End a process |\n| Clear-Host | cls, clear | Clear screen |\n\n### Useful PowerShell Examples\n\n```powershell\n# Get all running services\nGet-Service | Where-Object {$_.Status -eq 'Running'}\n\n# Get top 10 CPU-using processes\nGet-Process | Sort-Object CPU -Descending | Select-Object -First 10\n\n# Find large files\nGet-ChildItem -Recurse | Where-Object {$_.Length -gt 100MB}\n\n# Get help on any cmdlet\nGet-Help Get-Process -Full\n```", "markdown": True}},
            {"id": "w34", "type": "callout", "content": {"type": "info", "title": "PowerShell vs CMD", "message": "PowerShell can run CMD commands, but CMD cannot run PowerShell cmdlets. PowerShell is the future of Windows administration."}}
        ]
    ), mod6.id)

    # Module 7: Windows Updates
    mod7 = create_module(db, CourseModuleCreate(
        id="win-m7",
        title="Windows Updates",
        description="Manage and troubleshoot Windows Update",
        order_index=6,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m7-s1",
        title="Managing Updates",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w35", "type": "heading", "content": {"text": "Windows Update Management", "level": 1}},
            {"id": "w36", "type": "text", "content": {"text": "Keeping Windows updated is critical for security. Understanding how to manage updates is essential for IT support.", "markdown": True}},
            {"id": "w37", "type": "text", "content": {"text": "### Update Types\n\n**Quality Updates**\nMonthly security and bug fixes. Released on 'Patch Tuesday' (second Tuesday of each month).\n\n**Feature Updates**\nMajor Windows versions (e.g., 21H2, 22H2). Released once or twice per year.\n\n**Driver Updates**\nHardware driver updates. Optional, may cause issues.\n\n### Managing Updates\n\n**Access:** Settings > Update & Security > Windows Update\n\n**Options:**\n- Pause updates (up to 35 days)\n- View update history\n- Uninstall recent updates\n- Check for updates manually\n- Set active hours (avoid restart during work)\n\n### Business Environments\n\nEnterprises often use:\n- **WSUS** - Windows Server Update Services\n- **Intune** - Cloud-based management\n- **Group Policy** - Delay updates, control timing\n- **Windows Update for Business** - Defer updates", "markdown": True}},
            {"id": "w38", "type": "callout", "content": {"type": "warning", "title": "Update Caution", "message": "Always test updates before widespread deployment. Some updates can cause issues with specific hardware or software."}}
        ]
    ), mod7.id)

    # Module 8: Windows Security
    mod8 = create_module(db, CourseModuleCreate(
        id="win-m8",
        title="Windows Security",
        description="Configure Windows security features",
        order_index=7,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m8-s1",
        title="Windows Security Centre",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w39", "type": "heading", "content": {"text": "Windows Security Features", "level": 1}},
            {"id": "w40", "type": "text", "content": {"text": "Windows includes comprehensive security features through Windows Security (formerly Windows Defender Security Center).", "markdown": True}},
            {"id": "w41", "type": "text", "content": {"text": "### Windows Security Areas\n\n**Virus & Threat Protection**\n- Real-time antivirus protection\n- Scan options (Quick, Full, Custom)\n- Protection history\n- Ransomware protection (Controlled folder access)\n\n**Account Protection**\n- Windows Hello (biometric sign-in)\n- Dynamic lock (auto-lock when you leave)\n\n**Firewall & Network Protection**\n- Windows Firewall settings\n- Domain, Private, Public network profiles\n- Inbound/Outbound rules\n\n**App & Browser Control**\n- SmartScreen protection\n- Exploit protection settings\n\n**Device Security**\n- Core isolation (hardware security)\n- Secure boot status\n- TPM information\n\n**Device Performance & Health**\n- Health report\n- Fresh start (reset Windows)", "markdown": True}},
            {"id": "w42", "type": "callout", "content": {"type": "tip", "title": "Enterprise Antivirus", "message": "Many businesses use third-party antivirus solutions. When installed, they typically disable Windows Defender automatically."}}
        ]
    ), mod8.id)

    create_section(db, ModuleSectionCreate(
        id="win-m8-s2",
        title="User Account Control",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w43", "type": "heading", "content": {"text": "Understanding UAC", "level": 2}},
            {"id": "w44", "type": "text", "content": {"text": "User Account Control (UAC) protects against unauthorised system changes by requiring confirmation for administrative actions.", "markdown": True}},
            {"id": "w45", "type": "text", "content": {"text": "### UAC Levels\n\n**Always Notify**\nMost secure. Prompts for all system changes and app installations.\n\n**Notify When Apps Make Changes (Default)**\nPrompts when applications try to make changes. Not when you make changes.\n\n**Notify When Apps Make Changes (No Dim)**\nSame as above but doesn't dim the desktop.\n\n**Never Notify**\nUAC disabled. Not recommended - security risk.\n\n### Why UAC Matters\n\n- Prevents malware from silently installing\n- Stops accidental system changes\n- Ensures user consent for admin actions\n- Provides audit trail of elevated actions\n\n### Managing UAC\n\nAccess: Control Panel > User Accounts > Change User Account Control settings\n\nOr: Search 'UAC' in Start menu", "markdown": True}},
            {"id": "w46", "type": "callout", "content": {"type": "warning", "title": "Don't Disable UAC", "message": "Never disable UAC to 'avoid annoying prompts'. It's a critical security feature. Instead, investigate why so many prompts are appearing."}}
        ]
    ), mod8.id)

    # Module 9: Troubleshooting Windows
    mod9 = create_module(db, CourseModuleCreate(
        id="win-m9",
        title="Troubleshooting Windows",
        description="Diagnose and fix common Windows problems",
        order_index=8,
        duration="60 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m9-s1",
        title="Boot Problems",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w47", "type": "heading", "content": {"text": "Windows Boot Issues", "level": 1}},
            {"id": "w48", "type": "text", "content": {"text": "When Windows won't start properly, you need to access recovery options and troubleshooting tools.", "markdown": True}},
            {"id": "w49", "type": "text", "content": {"text": "### Accessing Recovery Options\n\n**Method 1: Interrupt Boot**\nTurn off during boot 3 times. Windows will enter recovery.\n\n**Method 2: Settings**\nSettings > Update & Security > Recovery > Advanced startup\n\n**Method 3: Shift + Restart**\nHold Shift while clicking Restart\n\n### Recovery Options\n\n**Safe Mode**\nLoads minimal drivers. Use for troubleshooting.\n- Safe Mode: Basic safe mode\n- Safe Mode with Networking: Includes network drivers\n- Safe Mode with Command Prompt: No GUI\n\n**System Restore**\nRevert to a previous restore point. Doesn't affect personal files.\n\n**Startup Repair**\nAutomatically fixes boot problems.\n\n**Command Prompt**\nManual repair commands:\n- `bootrec /fixmbr` - Repair Master Boot Record\n- `bootrec /fixboot` - Write new boot sector\n- `bootrec /rebuildbcd` - Rebuild boot configuration\n\n**Reset This PC**\nRe-install Windows. Can keep or remove files.", "markdown": True}},
            {"id": "w50", "type": "callout", "content": {"type": "tip", "title": "Bootable USB", "message": "Create a Windows installation USB using the Media Creation Tool. Essential for recovery when Windows won't boot at all."}}
        ]
    ), mod9.id)

    create_section(db, ModuleSectionCreate(
        id="win-m9-s2",
        title="Event Viewer",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w51", "type": "heading", "content": {"text": "Using Event Viewer", "level": 2}},
            {"id": "w52", "type": "text", "content": {"text": "Event Viewer records everything that happens on your Windows system. It's invaluable for troubleshooting.", "markdown": True}},
            {"id": "w53", "type": "text", "content": {"text": "### Key Event Logs\n\n**Application**\nEvents from applications. Look here for software crashes.\n\n**Security**\nLogin attempts, permission changes, audit events.\n\n**System**\nDriver issues, service failures, Windows components.\n\n**Setup**\nInstallation events for Windows components.\n\n### Event Levels\n\n| Level | Meaning |\n|-------|----------|\n| Critical | Serious failure occurred |\n| Error | Significant problem |\n| Warning | Potential issue |\n| Information | Normal operation logged |\n| Verbose | Detailed debugging info |\n\n### Investigating Events\n\n1. Note the timestamp of the problem\n2. Find events around that time\n3. Look at Error and Critical events first\n4. Check the Event ID and Source\n5. Google the Event ID for solutions", "markdown": True}},
            {"id": "w54", "type": "callout", "content": {"type": "tip", "title": "Event ID Search", "message": "When you find an error, search 'Event ID [number] [source]' for specific solutions and explanations."}}
        ]
    ), mod9.id)

    # Module 10: System Maintenance
    mod10 = create_module(db, CourseModuleCreate(
        id="win-m10",
        title="System Maintenance",
        description="Keep Windows running smoothly",
        order_index=9,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="win-m10-s1",
        title="Maintenance Tasks",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w55", "type": "heading", "content": {"text": "Keeping Windows Healthy", "level": 1}},
            {"id": "w56", "type": "text", "content": {"text": "Regular maintenance keeps Windows running smoothly and prevents issues before they occur.", "markdown": True}},
            {"id": "w57", "type": "text", "content": {"text": "### Regular Maintenance Tasks\n\n**Disk Cleanup**\nRemove temporary files, old Windows installations, and system cache.\n- Run: Search 'Disk Cleanup'\n- Or: Storage Sense in Settings > System > Storage\n\n**Storage Sense**\nAutomatic cleanup of temporary files.\n- Configure frequency\n- Auto-delete Downloads folder items\n- Clean recycle bin automatically\n\n**Defragmentation**\nOptimise HDDs (not needed for SSDs - Windows handles automatically).\n- Settings > System > Storage > Optimize drives\n- Runs automatically on schedule\n\n**System File Check**\nRepair corrupted Windows files:\n```\nsfc /scannow\nDISM /Online /Cleanup-Image /RestoreHealth\n```\n\n**Driver Updates**\nKeep drivers current but be cautious:\n- Use Windows Update for stable drivers\n- Get latest from manufacturer for issues\n- Create restore point before updating", "markdown": True}},
            {"id": "w58", "type": "callout", "content": {"type": "info", "title": "Automatic Maintenance", "message": "Windows performs many maintenance tasks automatically during idle time. Ensure your PC is on and idle occasionally."}}
        ]
    ), mod10.id)

    create_section(db, ModuleSectionCreate(
        id="win-m10-s2",
        title="Final Assessment",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "w59", "type": "heading", "content": {"text": "Windows for IT Assessment", "level": 1}},
            {"id": "w60", "type": "quiz", "content": {
                "questions": [
                    {"id": "wq1", "question": "Which Windows edition supports joining an Active Directory domain?", "type": "multiple_choice", "options": ["Windows Home", "Windows Pro", "All editions", "None - requires Server"], "correct_answer": "Windows Pro", "explanation": "Windows Pro and Enterprise can join domains. Windows Home cannot."},
                    {"id": "wq2", "question": "What keyboard shortcut opens Task Manager directly?", "type": "multiple_choice", "options": ["Ctrl + Alt + Delete", "Ctrl + Shift + Esc", "Win + X", "Alt + F4"], "correct_answer": "Ctrl + Shift + Esc", "explanation": "Ctrl + Shift + Esc opens Task Manager directly. Ctrl + Alt + Delete shows a menu."},
                    {"id": "wq3", "question": "Which command checks Windows system files for corruption?", "type": "multiple_choice", "options": ["chkdsk", "sfc /scannow", "diskpart", "format"], "correct_answer": "sfc /scannow", "explanation": "SFC (System File Checker) scans and repairs Windows system files."},
                    {"id": "wq4", "question": "What UAC setting is recommended for security?", "type": "multiple_choice", "options": ["Never Notify", "Notify only when apps make changes (default)", "Always Notify", "UAC should be disabled"], "correct_answer": "Notify only when apps make changes (default)", "explanation": "The default setting provides good security without excessive prompts."},
                    {"id": "wq5", "question": "Where would you look to investigate why an application crashed?", "type": "multiple_choice", "options": ["Task Manager", "Device Manager", "Event Viewer - Application log", "Windows Update"], "correct_answer": "Event Viewer - Application log", "explanation": "The Application log in Event Viewer records application crashes and errors."}
                ],
                "passing_score": 70
            }}
        ]
    ), mod10.id)

    print(f"Created course: {course.title} with 10 modules")
    return course


def create_cybersecurity_course(db: Session, instructor_id: int) -> Course:
    """Create Introduction to Cybersecurity course with 10 modules."""
    from app.plugins.courses.crud import create_module, create_section

    course_data = {
        "id": "intro-cybersecurity",
        "title": "Introduction to Cybersecurity",
        "description": "Begin your cybersecurity journey with essential security concepts. Learn about threats, defences, and best practices that protect organisations from cyber attacks. Foundation knowledge for any security-focused IT career.",
        "short_description": "Essential security concepts and practices for IT professionals",
        "level": "beginner",
        "category": "Cybersecurity",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 24,
        "related_skills": ["cybersecurity", "security", "networking", "risk-management", "compliance"],
        "xp_reward": 1300,
        "requirements": [
            "Basic IT knowledge (IT Support Fundamentals recommended)",
            "Understanding of networking concepts helpful",
            "Interest in security and protecting systems"
        ],
        "objectives": [
            "Understand the cybersecurity threat landscape",
            "Identify common attack types and vectors",
            "Implement basic security controls",
            "Recognise social engineering tactics",
            "Apply security best practices",
            "Understand compliance and governance basics"
        ],
    }

    course = Course(
        id=course_data["id"],
        title=course_data["title"],
        description=course_data["description"],
        short_description=course_data.get("short_description"),
        level="beginner",
        status="published",
        category=course_data.get("category"),
        instructor_id=course_data["instructor_id"],
        is_premium=False,
        price=0.0,
        estimated_hours=course_data.get("estimated_hours", 0),
        related_skills=course_data.get("related_skills", []),
        xp_reward=course_data.get("xp_reward", 0),
        requirements=course_data.get("requirements", []),
        objectives=course_data.get("objectives", []),
    )
    db.add(course)
    db.commit()
    db.refresh(course)

    # Module 1: Introduction to Cybersecurity
    mod1 = create_module(db, CourseModuleCreate(
        id="sec-m1",
        title="Welcome to Cybersecurity",
        description="Understand what cybersecurity is and why it matters",
        order_index=0,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m1-s1",
        title="What is Cybersecurity?",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c1", "type": "heading", "content": {"text": "Understanding Cybersecurity", "level": 1}},
            {"id": "c2", "type": "text", "content": {"text": "Cybersecurity is the practice of protecting systems, networks, and data from digital attacks. In our increasingly connected world, cybersecurity is no longer optional - it's essential for every organisation and individual.", "markdown": True}},
            {"id": "c3", "type": "text", "content": {"text": "### The CIA Triad\n\nThe foundation of cybersecurity rests on three principles:\n\n**Confidentiality**\nEnsuring information is accessible only to authorised individuals. Encryption, access controls, and authentication protect confidentiality.\n\n**Integrity**\nEnsuring data is accurate and hasn't been tampered with. Checksums, digital signatures, and audit trails maintain integrity.\n\n**Availability**\nEnsuring systems and data are accessible when needed. Redundancy, backups, and disaster recovery ensure availability.\n\nEvery security control aims to protect one or more of these principles.", "markdown": True}},
            {"id": "c4", "type": "callout", "content": {"type": "info", "title": "Growing Field", "message": "Cybersecurity has a significant skills gap. There are more job openings than qualified professionals, making it an excellent career path."}}
        ]
    ), mod1.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m1-s2",
        title="The Threat Landscape",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c5", "type": "heading", "content": {"text": "Who Are the Attackers?", "level": 2}},
            {"id": "c6", "type": "text", "content": {"text": "### Types of Threat Actors\n\n**Script Kiddies**\nAmateurs using pre-made tools. Low skill, opportunistic attacks.\n\n**Hacktivists**\nMotivated by ideology or politics. Target organisations they disagree with.\n\n**Organised Crime**\nProfessional criminals seeking financial gain. Ransomware, fraud, data theft.\n\n**Nation-States**\nGovernment-sponsored attackers. Espionage, sabotage, warfare.\n\n**Insider Threats**\nEmployees or contractors with malicious intent or negligence.\n\n### Attack Motivations\n\n- **Financial gain** - Ransomware, fraud, theft\n- **Espionage** - Stealing secrets or intellectual property\n- **Disruption** - Taking down services or infrastructure\n- **Revenge** - Disgruntled employees or competitors\n- **Challenge** - Proving skills, gaining notoriety", "markdown": True}},
            {"id": "c7", "type": "callout", "content": {"type": "warning", "title": "Everyone is a Target", "message": "Small businesses are often targeted because they have weaker defences. No organisation is 'too small to hack'."}}
        ]
    ), mod1.id)

    # Module 2: Common Attack Types
    mod2 = create_module(db, CourseModuleCreate(
        id="sec-m2",
        title="Common Attack Types",
        description="Learn about the most frequent cyber attacks",
        order_index=1,
        duration="60 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m2-s1",
        title="Malware",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c8", "type": "heading", "content": {"text": "Types of Malicious Software", "level": 1}},
            {"id": "c9", "type": "text", "content": {"text": "Malware (malicious software) is any software designed to harm or exploit systems.", "markdown": True}},
            {"id": "c10", "type": "text", "content": {"text": "### Common Malware Types\n\n**Virus**\nAttaches to legitimate programs. Spreads when the program runs. Needs user action to spread.\n\n**Worm**\nSelf-replicating. Spreads across networks automatically without user interaction.\n\n**Trojan**\nDisguised as legitimate software. Tricks users into installing it. Creates backdoors.\n\n**Ransomware**\nEncrypts files and demands payment. Modern variants also steal data.\n\n**Spyware**\nSecretly monitors user activity. Steals passwords, financial information.\n\n**Keylogger**\nRecords keystrokes. Captures passwords and sensitive data typed.\n\n**Rootkit**\nHides deep in the system. Very difficult to detect and remove.\n\n**Adware**\nDisplays unwanted advertisements. May also track browsing habits.", "markdown": True}},
            {"id": "c11", "type": "callout", "content": {"type": "warning", "title": "Ransomware Crisis", "message": "Ransomware attacks have increased dramatically. In 2023, the average ransom payment exceeded £1 million. Prevention is crucial."}}
        ]
    ), mod2.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m2-s2",
        title="Network Attacks",
        order_index=1,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c12", "type": "heading", "content": {"text": "Attacking Networks", "level": 2}},
            {"id": "c13", "type": "text", "content": {"text": "### Common Network Attack Types\n\n**Denial of Service (DoS)**\nOverwhelms systems with traffic, making them unavailable. DDoS uses multiple sources.\n\n**Man-in-the-Middle (MitM)**\nAttacker intercepts communication between two parties. Can read or modify traffic.\n\n**DNS Spoofing/Poisoning**\nCorrupts DNS records to redirect users to malicious sites.\n\n**ARP Spoofing**\nLinks attacker's MAC address to a legitimate IP. Enables traffic interception.\n\n**Packet Sniffing**\nCaptures network traffic to steal unencrypted data.\n\n**SQL Injection**\nInserts malicious code into database queries. Can steal or modify data.\n\n**Cross-Site Scripting (XSS)**\nInjects malicious scripts into web pages. Affects users viewing the page.", "markdown": True}},
            {"id": "c14", "type": "callout", "content": {"type": "tip", "title": "Defence in Depth", "message": "No single control stops all attacks. Layer multiple defences: firewalls, encryption, monitoring, training."}}
        ]
    ), mod2.id)

    # Module 3: Social Engineering
    mod3 = create_module(db, CourseModuleCreate(
        id="sec-m3",
        title="Social Engineering",
        description="Understand attacks that target human psychology",
        order_index=2,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m3-s1",
        title="Phishing and Pretexting",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c15", "type": "heading", "content": {"text": "Exploiting Human Nature", "level": 1}},
            {"id": "c16", "type": "text", "content": {"text": "Social engineering attacks target people rather than technology. They exploit trust, fear, urgency, and helpfulness.", "markdown": True}},
            {"id": "c17", "type": "text", "content": {"text": "### Phishing\n\nFraudulent emails designed to steal information or install malware.\n\n**Types of Phishing:**\n\n- **Mass phishing**: Generic emails to many recipients\n- **Spear phishing**: Targeted at specific individuals or groups\n- **Whaling**: Targeting executives and high-value individuals\n- **Smishing**: Phishing via SMS text messages\n- **Vishing**: Phishing via voice/phone calls\n\n**Red Flags:**\n- Urgency or fear tactics\n- Generic greetings ('Dear Customer')\n- Spelling and grammar errors\n- Suspicious sender addresses\n- Links that don't match displayed text\n- Requests for sensitive information\n- Unexpected attachments\n\n### Pretexting\n\nCreating a false scenario to manipulate victims.\n\n- Impersonating IT support, bank, or authority\n- Building trust over multiple interactions\n- Using gathered information to seem legitimate", "markdown": True}},
            {"id": "c18", "type": "callout", "content": {"type": "info", "title": "90% of Breaches", "message": "Over 90% of successful cyber attacks begin with a phishing email. Training users to spot phishing is critical."}}
        ]
    ), mod3.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m3-s2",
        title="Other Social Engineering",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c19", "type": "heading", "content": {"text": "Physical and Psychological Attacks", "level": 2}},
            {"id": "c20", "type": "text", "content": {"text": "### Physical Social Engineering\n\n**Tailgating/Piggybacking**\nFollowing authorised person through secure door. Exploits politeness.\n\n**Shoulder Surfing**\nWatching someone enter passwords or sensitive data.\n\n**Dumpster Diving**\nSearching rubbish for useful information. Documents, notes, hardware.\n\n**USB Drops**\nLeaving infected USB drives for curious people to plug in.\n\n### Psychological Techniques\n\n**Authority**\n'I'm from IT, I need your password.'\n\n**Urgency**\n'The CEO needs this immediately!'\n\n**Scarcity**\n'Only 2 licences left, act now!'\n\n**Social Proof**\n'Everyone in your department has done this.'\n\n**Reciprocity**\n'I helped you before, now I need a favour.'", "markdown": True}},
            {"id": "c21", "type": "callout", "content": {"type": "tip", "title": "Verify Everything", "message": "If someone claims to be from IT or management and asks for access, verify their identity through official channels first."}}
        ]
    ), mod3.id)

    # Module 4: Password Security
    mod4 = create_module(db, CourseModuleCreate(
        id="sec-m4",
        title="Password Security",
        description="Learn to create and manage strong passwords",
        order_index=3,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m4-s1",
        title="Creating Strong Passwords",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c22", "type": "heading", "content": {"text": "Password Best Practices", "level": 1}},
            {"id": "c23", "type": "text", "content": {"text": "Passwords are often the first line of defence. Weak passwords are easily cracked.", "markdown": True}},
            {"id": "c24", "type": "text", "content": {"text": "### What Makes a Strong Password?\n\n**Length Over Complexity**\nLonger passwords are harder to crack. 16+ characters is ideal.\n\n**Passphrase Method**\nUse a memorable phrase: 'correct horse battery staple'\nEasier to remember, harder to crack than 'P@55w0rd!'\n\n### Password Don'ts\n\n- Never reuse passwords across sites\n- Don't use personal information (birthdays, pet names)\n- Avoid common patterns (qwerty, 123456)\n- Don't share passwords, even with IT\n- Never write passwords on sticky notes\n\n### Password Managers\n\nStore all passwords securely with one master password.\n\n**Benefits:**\n- Generate random, unique passwords\n- Auto-fill credentials securely\n- Sync across devices\n- Encrypted storage\n\n**Popular Options:**\n- Bitwarden (open source, free tier)\n- 1Password\n- KeePass (local storage)\n- LastPass", "markdown": True}},
            {"id": "c25", "type": "callout", "content": {"type": "tip", "title": "Password Managers", "message": "Using a password manager with unique passwords for each site is the single best thing you can do for password security."}}
        ]
    ), mod4.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m4-s2",
        title="Multi-Factor Authentication",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c26", "type": "heading", "content": {"text": "Beyond Passwords: MFA", "level": 2}},
            {"id": "c27", "type": "text", "content": {"text": "Multi-Factor Authentication (MFA) adds extra verification beyond just a password.", "markdown": True}},
            {"id": "c28", "type": "text", "content": {"text": "### Authentication Factors\n\n**Something You Know**\nPassword, PIN, security questions.\n\n**Something You Have**\nPhone, hardware token, smart card.\n\n**Something You Are**\nFingerprint, face recognition, iris scan.\n\n### MFA Methods (Best to Worst)\n\n1. **Hardware Security Keys** (YubiKey, etc.)\n   - Most secure, phishing-resistant\n\n2. **Authenticator Apps** (Authy, Google/Microsoft Authenticator)\n   - Time-based one-time passwords (TOTP)\n   - Much better than SMS\n\n3. **Push Notifications**\n   - Approve login on your phone\n   - Vulnerable to fatigue attacks\n\n4. **SMS Codes**\n   - Better than nothing\n   - Vulnerable to SIM swapping\n\n5. **Email Codes**\n   - Weakest MFA option\n   - Compromised if email is hacked", "markdown": True}},
            {"id": "c29", "type": "callout", "content": {"type": "warning", "title": "Enable MFA Everywhere", "message": "MFA blocks over 99% of automated attacks. Enable it on all accounts that support it, especially email and financial accounts."}}
        ]
    ), mod4.id)

    # Module 5: Email and Web Security
    mod5 = create_module(db, CourseModuleCreate(
        id="sec-m5",
        title="Email and Web Security",
        description="Stay safe online",
        order_index=4,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m5-s1",
        title="Safe Browsing",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c30", "type": "heading", "content": {"text": "Browsing Securely", "level": 1}},
            {"id": "c31", "type": "text", "content": {"text": "The web is full of threats. Knowing how to browse safely is essential.", "markdown": True}},
            {"id": "c32", "type": "text", "content": {"text": "### HTTPS Everywhere\n\n**Look for:**\n- Padlock icon in address bar\n- URL starts with https://\n- No security warnings\n\n**Warning Signs:**\n- 'Not Secure' warning\n- Certificate errors\n- Padlock with warning triangle\n\n### Safe Browsing Practices\n\n- Keep browser and extensions updated\n- Don't click pop-ups or suspicious ads\n- Be wary of unfamiliar download sites\n- Check URLs before entering credentials\n- Use browser security settings\n- Consider an ad blocker\n\n### Spotting Malicious Sites\n\n- Misspelled domain names (amaz0n.com)\n- Unusual TLDs (.xyz, .top, .click)\n- Recently created domains\n- Excessive pop-ups or redirects\n- Poor grammar and design\n- Too-good-to-be-true offers", "markdown": True}},
            {"id": "c33", "type": "callout", "content": {"type": "tip", "title": "Check the URL", "message": "Always check the full URL before entering login credentials. Attackers create convincing fake login pages."}}
        ]
    ), mod5.id)

    # Module 6: Data Protection
    mod6 = create_module(db, CourseModuleCreate(
        id="sec-m6",
        title="Data Protection",
        description="Protect sensitive information",
        order_index=5,
        duration="50 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m6-s1",
        title="Encryption Basics",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c34", "type": "heading", "content": {"text": "Understanding Encryption", "level": 1}},
            {"id": "c35", "type": "text", "content": {"text": "Encryption transforms data into an unreadable format that can only be decoded with the correct key.", "markdown": True}},
            {"id": "c36", "type": "text", "content": {"text": "### Encryption Types\n\n**Symmetric Encryption**\nSame key encrypts and decrypts. Fast, but key sharing is a challenge.\n- AES (Advanced Encryption Standard) - Current standard\n- Used for: File encryption, disk encryption\n\n**Asymmetric Encryption**\nPublic key encrypts, private key decrypts. Slower, but solves key sharing.\n- RSA, ECC\n- Used for: HTTPS, email encryption, digital signatures\n\n### Where Encryption Is Used\n\n**Data at Rest**\n- Full disk encryption (BitLocker, FileVault)\n- File encryption\n- Database encryption\n\n**Data in Transit**\n- HTTPS (web traffic)\n- VPNs (network traffic)\n- Email encryption (S/MIME, PGP)\n\n**End-to-End Encryption**\n- Only sender and recipient can read\n- Examples: WhatsApp, Signal\n- Even the service provider can't access content", "markdown": True}},
            {"id": "c37", "type": "callout", "content": {"type": "info", "title": "BitLocker", "message": "Windows Pro and Enterprise include BitLocker for full disk encryption. Enable it to protect data if devices are lost or stolen."}}
        ]
    ), mod6.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m6-s2",
        title="Data Classification",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c38", "type": "heading", "content": {"text": "Classifying Data", "level": 2}},
            {"id": "c39", "type": "text", "content": {"text": "Not all data needs the same level of protection. Classification helps prioritise security efforts.", "markdown": True}},
            {"id": "c40", "type": "text", "content": {"text": "### Common Classification Levels\n\n**Public**\nNo damage if disclosed. Marketing materials, public website content.\n\n**Internal**\nNot for public. Internal memos, general business documents.\n\n**Confidential**\nCould cause damage if disclosed. Financial data, employee information.\n\n**Restricted/Secret**\nSerious damage if disclosed. Customer PII, trade secrets, source code.\n\n### Handling Based on Classification\n\n| Level | Encryption | Access | Disposal |\n|-------|------------|--------|----------|\n| Public | Optional | Open | Normal |\n| Internal | Recommended | Employees | Secure |\n| Confidential | Required | Need-to-know | Secure wipe |\n| Restricted | Required | Named individuals | Certified destruction |", "markdown": True}},
            {"id": "c41", "type": "callout", "content": {"type": "warning", "title": "Personal Data", "message": "Under UK GDPR, personal data requires special protection. Even names and email addresses are considered personal data."}}
        ]
    ), mod6.id)

    # Module 7: Network Security Basics
    mod7 = create_module(db, CourseModuleCreate(
        id="sec-m7",
        title="Network Security Basics",
        description="Secure network infrastructure",
        order_index=6,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m7-s1",
        title="Firewalls and Defence",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c42", "type": "heading", "content": {"text": "Network Defence Fundamentals", "level": 1}},
            {"id": "c43", "type": "text", "content": {"text": "Networks need multiple layers of protection to defend against attacks.", "markdown": True}},
            {"id": "c44", "type": "text", "content": {"text": "### Firewall Types\n\n**Packet Filtering**\nExamines packet headers. Allows/blocks based on IP, port, protocol.\n\n**Stateful Inspection**\nTracks connection state. More intelligent decisions.\n\n**Application Layer**\nInspects packet content. Can block specific applications or content.\n\n**Next-Generation (NGFW)**\nCombines all above plus:\n- Intrusion prevention\n- Deep packet inspection\n- Threat intelligence\n- SSL inspection\n\n### Other Network Security\n\n**IDS/IPS**\n- IDS: Detects and alerts on threats\n- IPS: Detects and blocks threats\n\n**Network Segmentation**\nSeparate networks for different functions.\n- Guest Wi-Fi separate from corporate\n- PCI systems isolated\n- Server networks separate from workstations\n\n**VPN (Virtual Private Network)**\nEncrypted tunnel for remote access or site-to-site connections.", "markdown": True}},
            {"id": "c45", "type": "callout", "content": {"type": "tip", "title": "Defence in Depth", "message": "No single control is sufficient. Layer multiple defences so if one fails, others provide protection."}}
        ]
    ), mod7.id)

    # Module 8: Security Policies
    mod8 = create_module(db, CourseModuleCreate(
        id="sec-m8",
        title="Security Policies",
        description="Understand security governance",
        order_index=7,
        duration="45 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m8-s1",
        title="Essential Security Policies",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c46", "type": "heading", "content": {"text": "Security Governance", "level": 1}},
            {"id": "c47", "type": "text", "content": {"text": "Security policies define how an organisation protects its assets. They provide rules and guidelines for employees.", "markdown": True}},
            {"id": "c48", "type": "text", "content": {"text": "### Key Security Policies\n\n**Acceptable Use Policy (AUP)**\nDefines acceptable use of company IT resources.\n- What employees can/cannot do\n- Personal use limits\n- Consequences of violations\n\n**Password Policy**\nPassword requirements and management.\n- Minimum length and complexity\n- Change frequency\n- Password reuse rules\n\n**Access Control Policy**\nWho can access what resources.\n- Principle of least privilege\n- Account management\n- Access reviews\n\n**Data Classification Policy**\nHow to handle different data types.\n- Classification levels\n- Handling requirements\n- Retention and disposal\n\n**Incident Response Policy**\nWhat to do when incidents occur.\n- Reporting procedures\n- Escalation path\n- Communication plan\n\n**Remote Work Policy**\nSecurity requirements for remote workers.\n- VPN usage\n- Home network security\n- Physical security", "markdown": True}},
            {"id": "c49", "type": "callout", "content": {"type": "info", "title": "Policies Require Training", "message": "Policies are only effective if employees know about them. Regular security awareness training is essential."}}
        ]
    ), mod8.id)

    # Module 9: Incident Response
    mod9 = create_module(db, CourseModuleCreate(
        id="sec-m9",
        title="Incident Response Basics",
        description="Respond to security incidents",
        order_index=8,
        duration="55 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m9-s1",
        title="The Incident Response Process",
        order_index=0,
        duration="25 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c50", "type": "heading", "content": {"text": "Handling Security Incidents", "level": 1}},
            {"id": "c51", "type": "text", "content": {"text": "A security incident is any event that threatens the confidentiality, integrity, or availability of systems or data.", "markdown": True}},
            {"id": "c52", "type": "text", "content": {"text": "### Incident Response Phases\n\n**1. Preparation**\n- Create incident response plan\n- Train the response team\n- Set up tools and communications\n- Define roles and responsibilities\n\n**2. Detection & Analysis**\n- Identify that an incident occurred\n- Determine scope and impact\n- Classify severity\n- Document everything\n\n**3. Containment**\n- Stop the incident from spreading\n- Short-term: Isolate affected systems\n- Long-term: Plan remediation\n\n**4. Eradication**\n- Remove the threat completely\n- Patch vulnerabilities\n- Reset compromised credentials\n- Remove malware\n\n**5. Recovery**\n- Restore systems to normal\n- Verify functionality\n- Monitor for reinfection\n- Bring systems back online\n\n**6. Lessons Learned**\n- Review what happened\n- Identify improvements\n- Update procedures\n- Share knowledge", "markdown": True}},
            {"id": "c53", "type": "callout", "content": {"type": "warning", "title": "Report Immediately", "message": "If you suspect a security incident, report it immediately. Don't try to investigate yourself - you might destroy evidence."}}
        ]
    ), mod9.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m9-s2",
        title="What to Report",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c54", "type": "heading", "content": {"text": "Recognising and Reporting Incidents", "level": 2}},
            {"id": "c55", "type": "text", "content": {"text": "### Examples of Security Incidents\n\n- Clicking a phishing link\n- Lost or stolen device\n- Suspicious emails asking for data\n- Unusual system behaviour\n- Unauthorised access attempt\n- Ransomware infection\n- Data breach or leak\n- Unknown software installed\n- Account compromise\n\n### What Information to Report\n\n**When**: Date and time you noticed it\n**What**: What you observed or what happened\n**How**: How you discovered it\n**Who**: Your details and anyone else involved\n**Actions**: What you've done so far\n\n### Preserve Evidence\n\n- Don't turn off affected computers (unless instructed)\n- Don't delete suspicious emails\n- Take screenshots if possible\n- Note error messages exactly\n- Save any relevant logs", "markdown": True}},
            {"id": "c56", "type": "callout", "content": {"type": "tip", "title": "Better Safe Than Sorry", "message": "If you're unsure whether something is an incident, report it anyway. It's better to investigate a false alarm than miss a real attack."}}
        ]
    ), mod9.id)

    # Module 10: Career in Cybersecurity
    mod10 = create_module(db, CourseModuleCreate(
        id="sec-m10",
        title="Cybersecurity Careers",
        description="Explore career paths in security",
        order_index=9,
        duration="40 minutes",
        status="published"
    ), course.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m10-s1",
        title="Security Career Paths",
        order_index=0,
        duration="20 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c57", "type": "heading", "content": {"text": "Building a Security Career", "level": 1}},
            {"id": "c58", "type": "text", "content": {"text": "Cybersecurity offers diverse career paths with strong job prospects and competitive salaries.", "markdown": True}},
            {"id": "c59", "type": "text", "content": {"text": "### Entry-Level Roles\n\n**Security Analyst (SOC Analyst)**\nMonitor security systems, analyse alerts, investigate incidents.\nCertifications: CompTIA Security+, CySA+\n\n**IT Security Technician**\nImplement security controls, manage security tools.\nCertifications: CompTIA Security+, Network+\n\n### Intermediate Roles\n\n**Penetration Tester**\nEthically hack systems to find vulnerabilities.\nCertifications: CEH, OSCP, PenTest+\n\n**Security Engineer**\nDesign and implement security solutions.\nCertifications: CISSP, CCSP\n\n**Incident Responder**\nInvestigate and respond to security incidents.\nCertifications: GCIH, GCFA\n\n### Advanced Roles\n\n**Security Architect**\nDesign organisation-wide security strategy.\n\n**Security Manager/CISO**\nLead security teams and programmes.\n\n**Security Consultant**\nAdvise organisations on security improvements.", "markdown": True}},
            {"id": "c60", "type": "callout", "content": {"type": "info", "title": "Skills Gap", "message": "There's a global shortage of cybersecurity professionals. Starting in IT support and building security skills is an excellent pathway into the field."}}
        ]
    ), mod10.id)

    create_section(db, ModuleSectionCreate(
        id="sec-m10-s2",
        title="Final Assessment",
        order_index=1,
        duration="15 minutes",
        is_required=True,
        content_blocks=[
            {"id": "c61", "type": "heading", "content": {"text": "Cybersecurity Fundamentals Assessment", "level": 1}},
            {"id": "c62", "type": "quiz", "content": {
                "questions": [
                    {"id": "cq1", "question": "What does the 'C' in CIA triad stand for?", "type": "multiple_choice", "options": ["Compliance", "Confidentiality", "Continuity", "Control"], "correct_answer": "Confidentiality", "explanation": "The CIA triad consists of Confidentiality, Integrity, and Availability."},
                    {"id": "cq2", "question": "Which type of malware encrypts files and demands payment?", "type": "multiple_choice", "options": ["Trojan", "Worm", "Ransomware", "Spyware"], "correct_answer": "Ransomware", "explanation": "Ransomware encrypts victim files and demands payment for the decryption key."},
                    {"id": "cq3", "question": "What percentage of cyber attacks begin with phishing?", "type": "multiple_choice", "options": ["50%", "70%", "90%", "100%"], "correct_answer": "90%", "explanation": "Over 90% of successful cyber attacks start with a phishing email."},
                    {"id": "cq4", "question": "Which MFA method is considered most secure?", "type": "multiple_choice", "options": ["SMS codes", "Email codes", "Hardware security keys", "Security questions"], "correct_answer": "Hardware security keys", "explanation": "Hardware security keys like YubiKey are the most secure MFA option, being phishing-resistant."},
                    {"id": "cq5", "question": "What should you do first if you suspect a security incident?", "type": "multiple_choice", "options": ["Try to fix it yourself", "Delete the suspicious email", "Report it immediately", "Turn off your computer"], "correct_answer": "Report it immediately", "explanation": "Report incidents immediately to preserve evidence and allow proper investigation."}
                ],
                "passing_score": 70
            }}
        ]
    ), mod10.id)

    print(f"Created course: {course.title} with 10 modules")
    return course


def create_comprehensive_courses(db: Session, instructor_id: int = 1) -> List[Course]:
    """Create all comprehensive courses."""
    courses = []

    course_ids = [
        "it-support-fundamentals",
        "networking-essentials",
        "windows-basics-it",
        "intro-cybersecurity"
    ]
    cleanup_existing_courses(db, course_ids)

    # Create IT Support course
    courses.append(create_it_support_course(db, instructor_id))

    # Create Networking course
    courses.append(create_networking_course(db, instructor_id))

    # Create Windows course
    courses.append(create_windows_course(db, instructor_id))

    # Create Cybersecurity course
    courses.append(create_cybersecurity_course(db, instructor_id))

    db.commit()
    return courses


def run_seed():
    """Run the comprehensive seed."""
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        print("Seeding comprehensive IT course data...")

        # Find an existing admin/tutor user
        instructor = db.query(User).filter(
            (User.role == UserRole.ADMIN) | (User.role == UserRole.TUTOR)
        ).first()

        if not instructor:
            # Fall back to any existing user
            instructor = db.query(User).first()

        if not instructor:
            print("Error: No users found in database. Please create a user first.")
            return

        print(f"Using instructor: {instructor.email} (ID: {instructor.id})")

        courses = create_comprehensive_courses(db, instructor_id=instructor.id)
        print(f"\nSuccessfully created {len(courses)} courses!")
        for course in courses:
            print(f"  - {course.title} ({course.id})")
    except Exception as e:
        print(f"\nError seeding data: {str(e)}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
