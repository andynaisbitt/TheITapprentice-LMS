"""
Seed Data for Courses Plugin
Creates sample IT courses with modules, sections, and content blocks for TheITApprentice.
"""
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List

# Import User models first to resolve relationships
from app.users.models import User, UserRole
from app.auth.email_verification import EmailVerification

from app.plugins.courses.models import Course, CourseModule, ModuleSection
from app.plugins.courses.schemas import (
    CourseModuleCreate,
    ModuleSectionCreate,
)


def create_sample_courses(db: Session, instructor_id: int = 1) -> List[Course]:
    """
    Create sample IT courses for TheITApprentice platform.

    Args:
        db: Database session
        instructor_id: ID of the instructor user (default: 1 - admin)

    Returns:
        List of created courses
    """
    courses = []

    # Course 1: IT Support Fundamentals
    it_support_course_data = {
        "id": "it-support-fundamentals",
        "title": "IT Support Fundamentals",
        "description": "Start your IT career with essential help desk and support skills. Learn how to troubleshoot common issues, provide excellent customer service, and handle tickets professionally. Perfect for aspiring IT support technicians.",
        "short_description": "Master the basics of IT support and help desk operations",
        "level": "beginner",  # Use lowercase string directly
        "category": "IT Support",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 8,
        "related_skills": ["troubleshooting", "customer-service", "ticketing", "communication"],
        "xp_reward": 400,
        "requirements": [
            "No prior IT experience required",
            "Basic computer skills (using mouse, keyboard, web browser)",
            "Willingness to help others solve problems"
        ],
        "objectives": [
            "Understand the role of IT support in organisations",
            "Learn professional ticket handling and documentation",
            "Troubleshoot common hardware and software issues",
            "Provide excellent customer service to end users",
            "Use remote support tools effectively",
            "Escalate issues appropriately"
        ],
        "is_featured": True,
        "status": "published",
    }

    # Module 1: Introduction to IT Support
    module_1_sections = [
        {
            "id": "it-support-m1-s1",
            "title": "What is IT Support?",
            "content_blocks": [
                {
                    "id": "block-1",
                    "type": "heading",
                    "content": {
                        "text": "Welcome to IT Support!",
                        "level": 1
                    }
                },
                {
                    "id": "block-2",
                    "type": "text",
                    "content": {
                        "text": "IT Support is the backbone of every organisation's technology operations. As an IT support technician, you'll be the first point of contact when users experience technical problems. Your role is crucial in keeping businesses running smoothly.",
                        "markdown": True
                    }
                },
                {
                    "id": "block-3",
                    "type": "callout",
                    "content": {
                        "type": "info",
                        "title": "Career Opportunity",
                        "message": "IT Support roles are in high demand! Entry-level positions often lead to specialised careers in networking, security, or system administration."
                    }
                },
                {
                    "id": "block-4",
                    "type": "text",
                    "content": {
                        "text": "### Key Responsibilities\n\n- Responding to help desk tickets and phone calls\n- Troubleshooting hardware and software issues\n- Setting up new user accounts and equipment\n- Documenting solutions for future reference\n- Escalating complex issues to senior technicians",
                        "markdown": True
                    }
                }
            ],
            "order_index": 0,
            "duration": "15 minutes",
            "is_required": True
        },
        {
            "id": "it-support-m1-s2",
            "title": "The Help Desk Workflow",
            "content_blocks": [
                {
                    "id": "block-5",
                    "type": "heading",
                    "content": {
                        "text": "Understanding the Ticket Lifecycle",
                        "level": 2
                    }
                },
                {
                    "id": "block-6",
                    "type": "text",
                    "content": {
                        "text": "Every IT support request follows a lifecycle from creation to resolution. Understanding this workflow helps you provide consistent, professional service.",
                        "markdown": True
                    }
                },
                {
                    "id": "block-7",
                    "type": "text",
                    "content": {
                        "text": "### Ticket Stages\n\n1. **New** - User submits a request\n2. **Assigned** - Ticket routed to technician\n3. **In Progress** - Active troubleshooting\n4. **Pending** - Waiting for user or parts\n5. **Resolved** - Issue fixed\n6. **Closed** - User confirms resolution",
                        "markdown": True
                    }
                },
                {
                    "id": "block-8",
                    "type": "quiz",
                    "content": {
                        "questions": [
                            {
                                "id": "q1",
                                "question": "What should you do first when receiving a new support ticket?",
                                "type": "multiple_choice",
                                "options": [
                                    "Read the full description and acknowledge receipt",
                                    "Immediately escalate to a senior technician",
                                    "Close the ticket without reading",
                                    "Delete the ticket"
                                ],
                                "correct_answer": 0,
                                "explanation": "Always read the full ticket description first and acknowledge receipt so the user knows their request is being handled."
                            }
                        ],
                        "passing_score": 70
                    }
                }
            ],
            "order_index": 1,
            "duration": "20 minutes",
            "is_required": True
        }
    ]

    module_1 = {
        "id": "it-support-module-1",
        "title": "Introduction to IT Support",
        "description": "Learn what IT support is and how the help desk operates",
        "order_index": 0,
        "duration": "35 minutes",
        "status": "published"
    }

    # Module 2: Troubleshooting Basics
    module_2_sections = [
        {
            "id": "it-support-m2-s1",
            "title": "The Troubleshooting Process",
            "content_blocks": [
                {
                    "id": "block-9",
                    "type": "heading",
                    "content": {
                        "text": "Systematic Troubleshooting",
                        "level": 2
                    }
                },
                {
                    "id": "block-10",
                    "type": "text",
                    "content": {
                        "text": "Good troubleshooting is like being a detective. You gather clues, form theories, and test them until you find the solution. Following a systematic approach saves time and ensures you don't miss anything.",
                        "markdown": True
                    }
                },
                {
                    "id": "block-11",
                    "type": "text",
                    "content": {
                        "text": "### The 6-Step Troubleshooting Method\n\n1. **Identify the problem** - Ask questions, gather information\n2. **Establish a theory** - What might be causing this?\n3. **Test the theory** - Try your solution\n4. **Create an action plan** - Steps to fix if theory is correct\n5. **Implement the fix** - Apply the solution\n6. **Document everything** - Record what worked for future reference",
                        "markdown": True
                    }
                },
                {
                    "id": "block-12",
                    "type": "callout",
                    "content": {
                        "type": "tip",
                        "title": "Pro Tip",
                        "message": "Always ask 'What changed recently?' - Many issues occur right after updates, new software installations, or configuration changes."
                    }
                }
            ],
            "order_index": 0,
            "duration": "25 minutes",
            "is_required": True
        }
    ]

    module_2 = {
        "id": "it-support-module-2",
        "title": "Troubleshooting Basics",
        "description": "Learn systematic approaches to solving IT problems",
        "order_index": 1,
        "duration": "45 minutes",
        "status": "published"
    }

    # Create IT Support course directly with string values
    try:
        from app.plugins.courses.crud import create_module, create_section

        # Clean up existing courses first
        course_ids_to_seed = ["it-support-fundamentals", "networking-essentials"]
        for course_id in course_ids_to_seed:
            existing = db.query(Course).filter(Course.id == course_id).first()
            if existing:
                # Delete sections first (via modules)
                for module in existing.modules:
                    db.query(ModuleSection).filter(ModuleSection.module_id == module.id).delete()
                # Delete modules
                db.query(CourseModule).filter(CourseModule.course_id == course_id).delete()
                # Delete course
                db.delete(existing)
                db.commit()
                print(f"Cleaned up existing course: {course_id}")

        it_support_course = Course(
            id=it_support_course_data["id"],
            title=it_support_course_data["title"],
            description=it_support_course_data["description"],
            short_description=it_support_course_data.get("short_description"),
            level="beginner",  # Use string directly
            status="published",  # Must be published to show on frontend
            category=it_support_course_data.get("category"),
            instructor_id=it_support_course_data["instructor_id"],
            is_premium=it_support_course_data.get("is_premium", False),
            price=it_support_course_data.get("price", 0.0),
            estimated_hours=it_support_course_data.get("estimated_hours", 0),
            related_skills=it_support_course_data.get("related_skills", []),
            xp_reward=it_support_course_data.get("xp_reward", 0),
            requirements=it_support_course_data.get("requirements", []),
            objectives=it_support_course_data.get("objectives", []),
        )
        db.add(it_support_course)
        db.commit()
        db.refresh(it_support_course)

        # Create Module 1 and its sections
        mod_1 = create_module(
            db,
            CourseModuleCreate(**module_1),
            it_support_course.id
        )
        for section_data in module_1_sections:
            create_section(
                db,
                ModuleSectionCreate(**section_data),
                mod_1.id
            )

        # Create Module 2 and its sections
        mod_2 = create_module(
            db,
            CourseModuleCreate(**module_2),
            it_support_course.id
        )
        for section_data in module_2_sections:
            create_section(
                db,
                ModuleSectionCreate(**section_data),
                mod_2.id
            )

        courses.append(it_support_course)
        print(f"Created course: {it_support_course.title}")

    except Exception as e:
        print(f"Error creating IT Support course: {str(e)}")
        db.rollback()

    # Course 2: Networking Essentials
    networking_course_data = {
        "id": "networking-essentials",
        "title": "Networking Essentials",
        "description": "Understand how computer networks work and learn to configure basic network settings. This course covers IP addressing, DNS, DHCP, and common network troubleshooting - essential knowledge for any IT professional.",
        "short_description": "Learn the fundamentals of computer networking",
        "level": "intermediate",
        "category": "Networking",
        "instructor_id": instructor_id,
        "is_premium": True,
        "price": 29.99,
        "estimated_hours": 12,
        "related_skills": ["networking", "tcp-ip", "troubleshooting", "infrastructure"],
        "xp_reward": 600,
        "requirements": [
            "Basic IT knowledge (IT Support Fundamentals recommended)",
            "Access to a computer for hands-on practice",
            "Curiosity about how the internet works"
        ],
        "objectives": [
            "Understand the OSI and TCP/IP networking models",
            "Configure IP addresses and subnet masks",
            "Explain how DNS and DHCP work",
            "Use command-line tools to diagnose network issues",
            "Identify common network hardware and their purposes",
            "Troubleshoot basic connectivity problems"
        ],
        "is_featured": True,
        "status": "published",
    }

    networking_module_1 = {
        "id": "networking-module-1",
        "title": "How Networks Work",
        "description": "Understanding the basics of computer networking",
        "order_index": 0,
        "duration": "60 minutes",
        "status": "published"
    }

    networking_section_1 = {
        "id": "networking-m1-s1",
        "title": "Introduction to Networks",
        "content_blocks": [
            {
                "id": "block-net-1",
                "type": "heading",
                "content": {
                    "text": "What is a Computer Network?",
                    "level": 1
                }
            },
            {
                "id": "block-net-2",
                "type": "text",
                "content": {
                    "text": "A computer network is simply two or more devices connected together to share resources and communicate. From your home Wi-Fi to the global internet, networks are everywhere in modern life.",
                    "markdown": True
                }
            },
            {
                "id": "block-net-3",
                "type": "text",
                "content": {
                    "text": "### Types of Networks\n\n- **LAN (Local Area Network)** - A network in a single location, like an office\n- **WAN (Wide Area Network)** - Networks spanning large distances, like the internet\n- **WLAN (Wireless LAN)** - A LAN that uses Wi-Fi\n- **VPN (Virtual Private Network)** - A secure tunnel over public networks",
                    "markdown": True
                }
            },
            {
                "id": "block-net-4",
                "type": "callout",
                "content": {
                    "type": "info",
                    "title": "Fun Fact",
                    "message": "The internet is essentially a network of networks - millions of LANs connected together through WANs!"
                }
            }
        ],
        "order_index": 0,
        "duration": "20 minutes",
        "is_required": True
    }

    try:
        networking_course = Course(
            id=networking_course_data["id"],
            title=networking_course_data["title"],
            description=networking_course_data["description"],
            short_description=networking_course_data.get("short_description"),
            level="intermediate",  # Use string directly
            status="published",    # Must be published to show on frontend
            category=networking_course_data.get("category"),
            instructor_id=networking_course_data["instructor_id"],
            is_premium=networking_course_data.get("is_premium", False),
            price=networking_course_data.get("price", 0.0),
            estimated_hours=networking_course_data.get("estimated_hours", 0),
            related_skills=networking_course_data.get("related_skills", []),
            xp_reward=networking_course_data.get("xp_reward", 0),
            requirements=networking_course_data.get("requirements", []),
            objectives=networking_course_data.get("objectives", []),
        )
        db.add(networking_course)
        db.commit()
        db.refresh(networking_course)

        mod_net = create_module(
            db,
            CourseModuleCreate(**networking_module_1),
            networking_course.id
        )
        create_section(
            db,
            ModuleSectionCreate(**networking_section_1),
            mod_net.id
        )

        courses.append(networking_course)
        print(f"Created course: {networking_course.title}")

    except Exception as e:
        print(f"Error creating Networking course: {str(e)}")
        db.rollback()

    # Course 3: Windows Basics for IT Professionals
    windows_course_data = {
        "id": "windows-basics-it",
        "title": "Windows Basics for IT Professionals",
        "description": "Master the fundamentals of Windows operating systems from an IT perspective. Learn to navigate the interface, manage user accounts, understand file systems, and configure essential settings. A must-have foundation for any IT career.",
        "short_description": "Essential Windows skills for IT support roles",
        "level": "beginner",
        "category": "Operating Systems",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 6,
        "related_skills": ["windows", "system-administration", "troubleshooting"],
        "xp_reward": 300,
        "requirements": [
            "No prior IT experience required",
            "Access to a Windows 10 or 11 computer",
            "Desire to learn IT fundamentals"
        ],
        "objectives": [
            "Navigate Windows interface confidently",
            "Manage local user accounts and permissions",
            "Understand NTFS file system and permissions",
            "Use Task Manager and system utilities",
            "Configure essential Windows settings",
            "Troubleshoot common Windows issues"
        ],
        "is_featured": True,
        "status": "published",
    }

    windows_module_1 = {
        "id": "windows-module-1",
        "title": "Navigating Windows",
        "description": "Learn the Windows interface inside and out",
        "order_index": 0,
        "duration": "45 minutes",
        "status": "published"
    }

    windows_section_1 = {
        "id": "windows-m1-s1",
        "title": "The Windows Desktop",
        "content_blocks": [
            {
                "id": "block-win-1",
                "type": "heading",
                "content": {
                    "text": "Understanding the Windows Desktop",
                    "level": 1
                }
            },
            {
                "id": "block-win-2",
                "type": "text",
                "content": {
                    "text": "The Windows desktop is your central workspace. As an IT professional, you'll need to know every corner of it to help users and configure systems efficiently.",
                    "markdown": True
                }
            },
            {
                "id": "block-win-3",
                "type": "text",
                "content": {
                    "text": "### Key Desktop Components\n\n- **Taskbar** - Quick access to apps, system tray, Start button\n- **Start Menu** - Access all programs and settings\n- **Desktop Icons** - Shortcuts to files and applications\n- **System Tray** - Network, sound, clock, background apps\n- **Action Center** - Notifications and quick settings",
                    "markdown": True
                }
            },
            {
                "id": "block-win-4",
                "type": "callout",
                "content": {
                    "type": "tip",
                    "title": "Keyboard Shortcut",
                    "message": "Press Windows + D to instantly show the desktop, hiding all open windows. Press again to restore them."
                }
            }
        ],
        "order_index": 0,
        "duration": "15 minutes",
        "is_required": True
    }

    windows_module_2 = {
        "id": "windows-module-2",
        "title": "User Account Management",
        "description": "Create and manage Windows user accounts",
        "order_index": 1,
        "duration": "45 minutes",
        "status": "published"
    }

    windows_section_2 = {
        "id": "windows-m2-s1",
        "title": "Types of User Accounts",
        "content_blocks": [
            {
                "id": "block-win-5",
                "type": "heading",
                "content": {
                    "text": "Windows User Account Types",
                    "level": 1
                }
            },
            {
                "id": "block-win-6",
                "type": "text",
                "content": {
                    "text": "Windows has different types of accounts with varying levels of access. Understanding these is crucial for security and user management.",
                    "markdown": True
                }
            },
            {
                "id": "block-win-7",
                "type": "text",
                "content": {
                    "text": "### Account Types\n\n| Type | Access Level | Use Case |\n|------|--------------|----------|\n| Administrator | Full access | IT staff, system config |\n| Standard User | Limited access | Day-to-day users |\n| Guest | Minimal access | Temporary access |\n\n### Microsoft vs Local Accounts\n\n- **Microsoft Account** - Syncs settings across devices, requires internet\n- **Local Account** - Works offline, settings stored locally only",
                    "markdown": True
                }
            }
        ],
        "order_index": 0,
        "duration": "20 minutes",
        "is_required": True
    }

    windows_module_3 = {
        "id": "windows-module-3",
        "title": "File System Basics",
        "description": "Understand NTFS, folders, and permissions",
        "order_index": 2,
        "duration": "40 minutes",
        "status": "published"
    }

    windows_section_3 = {
        "id": "windows-m3-s1",
        "title": "NTFS File System",
        "content_blocks": [
            {
                "id": "block-win-8",
                "type": "heading",
                "content": {
                    "text": "Understanding NTFS",
                    "level": 1
                }
            },
            {
                "id": "block-win-9",
                "type": "text",
                "content": {
                    "text": "NTFS (New Technology File System) is the default file system for Windows. It offers security features, large file support, and reliability that older systems lack.",
                    "markdown": True
                }
            },
            {
                "id": "block-win-10",
                "type": "text",
                "content": {
                    "text": "### NTFS Features\n\n- **File Permissions** - Control who can read, write, or execute files\n- **Encryption** - Protect sensitive data with EFS\n- **Compression** - Save disk space automatically\n- **Large Files** - Support files larger than 4GB\n- **Journaling** - Recover from crashes without data loss",
                    "markdown": True
                }
            },
            {
                "id": "block-win-11",
                "type": "callout",
                "content": {
                    "type": "warning",
                    "title": "Important",
                    "message": "Never modify permissions in C:\\Windows or C:\\Program Files unless you know exactly what you're doing. Incorrect permissions can break Windows!"
                }
            }
        ],
        "order_index": 0,
        "duration": "25 minutes",
        "is_required": True
    }

    # Add course_id to cleanup list
    course_ids_to_seed = ["windows-basics-it", "intro-cybersecurity"]
    for course_id in course_ids_to_seed:
        existing = db.query(Course).filter(Course.id == course_id).first()
        if existing:
            for module in existing.modules:
                db.query(ModuleSection).filter(ModuleSection.module_id == module.id).delete()
            db.query(CourseModule).filter(CourseModule.course_id == course_id).delete()
            db.delete(existing)
            db.commit()
            print(f"Cleaned up existing course: {course_id}")

    try:
        windows_course = Course(
            id=windows_course_data["id"],
            title=windows_course_data["title"],
            description=windows_course_data["description"],
            short_description=windows_course_data.get("short_description"),
            level="beginner",
            status="published",
            category=windows_course_data.get("category"),
            instructor_id=windows_course_data["instructor_id"],
            is_premium=windows_course_data.get("is_premium", False),
            price=windows_course_data.get("price", 0.0),
            estimated_hours=windows_course_data.get("estimated_hours", 0),
            related_skills=windows_course_data.get("related_skills", []),
            xp_reward=windows_course_data.get("xp_reward", 0),
            requirements=windows_course_data.get("requirements", []),
            objectives=windows_course_data.get("objectives", []),
        )
        db.add(windows_course)
        db.commit()
        db.refresh(windows_course)

        # Create Windows modules and sections
        mod_win_1 = create_module(db, CourseModuleCreate(**windows_module_1), windows_course.id)
        create_section(db, ModuleSectionCreate(**windows_section_1), mod_win_1.id)

        mod_win_2 = create_module(db, CourseModuleCreate(**windows_module_2), windows_course.id)
        create_section(db, ModuleSectionCreate(**windows_section_2), mod_win_2.id)

        mod_win_3 = create_module(db, CourseModuleCreate(**windows_module_3), windows_course.id)
        create_section(db, ModuleSectionCreate(**windows_section_3), mod_win_3.id)

        courses.append(windows_course)
        print(f"Created course: {windows_course.title}")

    except Exception as e:
        print(f"Error creating Windows course: {str(e)}")
        db.rollback()

    # Course 4: Introduction to Cybersecurity
    security_course_data = {
        "id": "intro-cybersecurity",
        "title": "Introduction to Cybersecurity",
        "description": "Learn the fundamentals of cybersecurity and protect yourself and your organisation from common threats. Covers password security, phishing awareness, safe browsing, and basic security practices everyone in IT should know.",
        "short_description": "Essential security knowledge for IT beginners",
        "level": "beginner",
        "category": "Cybersecurity",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 5,
        "related_skills": ["security", "awareness", "best-practices"],
        "xp_reward": 350,
        "requirements": [
            "Basic computer skills",
            "No security experience required",
            "Interest in staying safe online"
        ],
        "objectives": [
            "Understand common cyber threats",
            "Create and manage strong passwords",
            "Recognize phishing attempts",
            "Practice safe browsing habits",
            "Protect sensitive data",
            "Report security incidents properly"
        ],
        "is_featured": True,
        "status": "published",
    }

    security_module_1 = {
        "id": "security-module-1",
        "title": "Password Security",
        "description": "Master the art of secure passwords",
        "order_index": 0,
        "duration": "30 minutes",
        "status": "published"
    }

    security_section_1 = {
        "id": "security-m1-s1",
        "title": "Creating Strong Passwords",
        "content_blocks": [
            {
                "id": "block-sec-1",
                "type": "heading",
                "content": {
                    "text": "Why Passwords Matter",
                    "level": 1
                }
            },
            {
                "id": "block-sec-2",
                "type": "text",
                "content": {
                    "text": "Passwords are often the only barrier between attackers and your data. Weak passwords are one of the most common causes of security breaches.",
                    "markdown": True
                }
            },
            {
                "id": "block-sec-3",
                "type": "text",
                "content": {
                    "text": "### What Makes a Strong Password?\n\n- **Length** - At least 12 characters (longer is better)\n- **Complexity** - Mix of upper, lower, numbers, symbols\n- **Uniqueness** - Different for every account\n- **Unpredictable** - Not based on personal info\n\n### Bad Passwords to Avoid\n\n- `password123` - Too obvious\n- `John1990` - Personal info\n- `qwerty` - Keyboard pattern\n- `Summer2024!` - Seasonal/dated",
                    "markdown": True
                }
            },
            {
                "id": "block-sec-4",
                "type": "callout",
                "content": {
                    "type": "tip",
                    "title": "Pro Tip",
                    "message": "Use a password manager like Bitwarden, 1Password, or LastPass. You only need to remember one master password, and it generates unique strong passwords for everything else."
                }
            }
        ],
        "order_index": 0,
        "duration": "15 minutes",
        "is_required": True
    }

    security_module_2 = {
        "id": "security-module-2",
        "title": "Recognizing Threats",
        "description": "Learn to spot phishing, malware, and social engineering",
        "order_index": 1,
        "duration": "35 minutes",
        "status": "published"
    }

    security_section_2 = {
        "id": "security-m2-s1",
        "title": "Phishing Attacks",
        "content_blocks": [
            {
                "id": "block-sec-5",
                "type": "heading",
                "content": {
                    "text": "Recognizing Phishing",
                    "level": 1
                }
            },
            {
                "id": "block-sec-6",
                "type": "text",
                "content": {
                    "text": "Phishing is when attackers pretend to be someone trustworthy to trick you into revealing sensitive information or clicking malicious links.",
                    "markdown": True
                }
            },
            {
                "id": "block-sec-7",
                "type": "text",
                "content": {
                    "text": "### Red Flags to Watch For\n\n- **Urgency** - 'Act now or your account will be closed!'\n- **Generic greetings** - 'Dear Customer' instead of your name\n- **Suspicious sender** - Email doesn't match the company\n- **Grammar/spelling errors** - Professional companies proofread\n- **Suspicious links** - Hover to see the real URL\n- **Unexpected attachments** - Don't open unless expected",
                    "markdown": True
                }
            },
            {
                "id": "block-sec-8",
                "type": "callout",
                "content": {
                    "type": "warning",
                    "title": "When in Doubt",
                    "message": "If you receive a suspicious email claiming to be from your bank, employer, or any service - don't click links in the email. Go directly to the website by typing the address yourself."
                }
            }
        ],
        "order_index": 0,
        "duration": "20 minutes",
        "is_required": True
    }

    security_module_3 = {
        "id": "security-module-3",
        "title": "Safe Browsing",
        "description": "Stay safe while browsing the internet",
        "order_index": 2,
        "duration": "25 minutes",
        "status": "published"
    }

    security_section_3 = {
        "id": "security-m3-s1",
        "title": "Browsing Safely",
        "content_blocks": [
            {
                "id": "block-sec-9",
                "type": "heading",
                "content": {
                    "text": "Safe Browsing Habits",
                    "level": 1
                }
            },
            {
                "id": "block-sec-10",
                "type": "text",
                "content": {
                    "text": "The internet is full of useful resources, but also potential dangers. Following safe browsing practices protects you and your organisation.",
                    "markdown": True
                }
            },
            {
                "id": "block-sec-11",
                "type": "text",
                "content": {
                    "text": "### Safe Browsing Checklist\n\n- **Check for HTTPS** - Look for the padlock icon\n- **Keep browser updated** - Updates fix security holes\n- **Be careful with downloads** - Only download from trusted sources\n- **Use an ad blocker** - Blocks malicious ads\n- **Clear cookies regularly** - Protects privacy\n- **Use private browsing** - For sensitive tasks on shared computers",
                    "markdown": True
                }
            },
            {
                "id": "block-sec-12",
                "type": "callout",
                "content": {
                    "type": "info",
                    "title": "HTTPS Explained",
                    "message": "HTTPS means the connection between your browser and the website is encrypted. Without it (just HTTP), anyone on the same network could see what you're doing."
                }
            }
        ],
        "order_index": 0,
        "duration": "15 minutes",
        "is_required": True
    }

    try:
        security_course = Course(
            id=security_course_data["id"],
            title=security_course_data["title"],
            description=security_course_data["description"],
            short_description=security_course_data.get("short_description"),
            level="beginner",
            status="published",
            category=security_course_data.get("category"),
            instructor_id=security_course_data["instructor_id"],
            is_premium=security_course_data.get("is_premium", False),
            price=security_course_data.get("price", 0.0),
            estimated_hours=security_course_data.get("estimated_hours", 0),
            related_skills=security_course_data.get("related_skills", []),
            xp_reward=security_course_data.get("xp_reward", 0),
            requirements=security_course_data.get("requirements", []),
            objectives=security_course_data.get("objectives", []),
        )
        db.add(security_course)
        db.commit()
        db.refresh(security_course)

        # Create Security modules and sections
        mod_sec_1 = create_module(db, CourseModuleCreate(**security_module_1), security_course.id)
        create_section(db, ModuleSectionCreate(**security_section_1), mod_sec_1.id)

        mod_sec_2 = create_module(db, CourseModuleCreate(**security_module_2), security_course.id)
        create_section(db, ModuleSectionCreate(**security_section_2), mod_sec_2.id)

        mod_sec_3 = create_module(db, CourseModuleCreate(**security_module_3), security_course.id)
        create_section(db, ModuleSectionCreate(**security_section_3), mod_sec_3.id)

        courses.append(security_course)
        print(f"Created course: {security_course.title}")

    except Exception as e:
        print(f"Error creating Security course: {str(e)}")
        db.rollback()

    db.commit()
    return courses


def run_seed():
    """
    Run the seed data script.
    Usage: python -m app.plugins.courses.seed_data
    """
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        print("Seeding IT course data...")
        courses = create_sample_courses(db, instructor_id=1)
        print(f"\nSuccessfully created {len(courses)} courses!")
        for course in courses:
            print(f"  - {course.title} ({course.id})")
    except Exception as e:
        print(f"\nError seeding data: {str(e)}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
