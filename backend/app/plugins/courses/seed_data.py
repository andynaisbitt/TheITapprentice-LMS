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
