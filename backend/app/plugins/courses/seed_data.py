"""
Seed Data for Courses Plugin
Creates sample courses with modules, sections, and content blocks for testing.
"""
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List

from app.plugins.courses.models import Course, CourseModule, ModuleSection
from app.plugins.courses.schemas import (
    CourseCreate,
    CourseModuleCreate,
    ModuleSectionCreate,
)


def create_sample_courses(db: Session, instructor_id: int = 1) -> List[Course]:
    """
    Create sample courses for testing the LMS plugin.

    Args:
        db: Database session
        instructor_id: ID of the instructor user (default: 1 - admin)

    Returns:
        List of created courses
    """
    courses = []

    # Course 1: Python Fundamentals
    python_course_data = {
        "id": "python-fundamentals",
        "title": "Python Programming Fundamentals",
        "description": "Master the basics of Python programming with hands-on examples and interactive exercises. This comprehensive course covers everything from variables and data types to functions and object-oriented programming.",
        "short_description": "Learn Python from scratch with practical examples",
        "level": "beginner",
        "category": "Programming",
        "instructor_id": instructor_id,
        "is_premium": False,
        "price": 0.0,
        "estimated_hours": 12,
        "related_skills": ["python", "programming", "problem-solving", "debugging"],
        "xp_reward": 500,
        "requirements": [
            "No prior programming experience required",
            "A computer with internet connection",
            "Willingness to practice coding regularly"
        ],
        "objectives": [
            "Understand Python syntax and basic programming concepts",
            "Write functions and work with different data types",
            "Use control flow statements (if/else, loops)",
            "Handle errors and exceptions gracefully",
            "Create and use classes and objects",
            "Work with files and external data"
        ],
        "is_featured": True,
        "status": "published",
        "published_at": datetime.utcnow()
    }

    # Module 1: Getting Started
    module_1_sections = [
        {
            "id": "python-fund-m1-s1",
            "title": "Introduction to Python",
            "content_blocks": [
                {
                    "id": "block-1",
                    "type": "heading",
                    "content": {
                        "text": "Welcome to Python Programming!",
                        "level": 1
                    }
                },
                {
                    "id": "block-2",
                    "type": "text",
                    "content": {
                        "text": "Python is one of the most popular programming languages in the world. It's known for its simplicity, readability, and versatility. Whether you want to build web applications, analyze data, or create automation scripts, Python is an excellent choice.",
                        "markdown": True
                    }
                },
                {
                    "id": "block-3",
                    "type": "callout",
                    "content": {
                        "type": "info",
                        "title": "Why Learn Python?",
                        "message": "Python is beginner-friendly, has a massive community, extensive libraries, and is used by tech giants like Google, Netflix, and NASA!"
                    }
                },
                {
                    "id": "block-4",
                    "type": "video",
                    "content": {
                        "url": "https://www.youtube.com/watch?v=example",
                        "title": "What is Python?",
                        "duration": "5:30"
                    }
                }
            ],
            "order_index": 0,
            "duration": "15 minutes",
            "is_required": True
        },
        {
            "id": "python-fund-m1-s2",
            "title": "Your First Python Program",
            "content_blocks": [
                {
                    "id": "block-5",
                    "type": "heading",
                    "content": {
                        "text": "Hello, World!",
                        "level": 2
                    }
                },
                {
                    "id": "block-6",
                    "type": "text",
                    "content": {
                        "text": "Let's write your first Python program. The traditional first program in any language is 'Hello, World!'",
                        "markdown": True
                    }
                },
                {
                    "id": "block-7",
                    "type": "code",
                    "content": {
                        "code": "print('Hello, World!')",
                        "language": "python",
                        "caption": "Your first Python program",
                        "runnable": True
                    }
                },
                {
                    "id": "block-8",
                    "type": "quiz",
                    "content": {
                        "questions": [
                            {
                                "id": "q1",
                                "question": "What does the print() function do in Python?",
                                "type": "multiple_choice",
                                "options": [
                                    "Displays output to the console",
                                    "Saves data to a file",
                                    "Performs calculations",
                                    "Creates a new variable"
                                ],
                                "correct_answer": 0,
                                "explanation": "The print() function displays output to the console/terminal."
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
        "id": "python-fund-module-1",
        "title": "Getting Started with Python",
        "description": "Introduction to Python and your first program",
        "order_index": 0,
        "duration": "35 minutes",
        "status": "published"
    }

    # Module 2: Variables and Data Types
    module_2_sections = [
        {
            "id": "python-fund-m2-s1",
            "title": "Understanding Variables",
            "content_blocks": [
                {
                    "id": "block-9",
                    "type": "heading",
                    "content": {
                        "text": "Variables in Python",
                        "level": 2
                    }
                },
                {
                    "id": "block-10",
                    "type": "text",
                    "content": {
                        "text": "Variables are containers for storing data values. Unlike other languages, Python has no command for declaring a variable - you create one the moment you assign a value to it.",
                        "markdown": True
                    }
                },
                {
                    "id": "block-11",
                    "type": "code",
                    "content": {
                        "code": "# Creating variables\nname = 'Alice'\nage = 25\nheight = 5.6\nis_student = True\n\nprint(f'{name} is {age} years old')",
                        "language": "python",
                        "caption": "Variable examples",
                        "runnable": True
                    }
                },
                {
                    "id": "block-12",
                    "type": "callout",
                    "content": {
                        "type": "tip",
                        "title": "Naming Conventions",
                        "message": "Use descriptive variable names in lowercase with underscores (snake_case). Avoid single letters except for counters."
                    }
                }
            ],
            "order_index": 0,
            "duration": "25 minutes",
            "is_required": True
        }
    ]

    module_2 = {
        "id": "python-fund-module-2",
        "title": "Variables and Data Types",
        "description": "Learn how to work with different types of data in Python",
        "order_index": 1,
        "duration": "60 minutes",
        "status": "published"
    }

    # Create Python course
    from app.plugins.courses.crud import create_course, create_course_module, create_module_section

    try:
        # Create course
        python_course = create_course(db, CourseCreate(**python_course_data))

        # Create Module 1 and its sections
        mod_1 = create_course_module(
            db,
            python_course.id,
            CourseModuleCreate(**module_1)
        )
        for section_data in module_1_sections:
            create_module_section(
                db,
                mod_1.id,
                ModuleSectionCreate(**section_data)
            )

        # Create Module 2 and its sections
        mod_2 = create_course_module(
            db,
            python_course.id,
            CourseModuleCreate(**module_2)
        )
        for section_data in module_2_sections:
            create_module_section(
                db,
                mod_2.id,
                ModuleSectionCreate(**section_data)
            )

        courses.append(python_course)
        print(f"✅ Created course: {python_course.title}")

    except Exception as e:
        print(f"❌ Error creating Python course: {str(e)}")
        db.rollback()

    # Course 2: Web Development with React
    react_course_data = {
        "id": "react-fundamentals",
        "title": "React Web Development",
        "description": "Build modern, interactive web applications with React. Learn components, hooks, state management, and best practices for building scalable React applications.",
        "short_description": "Master React for building modern web apps",
        "level": "intermediate",
        "category": "Web Development",
        "instructor_id": instructor_id,
        "is_premium": True,
        "price": 49.99,
        "estimated_hours": 20,
        "related_skills": ["react", "javascript", "web-development", "frontend"],
        "xp_reward": 800,
        "requirements": [
            "Basic JavaScript knowledge",
            "Understanding of HTML and CSS",
            "Node.js installed on your computer"
        ],
        "objectives": [
            "Build React components using modern hooks",
            "Manage application state effectively",
            "Handle user events and forms",
            "Make API calls and handle async data",
            "Implement routing in single-page applications",
            "Deploy React applications to production"
        ],
        "is_featured": True,
        "status": "published",
        "published_at": datetime.utcnow()
    }

    react_module_1 = {
        "id": "react-fund-module-1",
        "title": "React Basics",
        "description": "Introduction to React and JSX",
        "order_index": 0,
        "duration": "90 minutes",
        "status": "published"
    }

    react_section_1 = {
        "id": "react-fund-m1-s1",
        "title": "What is React?",
        "content_blocks": [
            {
                "id": "block-react-1",
                "type": "heading",
                "content": {
                    "text": "Introduction to React",
                    "level": 1
                }
            },
            {
                "id": "block-react-2",
                "type": "text",
                "content": {
                    "text": "React is a JavaScript library for building user interfaces. It was developed by Facebook and is now maintained by Meta and a community of developers. React makes it painless to create interactive UIs.",
                    "markdown": True
                }
            },
            {
                "id": "block-react-3",
                "type": "code",
                "content": {
                    "code": "import React from 'react';\n\nfunction Welcome() {\n  return <h1>Hello, React!</h1>;\n}\n\nexport default Welcome;",
                    "language": "javascript",
                    "caption": "A simple React component",
                    "runnable": False
                }
            }
        ],
        "order_index": 0,
        "duration": "30 minutes",
        "is_required": True
    }

    try:
        react_course = create_course(db, CourseCreate(**react_course_data))

        mod_react = create_course_module(
            db,
            react_course.id,
            CourseModuleCreate(**react_module_1)
        )
        create_module_section(
            db,
            mod_react.id,
            ModuleSectionCreate(**react_section_1)
        )

        courses.append(react_course)
        print(f"✅ Created course: {react_course.title}")

    except Exception as e:
        print(f"❌ Error creating React course: {str(e)}")
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
        print("🌱 Seeding course data...")
        courses = create_sample_courses(db, instructor_id=1)
        print(f"\n✨ Successfully created {len(courses)} courses!")
        for course in courses:
            print(f"  - {course.title} ({course.id})")
    except Exception as e:
        print(f"\n❌ Error seeding data: {str(e)}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
