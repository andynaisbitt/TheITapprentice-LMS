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
    """Create tutorial categories"""
    categories = [
        {
            "name": "Web Development",
            "slug": "web-development",
            "description": "Learn modern web development technologies",
            "icon": "🌐",
            "color": "#3B82F6",
            "display_order": 1
        },
        {
            "name": "Programming",
            "slug": "programming",
            "description": "Master programming fundamentals and languages",
            "icon": "💻",
            "color": "#10B981",
            "display_order": 2
        },
        {
            "name": "DevOps",
            "slug": "devops",
            "description": "Infrastructure, deployment, and automation",
            "icon": "⚙️",
            "color": "#F59E0B",
            "display_order": 3
        },
        {
            "name": "Data Science",
            "slug": "data-science",
            "description": "Data analysis, ML, and AI fundamentals",
            "icon": "📊",
            "color": "#8B5CF6",
            "display_order": 4
        },
    ]

    created_categories = {}
    for cat_data in categories:
        existing = db.query(TutorialCategory).filter(
            TutorialCategory.slug == cat_data["slug"]
        ).first()

        if not existing:
            category = TutorialCategory(**cat_data)
            db.add(category)
            db.flush()
            created_categories[cat_data["slug"]] = category
            print(f"[OK] Created category: {cat_data['name']}")
        else:
            created_categories[cat_data["slug"]] = existing
            print(f"- Category already exists: {cat_data['name']}")

    db.commit()
    return created_categories


def create_tutorials(db: Session, categories: dict, admin_user: User):
    """Create sample tutorials"""

    tutorials_data = [
        {
            "title": "Getting Started with React Hooks",
            "slug": "getting-started-with-react-hooks",
            "description": "Learn the fundamentals of React Hooks and how to use them in your applications",
            "difficulty": "beginner",
            "estimated_time_minutes": 45,
            "category": "web-development",
            "thumbnail_url": None,
            "xp_reward": 100,
            "related_skills": ["React", "JavaScript", "Frontend"],
            "is_published": True,
            "is_featured": True,
            "steps": [
                {
                    "step_order": 1,
                    "title": "Introduction to Hooks",
                    "content": """
# What are React Hooks?

React Hooks are functions that let you "hook into" React state and lifecycle features from function components. They were introduced in React 16.8.

## Why Hooks?

- Simplify component logic
- Reuse stateful logic between components
- Avoid class component complexity
- Better code organization
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Hooks were introduced in React 16.8", "Hooks only work in function components"]
                },
                {
                    "step_order": 2,
                    "title": "Using useState Hook",
                    "content": """
# The useState Hook

The `useState` Hook lets you add state to function components.

## Syntax
```javascript
const [state, setState] = useState(initialValue);
```
                    """,
                    "code_example": """import React, { useState } from 'react';

function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}""",
                    "code_language": "javascript",
                    "hints": ["useState returns an array with 2 elements", "The first element is the current state value"]
                },
                {
                    "step_order": 3,
                    "title": "Using useEffect Hook",
                    "content": """
# The useEffect Hook

`useEffect` lets you perform side effects in function components. It serves the same purpose as `componentDidMount`, `componentDidUpdate`, and `componentWillUnmount` in class components.
                    """,
                    "code_example": """import React, { useState, useEffect } from 'react';

function Example() {
  const [count, setCount] = useState(0);

  // Similar to componentDidMount and componentDidUpdate:
  useEffect(() => {
    document.title = `You clicked ${count} times`;
  });

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}""",
                    "code_language": "javascript",
                    "hints": ["useEffect runs after every render by default", "You can control when it runs with a dependency array"]
                },
            ]
        },
        {
            "title": "Python for Beginners",
            "slug": "python-for-beginners",
            "description": "Learn Python programming from scratch with hands-on examples",
            "difficulty": "beginner",
            "estimated_time_minutes": 60,
            "category": "programming",
            "thumbnail_url": None,
            "xp_reward": 150,
            "related_skills": ["Python", "Programming", "Basics"],
            "is_published": True,
            "is_featured": False,
            "steps": [
                {
                    "step_order": 1,
                    "title": "Hello World",
                    "content": """
# Your First Python Program

Let's start with the classic "Hello, World!" program. This is the traditional first program when learning a new language.
                    """,
                    "code_example": """# This is a comment
print("Hello, World!")

# You can also print variables
name = "Python"
print(f"Hello, {name}!")""",
                    "code_language": "python",
                    "hints": ["The print() function displays output", "Use f-strings for string formatting"]
                },
                {
                    "step_order": 2,
                    "title": "Variables and Data Types",
                    "content": """
# Variables in Python

Python has several built-in data types:
- **int**: Integer numbers
- **float**: Decimal numbers
- **str**: Text strings
- **bool**: True or False
- **list**: Ordered collections
- **dict**: Key-value pairs
                    """,
                    "code_example": """# Different data types
age = 25                    # int
height = 5.9               # float
name = "Alice"             # str
is_student = True          # bool
hobbies = ["reading", "coding"]  # list
person = {"name": "Bob", "age": 30}  # dict

print(type(age))           # <class 'int'>
print(type(hobbies))       # <class 'list'>""",
                    "code_language": "python",
                    "hints": ["Python is dynamically typed", "Use type() to check variable types"]
                },
                {
                    "step_order": 3,
                    "title": "Control Flow",
                    "content": """
# If Statements and Loops

Learn how to control the flow of your program with conditionals and loops.
                    """,
                    "code_example": """# If statement
age = 18
if age >= 18:
    print("You are an adult")
else:
    print("You are a minor")

# For loop
fruits = ["apple", "banana", "cherry"]
for fruit in fruits:
    print(fruit)

# While loop
count = 0
while count < 5:
    print(count)
    count += 1""",
                    "code_language": "python",
                    "hints": ["Indentation is important in Python", "Use for loops to iterate over sequences"]
                },
            ]
        },
        {
            "title": "Docker Basics",
            "slug": "docker-basics",
            "description": "Learn how to containerize applications with Docker",
            "difficulty": "intermediate",
            "estimated_time_minutes": 90,
            "category": "devops",
            "thumbnail_url": None,
            "xp_reward": 200,
            "related_skills": ["Docker", "DevOps", "Containers"],
            "is_published": True,
            "is_featured": True,
            "steps": [
                {
                    "step_order": 1,
                    "title": "What is Docker?",
                    "content": """
# Introduction to Docker

Docker is a platform for developing, shipping, and running applications in containers. Containers are lightweight, standalone packages that include everything needed to run an application.

## Benefits
- Consistency across environments
- Isolation
- Resource efficiency
- Scalability
                    """,
                    "code_example": None,
                    "code_language": None,
                    "hints": ["Containers are not VMs", "Docker uses OS-level virtualization"]
                },
                {
                    "step_order": 2,
                    "title": "Creating a Dockerfile",
                    "content": """
# Writing Your First Dockerfile

A Dockerfile is a text file that contains instructions for building a Docker image.
                    """,
                    "code_example": """# Use an official Python runtime as base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "app.py"]""",
                    "code_language": "dockerfile",
                    "hints": ["Each instruction creates a layer", "Order matters for caching"]
                },
                {
                    "step_order": 3,
                    "title": "Building and Running Containers",
                    "content": """
# Docker Commands

Learn the essential Docker commands to build and run containers.
                    """,
                    "code_example": """# Build an image
docker build -t myapp:latest .

# Run a container
docker run -d -p 8000:8000 --name myapp-container myapp:latest

# List running containers
docker ps

# Stop a container
docker stop myapp-container

# Remove a container
docker rm myapp-container

# View logs
docker logs myapp-container""",
                    "code_language": "bash",
                    "hints": ["-d runs in detached mode", "-p maps ports host:container"]
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
        print(f"[OK] Created tutorial: {tutorial_data['title']} ({len(steps_data)} steps)")


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
        print(f"\n[OK] Created {len(categories)} categories\n")

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
