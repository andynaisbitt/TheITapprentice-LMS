# backend/app/plugins/skills/seed.py
"""
Skill System Seed Script

Seeds the 13 default IT skills into the database.
Run with: python -m app.plugins.skills.seed
"""
import logging
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from .models import Skill, SkillCategory

logger = logging.getLogger(__name__)

# The 13 IT Skills
DEFAULT_SKILLS = [
    # Technical Skills (9)
    {
        "name": "Networking",
        "slug": "networking",
        "description": "Understanding of network protocols, architecture, and troubleshooting. Includes TCP/IP, DNS, DHCP, routing, switching, and network security fundamentals.",
        "icon": "🌐",
        "category": SkillCategory.technical,
        "display_order": 1,
    },
    {
        "name": "Security",
        "slug": "security",
        "description": "Cybersecurity principles, threat detection, vulnerability assessment, and security best practices. Covers firewalls, encryption, identity management, and incident response.",
        "icon": "🔒",
        "category": SkillCategory.technical,
        "display_order": 2,
    },
    {
        "name": "Programming",
        "slug": "programming",
        "description": "Software development fundamentals including algorithms, data structures, and coding practices. Covers multiple languages like Python, JavaScript, Java, and C#.",
        "icon": "💻",
        "category": SkillCategory.technical,
        "display_order": 3,
    },
    {
        "name": "Systems Administration",
        "slug": "systems-administration",
        "description": "Managing and maintaining computer systems and servers. Includes Linux/Windows administration, user management, backup strategies, and system monitoring.",
        "icon": "🖥️",
        "category": SkillCategory.technical,
        "display_order": 4,
    },
    {
        "name": "Cloud Computing",
        "slug": "cloud-computing",
        "description": "Cloud platforms and services including AWS, Azure, and GCP. Covers cloud architecture, deployment models, cost optimization, and cloud-native development.",
        "icon": "☁️",
        "category": SkillCategory.technical,
        "display_order": 5,
    },
    {
        "name": "Databases",
        "slug": "databases",
        "description": "Database design, management, and optimization. Includes SQL, NoSQL, database administration, query optimization, and data modeling.",
        "icon": "🗄️",
        "category": SkillCategory.technical,
        "display_order": 6,
    },
    {
        "name": "DevOps",
        "slug": "devops",
        "description": "Development operations practices including CI/CD, containerization, infrastructure as code, and automation. Covers Docker, Kubernetes, Jenkins, and Terraform.",
        "icon": "⚙️",
        "category": SkillCategory.technical,
        "display_order": 7,
    },
    {
        "name": "Web Development",
        "slug": "web-development",
        "description": "Building web applications and services. Covers frontend (HTML, CSS, JavaScript, React), backend (APIs, servers), and full-stack development practices.",
        "icon": "🌍",
        "category": SkillCategory.technical,
        "display_order": 8,
    },
    {
        "name": "Hardware & Support",
        "slug": "hardware-support",
        "description": "Computer hardware, troubleshooting, and technical support. Includes PC assembly, peripherals, help desk operations, and end-user support.",
        "icon": "🔧",
        "category": SkillCategory.technical,
        "display_order": 9,
    },

    # Fundamental Skills (1)
    {
        "name": "Typing",
        "slug": "typing",
        "description": "Touch typing proficiency combining physical dexterity, muscle memory, and cognitive processing for fast, accurate text input. Covers WPM speed, accuracy, keyboard mastery, and typing endurance - a fundamental transferable skill that enhances productivity across all IT disciplines.",
        "icon": "⌨️",
        "category": SkillCategory.technical,
        "display_order": 10,
    },

    # Soft Skills (3)
    {
        "name": "Communication",
        "slug": "communication",
        "description": "Technical and professional communication skills. Includes documentation, presentations, email etiquette, and explaining complex concepts to non-technical audiences.",
        "icon": "💬",
        "category": SkillCategory.soft,
        "display_order": 11,
    },
    {
        "name": "Problem Solving",
        "slug": "problem-solving",
        "description": "Analytical thinking and troubleshooting methodology. Covers root cause analysis, debugging strategies, critical thinking, and systematic problem resolution.",
        "icon": "🧩",
        "category": SkillCategory.soft,
        "display_order": 12,
    },
    {
        "name": "Project Management",
        "slug": "project-management",
        "description": "IT project management methodologies and practices. Includes Agile, Scrum, Kanban, resource planning, risk management, and stakeholder communication.",
        "icon": "📊",
        "category": SkillCategory.soft,
        "display_order": 13,
    },
]


def seed_skills(db: Session) -> dict:
    """
    Seed the default skills into the database.
    Returns a summary of what was created/updated.
    """
    created = 0
    updated = 0
    skipped = 0

    for skill_data in DEFAULT_SKILLS:
        existing = db.query(Skill).filter(Skill.slug == skill_data["slug"]).first()

        if existing:
            # Update if any fields changed (except category which is enum)
            needs_update = False
            for key, value in skill_data.items():
                if key == "category":
                    if existing.category != value:
                        existing.category = value
                        needs_update = True
                elif getattr(existing, key) != value:
                    setattr(existing, key, value)
                    needs_update = True

            if needs_update:
                updated += 1
                logger.info(f"Updated skill: {skill_data['name']}")
            else:
                skipped += 1
        else:
            # Create new skill
            skill = Skill(**skill_data)
            db.add(skill)
            created += 1
            logger.info(f"Created skill: {skill_data['name']}")

    db.commit()

    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "total": len(DEFAULT_SKILLS)
    }


def run_seed():
    """Run the seed script."""
    logger.info("Starting skill seed...")
    db = SessionLocal()
    try:
        result = seed_skills(db)
        logger.info(f"Seed complete: {result}")
        return result
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_seed()
