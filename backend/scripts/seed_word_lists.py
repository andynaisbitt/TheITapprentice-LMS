#!/usr/bin/env python3
"""
Seed Script: Typing Game Word Lists
Creates initial word lists for the typing practice game.

Run: python scripts/seed_word_lists.py
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import all models first to ensure relationships are set up
from app.core.database import SessionLocal
from app.users.models import User  # Import User first to resolve relationships
from app.plugins.typing_game.models import TypingWordList


def seed_word_lists():
    """Seed initial word lists for typing practice"""
    db = SessionLocal()

    try:
        word_lists = [
            # Easy word lists
            {
                "id": "common-words",
                "name": "Common English Words",
                "description": "The most frequently used English words - perfect for beginners",
                "difficulty": "easy",
                "theme": "general",
                "words": [
                    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
                    "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
                    "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
                    "an", "will", "my", "one", "all", "would", "there", "their", "what",
                    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me"
                ],
                "unlock_level": 1,
                "is_featured": True,
                "is_active": True,
            },
            {
                "id": "short-words",
                "name": "Short Words Sprint",
                "description": "Quick 3-4 letter words for speed building",
                "difficulty": "easy",
                "theme": "general",
                "words": [
                    "cat", "dog", "run", "jump", "eat", "see", "go", "up", "no", "yes",
                    "hot", "cold", "big", "small", "old", "new", "good", "bad", "high", "low",
                    "fast", "slow", "long", "short", "hard", "soft", "wet", "dry", "red", "blue"
                ],
                "unlock_level": 1,
                "is_featured": False,
                "is_active": True,
            },
            # Medium word lists
            {
                "id": "programming-terms",
                "name": "Programming Keywords",
                "description": "Common programming terms and reserved keywords",
                "difficulty": "medium",
                "theme": "programming",
                "words": [
                    "function", "variable", "const", "return", "import", "export",
                    "class", "interface", "async", "await", "promise", "object",
                    "array", "string", "number", "boolean", "undefined", "null",
                    "console", "module", "require", "default", "extends", "implements"
                ],
                "unlock_level": 3,
                "is_featured": True,
                "is_active": True,
            },
            {
                "id": "web-development",
                "name": "Web Development",
                "description": "HTML, CSS, and JavaScript terminology",
                "difficulty": "medium",
                "theme": "technology",
                "words": [
                    "component", "element", "attribute", "selector", "property",
                    "flexbox", "grid", "margin", "padding", "border", "responsive",
                    "viewport", "breakpoint", "animation", "transition", "transform",
                    "fetch", "api", "endpoint", "request", "response", "header"
                ],
                "unlock_level": 3,
                "is_featured": False,
                "is_active": True,
            },
            {
                "id": "tech-terms",
                "name": "Technology Terms",
                "description": "Modern technology vocabulary",
                "difficulty": "medium",
                "theme": "technology",
                "words": [
                    "algorithm", "database", "encryption", "bandwidth", "protocol",
                    "server", "client", "network", "firewall", "authentication",
                    "authorization", "middleware", "framework", "library", "deployment",
                    "container", "kubernetes", "microservice", "scalable", "distributed"
                ],
                "unlock_level": 4,
                "is_featured": False,
                "is_active": True,
            },
            # Hard word lists
            {
                "id": "linux-commands",
                "name": "Linux Commands",
                "description": "Essential Linux terminal commands",
                "difficulty": "hard",
                "theme": "technology",
                "words": [
                    "chmod", "chown", "grep", "sed", "awk", "find", "xargs",
                    "sudo", "apt-get", "systemctl", "journalctl", "netstat",
                    "iptables", "ssh", "scp", "rsync", "crontab", "tar",
                    "curl", "wget", "nginx", "docker", "kubernetes", "ansible"
                ],
                "unlock_level": 5,
                "is_featured": True,
                "is_active": True,
            },
            {
                "id": "data-science",
                "name": "Data Science",
                "description": "Data science and machine learning terms",
                "difficulty": "hard",
                "theme": "science",
                "words": [
                    "regression", "classification", "clustering", "dimensionality",
                    "overfitting", "underfitting", "validation", "hyperparameter",
                    "gradient", "optimization", "neural", "network", "convolution",
                    "recurrent", "transformer", "attention", "embedding", "tokenization"
                ],
                "unlock_level": 6,
                "is_featured": False,
                "is_active": True,
            },
            {
                "id": "business-terms",
                "name": "Business English",
                "description": "Professional business vocabulary",
                "difficulty": "hard",
                "theme": "business",
                "words": [
                    "stakeholder", "deliverable", "leverage", "synergy", "scalable",
                    "proactive", "paradigm", "benchmark", "incentivize", "streamline",
                    "optimization", "acquisition", "revenue", "quarterly", "projection",
                    "implementation", "infrastructure", "sustainability", "compliance"
                ],
                "unlock_level": 5,
                "is_featured": False,
                "is_active": True,
            },
            # Expert word lists
            {
                "id": "code-snippets",
                "name": "Code Snippets",
                "description": "Real code patterns and syntax - for experts only",
                "difficulty": "expert",
                "theme": "programming",
                "words": [
                    "const handleSubmit = async (e) => {",
                    "import { useState, useEffect } from 'react';",
                    "export default function App() {",
                    "const [data, setData] = useState(null);",
                    "useEffect(() => { fetchData(); }, []);",
                    "try { await response.json(); } catch (e) {}",
                    "Object.keys(obj).map(key => obj[key])",
                    "arr.filter(item => item.active)",
                    "const { id, name, ...rest } = props;",
                    "if (!user?.isAuthenticated) return null;"
                ],
                "unlock_level": 8,
                "is_featured": True,
                "is_active": True,
            },
            {
                "id": "sql-queries",
                "name": "SQL Queries",
                "description": "Database query syntax and keywords",
                "difficulty": "expert",
                "theme": "programming",
                "words": [
                    "SELECT * FROM users WHERE active = true;",
                    "INSERT INTO products (name, price) VALUES",
                    "UPDATE orders SET status = 'shipped'",
                    "DELETE FROM sessions WHERE expired = true;",
                    "JOIN customers ON orders.customer_id",
                    "GROUP BY category HAVING COUNT(*) > 5",
                    "ORDER BY created_at DESC LIMIT 10",
                    "CREATE INDEX idx_email ON users(email);",
                    "ALTER TABLE posts ADD COLUMN views INT;",
                    "INNER JOIN products p ON o.product_id = p.id"
                ],
                "unlock_level": 9,
                "is_featured": False,
                "is_active": True,
            },
        ]

        created_count = 0
        updated_count = 0

        for wl_data in word_lists:
            # Check if word list exists
            existing = db.query(TypingWordList).filter(
                TypingWordList.id == wl_data["id"]
            ).first()

            if existing:
                # Update existing
                for key, value in wl_data.items():
                    setattr(existing, key, value)
                updated_count += 1
                print(f"  Updated: {wl_data['name']}")
            else:
                # Create new
                word_list = TypingWordList(**wl_data)
                db.add(word_list)
                created_count += 1
                print(f"  Created: {wl_data['name']}")

        db.commit()
        print(f"\nWord lists seeded: {created_count} created, {updated_count} updated")

    except Exception as e:
        db.rollback()
        print(f"Error seeding word lists: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("Seeding typing game word lists...")
    seed_word_lists()
    print("Done!")
