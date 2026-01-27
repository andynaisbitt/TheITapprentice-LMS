# backend/app/plugins/quizzes/seed_data.py
"""
Quiz Seed Data Script
Creates beginner-friendly IT quizzes for TheITApprentice platform.
Run with: python -m app.plugins.quizzes.seed_data
"""
import sys
from pathlib import Path
from sqlalchemy.orm import Session

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from app.core.database import SessionLocal
from app.plugins.quizzes.models import Quiz, QuizQuestion, QuizDifficulty, QuizStatus, QuestionType


# Quiz 1: IT Basics Quiz
IT_BASICS_QUIZ = {
    "id": "it-basics-quiz",
    "title": "IT Basics Quiz",
    "description": "Test your knowledge of fundamental IT concepts including hardware, software, and basic troubleshooting.",
    "instructions": "Answer all questions to the best of your ability. You need 70% to pass. Good luck!",
    "category": "IT Fundamentals",
    "tags": ["beginner", "hardware", "software", "basics"],
    "difficulty": QuizDifficulty.EASY,
    "related_skills": ["hardware-support", "problem-solving"],
    "time_limit_minutes": 15,
    "passing_score": 70,
    "max_attempts": 0,
    "xp_reward": 50,
    "xp_perfect": 100,
    "status": QuizStatus.PUBLISHED,
    "is_featured": True,
    "questions": [
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does CPU stand for?",
            "options": [
                {"id": "a", "text": "Central Processing Unit", "is_correct": True},
                {"id": "b", "text": "Computer Personal Unit", "is_correct": False},
                {"id": "c", "text": "Central Power Unit", "is_correct": False},
                {"id": "d", "text": "Core Processing Utility", "is_correct": False}
            ],
            "correct_answer": "a",
            "explanation": "CPU stands for Central Processing Unit. It's often called the 'brain' of the computer because it performs all the calculations and logic operations.",
            "points": 10,
            "order_index": 1
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "RAM is a type of permanent storage that keeps data even when the computer is turned off.",
            "options": [
                {"id": "true", "text": "True", "is_correct": False},
                {"id": "false", "text": "False", "is_correct": True}
            ],
            "correct_answer": "false",
            "explanation": "RAM (Random Access Memory) is volatile memory - it loses all data when power is removed. Hard drives and SSDs are permanent storage.",
            "points": 10,
            "order_index": 2
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which of the following is an INPUT device?",
            "options": [
                {"id": "a", "text": "Monitor", "is_correct": False},
                {"id": "b", "text": "Keyboard", "is_correct": True},
                {"id": "c", "text": "Printer", "is_correct": False},
                {"id": "d", "text": "Speakers", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "A keyboard is an input device because it sends data INTO the computer. Monitors, printers, and speakers are output devices.",
            "points": 10,
            "order_index": 3
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What file extension indicates a Microsoft Word document?",
            "options": [
                {"id": "a", "text": ".exe", "is_correct": False},
                {"id": "b", "text": ".pdf", "is_correct": False},
                {"id": "c", "text": ".docx", "is_correct": True},
                {"id": "d", "text": ".jpg", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": ".docx is the file extension for Microsoft Word documents. .exe is an executable program, .pdf is Adobe PDF, and .jpg is an image file.",
            "points": 10,
            "order_index": 4
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is the first step in basic troubleshooting?",
            "options": [
                {"id": "a", "text": "Reinstall the operating system", "is_correct": False},
                {"id": "b", "text": "Call technical support", "is_correct": False},
                {"id": "c", "text": "Have you tried turning it off and on again?", "is_correct": True},
                {"id": "d", "text": "Buy a new computer", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Restarting the device is often the first troubleshooting step because it clears temporary issues and resets the system state. It solves a surprising number of problems!",
            "points": 10,
            "order_index": 5
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does an Operating System (OS) do?",
            "options": [
                {"id": "a", "text": "Only runs games", "is_correct": False},
                {"id": "b", "text": "Manages hardware and software resources", "is_correct": True},
                {"id": "c", "text": "Only protects against viruses", "is_correct": False},
                {"id": "d", "text": "Only connects to the internet", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "An Operating System manages all hardware and software resources on a computer. Examples include Windows, macOS, and Linux.",
            "points": 10,
            "order_index": 6
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which storage device is typically faster?",
            "options": [
                {"id": "a", "text": "HDD (Hard Disk Drive)", "is_correct": False},
                {"id": "b", "text": "Floppy Disk", "is_correct": False},
                {"id": "c", "text": "SSD (Solid State Drive)", "is_correct": True},
                {"id": "d", "text": "CD-ROM", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "SSDs are much faster than HDDs because they have no moving parts and use flash memory. HDDs use spinning magnetic disks which are slower.",
            "points": 10,
            "order_index": 7
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is a web browser?",
            "options": [
                {"id": "a", "text": "A program that creates websites", "is_correct": False},
                {"id": "b", "text": "A program used to access and view websites", "is_correct": True},
                {"id": "c", "text": "A type of computer virus", "is_correct": False},
                {"id": "d", "text": "A file storage system", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "A web browser (like Chrome, Firefox, Edge, or Safari) is software that lets you access and view websites on the internet.",
            "points": 10,
            "order_index": 8
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What keyboard shortcut is used to copy selected text?",
            "options": [
                {"id": "a", "text": "Ctrl + V", "is_correct": False},
                {"id": "b", "text": "Ctrl + X", "is_correct": False},
                {"id": "c", "text": "Ctrl + C", "is_correct": True},
                {"id": "d", "text": "Ctrl + Z", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Ctrl+C copies, Ctrl+V pastes, Ctrl+X cuts, and Ctrl+Z undoes the last action. These are essential shortcuts for any IT professional!",
            "points": 10,
            "order_index": 9
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "An IP address is like a home address for your computer on a network.",
            "options": [
                {"id": "true", "text": "True", "is_correct": True},
                {"id": "false", "text": "False", "is_correct": False}
            ],
            "correct_answer": "true",
            "explanation": "Correct! An IP address uniquely identifies a device on a network, just like a home address identifies where you live.",
            "points": 10,
            "order_index": 10
        }
    ]
}


# Quiz 2: Networking Fundamentals Quiz
NETWORKING_QUIZ = {
    "id": "networking-fundamentals-quiz",
    "title": "Networking Fundamentals Quiz",
    "description": "Test your understanding of basic networking concepts including IP addresses, DNS, and network types.",
    "instructions": "This quiz covers essential networking knowledge. Take your time and think through each answer.",
    "category": "Networking",
    "tags": ["networking", "beginner", "ip", "dns"],
    "difficulty": QuizDifficulty.EASY,
    "related_skills": ["networking"],
    "time_limit_minutes": 15,
    "passing_score": 70,
    "max_attempts": 0,
    "xp_reward": 50,
    "xp_perfect": 100,
    "status": QuizStatus.PUBLISHED,
    "is_featured": True,
    "questions": [
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does LAN stand for?",
            "options": [
                {"id": "a", "text": "Large Area Network", "is_correct": False},
                {"id": "b", "text": "Local Area Network", "is_correct": True},
                {"id": "c", "text": "Long Access Network", "is_correct": False},
                {"id": "d", "text": "Linked Application Node", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "LAN stands for Local Area Network. It's a network confined to a small geographic area, like a home, office, or building.",
            "points": 10,
            "order_index": 1
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does DNS stand for and what does it do?",
            "options": [
                {"id": "a", "text": "Digital Network Service - provides antivirus protection", "is_correct": False},
                {"id": "b", "text": "Domain Name System - translates domain names to IP addresses", "is_correct": True},
                {"id": "c", "text": "Data Node Server - stores files on the network", "is_correct": False},
                {"id": "d", "text": "Dynamic Naming Service - assigns computer names", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "DNS (Domain Name System) translates human-readable domain names (like google.com) into IP addresses (like 142.250.80.46) that computers use to identify each other.",
            "points": 10,
            "order_index": 2
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which device connects multiple devices in a local network and forwards data to the correct destination?",
            "options": [
                {"id": "a", "text": "Modem", "is_correct": False},
                {"id": "b", "text": "Router", "is_correct": True},
                {"id": "c", "text": "Monitor", "is_correct": False},
                {"id": "d", "text": "Printer", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "A router connects devices in a network and directs (routes) traffic between them and the internet. A modem connects your network to your ISP.",
            "points": 10,
            "order_index": 3
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "Wi-Fi and the Internet are the same thing.",
            "options": [
                {"id": "true", "text": "True", "is_correct": False},
                {"id": "false", "text": "False", "is_correct": True}
            ],
            "correct_answer": "false",
            "explanation": "Wi-Fi is a wireless technology for connecting devices to a local network. The Internet is a global network of networks. You can have Wi-Fi without internet access!",
            "points": 10,
            "order_index": 4
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is the purpose of a firewall?",
            "options": [
                {"id": "a", "text": "To speed up internet connection", "is_correct": False},
                {"id": "b", "text": "To prevent unauthorized access to a network", "is_correct": True},
                {"id": "c", "text": "To store backup files", "is_correct": False},
                {"id": "d", "text": "To connect to wireless networks", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "A firewall monitors and controls network traffic, blocking unauthorized access while permitting legitimate communication.",
            "points": 10,
            "order_index": 5
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which of the following is a valid IPv4 address?",
            "options": [
                {"id": "a", "text": "192.168.1.256", "is_correct": False},
                {"id": "b", "text": "192.168.1.1", "is_correct": True},
                {"id": "c", "text": "192.168.1.1.1", "is_correct": False},
                {"id": "d", "text": "192.168.1", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "IPv4 addresses have 4 numbers (octets) separated by dots, each ranging from 0-255. 192.168.1.256 is invalid because 256 exceeds the maximum value.",
            "points": 10,
            "order_index": 6
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What protocol is commonly used for secure web browsing?",
            "options": [
                {"id": "a", "text": "HTTP", "is_correct": False},
                {"id": "b", "text": "FTP", "is_correct": False},
                {"id": "c", "text": "HTTPS", "is_correct": True},
                {"id": "d", "text": "SMTP", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "HTTPS (HTTP Secure) encrypts web traffic using TLS/SSL. Look for the padlock icon in your browser to confirm a site uses HTTPS.",
            "points": 10,
            "order_index": 7
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does DHCP do?",
            "options": [
                {"id": "a", "text": "Protects against malware", "is_correct": False},
                {"id": "b", "text": "Automatically assigns IP addresses to devices", "is_correct": True},
                {"id": "c", "text": "Speeds up downloads", "is_correct": False},
                {"id": "d", "text": "Creates secure passwords", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses to devices on a network, so you don't have to configure them manually.",
            "points": 10,
            "order_index": 8
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is the default port number for HTTP?",
            "options": [
                {"id": "a", "text": "21", "is_correct": False},
                {"id": "b", "text": "22", "is_correct": False},
                {"id": "c", "text": "80", "is_correct": True},
                {"id": "d", "text": "443", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "HTTP uses port 80 by default. HTTPS uses port 443, FTP uses port 21, and SSH uses port 22.",
            "points": 10,
            "order_index": 9
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "A WAN (Wide Area Network) covers a larger geographic area than a LAN.",
            "options": [
                {"id": "true", "text": "True", "is_correct": True},
                {"id": "false", "text": "False", "is_correct": False}
            ],
            "correct_answer": "true",
            "explanation": "Correct! WAN (Wide Area Network) spans large distances, connecting LANs across cities or countries. The internet itself is the largest WAN.",
            "points": 10,
            "order_index": 10
        }
    ]
}


# Quiz 3: Cybersecurity Basics Quiz
CYBERSECURITY_QUIZ = {
    "id": "cybersecurity-basics-quiz",
    "title": "Cybersecurity Basics Quiz",
    "description": "Test your knowledge of essential cybersecurity concepts including passwords, phishing, and safe browsing practices.",
    "instructions": "Security knowledge is crucial for every IT professional. This quiz covers the fundamentals.",
    "category": "Security",
    "tags": ["security", "phishing", "passwords", "malware"],
    "difficulty": QuizDifficulty.MEDIUM,
    "related_skills": ["security"],
    "time_limit_minutes": 12,
    "passing_score": 70,
    "max_attempts": 0,
    "xp_reward": 75,
    "xp_perfect": 150,
    "status": QuizStatus.PUBLISHED,
    "is_featured": True,
    "questions": [
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is phishing?",
            "options": [
                {"id": "a", "text": "A type of computer virus", "is_correct": False},
                {"id": "b", "text": "Fraudulent attempts to obtain sensitive information by disguising as trustworthy entity", "is_correct": True},
                {"id": "c", "text": "A method to speed up internet", "is_correct": False},
                {"id": "d", "text": "A secure email protocol", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "Phishing is a social engineering attack where criminals impersonate trusted entities to trick you into revealing sensitive information like passwords or credit card numbers.",
            "points": 10,
            "order_index": 1
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which password is the MOST secure?",
            "options": [
                {"id": "a", "text": "password123", "is_correct": False},
                {"id": "b", "text": "MyDog'sName", "is_correct": False},
                {"id": "c", "text": "Tr0ub4dor&3", "is_correct": False},
                {"id": "d", "text": "correct-horse-battery-staple", "is_correct": True}
            ],
            "correct_answer": "d",
            "explanation": "Long passphrases (like 'correct-horse-battery-staple') are more secure because they're harder to crack but easier to remember. Short complex passwords can be brute-forced faster.",
            "points": 10,
            "order_index": 2
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "Using the same password for multiple accounts is a safe practice.",
            "options": [
                {"id": "true", "text": "True", "is_correct": False},
                {"id": "false", "text": "False", "is_correct": True}
            ],
            "correct_answer": "false",
            "explanation": "Never reuse passwords! If one account is compromised, all accounts with that password become vulnerable. Use a password manager to generate and store unique passwords.",
            "points": 10,
            "order_index": 3
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is Two-Factor Authentication (2FA)?",
            "options": [
                {"id": "a", "text": "Using two different passwords", "is_correct": False},
                {"id": "b", "text": "Requiring two forms of identity verification", "is_correct": True},
                {"id": "c", "text": "Having two antivirus programs", "is_correct": False},
                {"id": "d", "text": "Logging in from two devices", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "2FA requires something you know (password) plus something you have (phone/token) or are (fingerprint). This makes accounts much harder to compromise.",
            "points": 10,
            "order_index": 4
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What type of malware encrypts files and demands payment for the decryption key?",
            "options": [
                {"id": "a", "text": "Virus", "is_correct": False},
                {"id": "b", "text": "Worm", "is_correct": False},
                {"id": "c", "text": "Ransomware", "is_correct": True},
                {"id": "d", "text": "Spyware", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Ransomware encrypts your files and demands payment (ransom) for the decryption key. Prevention through backups and security awareness is the best defense.",
            "points": 10,
            "order_index": 5
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which of these is a sign of a phishing email?",
            "options": [
                {"id": "a", "text": "The email is from your known colleague", "is_correct": False},
                {"id": "b", "text": "Urgent request to click a link or verify your account", "is_correct": True},
                {"id": "c", "text": "Professional formatting and correct grammar", "is_correct": False},
                {"id": "d", "text": "Email includes a normal signature", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "Phishing emails often create urgency ('Act now or your account will be closed!'), contain suspicious links, have poor grammar, or come from slightly misspelled email addresses.",
            "points": 10,
            "order_index": 6
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "Keeping your software and operating system updated helps protect against security vulnerabilities.",
            "options": [
                {"id": "true", "text": "True", "is_correct": True},
                {"id": "false", "text": "False", "is_correct": False}
            ],
            "correct_answer": "true",
            "explanation": "Correct! Updates often include security patches that fix known vulnerabilities. Keeping software updated is one of the most effective security practices.",
            "points": 10,
            "order_index": 7
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does encryption do?",
            "options": [
                {"id": "a", "text": "Deletes files permanently", "is_correct": False},
                {"id": "b", "text": "Converts data into a coded format that can only be read with a key", "is_correct": True},
                {"id": "c", "text": "Compresses files to save space", "is_correct": False},
                {"id": "d", "text": "Speeds up data transfer", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "Encryption scrambles data so only authorized parties with the decryption key can read it. It's essential for protecting sensitive data in transit and at rest.",
            "points": 10,
            "order_index": 8
        }
    ]
}


# Quiz 4: Python Basics Quiz
PYTHON_QUIZ = {
    "id": "python-basics-quiz",
    "title": "Python Basics Quiz",
    "description": "Test your knowledge of Python programming fundamentals including variables, data types, and control flow.",
    "instructions": "This quiz covers Python basics. Some questions include code - read them carefully!",
    "category": "Programming",
    "tags": ["python", "programming", "beginner", "coding"],
    "difficulty": QuizDifficulty.EASY,
    "related_skills": ["programming"],
    "time_limit_minutes": 15,
    "passing_score": 70,
    "max_attempts": 0,
    "xp_reward": 50,
    "xp_perfect": 100,
    "status": QuizStatus.PUBLISHED,
    "is_featured": True,
    "questions": [
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What will this code print?\n\nprint('Hello, World!')",
            "options": [
                {"id": "a", "text": "Hello, World!", "is_correct": True},
                {"id": "b", "text": "print('Hello, World!')", "is_correct": False},
                {"id": "c", "text": "Hello World", "is_correct": False},
                {"id": "d", "text": "Error", "is_correct": False}
            ],
            "correct_answer": "a",
            "explanation": "The print() function outputs text to the console. The text inside the quotes is displayed exactly as written.",
            "code_language": "python",
            "points": 10,
            "order_index": 1
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is the data type of the variable x in: x = 42",
            "options": [
                {"id": "a", "text": "str (string)", "is_correct": False},
                {"id": "b", "text": "int (integer)", "is_correct": True},
                {"id": "c", "text": "float", "is_correct": False},
                {"id": "d", "text": "bool (boolean)", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "42 is a whole number, so Python assigns it the int (integer) data type. If it were 42.0, it would be a float.",
            "code_language": "python",
            "points": 10,
            "order_index": 2
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What symbol is used for comments in Python?",
            "options": [
                {"id": "a", "text": "//", "is_correct": False},
                {"id": "b", "text": "/* */", "is_correct": False},
                {"id": "c", "text": "#", "is_correct": True},
                {"id": "d", "text": "<!--", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Python uses # for single-line comments. Everything after # on that line is ignored by Python.",
            "points": 10,
            "order_index": 3
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What will this code print?\n\nx = 5\ny = 3\nprint(x + y)",
            "options": [
                {"id": "a", "text": "53", "is_correct": False},
                {"id": "b", "text": "8", "is_correct": True},
                {"id": "c", "text": "x + y", "is_correct": False},
                {"id": "d", "text": "xy", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "When x and y are numbers, the + operator performs addition. 5 + 3 = 8.",
            "code_language": "python",
            "points": 10,
            "order_index": 4
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which of the following creates a list in Python?",
            "options": [
                {"id": "a", "text": "my_list = {1, 2, 3}", "is_correct": False},
                {"id": "b", "text": "my_list = (1, 2, 3)", "is_correct": False},
                {"id": "c", "text": "my_list = [1, 2, 3]", "is_correct": True},
                {"id": "d", "text": "my_list = <1, 2, 3>", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Lists in Python use square brackets []. Curly braces {} create sets or dictionaries, and parentheses () create tuples.",
            "code_language": "python",
            "points": 10,
            "order_index": 5
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "In Python, variable names are case-sensitive (myVar and myvar are different variables).",
            "options": [
                {"id": "true", "text": "True", "is_correct": True},
                {"id": "false", "text": "False", "is_correct": False}
            ],
            "correct_answer": "true",
            "explanation": "Correct! Python is case-sensitive. myVar, MyVar, and myvar are all treated as different variables.",
            "points": 10,
            "order_index": 6
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is the output of: print(len('Hello'))",
            "options": [
                {"id": "a", "text": "4", "is_correct": False},
                {"id": "b", "text": "5", "is_correct": True},
                {"id": "c", "text": "Hello", "is_correct": False},
                {"id": "d", "text": "len('Hello')", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "The len() function returns the length (number of characters) of a string. 'Hello' has 5 characters: H-e-l-l-o.",
            "code_language": "python",
            "points": 10,
            "order_index": 7
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which keyword is used to define a function in Python?",
            "options": [
                {"id": "a", "text": "function", "is_correct": False},
                {"id": "b", "text": "func", "is_correct": False},
                {"id": "c", "text": "def", "is_correct": True},
                {"id": "d", "text": "define", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Python uses 'def' to define functions. Example: def my_function():",
            "points": 10,
            "order_index": 8
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What will this code print?\n\nfor i in range(3):\n    print(i)",
            "options": [
                {"id": "a", "text": "1 2 3", "is_correct": False},
                {"id": "b", "text": "0 1 2", "is_correct": True},
                {"id": "c", "text": "0 1 2 3", "is_correct": False},
                {"id": "d", "text": "1 2", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "range(3) generates numbers 0, 1, 2 (three numbers starting from 0). Python uses zero-based indexing.",
            "code_language": "python",
            "points": 10,
            "order_index": 9
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What comparison operator checks if two values are equal?",
            "options": [
                {"id": "a", "text": "=", "is_correct": False},
                {"id": "b", "text": "==", "is_correct": True},
                {"id": "c", "text": "===", "is_correct": False},
                {"id": "d", "text": "!=", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "== checks equality, = is for assignment. != checks inequality. Python doesn't use === like JavaScript.",
            "points": 10,
            "order_index": 10
        }
    ]
}


# Quiz 5: Help Desk & Support Quiz
HELPDESK_QUIZ = {
    "id": "help-desk-support-quiz",
    "title": "Help Desk & Support Quiz",
    "description": "Test your knowledge of IT support best practices, customer service, and troubleshooting methodology.",
    "instructions": "This quiz covers essential help desk and IT support concepts. Think about real-world scenarios!",
    "category": "IT Support",
    "tags": ["helpdesk", "support", "customer-service", "troubleshooting"],
    "difficulty": QuizDifficulty.EASY,
    "related_skills": ["hardware-support", "communication", "problem-solving"],
    "time_limit_minutes": 12,
    "passing_score": 70,
    "max_attempts": 0,
    "xp_reward": 50,
    "xp_perfect": 100,
    "status": QuizStatus.PUBLISHED,
    "is_featured": False,
    "questions": [
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "A user calls saying their computer 'isn't working.' What should you do first?",
            "options": [
                {"id": "a", "text": "Tell them to restart it and call back if it still doesn't work", "is_correct": False},
                {"id": "b", "text": "Ask clarifying questions to understand the specific problem", "is_correct": True},
                {"id": "c", "text": "Escalate immediately to a senior technician", "is_correct": False},
                {"id": "d", "text": "Schedule an on-site visit", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "Always gather information first! 'Not working' could mean many things. Ask what they were trying to do and what exactly is happening.",
            "points": 10,
            "order_index": 1
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is a 'ticket' in IT support?",
            "options": [
                {"id": "a", "text": "A receipt for paid services", "is_correct": False},
                {"id": "b", "text": "A documented record of a support request", "is_correct": True},
                {"id": "c", "text": "A license for software", "is_correct": False},
                {"id": "d", "text": "An error message", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "A support ticket is a formal record of a user's issue or request. It tracks the problem, actions taken, and resolution for accountability and knowledge sharing.",
            "points": 10,
            "order_index": 2
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "When should you escalate an issue to a higher tier of support?",
            "options": [
                {"id": "a", "text": "Immediately for all issues", "is_correct": False},
                {"id": "b", "text": "Never - you should solve everything yourself", "is_correct": False},
                {"id": "c", "text": "When the issue is beyond your skill level or authorization", "is_correct": True},
                {"id": "d", "text": "Only when the user requests it", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Escalate when an issue requires expertise or access you don't have. Knowing when to escalate is a sign of professionalism, not weakness.",
            "points": 10,
            "order_index": 3
        },
        {
            "question_type": QuestionType.TRUE_FALSE,
            "question_text": "It's acceptable to use technical jargon when explaining solutions to non-technical users.",
            "options": [
                {"id": "true", "text": "True", "is_correct": False},
                {"id": "false", "text": "False", "is_correct": True}
            ],
            "correct_answer": "false",
            "explanation": "Avoid jargon with non-technical users. Use plain language and analogies they can understand. Your job is to help them, not impress them with terminology.",
            "points": 10,
            "order_index": 4
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What is the purpose of documentation in IT support?",
            "options": [
                {"id": "a", "text": "To create extra work for technicians", "is_correct": False},
                {"id": "b", "text": "To track issues, solutions, and build a knowledge base", "is_correct": True},
                {"id": "c", "text": "Only for billing purposes", "is_correct": False},
                {"id": "d", "text": "To report users who cause problems", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "Documentation helps track issues, ensures continuity, builds organizational knowledge, and provides evidence of actions taken. It's essential for professional IT support.",
            "points": 10,
            "order_index": 5
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "A frustrated user starts raising their voice at you. What's the best approach?",
            "options": [
                {"id": "a", "text": "Raise your voice to match theirs", "is_correct": False},
                {"id": "b", "text": "Hang up immediately", "is_correct": False},
                {"id": "c", "text": "Stay calm, acknowledge their frustration, and focus on solving the problem", "is_correct": True},
                {"id": "d", "text": "Transfer them to someone else immediately", "is_correct": False}
            ],
            "correct_answer": "c",
            "explanation": "Stay calm and professional. Acknowledge their frustration ('I understand this is frustrating') and redirect focus to the solution. Most users calm down when they feel heard.",
            "points": 10,
            "order_index": 6
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "What does SLA stand for in IT support?",
            "options": [
                {"id": "a", "text": "System Level Access", "is_correct": False},
                {"id": "b", "text": "Service Level Agreement", "is_correct": True},
                {"id": "c", "text": "Support Logic Application", "is_correct": False},
                {"id": "d", "text": "Standard Login Authority", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "SLA (Service Level Agreement) defines expected response times, resolution times, and service quality. It's a contract between IT and the business/customers.",
            "points": 10,
            "order_index": 7
        },
        {
            "question_type": QuestionType.MULTIPLE_CHOICE,
            "question_text": "Which troubleshooting principle suggests starting with the simplest solution first?",
            "options": [
                {"id": "a", "text": "FIFO (First In, First Out)", "is_correct": False},
                {"id": "b", "text": "Occam's Razor / Start with the obvious", "is_correct": True},
                {"id": "c", "text": "Always reinstall the OS first", "is_correct": False},
                {"id": "d", "text": "Replace hardware immediately", "is_correct": False}
            ],
            "correct_answer": "b",
            "explanation": "Start with simple solutions first - is it plugged in? Is it turned on? Have you restarted it? Most issues have simple causes. Don't overcomplicate troubleshooting.",
            "points": 10,
            "order_index": 8
        }
    ]
}


# All quizzes to seed
ALL_QUIZZES = [
    IT_BASICS_QUIZ,
    NETWORKING_QUIZ,
    CYBERSECURITY_QUIZ,
    PYTHON_QUIZ,
    HELPDESK_QUIZ,
]


def seed_quizzes(db: Session) -> dict:
    """
    Seed quizzes into the database.
    Uses upsert pattern - updates existing quizzes or creates new ones.

    Returns:
        dict with counts of created and updated quizzes
    """
    created = 0
    updated = 0

    for quiz_data in ALL_QUIZZES:
        quiz_id = quiz_data["id"]
        questions_data = quiz_data.pop("questions")

        # Check if quiz exists
        existing_quiz = db.query(Quiz).filter(Quiz.id == quiz_id).first()

        if existing_quiz:
            # Update existing quiz
            for key, value in quiz_data.items():
                setattr(existing_quiz, key, value)

            # Delete existing questions and recreate
            db.query(QuizQuestion).filter(QuizQuestion.quiz_id == quiz_id).delete()
            db.flush()

            # Create new questions
            for q_data in questions_data:
                question = QuizQuestion(quiz_id=quiz_id, **q_data)
                db.add(question)

            updated += 1
            print(f"  Updated: {quiz_data['title']} ({len(questions_data)} questions)")
        else:
            # Create new quiz
            quiz = Quiz(**quiz_data)
            quiz.id = quiz_id
            db.add(quiz)
            db.flush()

            # Create questions
            for q_data in questions_data:
                question = QuizQuestion(quiz_id=quiz_id, **q_data)
                db.add(question)

            created += 1
            print(f"  Created: {quiz_data['title']} ({len(questions_data)} questions)")

        # Re-add questions to quiz_data for next iteration if needed
        quiz_data["questions"] = questions_data

    db.commit()

    return {
        "created": created,
        "updated": updated,
        "total": len(ALL_QUIZZES),
        "total_questions": sum(len(q["questions"]) for q in ALL_QUIZZES)
    }


def run_seed():
    """
    Run the quiz seed script.
    Usage: python -m app.plugins.quizzes.seed_data
    """
    db = SessionLocal()

    try:
        print("Seeding beginner IT quizzes...")
        print("-" * 40)

        result = seed_quizzes(db)

        print("-" * 40)
        print(f"\nSeed complete!")
        print(f"  Created: {result['created']} quizzes")
        print(f"  Updated: {result['updated']} quizzes")
        print(f"  Total questions: {result['total_questions']}")

    except Exception as e:
        print(f"\nError seeding quizzes: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
