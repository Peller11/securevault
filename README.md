AegisVault 🔐
Secure storage. Controlled access. Built for trust.
AegisVault is a security-focused Flask application for securely storing and managing files. The project demonstrates practical web application security through encrypted file storage, secure authentication, role-based access control, defensive file handling, security monitoring, and automated security testing.
Built as a cybersecurity portfolio project with a focus on defense in depth.
 
⸻
 
Overview
AegisVault provides users with a protected environment for uploading, storing, and managing files while applying multiple layers of security.
The application combines:
Secure authentication
Password hashing
Role-based access control
AES-256-GCM encrypted file storage
Secure file validation
CSRF protection
Rate limiting
Account lockout
Audit logging
Security headers
Automated security testing
The goal is not simply to encrypt files, but to demonstrate how multiple security controls work together to protect a web application.
 
⸻
 
Security Architecture
                         ┌──────────────────┐
                         │     Browser      │
                         └────────┬─────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │      Flask App      │
                       │                     │
                       │ Authentication      │
                       │ Authorization       │
                       │ CSRF Protection     │
                       │ Rate Limiting       │
                       │ File Validation     │
                       └──────────┬──────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             ┌──────────────┐          ┌────────────────┐
             │    SQLite    │          │ Secure Storage │
             │              │          │                │
             │ Users        │          │ AES-256-GCM    │
             │ Files        │          │ Encryption     │
             │ Audit Logs   │          │                │
             │ Login Logs   │          │ Encrypted Data │
             └──────────────┘          └────────────────┘
 
⸻
 
🔐 Security Controls
Authentication
Argon2id password hashing
Secure session-based authentication
Generic authentication error messages
Account lockout protection
Login attempt tracking
Per-IP rate limiting
Secure logout
Authorization
AegisVault implements server-side role-based access control.
User
Manage their own files
Upload files
Download their own files
Delete their own files
View permitted account activity
Administrator
Access the administrative security dashboard
Review users and security events
Review login attempts
View file statistics
Monitor system activity
Administrators do not automatically receive access to the decrypted contents of users’ files.
Encryption
Files are protected using:
AES-256-GCM authenticated encryption
The implementation provides:
Confidentiality
Integrity
Authentication of encrypted data
Unique nonces for encrypted files
Additional authenticated data binding encrypted content to relevant metadata
Password Security
Passwords are never stored as plaintext.
AegisVault uses Argon2id, a password hashing algorithm designed to make password cracking significantly more expensive.
File Security
Uploaded files are protected through multiple validation layers:
Extension allow-list
Magic-byte/content validation
File size restrictions
Randomized server-side filenames
Path traversal protection
Strict ownership validation
Web Security
The application includes protections against common web application attacks:
CSRF attacks
Cross-Site Scripting (XSS)
SQL injection
Clickjacking
Brute-force authentication attempts
Unauthorized resource access
Security headers include controls such as:
Content Security Policy
HTTP Strict Transport Security
X-Frame-Options
 
⸻
 
🧪 Security Testing
AegisVault includes a dedicated security-focused automated test suite.
Tests cover areas including:
Authentication
Account lockout
Rate limiting
File validation
Encryption at rest
Encryption/decryption round trips
Cross-user authorization
Path traversal
CSRF protection
SQL injection payload handling
XSS escaping
Security headers
Administrator authorization
Test Result
46 / 46 tests passing ✅
Run the tests with:
python -m unittest discover -s tests -v


⸻


🛠️ Technology Stack
Technology
Purpose
Python
Core application language
Flask
Web framework
SQLite
Database
Cryptography
AES-256-GCM encryption
Argon2id
Password hashing
Jinja2
Server-side templating
HTML / CSS / JavaScript
User interface
unittest
Automated security testing


⸻


📁 Project Structure
aegisvault/
│
├── app/
│   ├── templates/
│   ├── static/
│   └── ...
│
├── scripts/
│   └── manage.py
│
├── tests/
│   ├── __init__.py
│   ├── base.py
│   ├── test_admin.py
│   ├── test_auth.py
│   ├── test_files.py
│   └── test_security.py
│
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
└── run.py


⸻


⚙️ Running Locally
1. Clone the repository
git clone https://github.com/Peller11/securevault.git
cd securevault
2. Create a virtual environment
Windows:
python -m venv .venv
.venv\Scripts\Activate.ps1
Linux/macOS:
python3 -m venv .venv
source .venv/bin/activate
3. Install dependencies
pip install -r requirements.txt
4. Configure environment variables
Copy the example environment file:
Copy-Item .env.example .env
Configure the required application secrets in .env.
Never commit .env or cryptographic secrets to source control.
5. Start the application
python run.py
The application will be available locally at:
http://127.0.0.1:5000


⸻


👤 Administrator Management
Administrator privileges are intentionally managed outside the web interface.
List users:
python scripts/manage.py list-users
Promote a user:
python scripts/manage.py promote <username>
Demote a user:
python scripts/manage.py demote <username>
This prevents users from granting themselves administrator privileges through the web application.


⸻


🧠 Security Design Principles
AegisVault follows a defense-in-depth approach.
Instead of relying on a single security mechanism, multiple independent controls protect the application:
Authentication
      ↓
Authorization
      ↓
Input & File Validation
      ↓
Encryption
      ↓
CSRF Protection
      ↓
Rate Limiting
      ↓
Audit Logging
      ↓
Automated Security Testing
Each layer addresses a different part of the application’s threat surface.


⸻


🎯 Threat Mitigation
Threat
Security Control
Password compromise
Argon2id hashing
Brute-force attacks
Rate limiting + account lockout
Unauthorized file access
Server-side ownership checks
File tampering
AES-256-GCM authentication
Path traversal
Random server-side filenames + validation
Malicious uploads
Extension + magic-byte validation
SQL injection
Parameterized queries
XSS
Jinja2 autoescaping
CSRF
CSRF protection
Clickjacking
X-Frame-Options
Session/network security
Secure security headers
Privilege escalation
Server-side RBAC


⸻


🔭 Future Improvements
Planned security and infrastructure improvements include:
TOTP-based multi-factor authentication
Email verification
Secure token-based password reset
Envelope encryption with per-file data-encryption keys
Streaming encryption/decryption for large files
Cryptographic key rotation
Per-user storage quotas
File versioning and recovery
Structured JSON audit logs
SIEM integration
CAPTCHA or proof-of-work protections
PostgreSQL support
Automated dependency scanning with pip-audit
Static security analysis with bandit
CI/CD security testing with GitHub Actions


⸻


⚠️ Disclaimer
AegisVault is an educational and cybersecurity portfolio project.
It demonstrates practical security engineering concepts but should undergo additional security review, infrastructure hardening, monitoring, backup planning, and key-management improvements before being used for production workloads containing sensitive information.


⸻


👨‍💻 Project
AegisVault
Cybersecurity-focused secure file storage application built with Python and Flask.
Focus areas:
Web Security · Cryptography · Authentication · Authorization · Secure File Handling · Security Testing