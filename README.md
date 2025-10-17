# Vulnerable Node.js Application

This is a deliberately vulnerable Node.js application created for educational purposes to demonstrate common security vulnerabilities that can be detected by GitHub CodeQL, Dependabot, and Secret Scanning.

## WARNING

**DO NOT USE THIS CODE IN PRODUCTION**. This application contains numerous security vulnerabilities and is intended solely for security training and demonstration purposes.

## Vulnerabilities

This application contains multiple vulnerabilities including but not limited to:

1. Outdated and vulnerable dependencies
2. Command injection
3. SQL injection
4. Cross-site scripting (XSS)
5. Insecure deserialization
6. Path traversal
7. Weak cryptography
8. Hardcoded credentials
9. Insecure direct object references
10. Prototype pollution
11. Regular expression denial of service (ReDoS)
12. Insecure random number generation
13. Weak password hashing
14. Insecure JWT implementation
15. No rate limiting
16. Insecure file operations
17. Hardcoded encryption keys
18. Insecure session management
19. No input sanitization for database queries
20. Exposing sensitive data in error messages
21. Exposed API keys and secrets
22. Hardcoded AWS credentials
23. Private SSH keys
24. OAuth client secrets
25. Payment processor API keys

## Setup

```bash
npm install
npm start
```

## Security Tools

This application is designed to trigger alerts in:

1. GitHub CodeQL
2. GitHub Dependabot
3. GitHub Secret Scanning
4. Other security scanning tools

## Educational Purpose

This application is meant to be used for:
- Security training
- Demonstrating how security scanning tools work
- Learning about common web application vulnerabilities
- Understanding secure coding practices (by seeing what NOT to do)
- Showing how secret scanning tools detect exposed credentials
