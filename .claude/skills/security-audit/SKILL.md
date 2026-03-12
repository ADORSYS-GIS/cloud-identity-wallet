---
name: security-audit
description: Audits code for security vulnerabilities covering OWASP Top 10, dependency risks, and infrastructure misconfigurations.
---

# Security Audit Skill

When performing a security audit, check every category below. Do not skip any section even if it seems unlikely to apply.

## 1. Injection Vulnerabilities
- **SQL Injection**: Verify all database queries use parameterized statements or an ORM; flag any string concatenation in queries
- **Command Injection**: Check for user input passed to shell commands, exec functions, or system calls; verify input is escaped or allowlisted
- **XSS (Cross-Site Scripting)**: Ensure all user-supplied content is escaped before rendering in HTML; check for raw HTML insertion APIs and unescaped template output
- **LDAP/NoSQL Injection**: Check queries against LDAP directories or NoSQL databases for unsanitized input
- **Template Injection**: Verify server-side templates do not evaluate user input as code

## 2. Input Validation and Sanitization
- All API endpoints validate input types, lengths, and formats before processing
- File uploads check file type (by content, not just extension), enforce size limits, and store outside the webroot
- URL parameters and query strings are decoded and validated
- JSON/XML request bodies are validated against a schema
- Reject unexpected fields (do not silently pass them through to the database)
- Use allowlists (not denylists) for input validation where possible

## 3. Authentication
- Passwords are hashed with a strong algorithm (bcrypt, scrypt, Argon2) — never MD5 or SHA-1
- Authentication tokens (JWT, session IDs) have appropriate expiration times
- Failed login attempts are rate-limited and do not reveal whether the username or password was wrong
- Multi-factor authentication is available for sensitive operations
- Password reset tokens are single-use, time-limited, and invalidated after use
- Session tokens are regenerated after login to prevent session fixation

## 4. Authorization
- Every API endpoint checks authorization, not just authentication
- Verify users cannot access or modify resources belonging to other users (IDOR)
- Role-based access control is enforced at the backend, not just the UI
- Admin endpoints are protected by role checks, not just hidden URLs
- Verify that privilege escalation is not possible through parameter tampering

## 5. Sensitive Data Exposure
- No secrets (API keys, tokens, passwords) are committed to the repository
- Sensitive data (PII, financial data) is encrypted at rest and in transit
- Logs do not contain passwords, tokens, credit card numbers, or full PII
- API error responses do not expose stack traces, SQL queries, or internal paths in production
- HTTP responses include appropriate security headers (no-cache for sensitive data)
- Check environment files, config files, and CI/CD pipelines for leaked credentials

## 6. Dependency Vulnerabilities
- Check for known vulnerabilities in dependencies (npm audit, pip-audit, OWASP dependency-check)
- Verify dependencies are pinned to specific versions (no unbound ranges in production)
- Check for abandoned or unmaintained dependencies
- Audit transitive dependencies, not just direct ones
- Verify package integrity (lock files, checksums)

## 7. CORS and CSP Configuration
- CORS origin header is set to specific trusted domains, never wildcard for authenticated endpoints
- Content-Security-Policy header restricts script sources, prevents inline scripts
- X-Frame-Options or CSP frame-ancestors prevent clickjacking
- X-Content-Type-Options nosniff prevents MIME-type sniffing
- Strict-Transport-Security enforces HTTPS with appropriate max-age

## 8. Infrastructure and Configuration
- Debug mode and development flags are disabled in production
- Default credentials are changed on all services
- Database ports and admin panels are not publicly exposed
- TLS certificates are valid and use strong cipher suites
- Verify least-privilege access for service accounts and IAM roles

## Output Format
Categorize findings by severity:
- **Critical**: Actively exploitable vulnerabilities (injection, auth bypass, data exposure)
- **High**: Vulnerabilities requiring specific conditions to exploit (IDOR, missing rate limits)
- **Medium**: Hardening gaps (missing headers, weak configuration)
- **Low**: Best practice improvements (dependency updates, logging improvements)

Include: affected file/line, description of the risk, and a specific remediation recommendation.
