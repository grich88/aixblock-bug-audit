#!/bin/bash

# Create GitHub issues for all vulnerabilities

echo "Creating GitHub issues for AIxBlock security vulnerabilities..."

# Issue 3: File Upload Path Traversal
gh issue create --title "HIGH: File Upload Path Traversal Vulnerability (CVSS 7.5)" --body-file "../GITHUB_ISSUE_3_FILE_UPLOAD.md" --label "bug"

# Issue 4: SQL Injection
gh issue create --title "HIGH: SQL Injection in Database Query Actions (CVSS 8.1)" --body-file "../GITHUB_ISSUE_4_SQL_INJECTION.md" --label "bug"

# Issue 5: Secrets Exposure
gh issue create --title "HIGH: Secrets and Sensitive Data Exposure (CVSS 7.2)" --body-file "../GITHUB_ISSUE_5_SECRETS_EXPOSURE.md" --label "bug"

# Issue 6: Cloud Service Abuse
gh issue create --title "HIGH: Cloud Service Abuse - AWS X-Ray Exploitation (CVSS 7.9)" --body-file "../GITHUB_ISSUE_6_CLOUD_SERVICE_ABUSE.md" --label "bug"

# Issue 7: Remote Access Persistence
gh issue create --title "HIGH: Remote Access Tool Persistence Vulnerability (CVSS 8.3)" --body-file "../GITHUB_ISSUE_7_REMOTE_ACCESS_PERSISTENCE.md" --label "bug"

# Issue 8: CORS Misconfiguration
gh issue create --title "MEDIUM: CORS Misconfiguration Vulnerability (CVSS 6.5)" --body-file "../GITHUB_ISSUE_8_CORS_MISCONFIGURATION.md" --label "bug"

# Issue 9: API Documentation Exposure
gh issue create --title "MEDIUM: API Documentation Information Disclosure (CVSS 6.1)" --body-file "../GITHUB_ISSUE_9_API_DOCUMENTATION_EXPOSURE.md" --label "bug"

# Issue 10: Rate Limiting
gh issue create --title "MEDIUM: Insufficient Rate Limiting (CVSS 6.2)" --body-file "../GITHUB_ISSUE_10_RATE_LIMITING.md" --label "bug"

# Issue 11: Information Disclosure
gh issue create --title "MEDIUM: Information Disclosure in Error Messages (CVSS 5.8)" --body-file "../GITHUB_ISSUE_11_INFORMATION_DISCLOSURE.md" --label "bug"

echo "All GitHub issues created successfully!"
