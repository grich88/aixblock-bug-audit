# 📋 COMPREHENSIVE METHODS, TECHNIQUES & TOOLS INVENTORY

## **Complete List of All Input Methods, Techniques, and Sites from Entire Chat Thread**

---

## **🔍 VULNERABILITY TYPES COVERED**

### **Web Application Vulnerabilities**
1. **Cross-Site Scripting (XSS)**
   - Reflected XSS
   - Stored XSS  
   - DOM-based XSS
   - Payloads: `<script>alert(1)</script>`, `<img onerror=...>`

2. **Server-Side Request Forgery (SSRF)**
   - Internal IP targeting (127.0.0.1, 169.254.169.254)
   - Cloud metadata exploitation
   - HTTP redirect bypass techniques
   - Cross-protocol attacks

3. **Remote Code Execution (RCE)**
   - Server-Side Template Injection (SSTI)
   - Insecure deserialization
   - Command injection
   - File upload webshells

4. **Insecure Direct Object Reference (IDOR)**
   - Object ID manipulation
   - Horizontal privilege escalation
   - Vertical privilege escalation
   - GraphQL mutation exploitation

5. **SQL Injection (SQLi)**
   - Union-based SQLi
   - Boolean-based blind SQLi
   - Time-based blind SQLi
   - Second-order injection

6. **Broken Authentication & Access Control**
   - JWT manipulation
   - Session fixation
   - Password reset bypass
   - Role-based access control flaws

7. **CORS Misconfiguration**
   - Wildcard origin with credentials
   - Cross-origin request forgery
   - Credential theft
   - Data exfiltration

### **WebSocket Vulnerabilities**
1. **Cross-Site WebSocket Hijacking (CSWH)**
   - Origin header bypass
   - Cookie-based authentication flaws
   - CSRF on WebSocket handshake

2. **Injection via WebSocket Messages**
   - XSS through WebSocket data
   - SQL injection via messages
   - JSON/XML injection

3. **Denial of Service (DoS)**
   - Connection flooding
   - Large frame attacks
   - Resource exhaustion

### **API Vulnerabilities**
1. **Broken Object-Level Authorization (BOLA)**
2. **Broken Authentication (API2)**
3. **Server-Side Request Forgery (API7)**
4. **Injection (API8)**
5. **Security Misconfiguration (API8)**
6. **Inventory (API9)**

### **AI/ML System Vulnerabilities**
1. **Prompt Injection / Jailbreaking**
   - "Ignore previous instructions..." attacks
   - Hidden instruction injection
   - Multi-modal prompt injection
   - Indirect prompt injection via web content

2. **Model Poisoning**
   - Training data poisoning
   - Backdoor triggers
   - Federated learning attacks
   - Random noise poisoning

3. **Adversarial Evasion**
   - Image classification attacks
   - Text classification bypass
   - Adversarial training

4. **Model Theft and Privacy**
   - Model extraction
   - Membership inference
   - Data extraction

5. **Insecure AI Frameworks**
   - Shadow vulnerabilities
   - Deserialization flaws
   - Template injection in AI libs

### **Cloud Infrastructure Vulnerabilities**
1. **Metadata SSRF and Token Theft**
   - AWS IMDS exploitation
   - GCP metadata access
   - Azure metadata abuse

2. **Open Storage Buckets**
   - S3 bucket enumeration
   - GCP bucket access
   - Azure blob exposure

3. **AWS Shadow Resources**
   - Bucket Monopoly attacks
   - CloudFormation template hijacking
   - SageMaker artifact theft

4. **IAM Misconfiguration**
   - Over-permissive roles
   - Cross-account trust abuse
   - Privilege escalation

5. **Kubernetes/Container Risks**
   - EKS/GKE exposure
   - Container image CVEs
   - Network policy bypass

6. **CLI and API Tool Leaks**
   - LeakyCLI vulnerabilities
   - CI log credential exposure
   - Build system secrets

---

## **🛠️ DETECTION TOOLS & SCANNERS**

### **Static Code Analysis**
- **Semgrep** - Static code analysis (210 findings)
- **Bandit** - Python security analysis (49 HIGH severity issues)
- **Retire.js** - JavaScript vulnerability detection
- **RIPS** - PHP security scanner
- **SonarQube** - Code quality and security
- **OWASP Dependency-Check** - Dependency vulnerability scanning

### **Dynamic Web Application Testing**
- **Burp Suite** - Web application security testing
  - Burp Scanner
  - Burp Repeater
  - Burp Intruder
  - Burp Collaborator
  - Burp Extensions (Collaborator Everywhere)
- **OWASP ZAP** - Open source web application security scanner
- **Wapiti** - Web application vulnerability scanner
- **Acunetix** - Commercial web vulnerability scanner
- **Nessus** - Vulnerability scanner

### **Secrets Detection**
- **TruffleHog** - Secrets detection in git repos
- **GitLeaks** - Secret scanning
- **GitGuardian** - Secret detection
- **Detect-secrets** - Secret scanning tool

### **API Testing Tools**
- **Postman** - API development and testing
- **Newman** - Postman CLI
- **wscurl** - WebSocket API testing
- **APIs.guru** - API discovery
- **Spectral** - API linting
- **OWASP ZAP API Scanner** - API security testing

### **WebSocket Testing**
- **Burp Suite WebSockets Panel** - WebSocket interception
- **Burp Repeater WebSocket** - WebSocket message replay
- **Burp Intruder WebSocket** - WebSocket fuzzing

### **Cloud Security Tools**
- **ScoutSuite** - Multi-cloud security auditing (AWS/Azure/GCP)
- **Pacu** - AWS exploitation framework
- **CloudSploit** - Cloud security scanning
- **CloudMapper** - Cloud infrastructure mapping
- **AWS IAM Access Analyzer** - IAM policy analysis
- **Prowler** - AWS security assessment
- **Trivy** - Container vulnerability scanner

### **AI/ML Security Tools**
- **CleverHans** - Adversarial examples library
- **Snyk** - Dependency vulnerability scanning
- **OWASP Dependency-Check** - AI framework scanning
- **eBPF hooks** - Runtime monitoring (emerging)

### **Network and Infrastructure**
- **Hydra** - Password brute-forcing
- **sqlmap** - SQL injection testing
- **XSSer** - XSS testing
- **XSStrike** - XSS testing
- **SSRFMap** - SSRF testing
- **BeEF** - Browser exploitation framework

---

## **🎯 TESTING METHODOLOGIES**

### **Comprehensive Penetration Testing Framework**
1. **Reconnaissance Phase**
   - Domain enumeration
   - Subdomain discovery
   - Port scanning
   - Service identification

2. **Vulnerability Assessment**
   - Static code analysis
   - Dynamic application testing
   - Manual testing
   - Automated scanning

3. **Exploitation Phase**
   - Proof-of-concept development
   - Live exploitation
   - Evidence capture
   - Impact assessment

4. **Reporting Phase**
   - Vulnerability documentation
   - Risk assessment
   - Remediation recommendations
   - Compliance verification

### **AIxBlock-Specific Testing Methodology**
1. **Target Identification**
   - `workflow.aixblock.io` (Critical)
   - `api.aixblock.io` (Critical)
   - `app.aixblock.io` (High)
   - `webhook.aixblock.io` (Medium)
   - `mcp.aixblock.io` (Medium)

2. **Endpoint Discovery**
   - API endpoint enumeration
   - WebSocket endpoint discovery
   - Configuration endpoint testing
   - Authentication endpoint analysis

3. **Vulnerability Testing**
   - Information disclosure testing
   - Authentication bypass testing
   - Authorization testing
   - Input validation testing
   - CORS testing

---

## **📊 VULNERABILITY SCORING & ASSESSMENT**

### **CVSS v3.1 Scoring**
- **Critical**: 9.0-10.0
- **High**: 7.0-8.9
- **Medium**: 4.0-6.9
- **Low**: 0.1-3.9

### **AIxBlock Bug Bounty Rewards**
- **Critical**: $750 + 1,500 tokens
- **High**: $450 + 1,000 tokens
- **Medium**: $200 + 500 tokens
- **Low**: 200 tokens

---

## **🔒 MITIGATION STRATEGIES**

### **Web Application Security**
- **XSS Prevention**: Output encoding, CSP, safe frameworks
- **SSRF Prevention**: URL validation, allowlists, network controls
- **RCE Prevention**: Avoid eval, safe deserialization, input validation
- **IDOR Prevention**: Server-side authorization, unpredictable IDs
- **SQLi Prevention**: Parameterized queries, input validation
- **Auth Prevention**: MFA, secure sessions, proper JWT validation

### **WebSocket Security**
- **CSWH Prevention**: Origin validation, CSRF tokens
- **Injection Prevention**: Input sanitization, output encoding
- **DoS Prevention**: Rate limiting, connection limits, WSS

### **API Security**
- **BOLA Prevention**: Strict authorization checks
- **Auth Prevention**: Strong authentication, token validation
- **SSRF Prevention**: URL validation, allowlists
- **Injection Prevention**: Input validation, parameterized queries

### **AI/ML Security**
- **Prompt Injection Prevention**: Role constraints, output monitoring
- **Model Poisoning Prevention**: Data validation, anomaly detection
- **Adversarial Prevention**: Adversarial training, input sanitization
- **Framework Security**: Trusted models, sandboxing, updates

### **Cloud Security**
- **Metadata Prevention**: IMDSv2, network controls
- **Storage Prevention**: ACL enforcement, public access blocking
- **IAM Prevention**: Least privilege, regular reviews
- **Container Prevention**: Updated images, network policies

---

## **📋 TESTING CHECKLISTS**

### **Pre-Submission Requirements**
- [ ] Repository starred
- [ ] Repository forked
- [ ] Account verification
- [ ] Live PoC development
- [ ] Screenshot capture
- [ ] Code fix implementation
- [ ] PR submission

### **Vulnerability Testing Checklist**
- [ ] Scope compliance verification
- [ ] Live endpoint testing
- [ ] Evidence documentation
- [ ] Impact assessment
- [ ] CVSS scoring
- [ ] Remediation recommendations

### **Submission Compliance Checklist**
- [ ] Issue creation
- [ ] Code fix branch
- [ ] Pull request submission
- [ ] Enhanced evidence
- [ ] Final compliance verification
- [ ] Monitoring setup

---

## **🏆 SUCCESSFUL VULNERABILITY PATTERNS**

### **From AIxBlock Rewarded Reports**
1. **IDOR**: $450 + 1000 tokens (@0xygyn-X)
2. **Stored XSS**: $200-450 + 500-1000 tokens (@eMKayRa0, @sonw-vh)
3. **Auth Bypass**: $225 + 500 tokens (@0XZAMAJ, @eMKayRa0)
4. **Path Traversal**: $100 + 250 tokens (@comradeflats)
5. **Rate Limiting Bypass**: $100 + 250 tokens (@Wizard0fthedigitalage, @0xygyn-X)
6. **Session Mismanagement**: $225 + 500 tokens (@eMKayRa0)

### **Our Successful Submissions**
1. **Configuration Information Disclosure** (Issue #309) - High (CVSS 7.2) - $450 + 1,000 tokens
2. **CORS Misconfiguration** (Issue #311) - Medium (CVSS 6.5) - $200 + 500 tokens

---

## **📚 REFERENCE SOURCES**

### **Authoritative References**
- **OWASP** - Web/API/GenAI Top 10
- **PortSwigger Academy** - Web security education
- **Kaspersky Securelist** - Security research
- **F5 Labs** - Cloud security research
- **AquaSec** - Cloud security analysis
- **Oligo Security** - AI security research

### **Industry Research**
- **Assetnote** - cPanel XSS research
- **Cyber Defense Magazine** - AI security analysis
- **The Hacker News** - Security news
- **Medium** - Security research articles

### **Bug Bounty Platforms**
- **HackerOne** - Public vulnerability reports
- **Bugcrowd** - Security research
- **AIxBlock Bug Bounty** - Target-specific research

---

## **🎯 NEXT TESTING PRIORITIES**

### **AI/ML Specific Testing**
1. **Prompt Injection Testing**
   - Direct prompt injection
   - Indirect prompt injection via web content
   - Multi-modal prompt injection
   - Jailbreaking attempts

2. **Model Security Testing**
   - Model poisoning detection
   - Adversarial example testing
   - Model extraction attempts
   - Privacy inference testing

### **WebSocket Testing**
1. **Cross-Site WebSocket Hijacking**
2. **WebSocket Message Injection**
3. **WebSocket DoS Testing**

### **API Endpoint Discovery**
1. **GraphQL Testing**
2. **REST API Enumeration**
3. **Webhook Testing**
4. **Authentication Testing**

### **Business Logic Testing**
1. **Workflow Execution Testing**
2. **Multi-step Process Testing**
3. **State Management Testing**
4. **Transaction Testing**

---

**Status**: ✅ **COMPREHENSIVE INVENTORY COMPLETE**

This inventory includes all methods, techniques, tools, and sites mentioned throughout our entire conversation thread, ensuring complete coverage of penetration testing methodologies for AIxBlock bug bounty submissions.

**PROPRIETARY METHODOLOGY - KEEP LOCAL AND CONFIDENTIAL** 🏆
