# 🧪 Testing Guide - CORS Vulnerability & Fix

## **🛠️ Open-Source Security Tools Integration**

### **Comprehensive Tool Arsenal (2024-2025)**
Our testing methodology now includes a complete arsenal of open-source security tools for multi-domain testing:

#### **Web Application Security Tools**
- **OWASP ZAP**: Full-featured web app scanner/proxy for injections
- **Wapiti**: Black-box web vulnerability scanner with fuzzing
- **sqlmap**: Automated SQL injection tool with DB takeover
- **XSStrike**: Advanced XSS detection with intelligent fuzzing
- **SSRFmap**: Automatic SSRF fuzzer/exploitation tool
- **Nikto**: Web server scanner for vulnerable files and configs
- **TruffleHog**: Secrets scanner for repos and files
- **TestSSL.sh**: SSL/TLS configuration checker

#### **API Security Tools**
- **Autoswagger**: OpenAPI/Swagger API scanner for broken auth
- **JWT Tool**: JWT token strength testing
- **Kiterunner**: Hidden API endpoint discovery
- **Arjun**: HTTP parameter discovery
- **GraphQL Voyager/GraphiQL**: GraphQL schema introspection

#### **Container & Infrastructure Tools**
- **Trivy**: Comprehensive container and K8s scanner
- **Grype**: Container image vulnerability scanner
- **Kube-bench**: Kubernetes CIS Benchmark checking
- **Lynis**: Unix/Linux security auditing
- **Nmap**: Network port scanning

#### **Smart Contract Security Tools**
- **Solana X-Ray**: Static analyzer for Solana Rust code
- **Cargo Audit**: Rust dependency vulnerability checking
- **Soteria**: Solana security toolkit and guidelines

### **Tool Integration Strategy**

**Phase 1: Reconnaissance**
1. Subdomain enumeration (Amass, Subfinder)
2. Port scanning (Nmap)
3. Service identification (Nmap -sV)

**Phase 2: Vulnerability Discovery**
1. Web app scanning (OWASP ZAP, Wapiti)
2. API testing (Autoswagger, Postman)
3. Container scanning (Trivy, Grype)

**Phase 3: Exploitation & Validation**
1. Manual testing (curl, custom scripts)
2. Exploit development (custom tools)
3. Impact assessment (CVSS scoring)

**Phase 4: Remediation & Verification**
1. Code fixes (static analysis tools)
2. Configuration hardening (Lynis, Kube-bench)
3. Re-testing (verification scans)

---

## **🤖 AI-Assisted Security Testing Methodology**

This guide incorporates the latest AI-human hybrid approach for security testing, based on comprehensive analysis of AI-driven vs human-led security auditing.

### **Hybrid Testing Approach:**
- **AI Tools**: Pattern recognition, automated scanning, code analysis
- **Human Expertise**: Context understanding, validation, business impact assessment
- **Best Practice**: Always verify AI findings with manual testing

---

## **Testing the Vulnerability**

### **1. Test Current Vulnerable State**

**Check CORS Headers:**
```bash
curl -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" -X OPTIONS https://workflow.aixblock.io/api/workflows
```

**Expected Vulnerable Response:**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: *
Access-Control-Expose-Headers: *
```

**Test WebSocket CORS:**
```bash
curl -H "Origin: https://evil.com" -H "Connection: Upgrade" -H "Upgrade: websocket" https://workflow.aixblock.io/socket.io/
```

### **2. Test Malicious Exploit**

**Create Test File (`exploit.html`):**
```html
<!DOCTYPE html>
<html>
<head><title>CORS Exploit Test</title></head>
<body>
    <h1>AIxBlock CORS Exploit Test</h1>
    <div id="output">Testing...</div>
    <script>
        fetch('https://workflow.aixblock.io/api/workflows', {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            document.getElementById('output').innerHTML = 
                '<h2>SUCCESS: Vulnerable to CORS attack!</h2>' +
                '<p>Response status: ' + response.status + '</p>' +
                '<p>This proves the vulnerability exists.</p>';
        })
        .catch(error => {
            document.getElementById('output').innerHTML = 
                '<h2>BLOCKED: CORS protection working</h2>' +
                '<p>Error: ' + error.message + '</p>';
        });
    </script>
</body>
</html>
```

**Test Steps:**
1. Save as `exploit.html`
2. Open in browser while logged into `workflow.aixblock.io`
3. If vulnerable: You'll see "SUCCESS" message
4. If fixed: You'll see "BLOCKED" message

---

## **Testing the Fix**

### **1. Apply the Fix**

**Replace in `server.ts`:**
```typescript
// OLD (Vulnerable):
await app.register(cors, {
    origin: '*',
    exposedHeaders: ['*'],
    methods: ['*'],
})

// NEW (Fixed):
await app.register(cors, {
    origin: [
        'https://app.aixblock.io',
        'https://workflow.aixblock.io',
        'https://workflow-live.aixblock.io'
    ],
    credentials: true,
    exposedHeaders: ['Content-Type', 'Authorization'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Origin', 'Content-Type', 'Accept', 'Authorization', 'X-Requested-With']
})
```

**Replace in `app.ts`:**
```typescript
// OLD (Vulnerable):
await app.register(fastifySocketIO, {
    cors: {
        origin: '*',
    },
    // ...
})

// NEW (Fixed):
await app.register(fastifySocketIO, {
    cors: {
        origin: [
            'https://app.aixblock.io',
            'https://workflow.aixblock.io',
            'https://workflow-live.aixblock.io'
        ],
        credentials: true
    },
    // ...
})
```

### **2. Test Fixed State**

**Test Legitimate Origins (Should Work):**
```bash
# Test app.aixblock.io
curl -H "Origin: https://app.aixblock.io" -H "Access-Control-Request-Method: POST" -X OPTIONS https://workflow.aixblock.io/api/workflows

# Test workflow.aixblock.io  
curl -H "Origin: https://workflow.aixblock.io" -H "Access-Control-Request-Method: POST" -X OPTIONS https://workflow.aixblock.io/api/workflows

# Test workflow-live.aixblock.io
curl -H "Origin: https://workflow-live.aixblock.io" -H "Access-Control-Request-Method: POST" -X OPTIONS https://workflow.aixblock.io/api/workflows
```

**Expected Fixed Response:**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.aixblock.io
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Expose-Headers: Content-Type, Authorization
```

**Test Malicious Origins (Should Be Blocked):**
```bash
# Test evil.com (should be blocked)
curl -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" -X OPTIONS https://workflow.aixblock.io/api/workflows

# Test attacker.com (should be blocked)
curl -H "Origin: https://attacker.com" -H "Access-Control-Request-Method: POST" -X OPTIONS https://workflow.aixblock.io/api/workflows
```

**Expected Blocked Response:**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
```

### **3. Test WebSocket CORS Fix**

**Test Legitimate WebSocket:**
```bash
curl -H "Origin: https://app.aixblock.io" -H "Connection: Upgrade" -H "Upgrade: websocket" https://workflow.aixblock.io/socket.io/
```

**Test Malicious WebSocket:**
```bash
curl -H "Origin: https://evil.com" -H "Connection: Upgrade" -H "Upgrade: websocket" https://workflow.aixblock.io/socket.io/
```

---

## **4. Functional Testing**

### **Test Application Functionality**

1. **Login to AIxBlock**
   - Go to `https://app.aixblock.io`
   - Login with your credentials
   - Verify you can access workflows

2. **Test Workflow Creation**
   - Create a new workflow
   - Verify it works correctly
   - Check that CORS doesn't break functionality

3. **Test API Calls**
   - Make API calls from the legitimate frontend
   - Verify they work with the new CORS settings
   - Check browser console for errors

### **Test Cross-Origin Scenarios**

1. **Legitimate Cross-Origin**
   - From `app.aixblock.io` to `workflow.aixblock.io`
   - Should work with new CORS settings

2. **Malicious Cross-Origin**
   - From `evil.com` to `workflow.aixblock.io`
   - Should be blocked by CORS

---

## **5. Verification Checklist**

### **Vulnerability Confirmed:**
- [ ] `curl` shows `Access-Control-Allow-Origin: *`
- [ ] `exploit.html` successfully accesses APIs
- [ ] Malicious origins can make authenticated requests

### **Fix Applied:**
- [ ] `curl` shows specific origins in `Access-Control-Allow-Origin`
- [ ] `exploit.html` is blocked
- [ ] Malicious origins return `Access-Control-Allow-Origin: null`
- [ ] Legitimate origins still work
- [ ] WebSocket connections work for legitimate origins
- [ ] Application functionality unchanged

### **Security Improved:**
- [ ] No wildcard origins
- [ ] Credentials properly handled
- [ ] Headers restricted to necessary ones
- [ ] Methods limited to required ones
- [ ] WebSocket CORS also fixed

---

## **6. Troubleshooting**

### **If Fix Doesn't Work:**
1. Check that both `server.ts` and `app.ts` are updated
2. Restart the application server
3. Clear browser cache
4. Check server logs for errors

### **If Legitimate Access Breaks:**
1. Verify all legitimate origins are in the allowlist
2. Check that credentials are enabled
3. Ensure required headers are in `allowedHeaders`
4. Test with different browsers

### **If Malicious Access Still Works:**
1. Verify the fix was applied correctly
2. Check that the server restarted
3. Test with different malicious origins
4. Verify both HTTP and WebSocket CORS are fixed

---

**✅ When all tests pass, the CORS vulnerability is successfully fixed!**
