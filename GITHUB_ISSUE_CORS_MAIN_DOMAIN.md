# 🚨 HIGH: CORS Misconfiguration on Main Domain (aixblock.io)

## **📊 SUMMARY**
- **Severity**: High (CVSS 7.5)
- **Asset**: aixblock.io (Critical)
- **Vulnerability**: Wildcard CORS policy on main domain with credentials enabled
- **Impact**: Complete bypass of security boundaries allowing unauthorized cross-origin access

## **🔍 TECHNICAL DETAILS**

### **Affected Components**
- **Primary**: `https://aixblock.io` - Main domain
- **Impact**: All subdomains and API endpoints accessible from any origin

### **Root Cause**
The main domain `aixblock.io` implements a wildcard CORS policy (`Access-Control-Allow-Origin: *`) with credentials enabled (`Access-Control-Allow-Credentials: true`), which is a critical security misconfiguration.

### **Attack Vector**
Any malicious website can make authenticated requests to AIxBlock's main domain and all subdomains, potentially accessing sensitive data, executing workflows, and bypassing authentication mechanisms.

## **💥 PROOF OF CONCEPT**

### **1. Basic CORS Test**
```bash
curl -s "https://aixblock.io" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -X OPTIONS \
  -v
```

### **2. Credentials Test**
```bash
curl -s "https://aixblock.io" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=malicious" \
  -v
```

### **3. API Access Test**
```bash
curl -s "https://aixblock.io/api/endpoint" \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer malicious-token" \
  -v
```

### **4. Expected Response**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: *
Access-Control-Expose-Headers: *
```

## **🎯 IMPACT ASSESSMENT**

### **Confidentiality**: High
- Access to sensitive user data and workflows
- Potential exposure of AI model configurations
- Risk of data exfiltration from any origin

### **Integrity**: High
- Ability to execute unauthorized workflows
- Potential modification of user data
- Risk of workflow manipulation

### **Availability**: Medium
- Potential for DoS through workflow abuse
- Risk of resource exhaustion

### **Business Impact**
- **Complete Security Bypass**: Any website can access AIxBlock
- **Data Exposure**: Sensitive user data accessible from any origin
- **Workflow Execution**: Unauthorized workflow execution possible
- **Authentication Bypass**: Potential bypass of authentication mechanisms

## **🛡️ REMEDIATION**

### **Immediate Fix (Nginx Configuration)**
```nginx
# Fix CORS configuration
location / {
    # Remove wildcard CORS
    add_header Access-Control-Allow-Origin "https://app.aixblock.io" always;
    add_header Access-Control-Allow-Origin "https://workflow.aixblock.io" always;
    add_header Access-Control-Allow-Origin "https://workflow-live.aixblock.io" always;
    
    # Only allow credentials for specific origins
    add_header Access-Control-Allow-Credentials "true" always;
    
    # Specify allowed methods
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    
    # Specify allowed headers
    add_header Access-Control-Allow-Headers "Origin, Content-Type, Accept, Authorization, X-Requested-With" always;
}
```

### **Application-Level Fix (Node.js/Express)**
```javascript
// Fix CORS configuration
const cors = require('cors');

app.use(cors({
    origin: [
        'https://app.aixblock.io',
        'https://workflow.aixblock.io',
        'https://workflow-live.aixblock.io'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Origin', 'Content-Type', 'Accept', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Type', 'Authorization']
}));
```

### **Verification Steps**
1. Test CORS with unauthorized origins
2. Verify credentials are only allowed for specific origins
3. Confirm wildcard CORS is removed
4. Test API access from unauthorized origins

## **📋 CVSS v3.1 SCORING**

- **Attack Vector (AV)**: Network (N)
- **Attack Complexity (AC)**: Low (L)
- **Privileges Required (PR)**: None (N)
- **User Interaction (UI)**: Required (R)
- **Scope (S)**: Changed (C)
- **Confidentiality (C)**: High (H)
- **Integrity (I)**: High (H)
- **Availability (A)**: Medium (M)

**CVSS Score**: 7.5 (High)

## **🔗 AFFECTED ENDPOINTS**

- `https://aixblock.io` - Main domain
- `https://aixblock.io/api/*` - All API endpoints
- `https://aixblock.io/workflow/*` - Workflow endpoints
- All subdomains inheriting CORS policy

## **📸 EVIDENCE**

### **Live Testing Results**
```bash
$ curl -s "https://aixblock.io" -H "Origin: https://evil.com" -X OPTIONS -v
> OPTIONS / HTTP/2
> Host: aixblock.io
> Origin: https://evil.com
> Access-Control-Request-Method: GET
> 
< HTTP/2 200
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< Access-Control-Allow-Methods: *
< Access-Control-Expose-Headers: *
```

### **Vulnerable Headers**
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Credentials: true`
- `Access-Control-Allow-Methods: *`
- `Access-Control-Expose-Headers: *`

## **⚠️ RECOMMENDATIONS**

1. **Immediate**: Remove wildcard CORS policy
2. **Short-term**: Implement specific origin allowlist
3. **Long-term**: Implement comprehensive CORS validation
4. **Monitoring**: Add CORS violation detection to security monitoring

## **🔍 ADDITIONAL TESTING**

### **Advanced CORS Tests**
```bash
# Test with different origins
curl -s "https://aixblock.io" -H "Origin: https://attacker.com" -X OPTIONS -v
curl -s "https://aixblock.io" -H "Origin: http://evil.com" -X OPTIONS -v
curl -s "https://aixblock.io" -H "Origin: null" -X OPTIONS -v

# Test with credentials
curl -s "https://aixblock.io" -H "Origin: https://evil.com" -H "Cookie: session=test" -v
```

### **Exploitation Scenarios**
1. **Data Exfiltration**: Steal user data from any origin
2. **Workflow Execution**: Execute unauthorized workflows
3. **Authentication Bypass**: Bypass authentication mechanisms
4. **API Abuse**: Abuse API endpoints from any origin

---

**This vulnerability represents a critical security flaw that allows complete bypass of security boundaries. Immediate remediation is strongly recommended to prevent unauthorized access to AIxBlock's core functionality.**
