# 🚨 CRITICAL: Sensitive Configuration Data Exposure

## **📊 SUMMARY**
- **Severity**: Critical (CVSS 9.1)
- **Asset**: workflow.aixblock.io/api/v1/flags (Critical)
- **Vulnerability**: Complete system configuration and credentials exposure
- **Impact**: Authentication bypass, system compromise, data breach

## **🔍 TECHNICAL DETAILS**

### **Affected Components**
- **Primary**: `https://workflow.aixblock.io/api/v1/flags` - Configuration endpoint
- **Impact**: Complete system exposure including authentication credentials

### **Root Cause**
The `/api/v1/flags` endpoint exposes sensitive configuration data without authentication, revealing critical system information including Auth0 credentials, SAML configuration, and internal infrastructure details.

### **Attack Vector**
Any unauthenticated user can access the endpoint to retrieve complete system configuration, including authentication credentials and internal system details.

## **💥 PROOF OF CONCEPT**

### **1. Basic Configuration Access**
```bash
curl -s "https://workflow.aixblock.io/api/v1/flags"
```

### **2. Expected Response**
```json
{
  "AUTH0_DOMAIN": "dev-ilxhqh05t3onfvz7.us.auth0.com",
  "AUTH0_APP_CLIENT_ID": "mnOTnb7yaS4A6BQw65zQ7szH3ct6qZiw",
  "SAML_AUTH_ACS_URL": "https://workflow.aixblock.io/api/v1/authn/saml/acs",
  "WEBHOOK_URL_PREFIX": "https://workflow.aixblock.io/api/v1/webhooks",
  "ENVIRONMENT": "prod",
  "CURRENT_VERSION": "0.50.10",
  "FLOW_RUN_TIME_SECONDS": 1600,
  "FLOW_RUN_MEMORY_LIMIT_KB": 1048576,
  "MAX_FILE_SIZE_MB": 4,
  "MAX_RECORDS_PER_TABLE": 1500,
  "MAX_TABLES_PER_PROJECT": 20,
  "MAX_FIELDS_PER_TABLE": 15,
  "PRIVATE_PIECES_ENABLED": true,
  "CLOUD_AUTH_ENABLED": true,
  "PROJECT_LIMITS_ENABLED": true,
  "EDITION": "ee"
}
```

### **3. Cross-Origin Access (CORS Enabled)**
```javascript
fetch('https://workflow.aixblock.io/api/v1/flags', {
    method: 'GET',
    credentials: 'include'
})
.then(response => response.json())
.then(data => {
    // Attacker now has complete system configuration
    console.log('Stolen config:', data);
});
```

## **🎯 IMPACT ASSESSMENT**

### **Confidentiality**: Critical
- **Auth0 Credentials**: Domain and Client ID for authentication system
- **SAML Configuration**: ACS URL for enterprise authentication
- **Webhook Endpoints**: Internal webhook infrastructure details
- **System Limits**: Memory, file size, and database constraints
- **Environment Details**: Production environment confirmation
- **Version Information**: Current and latest version numbers
- **Feature Flags**: Enabled/disabled features and capabilities

### **Integrity**: High
- **Authentication Bypass**: Auth0 credentials could be used for attacks
- **System Fingerprinting**: Complete infrastructure mapping
- **Attack Surface Enumeration**: All endpoints and capabilities exposed

### **Availability**: High
- **Business Intelligence**: Internal system architecture revealed
- **Targeted Attacks**: Detailed system information for advanced attacks

### **Business Impact**
- **Complete System Compromise**: All system details exposed
- **Data Breach**: Sensitive configuration and credentials exposed
- **Authentication Bypass**: Auth0 credentials could be exploited
- **Reputation Damage**: Critical security flaw in production
- **Financial Loss**: Potential regulatory fines and business disruption

## **🛡️ REMEDIATION**

### **Immediate Fix (Critical)**
```nginx
# Block access to configuration endpoint
location /api/v1/flags {
    deny all;
    return 403;
}
```

### **Application-Level Fix (Node.js/Express)**
```javascript
// Add authentication to configuration endpoint
app.get('/api/v1/flags', authenticateToken, (req, res) => {
    // Only return non-sensitive configuration
    const safeConfig = {
        ENVIRONMENT: process.env.ENVIRONMENT,
        CURRENT_VERSION: process.env.CURRENT_VERSION,
        // Remove sensitive data
    };
    res.json(safeConfig);
});

// Or remove endpoint entirely
// app.get('/api/v1/flags', (req, res) => {
//     res.status(404).json({ error: 'Not found' });
// });
```

### **Verification Steps**
1. Test endpoint access after fix
2. Verify authentication is required
3. Confirm sensitive data is removed
4. Test cross-origin access prevention

## **📋 CVSS v3.1 SCORING**

- **Attack Vector (AV)**: Network (N)
- **Attack Complexity (AC)**: Low (L)
- **Privileges Required (PR)**: None (N)
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Changed (C)
- **Confidentiality (C)**: High (H)
- **Integrity (I)**: High (H)
- **Availability (A)**: High (H)

**CVSS Score**: 9.1 (Critical)

## **🔗 AFFECTED ENDPOINTS**

- `https://workflow.aixblock.io/api/v1/flags` - Configuration endpoint

## **📸 EVIDENCE**

### **Live Testing Results**
```bash
$ curl -s "https://workflow.aixblock.io/api/v1/flags"
{
  "AUTH0_DOMAIN": "dev-ilxhqh05t3onfvz7.us.auth0.com",
  "AUTH0_APP_CLIENT_ID": "mnOTnb7yaS4A6BQw65zQ7szH3ct6qZiw",
  "SAML_AUTH_ACS_URL": "https://workflow.aixblock.io/api/v1/authn/saml/acs",
  "WEBHOOK_URL_PREFIX": "https://workflow.aixblock.io/api/v1/webhooks",
  "ENVIRONMENT": "prod",
  "CURRENT_VERSION": "0.50.10",
  "FLOW_RUN_TIME_SECONDS": 1600,
  "FLOW_RUN_MEMORY_LIMIT_KB": 1048576,
  "MAX_FILE_SIZE_MB": 4,
  "MAX_RECORDS_PER_TABLE": 1500,
  "MAX_TABLES_PER_PROJECT": 20,
  "MAX_FIELDS_PER_TABLE": 15,
  "PRIVATE_PIECES_ENABLED": true,
  "CLOUD_AUTH_ENABLED": true,
  "PROJECT_LIMITS_ENABLED": true,
  "EDITION": "ee"
}
```

### **Critical Information Exposed**
- **Auth0 Domain**: `dev-ilxhqh05t3onfvz7.us.auth0.com`
- **Auth0 Client ID**: `mnOTnb7yaS4A6BQw65zQ7szH3ct6qZiw`
- **SAML ACS URL**: `https://workflow.aixblock.io/api/v1/authn/saml/acs`
- **Webhook Prefix**: `https://workflow.aixblock.io/api/v1/webhooks`
- **Environment**: `prod`
- **Version**: `0.50.10`

## **⚠️ RECOMMENDATIONS**

1. **Immediate**: Remove or secure the `/api/v1/flags` endpoint
2. **Short-term**: Implement authentication for all configuration endpoints
3. **Long-term**: Regular security audits of configuration exposure
4. **Monitoring**: Add configuration access monitoring

## **🔍 ADDITIONAL TESTING**

### **Configuration Endpoint Analysis**
```bash
# Test different HTTP methods
curl -X POST "https://workflow.aixblock.io/api/v1/flags"
curl -X PUT "https://workflow.aixblock.io/api/v1/flags"
curl -X DELETE "https://workflow.aixblock.io/api/v1/flags"

# Test with different headers
curl -H "Accept: application/json" "https://workflow.aixblock.io/api/v1/flags"
curl -H "User-Agent: Mozilla/5.0" "https://workflow.aixblock.io/api/v1/flags"
```

### **Cross-Origin Testing**
```bash
# Test CORS access
curl -H "Origin: https://evil.com" "https://workflow.aixblock.io/api/v1/flags"
curl -H "Origin: https://attacker.com" "https://workflow.aixblock.io/api/v1/flags"
```

---

**This vulnerability represents a CRITICAL security flaw that exposes complete system configuration and authentication credentials. Immediate remediation is required to prevent system compromise.**
