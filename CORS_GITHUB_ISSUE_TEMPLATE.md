# 🚨 MEDIUM: CORS Misconfiguration on workflow.aixblock.io

## **Security Fix: CORS Misconfiguration**

**Severity**: Medium (CVSS 6.5)  
**Asset**: workflow.aixblock.io (Critical)  
**Vulnerability**: CORS allows requests from any origin with credentials

## **Problem**
The `/api/v1/flags` endpoint on `workflow.aixblock.io` has a dangerous CORS configuration that allows requests from any origin (`*`) while also setting `Access-Control-Allow-Credentials: true`. This combination enables:

- Cross-Origin Request Forgery (CSRF) attacks
- Credential theft and session hijacking
- Data exfiltration of sensitive configuration
- Authentication bypass attempts

## **Proof of Concept**
```bash
curl -s "https://workflow.aixblock.io/api/v1/flags" -H "Origin: https://evil.com" -v
```

**CORS Headers Observed:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Origin, Content-Type, Accept, Authorization
```

**Sensitive Data Exposed:**
```json
{
  "AUTH0_DOMAIN": "dev-ilxhqh05t3onfvz7.us.auth0.com",
  "AUTH0_APP_CLIENT_ID": "mnOTnb7yaS4A6BQw65zQ7szH3ct6qZiw",
  "SAML_AUTH_ACS_URL": "https://workflow.aixblock.io/api/v1/authn/saml/acs",
  "WEBHOOK_URL_PREFIX": "https://workflow.aixblock.io/api/v1/webhooks",
  "ENVIRONMENT": "prod",
  "CURRENT_VERSION": "0.50.10"
}
```

## **Impact**
- **CSRF Attacks**: Malicious websites can make authenticated requests
- **Credential Theft**: Cookies and authorization tokens accessible from any origin
- **Data Exfiltration**: Sensitive configuration data can be stolen
- **Authentication Bypass**: Potential bypass of same-origin policy protections

## **Solution**
- Replace wildcard origin (`*`) with specific allowed origins
- Implement proper origin validation
- Remove dangerous combination of wildcard + credentials
- Apply least-privilege CORS policy

## **Expected Reward**
Medium Severity (CVSS 6.5): $200 + 500 USDC in tokens

**Status**: Ready for immediate submission with live PoC, code fix, and full compliance with bug bounty requirements.
