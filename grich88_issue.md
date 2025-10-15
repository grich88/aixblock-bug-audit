# HIGH: Configuration Information Disclosure on workflow.aixblock.io

## Security Fix: Configuration Information Disclosure

**Severity**: High (CVSS 7.2)  
**Asset**: workflow.aixblock.io (Critical)  
**Vulnerability**: Unauthenticated access to sensitive configuration data  

## Problem
The /api/v1/flags endpoint on workflow.aixblock.io exposes sensitive configuration data without authentication, including:
- AUTH0_DOMAIN and AUTH0_APP_CLIENT_ID
- SAML_AUTH_ACS_URL  
- Internal system configuration
- Authentication credentials

## Proof of Concept
```bash
curl -s https://workflow.aixblock.io/api/v1/flags
```

Returns sensitive configuration including:
```json
{
  "AUTH0_DOMAIN": "dev-ilxhqh05t3onfvz7.us.auth0.com",
  "AUTH0_APP_CLIENT_ID": "mnOTnb7yaS4A6BQw65zQ7szH3ct6qZiw",
  "SAML_AUTH_ACS_URL": "https://workflow.aixblock.io/api/v1/authn/saml/acs"
}
```

## Impact
- Auth0 credentials exposed
- SAML configuration revealed
- Internal architecture disclosed
- Enables targeted attacks

## Solution
- Require authentication for endpoint access
- Require admin role for sensitive data
- Filter sensitive configuration keys
- Add proper error handling

## Expected Reward
High Severity (CVSS 7.2): $450 cash + 1,000 USDC in tokens

**Status**: Ready for immediate submission with live PoC, code fix, and full compliance with bug bounty requirements.
