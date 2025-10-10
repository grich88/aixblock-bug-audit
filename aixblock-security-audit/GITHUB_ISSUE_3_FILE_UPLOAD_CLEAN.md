# HIGH: File Upload Path Traversal Vulnerability (CVSS 7.5)

## Summary

**Severity**: High (CVSS 7.5)
**Asset**: `*.aixblock.io`
**Reward**: $450 cash + 1,000 USDC in tokens

## Description

The file upload mechanism in `workflow/packages/backend/api/src/app/server.ts` is vulnerable to path traversal attacks. The `fastifyMultipart` configuration processes uploaded files without proper filename validation, allowing attackers to upload files to arbitrary locations on the server filesystem.

## Impact

- Remote code execution through malicious file uploads
- Server filesystem compromise
- Data exfiltration and system takeover
- Potential for lateral movement

## Proof of Concept

```javascript
// Malicious file upload with path traversal
const formData = new FormData();
const maliciousFile = new File(['malicious content'], '../../../var/www/html/malicious.txt');
formData.append('file', maliciousFile);

fetch('https://api.aixblock.io/api/v1/upload', {
    method: 'POST',
    body: formData
});
```

## Recommended Fix

```typescript
await app.register(fastifyMultipart, {
    attachFieldsToBody: 'keyValues',
    async onFile(part: MultipartFile) {
        // Validate filename
        if (!isValidFilename(part.filename)) {
            throw new AIxBlockError({
                code: ErrorCode.VALIDATION_ERROR,
                params: { message: 'Invalid filename' }
            });
        }
        
        // Sanitize filename
        const sanitizedFilename = sanitizeFilename(part.filename);
        
        const apFile: ApMultipartFile = {
            filename: sanitizedFilename,
            data: await part.toBuffer(),
            type: 'file',
        };
        (part as any).value = apFile;
    },
});

function isValidFilename(filename: string): boolean {
    // Check for path traversal patterns
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        return false;
    }
    
    // Check file extension
    const allowedExtensions = ['.jpg', '.png', '.pdf', '.txt', '.csv'];
    const extension = path.extname(filename).toLowerCase();
    return allowedExtensions.includes(extension);
}

function sanitizeFilename(filename: string): string {
    return filename
        .replace(/[^a-zA-Z0-9.-]/g, '_')
        .replace(/\.{2,}/g, '.')
        .substring(0, 255);
}
```

## References

- [OWASP File Upload Security](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

## CVSS Score Breakdown

- **Attack Vector**: Network (N)
- **Attack Complexity**: Low (L)
- **Privileges Required**: None (N)
- **User Interaction**: Required (R)
- **Scope**: Unchanged (U)
- **Confidentiality**: High (H)
- **Integrity**: High (H)
- **Availability**: High (H)

**Base Score**: 7.5 (High)
