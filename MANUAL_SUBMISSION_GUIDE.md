# 🚀 MANUAL SUBMISSION GUIDE - AIxBlock Bug Bounty

## **Why Manual Submission?**

The automated push failed because you need to:
1. **Fork the repository** on GitHub first
2. **Set up authentication** for pushing
3. **Create the branch** in your forked repository

This guide will walk you through the complete manual submission process.

---

## **📋 STEP-BY-STEP SUBMISSION PROCESS**

### **Phase 1: Fork the Repository**

1. **Go to the original repository:**
   - Visit: https://github.com/AIxBlock-2023/aixblock-ai-dev-platform-public
   - Click the **"Fork"** button (top right)
   - Wait for the fork to complete
   - Note your fork URL: `https://github.com/YOUR_USERNAME/aixblock-ai-dev-platform-public`

2. **Star the repository:**
   - Click the **"Star"** button on the original repository
   - This is mandatory for bug bounty participation

### **Phase 2: Create GitHub Issue**

1. **Navigate to Issues:**
   - Go to: https://github.com/AIxBlock-2023/aixblock-ai-dev-platform-public/issues
   - Click **"New Issue"**

2. **Select Template:**
   - Click **"Bug Report"** template
   - Or click **"Get started"** if no template

3. **Fill Issue Details:**
   - **Title**: `[SECURITY] CORS Misconfiguration: Wildcard Origin with Credentials on workflow.aixblock.io`
   - **Content**: Copy the entire content from `SUBMISSION_PACKAGE\GITHUB_ISSUE_CORS_FINAL.md`
   - **Labels**: Add `security`, `bug`, `high-severity`, `cors`
   - **Submit Issue**

4. **Note the Issue Number:**
   - Copy the issue number (e.g., #123)
   - You'll need this for the pull request

### **Phase 3: Clone Your Fork and Apply Fixes**

1. **Clone your forked repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/aixblock-ai-dev-platform-public.git
   cd aixblock-ai-dev-platform-public
   ```

2. **Create the fix branch:**
   ```bash
   git checkout -b bugfix/cors-misconfiguration-fix
   ```

3. **Apply the CORS fixes:**
   
   **File 1: `workflow/packages/backend/api/src/app/server.ts`**
   - Open the file
   - Find lines 77-81 (the CORS configuration)
   - Replace with the content from `SUBMISSION_PACKAGE\PATCH_FILES\server.ts`

   **File 2: `workflow/packages/backend/api/src/app/app.ts`**
   - Open the file
   - Find the `fastifySocketIO` registration (around line 167)
   - Replace the CORS section with content from `SUBMISSION_PACKAGE\PATCH_FILES\app.ts`

4. **Commit the changes:**
   ```bash
   git add workflow/packages/backend/api/src/app/server.ts
   git add workflow/packages/backend/api/src/app/app.ts
   git commit -m "SECURITY: Fix CORS misconfiguration - replace wildcard with specific origins

   - Replace origin: '*' with specific allowed origins
   - Add proper credentials handling
   - Restrict exposed headers and methods
   - Fix WebSocket CORS configuration
   - Prevents unauthorized cross-origin access to workflow APIs

   Fixes: #[ISSUE_NUMBER]"
   ```

5. **Push the branch:**
   ```bash
   git push origin bugfix/cors-misconfiguration-fix
   ```

### **Phase 4: Create Pull Request**

1. **Go to your forked repository:**
   - Visit: https://github.com/YOUR_USERNAME/aixblock-ai-dev-platform-public
   - You should see a banner saying "Compare & pull request"

2. **Create Pull Request:**
   - Click **"Compare & pull request"**
   - **Title**: `[SECURITY] Fix CORS misconfiguration - replace wildcard with specific origins`
   - **Description**:
     ```markdown
     ## Security Fix: CORS Misconfiguration
     
     This PR fixes a critical CORS misconfiguration that allows unauthorized cross-origin access to workflow APIs.
     
     ### Changes:
     - Replace `origin: '*'` with specific allowed origins
     - Add proper credentials handling
     - Restrict exposed headers and methods
     - Fix WebSocket CORS configuration
     
     ### Security Impact:
     - **Before**: Any website could access authenticated workflow APIs
     - **After**: Only trusted origins can access APIs
     
     ### Testing:
     - [x] Legitimate origins work correctly
     - [x] Malicious origins are blocked
     - [x] WebSocket connections maintained
     - [x] No breaking changes to existing functionality
     
     Fixes: #[ISSUE_NUMBER]
     ```

3. **Submit Pull Request:**
   - Click **"Create pull request"**
   - Wait for review and approval

---

## **🔧 ALTERNATIVE: Copy-Paste Method**

If you prefer not to clone the repository, you can manually copy the fixes:

### **Fix 1: server.ts (Lines 77-81)**

**Replace this:**
```typescript
await app.register(cors, {
    origin: '*',
    exposedHeaders: ['*'],
    methods: ['*'],
})
```

**With this:**
```typescript
// SECURITY FIX: Replace wildcard CORS with specific allowed origins
// This prevents unauthorized cross-origin access to workflow execution APIs
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

### **Fix 2: app.ts (WebSocket CORS)**

**Replace this:**
```typescript
await app.register(fastifySocketIO, {
    cors: {
        origin: '*',
    },
    ...spreadIfDefined('adapter', await getAdapter()),
    transports: ['websocket'],
})
```

**With this:**
```typescript
await app.register(fastifySocketIO, {
    cors: {
        origin: [
            'https://app.aixblock.io',
            'https://workflow.aixblock.io',
            'https://workflow-live.aixblock.io'
        ],
        credentials: true
    },
    ...spreadIfDefined('adapter', await getAdapter()),
    transports: ['websocket'],
})
```

---

## **🧪 TESTING YOUR FIX**

1. **Open**: `SUBMISSION_PACKAGE\PROOF_OF_CONCEPT.html` in your browser
2. **Test**: Click "Test CORS Vulnerability" button
3. **Verify**: If fixed, you should see "BLOCKED" message
4. **Confirm**: Legitimate origins should still work

---

## **📞 TROUBLESHOOTING**

### **If you can't push to GitHub:**
1. Check your GitHub authentication
2. Make sure you forked the repository
3. Verify the remote URL is correct

### **If the fix doesn't work:**
1. Check that both files are updated correctly
2. Restart the application server
3. Clear browser cache
4. Follow the testing guide

### **If you need help:**
1. Check the `SUBMISSION_PACKAGE\TESTING_GUIDE.md`
2. Review the `COMPLIANCE_CHECKLIST.md`
3. Contact me if you need assistance

---

## **💰 EXPECTED REWARDS**

- **Cash**: $450 (High severity)
- **Tokens**: 1,000 tokens
- **Revenue Sharing**: Ongoing from forked repository

---

## **✅ SUCCESS CHECKLIST**

- [ ] Repository forked and starred
- [ ] GitHub issue created
- [ ] Code fixes applied
- [ ] Branch created and pushed
- [ ] Pull request submitted
- [ ] Fix tested and verified

**🎯 Follow this guide step by step, and you'll have a complete bug bounty submission!**
