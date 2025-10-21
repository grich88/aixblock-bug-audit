# 📋 AIxBlock Bug Bounty Submission Instructions

## **Step-by-Step Submission Guide**

### **Phase 1: Repository Setup**

1. **Fork the Repository**
   - Go to: https://github.com/AIxBlock-2023/aixblock-ai-dev-platform-public
   - Click "Fork" button (top right)
   - Wait for fork to complete

2. **Star the Repository**
   - Click the "Star" button on the original repository
   - This is mandatory for bug bounty participation

### **Phase 2: Create GitHub Issue**

1. **Navigate to Issues**
   - Go to: https://github.com/AIxBlock-2023/aixblock-ai-dev-platform-public/issues
   - Click "New Issue"

2. **Select Template**
   - Click "Bug Report" template
   - Or use "Get started" if no template

3. **Fill Issue Details**
   - **Title**: `[SECURITY] CORS Misconfiguration: Wildcard Origin with Credentials on workflow.aixblock.io`
   - **Content**: Copy entire content from `GITHUB_ISSUE_CORS_FINAL.md`
   - **Labels**: Add `security`, `bug`, `high-severity`, `cors`
   - **Submit Issue**

4. **Note Issue Number**
   - Copy the issue number (e.g., #123)
   - You'll need this for the pull request

### **Phase 3: Apply Code Fixes**

1. **Clone Your Fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/aixblock-ai-dev-platform-public.git
   cd aixblock-ai-dev-platform-public
   ```

2. **Create Fix Branch**
   ```bash
   git checkout -b bugfix/cors-misconfiguration-fix
   ```

3. **Apply Patches**
   - Copy `PATCH_FILES/server.ts` to `workflow/packages/backend/api/src/app/server.ts`
   - Copy `PATCH_FILES/app.ts` to `workflow/packages/backend/api/src/app/app.ts`

4. **Commit Changes**
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

5. **Push Branch**
   ```bash
   git push origin bugfix/cors-misconfiguration-fix
   ```

### **Phase 4: Create Pull Request**

1. **Navigate to Your Fork**
   - Go to: https://github.com/YOUR_USERNAME/aixblock-ai-dev-platform-public
   - You should see "Compare & pull request" button

2. **Create Pull Request**
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

3. **Submit Pull Request**
   - Click "Create pull request"
   - Wait for review and approval

### **Phase 5: Verification**

1. **Test the Fix**
   - Follow `TESTING_GUIDE.md` to verify the fix works
   - Ensure legitimate access still works
   - Confirm malicious access is blocked

2. **Monitor Progress**
   - Check issue for updates
   - Respond to any questions from maintainers
   - Provide additional information if requested

### **Phase 6: Reward Collection**

1. **Wait for Approval**
   - Maintainers will review the fix
   - They may ask for clarification or additional changes
   - Once approved, the fix will be merged

2. **Receive Rewards**
   - **Cash**: $450 (High severity)
   - **Tokens**: 1,000 tokens
   - **Revenue Sharing**: Ongoing from forked repository

---

## **📞 Support**

If you encounter any issues during submission:

1. **Check the original issue** for updates
2. **Review the compliance checklist** in `COMPLIANCE_CHECKLIST.md`
3. **Test your fix** using `TESTING_GUIDE.md`
4. **Contact maintainers** through GitHub issues if needed

---

## **✅ Success Criteria**

Your submission is successful when:
- [ ] GitHub issue created and acknowledged
- [ ] Pull request submitted and approved
- [ ] Code fix merged into main branch
- [ ] Bug bounty rewards received

**Good luck with your submission! 🚀**
