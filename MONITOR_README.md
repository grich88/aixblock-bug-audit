# AIxBlock Issue Monitor

This script monitors your GitHub issues for new comments from the AIxBlock team and other contributors.

## Files Created

- `monitor_issues.ps1` - Main PowerShell monitoring script
- `run_monitor.bat` - Batch file to run continuous monitoring
- `check_issues_once.bat` - Batch file to check once and exit
- `MONITOR_README.md` - This documentation

## Usage

### Option 1: Continuous Monitoring
```bash
# Run continuously (checks every 30 minutes)
run_monitor.bat
```

### Option 2: Single Check
```bash
# Check once and exit
check_issues_once.bat
```

### Option 3: PowerShell Direct
```powershell
# Run continuously
.\monitor_issues.ps1

# Run once
.\monitor_issues.ps1 -once
```

## What It Monitors

- **Repository**: AIxBlock-2023/awesome-ai-dev-platform-opensource
- **Issues**: All issues created by `grich88`
- **Comments**: New comments from anyone other than `grich88`
- **Check Interval**: Every 30 minutes (configurable)

## Your Issues Being Monitored

| Issue # | Title | Severity |
|---------|-------|----------|
| #296 | JWT Algorithm Confusion | Critical |
| #297 | Webhook Payload Validation | High |
| #298 | File Upload Path Traversal | High |
| #299 | SQL Injection | High |
| #300 | CORS Misconfiguration | Medium |
| #301 | Secrets Exposure | High |
| #302 | Cloud Service Abuse | High |
| #303 | Remote Access Persistence | High |
| #304 | API Documentation Exposure | Medium |
| #305 | Rate Limiting | Medium |
| #306 | Information Disclosure | Medium |

## Output Files

- `issue_monitor_log.txt` - Log of all monitoring activity
- `last_check_data.json` - Data from last check (prevents duplicates)

## Prerequisites

1. **GitHub CLI**: Must be installed and authenticated
   ```bash
   gh auth login
   ```

2. **PowerShell**: Must allow script execution
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Configuration

Edit `monitor_issues.ps1` to change:
- `$checkIntervalMinutes` - How often to check (default: 30 minutes)
- `$repoOwner` - Repository owner (default: AIxBlock-2023)
- `$repoName` - Repository name (default: awesome-ai-dev-platform-opensource)
- `$issueAuthor` - Your GitHub username (default: grich88)

## Expected Timeline

Based on AIxBlock's bug bounty program:
- **Acknowledgment**: Within 48 hours
- **Validation**: Within 7 business days
- **Severity Confirmation**: After validation
- **Public Disclosure**: After fix is merged

## Troubleshooting

### GitHub CLI Not Found
```bash
# Install GitHub CLI
winget install GitHub.cli
```

### Authentication Issues
```bash
# Re-authenticate
gh auth login
```

### PowerShell Execution Policy
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Security Notes

- Script only reads issue data (no write permissions needed)
- Uses GitHub CLI authentication
- No sensitive data stored locally
- Logs are local only

## Next Steps

1. Run the monitor to track AIxBlock team responses
2. Respond promptly to any validation requests
3. Provide additional information if requested
4. Track reward confirmation after validation

## Estimated Rewards

- **Total Value**: $13,850
- **Cash**: $4,350
- **Tokens**: 9,500 USDC
- **Critical**: $750 + 1,500 USDC
- **High**: $450 + 1,000 USDC each (6 issues)
- **Medium**: $200 + 500 USDC each (4 issues)
