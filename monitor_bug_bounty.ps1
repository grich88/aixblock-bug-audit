# AIxBlock Bug Bounty Monitoring Script
# Monitors GitHub issues and PRs for AIxBlock team responses
# Based on successful Issue #309 submission methodology

$issueNumber = 309
$prNumber = 310
$repo = "AIxBlock-2023/awesome-ai-dev-platform-public"
$logFile = "bug_bounty_monitor.log"

Write-Host "🔍 Monitoring AIxBlock Bug Bounty Issue #$issueNumber and PR #$prNumber" -ForegroundColor Green
Write-Host "Repository: $repo" -ForegroundColor Cyan
Write-Host "Log File: $logFile" -ForegroundColor Yellow
Write-Host "Based on successful Issue #309 submission methodology" -ForegroundColor Magenta
Write-Host ""

# Function to check issue status
function Check-IssueStatus {
    try {
        $issue = gh issue view $issueNumber --repo $repo --json state,title,author,comments,assignees,labels
        $issueData = $issue | ConvertFrom-Json
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        Write-Host "[$timestamp] Issue Status Check:" -ForegroundColor Blue
        Write-Host "  State: $($issueData.state)" -ForegroundColor $(if($issueData.state -eq "closed") {"Red"} else {"Green"})
        Write-Host "  Title: $($issueData.title)" -ForegroundColor White
        Write-Host "  Author: $($issueData.author.login)" -ForegroundColor Cyan
        Write-Host "  Comments: $($issueData.comments.Count)" -ForegroundColor Yellow
        Write-Host "  Assignees: $($issueData.assignees.Count)" -ForegroundColor Magenta
        Write-Host "  Labels: $($issueData.labels.Count)" -ForegroundColor Gray
        
        # Log to file
        Add-Content -Path $logFile -Value "[$timestamp] State: $($issueData.state), Comments: $($issueData.comments.Count), Assignees: $($issueData.assignees.Count)"
        
        # Check for new comments
        if ($issueData.comments.Count -gt 0) {
            Write-Host "  Latest Comments:" -ForegroundColor Yellow
            foreach ($comment in $issueData.comments) {
                $commentTime = [DateTime]::Parse($comment.createdAt).ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "    [$commentTime] $($comment.author.login): $($comment.body.Substring(0, [Math]::Min(100, $comment.body.Length)))..." -ForegroundColor Gray
            }
        }
        
        # Check for assignees (AIxBlock team response)
        if ($issueData.assignees.Count -gt 0) {
            Write-Host "  🎯 ASSIGNED TO AIXBLOCK TEAM!" -ForegroundColor Green
            foreach ($assignee in $issueData.assignees) {
                Write-Host "    Assignee: $($assignee.login)" -ForegroundColor Green
            }
        }
        
        return $issueData
    }
    catch {
        Write-Host "Error checking issue: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to check for AIxBlock team members
function Check-AIxBlockTeam {
    $aixblockTeam = @("tqphu27", "AIxBlock-2023", "aixblock-team")
    
    if ($issueData.assignees.Count -gt 0) {
        foreach ($assignee in $issueData.assignees) {
            if ($aixblockTeam -contains $assignee.login) {
                Write-Host "  🚨 AIXBLOCK TEAM RESPONSE DETECTED!" -ForegroundColor Red
                Write-Host "    Team Member: $($assignee.login)" -ForegroundColor Red
                return $true
            }
        }
    }
    
    if ($issueData.comments.Count -gt 0) {
        foreach ($comment in $issueData.comments) {
            if ($aixblockTeam -contains $comment.author.login) {
                Write-Host "  🚨 AIXBLOCK TEAM COMMENT DETECTED!" -ForegroundColor Red
                Write-Host "    Team Member: $($comment.author.login)" -ForegroundColor Red
                Write-Host "    Comment: $($comment.body.Substring(0, [Math]::Min(200, $comment.body.Length)))..." -ForegroundColor Red
                return $true
            }
        }
    }
    
    return $false
}

# Function to check PR status
function Check-PRStatus {
    try {
        $pr = gh pr view $prNumber --repo $repo --json state,title,author,comments,assignees,labels,reviewDecision,mergeable
        $prData = $pr | ConvertFrom-Json
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] PR #$prNumber Status: $($prData.state)" -ForegroundColor Cyan
        
        if ($prData.assignees.Count -gt 0) {
            $assignees = $prData.assignees | ForEach-Object { $_.login } | Join-String -Separator ", "
            Write-Host "  📋 Assigned to: $assignees" -ForegroundColor Yellow
        }
        
        if ($prData.reviewDecision) {
            Write-Host "  🔍 Review Decision: $($prData.reviewDecision)" -ForegroundColor Magenta
        }
        
        if ($prData.mergeable -eq $true) {
            Write-Host "  ✅ Ready to merge" -ForegroundColor Green
        } elseif ($prData.mergeable -eq $false) {
            Write-Host "  ❌ Merge conflicts detected" -ForegroundColor Red
        }
        
        # Log PR status
        $logEntry = "[$timestamp] PR #$prNumber - State: $($prData.state), Assignees: $($prData.assignees.Count), Review: $($prData.reviewDecision)"
        Add-Content -Path $logFile -Value $logEntry
        
        return $prData
    }
    catch {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] Error checking PR status: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Main monitoring loop
Write-Host "Starting monitoring loop... (Press Ctrl+C to stop)" -ForegroundColor Green
Write-Host ""

$checkCount = 0
while ($true) {
    $checkCount++
    Write-Host "=== Check #$checkCount ===" -ForegroundColor Blue
    
    $issueData = Check-IssueStatus
    $prData = Check-PRStatus
    
    if ($issueData) {
        $teamResponse = Check-AIxBlockTeam
        
        if ($teamResponse) {
            Write-Host "🎯 AIXBLOCK TEAM HAS RESPONDED!" -ForegroundColor Red
            Write-Host "Check the issue for details: https://github.com/$repo/issues/$issueNumber" -ForegroundColor Yellow
            break
        }
        
        if ($issueData.state -eq "closed") {
            Write-Host "🔒 Issue has been closed!" -ForegroundColor Red
            break
        }
    }
    
    Write-Host "Waiting 5 minutes before next check..." -ForegroundColor Gray
    Start-Sleep -Seconds 300  # 5 minutes
    Write-Host ""
}
