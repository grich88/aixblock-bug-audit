# AIxBlock Issue List Script
# Lists all your GitHub issues with their current status

# Configuration
$repoOwner = "AIxBlock-2023"
$repoName = "awesome-ai-dev-platform-opensource"
$issueAuthor = "grich88"

# Function to get all issues created by the specified author
function Get-AuthorIssues {
    $issues = gh issue list --repo "$repoOwner/$repoName" --author $issueAuthor --json number,title,url,createdAt,state,comments --limit 100
    return $issues | ConvertFrom-Json
}

# Function to get comments for a specific issue
function Get-IssueComments {
    param (
        [Parameter(Mandatory=$true)]
        [int]$IssueNumber
    )
    
    $comments = gh issue view $IssueNumber --repo "$repoOwner/$repoName" --json comments
    return ($comments | ConvertFrom-Json).comments
}

# Main function
function Show-IssueList {
    Write-Host "AIxBlock Security Issues - Status Report" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host ""
    
    # Get all issues by the author
    $issues = Get-AuthorIssues
    
    # Sort by issue number
    $issues = $issues | Sort-Object number
    
    Write-Host "Total Issues: $($issues.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($issue in $issues) {
        $issueNumber = $issue.number
        $issueTitle = $issue.title
        $issueState = $issue.state
        $issueUrl = $issue.url
        $createdAt = [DateTime]::Parse($issue.createdAt)
        
        # Get comments
        $comments = Get-IssueComments -IssueNumber $issueNumber
        $commentCount = $comments.Count
        
        # Determine severity from title
        $severity = if ($issueTitle -match "CRITICAL") { "Critical" }
                   elseif ($issueTitle -match "HIGH") { "High" }
                   elseif ($issueTitle -match "MEDIUM") { "Medium" }
                   else { "Unknown" }
        
        # Color coding
        $stateColor = if ($issueState -eq "OPEN") { "Green" } else { "Red" }
        $severityColor = switch ($severity) {
            "Critical" { "Red" }
            "High" { "Yellow" }
            "Medium" { "Cyan" }
            default { "White" }
        }
        
        Write-Host "Issue #$issueNumber" -ForegroundColor White -NoNewline
        Write-Host " [$severity]" -ForegroundColor $severityColor -NoNewline
        Write-Host " [$issueState]" -ForegroundColor $stateColor
        Write-Host "  $issueTitle" -ForegroundColor Gray
        Write-Host "  Created: $($createdAt.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
        Write-Host "  Comments: $commentCount" -ForegroundColor Gray
        Write-Host "  URL: $issueUrl" -ForegroundColor Blue
        Write-Host ""
    }
    
    # Summary
    $criticalCount = ($issues | Where-Object { $_.title -match "CRITICAL" }).Count
    $highCount = ($issues | Where-Object { $_.title -match "HIGH" }).Count
    $mediumCount = ($issues | Where-Object { $_.title -match "MEDIUM" }).Count
    
    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "  Critical: $criticalCount" -ForegroundColor Red
    Write-Host "  High: $highCount" -ForegroundColor Yellow
    Write-Host "  Medium: $mediumCount" -ForegroundColor Cyan
    Write-Host ""
    
    # Estimated rewards
    $totalCash = ($criticalCount * 750) + ($highCount * 450) + ($mediumCount * 200)
    $totalTokens = ($criticalCount * 1500) + ($highCount * 1000) + ($mediumCount * 500)
    
    Write-Host "Estimated Rewards:" -ForegroundColor Green
    Write-Host "  Cash: `$$totalCash" -ForegroundColor Green
    Write-Host "  Tokens: $totalTokens USDC" -ForegroundColor Green
    Write-Host "  Total Value: `$$($totalCash + $totalTokens)" -ForegroundColor Green
}

# Check if GitHub CLI is installed
try {
    $null = gh --version
} catch {
    Write-Host "ERROR: GitHub CLI (gh) is not installed or not in PATH. Please install it from https://cli.github.com/" -ForegroundColor Red
    exit 1
}

# Check if authenticated
try {
    $auth = gh auth status
    if (-not $auth) {
        Write-Host "ERROR: Not authenticated with GitHub CLI. Please run 'gh auth login'" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "ERROR: Not authenticated with GitHub CLI. Please run 'gh auth login'" -ForegroundColor Red
    exit 1
}

# Run the list
Show-IssueList
