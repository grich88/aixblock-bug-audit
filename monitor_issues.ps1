# AIxBlock Issue Monitor Script
# This script checks for new comments on your GitHub issues and notifies you of any responses

# Configuration
$repoOwner = "AIxBlock-2023"
$repoName = "awesome-ai-dev-platform-opensource"
$issueAuthor = "grich88"
$logFile = "issue_monitor_log.txt"
$dataFile = "last_check_data.json"
$checkIntervalMinutes = 30

# Function to get all issues created by the specified author
function Get-AuthorIssues {
    $issues = gh issue list --repo "$repoOwner/$repoName" --author $issueAuthor --json number,title,url,createdAt --limit 100
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

# Function to log messages
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $logFile
    Write-Host "$timestamp - $Message"
}

# Function to load previous check data
function Get-PreviousCheckData {
    if (Test-Path $dataFile) {
        $data = Get-Content $dataFile | ConvertFrom-Json
        return $data
    } else {
        return @{
            lastCheck = (Get-Date).AddDays(-1).ToString("o")
            commentCounts = @{}
        }
    }
}

# Function to save current check data
function Save-CheckData {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Data
    )
    
    $Data | ConvertTo-Json | Out-File -FilePath $dataFile
}

# Main monitoring function
function Start-IssueMonitor {
    param (
        [switch]$RunOnce
    )
    
    Write-Log "Starting AIxBlock issue monitor..."
    
    while ($true) {
        try {
            $previousData = Get-PreviousCheckData
            $currentData = @{
                lastCheck = (Get-Date).ToString("o")
                commentCounts = @{}
            }
            
            # Get all issues by the author
            $issues = Get-AuthorIssues
            Write-Log "Found $($issues.Count) issues by $issueAuthor"
            
            foreach ($issue in $issues) {
                $issueNumber = $issue.number
                $issueTitle = $issue.title
                
                # Get comments for this issue
                $comments = Get-IssueComments -IssueNumber $issueNumber
                $commentCount = $comments.Count
                
                # Store current comment count
                $currentData.commentCounts["$issueNumber"] = $commentCount
                
                # Check if this is a new issue or has new comments
                $previousCount = if ($previousData.commentCounts.PSObject.Properties.Name -contains "$issueNumber") { 
                    $previousData.commentCounts."$issueNumber" 
                } else { 
                    0 
                }
                
                if ($commentCount -gt $previousCount) {
                    $newComments = $comments | Select-Object -Last ($commentCount - $previousCount)
                    
                    foreach ($comment in $newComments) {
                        $author = $comment.author.login
                        if ($author -ne $issueAuthor) {
                            $createdAt = [DateTime]::Parse($comment.createdAt)
                            $lastCheck = [DateTime]::Parse($previousData.lastCheck)
                            
                            if ($createdAt -gt $lastCheck) {
                                Write-Log "NEW COMMENT on Issue #$issueNumber ($issueTitle) from $author at $createdAt"
                                Write-Log "Comment: $($comment.body.Substring(0, [Math]::Min(100, $comment.body.Length)))..."
                                Write-Log "URL: $($issue.url)"
                                Write-Log "---"
                            }
                        }
                    }
                }
            }
            
            # Save current data for next check
            Save-CheckData -Data $currentData
            
            if ($RunOnce) {
                break
            }
            
            Write-Log "Waiting $checkIntervalMinutes minutes before next check..."
            Start-Sleep -Seconds ($checkIntervalMinutes * 60)
            
        } catch {
            Write-Log "ERROR: $_"
            Write-Log "Waiting 5 minutes before retry..."
            Start-Sleep -Seconds 300
        }
    }
}

# Check if GitHub CLI is installed
try {
    $null = gh --version
} catch {
    Write-Log "ERROR: GitHub CLI (gh) is not installed or not in PATH. Please install it from https://cli.github.com/"
    exit 1
}

# Check if authenticated
try {
    $auth = gh auth status
    if (-not $auth) {
        Write-Log "ERROR: Not authenticated with GitHub CLI. Please run 'gh auth login'"
        exit 1
    }
} catch {
    Write-Log "ERROR: Not authenticated with GitHub CLI. Please run 'gh auth login'"
    exit 1
}

# Run the monitor
if ($args -contains "-once") {
    Start-IssueMonitor -RunOnce
} else {
    Start-IssueMonitor
}
