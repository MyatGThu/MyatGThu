#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Creates a new Active Directory user by copying a reference/template user,
    including all group memberships.

.DESCRIPTION
    This script automates AD user creation by:
      1. Copying properties from a reference user (department, company, OU, etc.)
      2. Assigning the same group memberships as the reference user
      3. Confirming successful creation and group assignment

.PARAMETER ReferenceUser
    SamAccountName of the existing user to copy from.

.PARAMETER FirstName
    First name of the new user.

.PARAMETER LastName
    Last name of the new user.

.PARAMETER Username
    SamAccountName (logon name) for the new user.
    If omitted, defaults to first initial + last name (e.g. jdoe).

.PARAMETER Password
    Initial password for the new user (SecureString).
    If omitted, the script will prompt securely.

.PARAMETER UPNSuffix
    UPN suffix (e.g. contoso.com). Defaults to the domain's UPN suffix.

.EXAMPLE
    .\New-ADUserFromTemplate.ps1 -ReferenceUser "jsmith" -FirstName "Jane" -LastName "Doe"

.EXAMPLE
    .\New-ADUserFromTemplate.ps1 -ReferenceUser "jsmith" -FirstName "Jane" -LastName "Doe" `
        -Username "jdoe" -UPNSuffix "contoso.com"
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$ReferenceUser,

    [Parameter(Mandatory)]
    [string]$FirstName,

    [Parameter(Mandatory)]
    [string]$LastName,

    [string]$Username,

    [SecureString]$Password,

    [string]$UPNSuffix
)

#region ── Helpers ────────────────────────────────────────────────────────────

function Write-Step   { param([string]$Msg) Write-Host "`n[*] $Msg" -ForegroundColor Cyan }
function Write-Ok     { param([string]$Msg) Write-Host "    [+] $Msg" -ForegroundColor Green }
function Write-Warn   { param([string]$Msg) Write-Host "    [!] $Msg" -ForegroundColor Yellow }
function Write-Fail   { param([string]$Msg) Write-Host "    [-] $Msg" -ForegroundColor Red }

#endregion

#region ── Pre-flight checks ─────────────────────────────────────────────────

Write-Step "Checking prerequisites..."

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Ok "ActiveDirectory module loaded."
} catch {
    Write-Fail "ActiveDirectory module not found. Install RSAT or run on a DC."
    exit 1
}

# Test domain connectivity
try {
    $domain = Get-ADDomain -ErrorAction Stop
    Write-Ok "Connected to domain: $($domain.DNSRoot)"
} catch {
    Write-Fail "Cannot reach Active Directory: $_"
    exit 1
}

#endregion

#region ── Resolve reference user ────────────────────────────────────────────

Write-Step "Resolving reference user '$ReferenceUser'..."

$refProperties = @(
    'SamAccountName','GivenName','Surname','DisplayName',
    'Department','Title','Company','Office','StreetAddress',
    'City','State','PostalCode','Country',
    'DistinguishedName','Enabled','ScriptPath',
    'ProfilePath','HomeDrive','HomeDirectory',
    'Manager','MemberOf','Description'
)

try {
    $refUser = Get-ADUser -Identity $ReferenceUser -Properties $refProperties -ErrorAction Stop
    Write-Ok "Found reference user: $($refUser.DisplayName) [$($refUser.SamAccountName)]"
} catch {
    Write-Fail "Reference user '$ReferenceUser' not found: $_"
    exit 1
}

# Derive target OU from reference user's DN  (strip the CN=xxx, part)
$targetOU = ($refUser.DistinguishedName -split ',', 2)[1]
Write-Ok "Target OU: $targetOU"

#endregion

#region ── Build new user attributes ─────────────────────────────────────────

# Default username to first-initial + lastname
if (-not $Username) {
    $Username = ($FirstName[0] + $LastName).ToLower() -replace '\s',''
}

# UPN suffix
if (-not $UPNSuffix) {
    $UPNSuffix = $domain.DNSRoot
}

$newUPN        = "$Username@$UPNSuffix"
$newDisplayName = "$FirstName $LastName"

# Check for username collision
Write-Step "Checking for username conflicts..."
$existing = Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Fail "A user with SamAccountName '$Username' already exists: $($existing.DistinguishedName)"
    exit 1
}
Write-Ok "Username '$Username' is available."

# Prompt for password if not supplied
if (-not $Password) {
    Write-Host ""
    $Password = Read-Host "Enter initial password for '$Username'" -AsSecureString
}

#endregion

#region ── Create user ────────────────────────────────────────────────────────

Write-Step "Creating new AD user '$Username'..."

$newUserParams = @{
    SamAccountName        = $Username
    UserPrincipalName     = $newUPN
    GivenName             = $FirstName
    Surname               = $LastName
    DisplayName           = $newDisplayName
    Name                  = $newDisplayName
    AccountPassword       = $Password
    ChangePasswordAtLogon = $true
    Enabled               = $true
    Path                  = $targetOU
}

# Copy optional attributes from reference user if they are populated
$optionalMap = @{
    Department    = $refUser.Department
    Title         = $refUser.Title
    Company       = $refUser.Company
    Office        = $refUser.Office
    StreetAddress = $refUser.StreetAddress
    City          = $refUser.City
    State         = $refUser.State
    PostalCode    = $refUser.PostalCode
    Country       = $refUser.Country
    Description   = $refUser.Description
    ScriptPath    = $refUser.ScriptPath
    Manager       = $refUser.Manager
}

foreach ($key in $optionalMap.Keys) {
    if ($optionalMap[$key]) {
        $newUserParams[$key] = $optionalMap[$key]
    }
}

try {
    if ($PSCmdlet.ShouldProcess($newDisplayName, "Create AD User")) {
        New-ADUser @newUserParams -ErrorAction Stop
        Write-Ok "User account '$Username' created successfully."
    }
} catch {
    Write-Fail "Failed to create user: $_"
    exit 1
}

#endregion

#region ── Copy group memberships ────────────────────────────────────────────

Write-Step "Copying group memberships from '$ReferenceUser'..."

$groups     = $refUser.MemberOf
$succeeded  = [System.Collections.Generic.List[string]]::new()
$failed     = [System.Collections.Generic.List[string]]::new()

if ($groups.Count -eq 0) {
    Write-Warn "Reference user is not a member of any groups."
} else {
    foreach ($groupDN in $groups) {
        try {
            $groupName = (Get-ADGroup -Identity $groupDN -ErrorAction Stop).Name
            if ($PSCmdlet.ShouldProcess($groupName, "Add '$Username' to group")) {
                Add-ADGroupMember -Identity $groupDN -Members $Username -ErrorAction Stop
                $succeeded.Add($groupName)
                Write-Ok "Added to: $groupName"
            }
        } catch {
            $failed.Add($groupDN)
            Write-Warn "Could not add to group '$groupDN': $_"
        }
    }
}

#endregion

#region ── Verification ───────────────────────────────────────────────────────

Write-Step "Verifying new user creation..."

Start-Sleep -Seconds 2   # brief pause for AD replication

try {
    $verifyProps = @('SamAccountName','DisplayName','Enabled','DistinguishedName','MemberOf')
    $newUser = Get-ADUser -Identity $Username -Properties $verifyProps -ErrorAction Stop

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  VERIFICATION REPORT" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Full Name   : $($newUser.DisplayName)"
    Write-Host "  Username    : $($newUser.SamAccountName)"
    Write-Host "  UPN         : $newUPN"
    Write-Host "  OU          : $targetOU"
    Write-Host "  Account     : $(if ($newUser.Enabled) { 'Enabled' } else { 'Disabled' })"
    Write-Host "  Groups Added: $($succeeded.Count) / $($groups.Count)"

    if ($succeeded.Count -gt 0) {
        Write-Host ""
        Write-Host "  Group Memberships:" -ForegroundColor Cyan
        foreach ($g in $succeeded) {
            Write-Host "    + $g" -ForegroundColor Green
        }
    }

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed Group Assignments:" -ForegroundColor Yellow
        foreach ($g in $failed) {
            Write-Host "    - $g" -ForegroundColor Yellow
        }
    }

    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    if ($newUser.Enabled -and $newUser.SamAccountName -eq $Username) {
        Write-Ok "SUCCESS: User '$Username' has been created and verified in Active Directory."
    } else {
        Write-Warn "User was created but may require manual review (account disabled or name mismatch)."
    }

} catch {
    Write-Fail "Verification failed — user '$Username' could not be retrieved: $_"
    Write-Warn "The account may still have been created. Check AD manually."
    exit 1
}

#endregion
