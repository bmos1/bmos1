param (
    [string]$Rhost,
    [string]$User,
    [string]$Pass,
    [string]$Run,
    [switch]$Help
)

function Show-Help {
    Write-Host "`nUsage:"
    Write-Host "  CimExec.ps1 -Rhost <target> -User <username> -Pass <password> -Run <command>"
    Write-Host "`nExample:"
    Write-Host "  CimExec.ps1 -Rhost 192.168.1.10 -User admin -Pass P@ssw0rd -Run 'cmd.exe /c whoami'"
}

# Show help if -Help is used or required params are missing
if ($Help -or !$Rhost -or !$User -or !$Pass -or !$Run) {
    Show-Help
    return
}

$secure = ConvertTo-SecureString $Pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($User, $secure)
$opt = New-CimSessionOption -Protocol DCOM
$sess = New-CimSession -ComputerName $Rhost -Credential $cred -SessionOption $opt

Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Run}
