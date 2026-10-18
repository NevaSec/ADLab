#Requires -RunAsAdministrator

$Config = @{
    DomainName       = "NEVASEC"
    DomainFQDN       = "NEVASEC.LOCAL"
    DomainNetBIOS    = "NEVASEC"
    SafeModeAdminPwd = "R00tR00t"
    HostName         = "DC01"
    StaticIPSuffix   = ".250"
    DomainMode       = "WinThreshold"
    ForestMode       = "WinThreshold"
}

function ConvertFrom-B64 {
    param([string]$s)
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($s))
}

function Set-IPAddress {
    try {
        $NetAdapter = Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
        $IPAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
        $Gateway = ((Get-NetIPConfiguration -InterfaceAlias $NetAdapter).IPv4DefaultGateway).NextHop
        $IPByte = $IPAddress.Split(".")

        if ($IPByte[0] -eq "169" -And $IPByte[1] -eq "254") {
            Write-Host "`n[ERREUR] $IPAddress est une adresse Link-Local, parametres reseau de la VM a verifier.`n" -ForegroundColor Red
            Read-Host "Appuyez sur Entree pour quitter"
            exit 1
        }
        else {
            $StaticIP = ($IPByte[0] + "." + $IPByte[1] + "." + $IPByte[2] + $Config.StaticIPSuffix)
            Write-Host "Configuration de l'IP statique: $StaticIP" -ForegroundColor Green
            netsh interface ipv4 set address name="$NetAdapter" static $StaticIP 255.255.255.0 $Gateway
            Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("127.0.0.1","1.1.1.1")
        }
    }
    catch {
        Write-Error "Erreur lors de la configuration IP: $($_.Exception.Message)"
        Read-Host "Appuyez sur Entree pour quitter"
        exit 1
    }
}

function Nuke-Defender{

    Set-MpPreference -DisableRealtimeMonitoring $true | Out-Null
    Set-MpPreference -DisableRemovableDriveScanning $true | Out-Null
    Set-MpPreference -DisableArchiveScanning  $true | Out-Null
    Set-MpPreference -DisableAutoExclusions  $true | Out-Null
    Set-MpPreference -DisableBehaviorMonitoring  $true | Out-Null
    Set-MpPreference -DisableBlockAtFirstSeen $true | Out-Null
    Set-MpPreference -DisableCatchupFullScan  $true | Out-Null
    Set-MpPreference -DisableCatchupQuickScan $true | Out-Null
    Set-MpPreference -DisableEmailScanning $true | Out-Null
    Set-MpPreference -DisableIntrusionPreventionSystem  $true | Out-Null
    Set-MpPreference -DisableIOAVProtection  $true | Out-Null
    Set-MpPreference -DisablePrivacyMode  $true | Out-Null
    Set-MpPreference -DisableRestorePoint  $true | Out-Null
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan  $true | Out-Null
    Set-MpPreference -DisableScanningNetworkFiles  $true | Out-Null
    Set-MpPreference -DisableScriptScanning $true | Out-Null

    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0 > $null
    reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > $null
    reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
    reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f > $null

    schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > $null
    schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > $null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f /v sc_fdrespub /t REG_EXPAND_SZ /d "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"

    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Disabled
    Stop-Service bits -Force -ErrorAction SilentlyContinue
    Set-Service bits -StartupType Disabled
    Stop-Service dosvc -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dosvc" -Name "Start" -Value 4
    takeown /f "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /a /r > $null 2>&1
    icacls "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /grant administrators:F /t > $null 2>&1
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1

    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
}

function Get-QoL{
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > $null

    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_DWORD /d "0" /f > $null
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f > $null
    reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_DWORD /d "0" /f > $null

    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

function Set-Wallpaper{
    try {
        $dir = "C:\ProgramData\NevaSec"
        $img = "$dir\nevasec.png"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/NevaSec/ADLab/raw/main/assets/nevasec.png" -OutFile $img

        $set = {
            param($base)
            $k = "$base\Control Panel\Desktop"
            if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
            Set-ItemProperty -Path $k -Name WallPaper      -Value $img
            Set-ItemProperty -Path $k -Name WallpaperStyle -Value "6"
            Set-ItemProperty -Path $k -Name TileWallpaper  -Value "0"
        }

        # Profils utilisateurs actuellement charges
        Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'S-1-5-21-.+\d$' -and $_.Name -notmatch '_Classes$' } | ForEach-Object { & $set "Registry::$($_.Name)" }

        # Hive Default -> tout nouveau profil heritera du fond
        reg load "HKU\NevaSecDef" "C:\Users\Default\NTUSER.DAT" > $null 2>&1
        & $set "Registry::HKEY_USERS\NevaSecDef"
        [gc]::Collect(); Start-Sleep -Milliseconds 500
        reg unload "HKU\NevaSecDef" > $null 2>&1

        # Application immediate pour la session courante
        Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public class Wp { [DllImport("user32.dll",CharSet=CharSet.Auto)] public static extern int SystemParametersInfo(int a,int u,string p,int f); }' -ErrorAction SilentlyContinue
        [Wp]::SystemParametersInfo(20,0,$img,3) | Out-Null

        # Lock / login screen (policy machine-wide, honoree sur les editions Server)
        $lock = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        if (-not (Test-Path $lock)) { New-Item -Path $lock -Force | Out-Null }
        Set-ItemProperty -Path $lock -Name LockScreenImage -Value $img
    }
    catch {
        Write-Host "[AVERTISSEMENT] Configuration du fond d'ecran ignoree: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Add-User{
    param(
        [Parameter()][string]$prenom,
        [Parameter()][string]$nom,
        [Parameter()][string]$sam,
        [Parameter()][string]$Path,
        [Parameter()][string]$mdp
    )

    $mdp = ConvertFrom-B64 $mdp
    New-ADUser -Name "$prenom $nom" -GivenName "$prenom" -Surname "$nom" -SamAccountName "$sam" -UserPrincipalName "$sam@nevasec.local" -Path $Path -AccountPassword (ConvertTo-SecureString $mdp -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
}

function Build-Server{
    try {
        Write-Host "`n  [++] Installation ADDS" -ForegroundColor Cyan
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

        Write-Host "`n  [++] Import module AD" -ForegroundColor Cyan
        Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null

        Write-Host "`n  [++] Installation domaine $($Config.DomainFQDN)" -ForegroundColor Cyan
        Install-ADDSForest -SkipPreChecks `
            -CreateDnsDelegation:$false `
            -DatabasePath "C:\Windows\NTDS" `
            -DomainMode $Config.DomainMode `
            -DomainName $Config.DomainFQDN `
            -DomainNetbiosName $Config.DomainNetBIOS `
            -ForestMode $Config.ForestMode `
            -InstallDns:$true `
            -LogPath "C:\Windows\NTDS" `
            -NoRebootOnCompletion:$false `
            -SysvolPath "C:\Windows\SYSVOL" `
            -Force:$true `
            -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText $Config.SafeModeAdminPwd -Force) `
            -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Error "Erreur installation AD: $($_.Exception.Message)"
        Read-Host "Appuyez sur Entree pour quitter"
        exit 1
    }
}

function Add-ServerContent{

    if (Get-ADUser -Filter "SamAccountName -eq 'svc-sql'" -ErrorAction SilentlyContinue) {
        Write-Host "`n[INFO] Comptes du lab deja presents : configuration AD deja effectuee, rien a faire." -ForegroundColor Green
        return
    }

    Write-Host("`n  [++] Installation ADCS")
    Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

    Install-WindowsFeature -Name ADCS-Web-Enrollment -IncludeManagementTools

    Install-AdcsWebEnrollment -Force

    Write-Host("`n  [++] Installation RSAT")
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null
    Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null
    Add-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature

    $base      = "DC=nevasec,DC=local"
    $ouGroupes = "OU=Groupes,$base"
    New-ADOrganizationalUnit -Name "Groupes" -Path $base
    New-ADOrganizationalUnit -Name "Comptes desactives" -Path $base
    New-ADOrganizationalUnit -Name "NevaSec" -Path $base
    $org = "OU=NevaSec,$base"
    foreach ($o in "Direction","Finance","RH","Management","Commercial","Marketing","Consultants","IT","Comptes de service","Comptes administrateurs") {
        New-ADOrganizationalUnit -Name $o -Path $org
    }
    $ouDir  = "OU=Direction,$org"
    $ouFin  = "OU=Finance,$org"
    $ouRH   = "OU=RH,$org"
    $ouMgmt = "OU=Management,$org"
    $ouComm = "OU=Commercial,$org"
    $ouMkt  = "OU=Marketing,$org"
    $ouCons = "OU=Consultants,$org"
    $ouIT   = "OU=IT,$org"
    $ouSvc  = "OU=Comptes de service,$org"
    $ouAdm  = "OU=Comptes administrateurs,$org"
    $ouDis  = "OU=Comptes desactives,$base"

    foreach ($grp in "RH","Management","Consultants","Commercial","IT","Backup","Finance","Direction","Marketing","Helpdesk","DBA","Developpeurs","VPN-Users","Partage-Finance") {
        New-ADGroup -Name $grp -GroupScope Global -Path $ouGroupes
    }

    Add-User -prenom "Richard"  -nom "Cuvillier"  -sam "rcuvillier"   -Path $ouMgmt -mdp "TgBlAHYAYQBzAGUAYwAxADIAMwA="
    New-ADUser -Name "svc-sql" -GivenName "svc" -Surname "sql" -SamAccountName "svc-sql" -Description "Service account SQL" -UserPrincipalName "svc-sql@nevasec.local" -Path $ouSvc -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "cwBxAGwAMAB2ADMALQB1AA==") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount -PassThru | Out-Null
    Add-User -prenom "Louise"   -nom "Chappuis"   -sam "lchappuis"    -Path $ouRH   -mdp "QQB6AGUAcgB0AHkAMQAyADMA"
    Add-User -prenom "Henri"    -nom "Walter"     -sam "hwalter"      -Path $ouCons -mdp "TgBlAHYAYQBzAGUAYwAqADkAOAA="
    Add-User -prenom "Celine"   -nom "Marchand"   -sam "cmarchand"    -Path $ouFin  -mdp "QQB1AHQAbwBtAG4AZQAyADAAMgA3AA=="
    Add-User -prenom "Admin"    -nom "Sylvain Cormier" -sam "adm-scormier" -Path $ouAdm -mdp "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -prenom "Olivier"  -nom "Bossuet"    -sam "obossuet"     -Path $ouComm -mdp "YgB4AEwAIQBAADIATQBlADEATQA4AHUA"
    Add-User -prenom "Kevin"    -nom "Moreau"     -sam "kmoreau"      -Path $ouMkt  -mdp "VwBlAGwAYwBvAG0AZQAyADAAMgA3ACEA"
    Add-User -prenom "Basile"   -nom "Delacroix"  -sam "bdelacroix"   -Path $ouMgmt -mdp "QQB6AGUAcgB0AHkAIwAxADUA"
    New-ADUser -Name "svc-backup" -GivenName "svc" -Surname "backup" -SamAccountName "svc-backup" -Description "Service account backup. Mdp: B4ckup-S3rv1c3" -UserPrincipalName "svc-backup@nevasec.local" -Path $ouSvc -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "QgA0AGMAawB1AHAALQBTADMAcgB2ADEAYwAzAA==") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    Add-User -prenom "Thibault" -nom "Roussel"    -sam "troussel"     -Path $ouFin  -mdp "NwBiAFEAIQB4ADIAVgBtADkAawBMAHIAYQBQAA=="
    Add-User -prenom "Bertrand" -nom "Dubois"     -sam "bdubois"      -Path $ouCons -mdp "SwBpAEwAbABFAHIANQAhAA=="
    Add-User -prenom "Jean-Marc" -nom "Lefevre"   -sam "jlefevre"     -Path $ouDir  -mdp "RwB0ADQAJABwAFIAOAB3AFoAIQBxAG4ARAB4AA=="
    Add-User -prenom "Sarah"    -nom "Meyer"      -sam "smeyer"       -Path $ouRH   -mdp "TgBlAHYAYQBzAGUAYwAyADAAMgA4ACEA"
    New-ADUser -Name "svc-web" -GivenName "svc" -Surname "web" -SamAccountName "svc-web" -Description "Service account IIS web" -UserPrincipalName "svc-web@nevasec.local" -Path $ouSvc -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "UABAAHMAcwBXADAAcgBkAC0AMgAwADEAMQAhAA==") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount | Out-Null
    Add-User -prenom "Emilie"   -nom "Garnier"    -sam "egarnier"     -Path $ouMkt  -mdp "UAByAGkAbgB0AGUAbQBwAHMALQAyADAAMgA4AA=="
    Add-User -prenom "Didier"   -nom "Leroux"     -sam "dleroux"      -Path $ouCons -mdp "TgBlAHYAYQAqADkAOAAyAA=="
    Add-User -prenom "Martine"  -nom "Baudet"     -sam "mbaudet"      -Path $ouMgmt -mdp "NgA3AEQAMQBmAEQAJQAlAGsAOAByADgA"
    New-ADUser -Name "Arnaud Trottier" -GivenName "Arnaud" -Surname "Trottier" -SamAccountName "atrottier" -Description "Desactive le 14/06/2026" -UserPrincipalName "atrottier@nevasec.local" -Path $ouDis -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "SABlAGwAbABvADIAMAAyADYAIQA=") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    Add-User -prenom "Jessica"  -nom "Plantier"   -sam "jplantier"    -Path $ouComm -mdp "TgAzAHYANABnAHIAMAB1AHAA"
    Add-User -prenom "Nadia"    -nom "Benali"     -sam "nbenali"      -Path $ouFin  -mdp "VgBhAGMAYQBuAGMAZQBzAC0ARQB0AGUAMgAwADIANwA="
    New-ADUser -Name "svc-legacy" -GivenName "svc" -Surname "legacy" -SamAccountName "svc-legacy" -Description "Service account legacy app" -UserPrincipalName "svc-legacy@nevasec.local" -Path $ouSvc -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "SwBpAGwAbAB0AGgAaQBzAGwAZQBnAGEAYwB5ACEA") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount | Out-Null
    Add-User -prenom "Christine" -nom "Vasseur"   -sam "cvasseur"     -Path $ouDir  -mdp "TQBhAHIAcwBlAGkAbABsAGUAMgAwADIAOAAhAA=="
    Add-User -prenom "Pascal"   -nom "Mesny"      -sam "pmesny"       -Path $ouCons -mdp "dwBzADkAcABBACYAbABnADcATgAzADIA"
    Add-User -prenom "Fabrice"  -nom "Girault"    -sam "fgirault"     -Path $ouRH   -mdp "QQB6AGUAcgB0AHkAMgAwADIANwA="
    Add-User -prenom "Admin"    -nom "Maxime Laurens" -sam "adm-mlaurens" -Path $ouAdm -mdp "UwB1AHAAZQByAC0AUABhAHMAcwB3AG8AcgBkAC0ANAAtAEEAZABtAGkAbgA="
    Add-User -prenom "Jade"     -nom "Schneider"  -sam "jschneider"   -Path $ouComm -mdp "VAB6AGoAMAA0ADQAWgBlAFYAJgBZAHUA"
    Add-User -prenom "Sofian"   -nom "Haddad"     -sam "shaddad"      -Path $ouMkt  -mdp "SwBwADkAIwBtAFgAMgB2AEwANwAhAGIAUQBlAA=="
    Add-User -prenom "Ludovic"  -nom "Michaux"    -sam "lmichaux"     -Path $ouMgmt -mdp "TgBlAHYAYQBzAGUAYwAyADAAMgA3AA=="
    New-ADUser -Name "svc-report" -GivenName "svc" -Surname "report" -SamAccountName "svc-report" -Description "Service account reporting" -UserPrincipalName "svc-report@nevasec.local" -Path $ouSvc -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "UgBhAHAAcABvAHIAdABzAC0AMgAwADIANwA=") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Enable-ADAccount | Out-Null
    Add-User -prenom "Lydia"    -nom "Beaumont"   -sam "lbeaumont"    -Path $ouCons -mdp "VAAwAGsAaQAwAEgAMAB0ADMAbAA="
    Add-User -prenom "Nathalie" -nom "Perrin"     -sam "nperrin"      -Path $ouRH   -mdp "TgBhAHQAaABhAGwAaQBlADIAMAAyADcA"
    New-ADUser -Name "Guillaume Brazier" -GivenName "Guillaume" -Surname "Brazier" -SamAccountName "gbrazier" -Description "Desactive le 25/08/2026" -UserPrincipalName "gbrazier@nevasec.local" -Path $ouDis -AccountPassword (ConvertTo-SecureString (ConvertFrom-B64 "UwB1AG0AbQBlAHIAMgAwADIANwA=") -AsPlainText -Force) -PasswordNeverExpires $true -PassThru | Out-Null
    Add-User -prenom "Sylvain"  -nom "Cormier"    -sam "scormier"     -Path $ouIT   -mdp "egBMADAAVAAxAE4AIQA0AEEAQQBZAHIA"
    Add-User -prenom "Alexia"   -nom "Chabert"    -sam "achabert"     -Path $ouCons -mdp "UABPAGkAdQAqACYAOAA3AF4AJQA="
    Add-User -prenom "Laetitia" -nom "Portier"    -sam "lportier"     -Path $ouComm -mdp "UAByAGkAbgB0AGUAbQBwAHMAMgAwADIAOAAhAA=="
    Add-User -prenom "Quentin"  -nom "Faure"      -sam "qfaure"       -Path $ouCons -mdp "RgBvAG8AdABiAGEAbABsAC0AMgAwADIANwA="
    Add-User -prenom "Maxime"   -nom "Laurens"    -sam "mlaurens"     -Path $ouIT   -mdp "IQAwAE4AZQB2AGEAZwByAHUAcAAwACEA"
    Add-User -prenom "Dylan"    -nom "Brassard"   -sam "dbrassard"    -Path $ouCons -mdp "SwBzAGQAaQAzADQAMgA2AEMAJgB2AGUA"
    Add-User -prenom "Remi"     -nom "Colin"      -sam "rcolin"       -Path $ouIT   -mdp "SABpAHYAZQByADIAMAAyADgAIQA="
    Add-User -prenom "Helpdesk" -nom "Deploiement" -sam "hdesk"        -Path $ouIT   -mdp "SABkACEANwBrAFAAMgBtAFgAegA5AFEAdwAkAEwAcgA="
    Add-User -prenom "Cyrille"  -nom "Toutain"    -sam "ctoutain"     -Path $ouComm -mdp "cQBzAGcANQA2ADQAUwBGADIALQAkAA=="
    Add-User -prenom "Manon"    -nom "Aubry"      -sam "maubry"       -Path $ouCons -mdp "MwB2AE4AcQBaADgAdwAhAHIATAB4AFAAMgA="
    Add-User -prenom "Lara"     -nom "Fournier"   -sam "lfournier"    -Path $ouCons -mdp "OAA3AGMAYgB6AHUAdgBzAEYAMAAyACYA"
    Add-User -prenom "Patrick"  -nom "Lemoine"    -sam "plemoine"     -Path $ouComm -mdp "TQBhAHIAcwBlAGkAbABsAGUAMgAwADIAOAAhAA=="
    Add-User -prenom "Hugo"     -nom "Dupuy"      -sam "hdupuy"       -Path $ouCons -mdp "WAAyAHcAXgB2AFkANAAzADIARQBvAFAA"
    Add-User -prenom "Julien"   -nom "Breton"     -sam "jbreton"      -Path $ouIT   -mdp "RABxADcAIQB6AFIAMgB3AFgAOQBtAEsAcABMAA=="
    Add-User -prenom "Pierre"   -nom "Sylvestre"  -sam "psylvestre"   -Path $ouCons -mdp "UABhAHMAcwB3AG8AcgBkADEAMgAzACEA"

    Add-ADGroupMember -Identity "Management"   -Members rcuvillier,bdelacroix,mbaudet,lmichaux
    Add-ADGroupMember -Identity "RH"           -Members lchappuis,smeyer,fgirault,nperrin
    Add-ADGroupMember -Identity "Consultants"  -Members hwalter,bdubois,dleroux,pmesny,lbeaumont,achabert,dbrassard,lfournier,hdupuy,psylvestre,qfaure,maubry
    Add-ADGroupMember -Identity "Commercial"   -Members obossuet,jplantier,jschneider,lportier,ctoutain,plemoine
    Add-ADGroupMember -Identity "Finance"      -Members cmarchand,troussel,nbenali
    Add-ADGroupMember -Identity "Direction"    -Members jlefevre,cvasseur
    Add-ADGroupMember -Identity "Marketing"    -Members kmoreau,egarnier,shaddad
    Add-ADGroupMember -Identity "IT"           -Members scormier,mlaurens
    Add-ADGroupMember -Identity "Helpdesk"     -Members rcolin,jbreton,hdesk
    Add-ADGroupMember -Identity "DBA"          -Members svc-sql,svc-web,jbreton
    Add-ADGroupMember -Identity "Developpeurs" -Members qfaure,maubry
    Add-ADGroupMember -Identity "VPN-Users"    -Members nbenali,egarnier,plemoine
    Add-ADGroupMember -Identity "Partage-Finance" -Members cmarchand,troussel
    Add-ADGroupMember -Identity "Backup"       -Members svc-backup
    Add-ADGroupMember -Identity "Management"   -Members (Get-ADGroup "Direction")
    Add-ADGroupMember -Identity "$((Get-ADDomain).DomainSID.Value)-512" -Members adm-scormier,adm-mlaurens

    setspn -A DC01/svc-sql.nevasec.local:`60111 nevasec\svc-sql > $null
    setspn -A svc-sql/nevasec.local nevasec\svc-sql > $null
    setspn -A DomainController/svc-sql.nevasec.local:`60111 nevasec\svc-sql > $null
    setspn -A HTTP/svc-web.nevasec.local nevasec\svc-web > $null

    Get-ADUser -Identity "svc-legacy" | Set-ADAccountControl -DoesNotRequirePreAuth:$true

    Write-Host("`n  [++] Configuration gMSA")
    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction SilentlyContinue | Out-Null
    New-ADServiceAccount -Name "svc-gmsa" -DNSHostName "svc-gmsa.nevasec.local" -PrincipalsAllowedToRetrieveManagedPassword "Developpeurs" -Path $ouSvc -Enabled $true -WarningAction SilentlyContinue

    mkdir C:\Share
    $everyoneName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")).Translate([System.Security.Principal.NTAccount]).Value
    $usersName    = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")).Translate([System.Security.Principal.NTAccount]).Value
    New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess $usersName -FullAccess $everyoneName -WarningAction SilentlyContinue | Out-Null

    Invoke-WebRequest -Uri "https://github.com/NevaSec/ADLab/raw/main/assets/LdapAdminPortable.zip" -OutFile "C:\Share\LdapAdminPortable.zip"
    Invoke-WebRequest -Uri "https://github.com/NevaSec/ADLab/raw/main/assets/share.zip" -OutFile "C:\Share\share.zip"
    Expand-Archive -Path "C:\Share\share.zip" -DestinationPath "C:\Share" -Force
    Remove-Item "C:\Share\share.zip" -Force

    Write-Host("`n  [++] Configuration GPO")
    New-GPO -Name "CustomGPO"

    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" -ValueName "DependOnService" -Type MultiString -Value "RpcSs\0http\0fpdhost\0LanmanWorkstation"
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "sc_fdredpub" -Type MultiString -Value "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -ValueName "LocalAccountTokenFilterPolicy" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 1 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "CustomGPO" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -ValueName "DisabledComponents" -Value 0x20 -Type Dword

    New-GPLink -Name "CustomGPO" -Target "DC=NEVASEC,DC=local" -LinkEnabled Yes -Enforced Yes

    $gppGpoName = "Postes - Compte admin local"
    $gppGpo = New-GPO -Name $gppGpoName
    New-GPLink -Name $gppGpoName -Target "DC=nevasec,DC=local" -LinkEnabled Yes | Out-Null
    $gppGuid = "{$($gppGpo.Id.Guid.ToUpper())}"
    $gppDir = "C:\Windows\SYSVOL\sysvol\nevasec.local\Policies\$gppGuid\Machine\Preferences\Groups"
    New-Item -Path $gppDir -ItemType Directory -Force | Out-Null
    New-Item "$gppDir\Groups.xml" -ItemType File -Value ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQA4ACIAPwA+AA0ACgA8AEcAcgBvAHUAcABzACAAYwBsAHMAaQBkAD0AIgB7ADMAMQAyADUARQA5ADMANwAtAEUAQgAxADYALQA0AGIANABjAC0AOQA5ADMANAAtADUANAA0AEYAQwA2AEQAMgA0AEQAMgA2AH0AIgA+ADwAVQBzAGUAcgAgAGMAbABzAGkAZAA9ACIAewBEAEYANQBGADEAOAA1ADUALQA1ADEARQA1AC0ANABkADIANAAtADgAQgAxAEEALQBEADkAQgBEAEUAOQA4AEIAQQAxAEQAMQB9ACIAIABuAGEAbQBlAD0AIgBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAZQB1AHIAIgAgAGkAbQBhAGcAZQA9ACIAMgAiACAAYwBoAGEAbgBnAGUAZAA9ACIAMgAwADIAMgAtADAAMwAtADEANAAgADAAOQA6ADEAMgA6ADQANwAiACAAdQBpAGQAPQAiAHsAMgBEADQAQgAyAEMAMwBBAC0AOQBGADEARQAtADQARQA3AEIALQA5AEMAMgAxAC0ANQBBADEAQgA3AEUANgBGADAAQwA0ADQAfQAiAD4APABQAHIAbwBwAGUAcgB0AGkAZQBzACAAYQBjAHQAaQBvAG4APQAiAFUAIgAgAG4AZQB3AE4AYQBtAGUAPQAiACIAIABmAHUAbABsAE4AYQBtAGUAPQAiAEMAbwBtAHAAdABlACAAYQBkAG0AaQBuAGkAcwB0AHIAYQB0AGUAdQByACAAbABvAGMAYQBsACIAIABkAGUAcwBjAHIAaQBwAHQAaQBvAG4APQAiAEMAbwBtAHAAdABlACAAYQBkAG0AaQBuACAAbABvAGMAYQBsACAAcwB0AGEAbgBkAGEAcgBkAGkAcwBlACAALQAgAGQAZQBwAGwAbwBpAGUAbQBlAG4AdAAgAHAAYQByAGMAIgAgAGMAcABhAHMAcwB3AG8AcgBkAD0AIgBIAEYAMABiADgASQBNAFoARQBKAFcAWABxAGMANgA1ADgAawBqAEoASQBpAHkANwArAGkARgBWADkAMQBKAG0AZQBQAC8AaABNACsAWABiAHEALwBJAD0AIgAgAGMAaABhAG4AZwBlAEwAbwBnAG8AbgA9ACIAMAAiACAAbgBvAEMAaABhAG4AZwBlAD0AIgAwACIAIABuAGUAdgBlAHIARQB4AHAAaQByAGUAcwA9ACIAMQAiACAAYQBjAGMAdABEAGkAcwBhAGIAbABlAGQAPQAiADAAIgAgAHMAdQBiAEEAdQB0AGgAbwByAGkAdAB5AD0AIgBSAEkARABfAEEARABNAEkATgAiACAAdQBzAGUAcgBOAGEAbQBlAD0AIgBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAZQB1AHIAIgAvAD4APAAvAFUAcwBlAHIAPgA8AC8ARwByAG8AdQBwAHMAPgA="))) | Out-Null
    Set-Content -Path "C:\Windows\SYSVOL\sysvol\nevasec.local\Policies\$gppGuid\GPT.INI" -Value "[General]`r`nVersion=1`r`ndisplayName=$gppGpoName" -Encoding ASCII
    Set-ADObject -Identity "CN=$gppGuid,CN=Policies,CN=System,DC=nevasec,DC=local" -Replace @{gPCMachineExtensionNames="[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"; versionNumber=1}

    Write-Host("`n  [++] Configuration ACLs")
    Set-Delegations

    Write-Host("`n  [++] Configuration ADCS template")
    New-CertTemplate -DisplayName "VPNCert" -SourceTemplateCN "User"
    New-CertTemplate -DisplayName "HelpdeskWorkstation" -SourceTemplateCN "User" -NameFlag 0 -FullControlGroup "Helpdesk"
}

function New-CertTemplate {
    param(
        [string]$DisplayName = "VPNCert",
        [string]$SourceTemplateCN = "User",
        [int]$NameFlag = 1,
        [string]$FullControlGroup = ""
    )

    $ConfigNC = (Get-ADRootDSE).configurationNamingContext
    $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    $Source = Get-ADObject -SearchBase $TemplatePath -Filter "cn -eq '$SourceTemplateCN'" -Properties *

    if (-not $Source) {
        Write-Host "    Template source introuvable: $SourceTemplateCN" -ForegroundColor Red
        return
    }

    $OIDPath = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
    $ExistingOIDs = Get-ADObject -SearchBase $OIDPath -Filter "objectClass -eq 'msPKI-Enterprise-Oid'" -Properties msPKI-Cert-Template-OID | Select-Object -First 1
    if ($ExistingOIDs) {
        $ForestOID = ($ExistingOIDs.'msPKI-Cert-Template-OID') -replace '\.\d+\.\d+$', ''
    } else {
        $ForestOID = "1.3.6.1.4.1.311.21.8"
    }
    $Part1 = Get-Random -Minimum 10000000 -Maximum 99999999
    $Part2 = Get-Random -Minimum 10000000 -Maximum 99999999
    $NewOID = "$ForestOID.$Part1.$Part2"
    $OIDName = $DisplayName.Replace(' ','') + "-" + (Get-Random -Minimum 10000 -Maximum 99999)

    New-ADObject -Path $OIDPath -Name $OIDName -Type "msPKI-Enterprise-Oid" -OtherAttributes @{
        'displayName' = $DisplayName
        'flags' = [System.Int32]1
        'msPKI-Cert-Template-OID' = $NewOID
    }

    $pKIExpirationPeriod = [byte[]](0x00, 0x80, 0x1A, 0x06, 0x00, 0x00, 0x00, 0x00)
    $pKIOverlapPeriod = [byte[]](0x00, 0x80, 0xA6, 0x0A, 0x02, 0x00, 0x00, 0x00)
    $pKIKeyUsage = [byte[]](0xA0, 0x00)

    $TemplateAttrs = @{
        'displayName' = $DisplayName
        'msPKI-Cert-Template-OID' = $NewOID
        'flags' = [System.Int32]131649
        'revision' = [System.Int32]100
        'msPKI-Template-Schema-Version' = [System.Int32]2
        'msPKI-Template-Minor-Revision' = [System.Int32]1
        'msPKI-RA-Signature' = [System.Int32]0
        'pKIMaxIssuingDepth' = [System.Int32]0
        'pKIDefaultKeySpec' = [System.Int32]1
        'msPKI-Enrollment-Flag' = [System.Int32]0
        'msPKI-Private-Key-Flag' = [System.Int32]16842752
        'msPKI-Minimal-Key-Size' = [System.Int32]2048
        'msPKI-Certificate-Name-Flag' = [System.Int32]$NameFlag
        'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2')
        'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.2')
        'pKICriticalExtensions' = @('2.5.29.15')
        'pKIDefaultCSPs' = @('1,Microsoft RSA SChannel Cryptographic Provider')
        'pKIExpirationPeriod' = $pKIExpirationPeriod
        'pKIOverlapPeriod' = $pKIOverlapPeriod
        'pKIKeyUsage' = $pKIKeyUsage
    }

    $TemplateCN = $DisplayName.Replace(' ','')
    New-ADObject -Path $TemplatePath -Name $TemplateCN -Type pKICertificateTemplate -OtherAttributes $TemplateAttrs

    Start-Sleep -Seconds 2

    $TemplateObj = Get-ADObject -SearchBase $TemplatePath -Filter "cn -eq '$TemplateCN'"
    if (-not $TemplateObj) {
        Write-Host "    Erreur: template non cree" -ForegroundColor Red
        return
    }

    $DomainUsersSID = (Get-ADGroup -Identity "$((Get-ADDomain).DomainSID.Value)-513").SID
    $acl = Get-Acl "AD:$($TemplateObj.DistinguishedName)"

    $EnrollGUID = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $DomainUsersSID,
        "ExtendedRight",
        "Allow",
        $EnrollGUID
    )
    $acl.AddAccessRule($ace)

    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $DomainUsersSID,
        "GenericRead",
        "Allow"
    )
    $acl.AddAccessRule($ace2)

    if ($FullControlGroup) {
        $CtrlSID = (Get-ADGroup -Identity $FullControlGroup).SID
        $ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($CtrlSID, "GenericAll", "Allow")
        $acl.AddAccessRule($ace3)
    }

    Set-Acl "AD:$($TemplateObj.DistinguishedName)" $acl

    $EnrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    $CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter *
    foreach ($CA in $CAs) {
        Set-ADObject -Identity $CA.DistinguishedName -Add @{certificateTemplates=$TemplateCN}
    }
}

function Set-Delegations {
    Import-Module ActiveDirectory

    $BackupSID = (Get-ADGroup -Identity "Backup").SID
    $DomainDN = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl "AD:$DomainDN"
    $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($BackupSID, "ExtendedRight", "Allow", [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
    $acl.AddAccessRule($ace1)
    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($BackupSID, "ExtendedRight", "Allow", [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
    $acl.AddAccessRule($ace2)
    Set-Acl "AD:$DomainDN" $acl

    $SvcLegacySID = (Get-ADUser -Identity "svc-legacy").SID
    $SvcSqlDN = (Get-ADUser -Identity "svc-sql").DistinguishedName
    $acl = Get-Acl "AD:$SvcSqlDN"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($SvcLegacySID, "ExtendedRight", "Allow", [GUID]"00299570-246d-11d0-a768-00aa006e0529")
    $acl.AddAccessRule($ace)
    Set-Acl "AD:$SvcSqlDN" $acl

    $SvcSqlSID = (Get-ADUser -Identity "svc-sql").SID
    $SvcBackupDN = (Get-ADUser -Identity "svc-backup").DistinguishedName
    $acl = Get-Acl "AD:$SvcBackupDN"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($SvcSqlSID, "GenericAll", "Allow")
    $acl.AddAccessRule($ace)
    Set-Acl "AD:$SvcBackupDN" $acl

    $ITGroupSID = (Get-ADGroup -Identity "IT").SID
    $AdminGroupDN = (Get-ADGroup -Identity "S-1-5-32-544").DistinguishedName
    $acl = Get-Acl "AD:$AdminGroupDN"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($ITGroupSID, "GenericWrite", "Allow")
    $acl.AddAccessRule($ace)
    Set-Acl "AD:$AdminGroupDN" $acl

    $org = "OU=NevaSec," + (Get-ADDomain).DistinguishedName

    $HelpdeskSID    = (Get-ADGroup -Identity "Helpdesk").SID
    $ForceChangePwd = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
    $UserClassGUID  = [GUID]"bf967aba-0de6-11d0-a285-00aa003049e2"
    foreach ($o in "Direction","Finance","RH","Management","Commercial","Marketing","Consultants") {
        $ouDN = "OU=$o,$org"
        $acl = Get-Acl "AD:$ouDN"
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($HelpdeskSID, "ExtendedRight", "Allow", $ForceChangePwd, "Descendents", $UserClassGUID)
        $acl.AddAccessRule($ace)
        Set-Acl "AD:$ouDN" $acl
    }

    $DevSID = (Get-ADGroup -Identity "Developpeurs").SID
    $WebDN  = (Get-ADUser -Identity "svc-web").DistinguishedName
    $acl = Get-Acl "AD:$WebDN"
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($DevSID, "GenericWrite", "Allow")))
    Set-Acl "AD:$WebDN" $acl

    $CvSID = (Get-ADUser -Identity "cvasseur").SID
    $PfDN  = (Get-ADGroup -Identity "Partage-Finance").DistinguishedName
    $acl = Get-Acl "AD:$PfDN"
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($CvSID, "WriteOwner", "Allow")))
    Set-Acl "AD:$PfDN" $acl

    $JbSID  = (Get-ADUser -Identity "jbreton").SID
    $RepDN  = (Get-ADUser -Identity "svc-report").DistinguishedName
    $acl = Get-Acl "AD:$RepDN"
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($JbSID, "WriteDacl", "Allow")))
    Set-Acl "AD:$RepDN" $acl

    $GmsaSID = (Get-ADServiceAccount -Identity "svc-gmsa").SID
    $BkDN    = (Get-ADUser -Identity "svc-backup").DistinguishedName
    $acl = Get-Acl "AD:$BkDN"
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GmsaSID, "GenericAll", "Allow")))
    Set-Acl "AD:$BkDN" $acl
}

function Invoke-LabSetup{
    $labNames = @('DC01','SRV01','PC01')
    if ($labNames -contains $env:COMPUTERNAME -and $env:COMPUTERNAME -ne $Config.HostName) {
        Write-Host "[ERREUR] Cette machine s'appelle '$env:COMPUTERNAME' mais vous avez lance le script de $($Config.HostName). Mauvais choix, aucune action effectuee." -ForegroundColor Red
        return
    }

    if ($env:COMPUTERNAME -ne $Config.HostName) {
        Write-Host "`n[ETAPE 1/3] Premiere execution detectee" -ForegroundColor Cyan
        Write-Host "Configuration reseau..." -ForegroundColor Yellow
        Set-IPAddress
        Write-Host "Configuration securite..." -ForegroundColor Yellow
        Nuke-Defender
        Write-Host "Configuration systeme..." -ForegroundColor Yellow
        Get-QoL
        Write-Host "Desactivation ouverture auto Server Manager et verrouillage auto..." -ForegroundColor Yellow
        reg add "HKLM\SOFTWARE\Microsoft\ServerManager" /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f > $null
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 0 /f > $null
        Write-Host "Configuration du fond d'ecran..." -ForegroundColor Yellow
        Set-Wallpaper
        Write-Host "`nRedemarrage en cours..." -ForegroundColor Green
        Start-Sleep -Seconds 5
        Rename-Computer -NewName $Config.HostName -Restart
    }
    elseif ($env:USERDNSDOMAIN -ne $Config.DomainFQDN) {
        Write-Host "`n[ETAPE 2/3] Deuxieme execution detectee" -ForegroundColor Cyan
        Write-Host "Installation Active Directory..." -ForegroundColor Yellow
        Build-Server
    }
    elseif ($env:COMPUTERNAME -eq $Config.HostName -and $env:USERDNSDOMAIN -eq $Config.DomainFQDN) {
        $exists = $false
        try {
            $user = Get-ADUser -Identity "svc-sql" -ErrorAction Stop
            $exists = $true
            Write-Host "`n[INFO] Lab deja configure !" -ForegroundColor Green
        }
        catch {
            $exists = $false
        }

        if (-not $exists) {
            Write-Host "`n[ETAPE 3/3] Troisieme execution detectee" -ForegroundColor Cyan
            Write-Host "Configuration du contenu AD..." -ForegroundColor Yellow
            try {
                Add-ServerContent
                Write-Host "`n[SUCCES] Configuration de $($Config.HostName) terminee !" -ForegroundColor Green
                Write-Host "`nEtape manuelle:" -ForegroundColor Yellow
                Write-Host "  Executer sur DC01 apres config de SRV01:" -ForegroundColor Yellow
                Write-Host "  Get-ADComputer -Identity SRV01 | Set-ADAccountControl -TrustedForDelegation `$true" -ForegroundColor Yellow
            }
            catch {
                Write-Error "Erreur: $($_.Exception.Message)"
                Read-Host "Appuyez sur Entree pour quitter"
                exit 1
            }
        }
    }
}
