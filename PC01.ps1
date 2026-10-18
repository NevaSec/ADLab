#Requires -RunAsAdministrator

$Config = @{
    DomainName      = "NEVASEC"
    DomainFQDN      = "NEVASEC.LOCAL"
    DomainAdminUser = "Administrateur"
    DomainAdminPwd  = "R00tR00t"
    HostName        = "PC01"
    DCStaticIPSuffix = ".250"
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

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f > $null
}

function Invoke-LabSetup {

    $labNames = @('DC01','SRV01','PC01')
    if ($labNames -contains $env:COMPUTERNAME -and $env:COMPUTERNAME -ne $Config.HostName) {
        Write-Host "[ERREUR] Cette machine s'appelle '$env:COMPUTERNAME' mais vous avez lance le script de $($Config.HostName). Mauvais choix, aucune action effectuee." -ForegroundColor Red
        return
    }

    if ($env:COMPUTERNAME -ne $Config.HostName) {
        Write-Host "`n[ETAPE 1/3] Changement des parametres IP et du nom, puis redemarrage..." -ForegroundColor Cyan

        try {
            Nuke-Defender

            $NetAdapter = Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
            $IPAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapter | Select-Object -ExpandProperty IPAddress
            $IPByte = $IPAddress.Split(".")
            $DNS = ($IPByte[0] + "." + $IPByte[1] + "." + $IPByte[2] + $Config.DCStaticIPSuffix)

            Write-Host "Configuration DNS: $DNS" -ForegroundColor Green
            Set-DnsClientServerAddress -InterfaceAlias $NetAdapter -ServerAddresses ("$DNS","1.1.1.1")
            Disable-NetAdapterPowerManagement -Name "$NetAdapter"
            netsh interface ipv6 set dnsservers "$NetAdapter" dhcp

            Write-Host "Renommage de la machine en $($Config.HostName)..." -ForegroundColor Green
            Rename-Computer -NewName $Config.HostName -Restart
        }
        catch {
            Write-Error "Erreur lors de la configuration initiale: $($_.Exception.Message)"
            Read-Host "Appuyez sur Entree pour quitter"
            exit 1
        }
    }
    elseif ($env:COMPUTERNAME -eq $Config.HostName -and $env:USERDNSDOMAIN -ne $Config.DomainFQDN) {
        Write-Host "`n[ETAPE 2/3] Ajout au domaine et redemarrage..." -ForegroundColor Cyan

        try {

            $password = $Config.DomainAdminPwd | ConvertTo-SecureString -asPlainText -Force
            $username = "$($Config.DomainName)\$($Config.DomainAdminUser)"
            $credential = New-Object System.Management.Automation.PSCredential($username, $password)

            Write-Host "Test de connectivite au domaine $($Config.DomainFQDN)..." -ForegroundColor Yellow
            if (Test-Connection -ComputerName $Config.DomainFQDN -Count 5 -Quiet) {
                Write-Host "Domaine accessible, jonction en cours..." -ForegroundColor Green
                Add-Computer -DomainName $Config.DomainName -Credential $credential -ErrorAction Stop | Out-Null
                Start-Sleep 5
                Restart-Computer
            }
            else {
                Write-Error "Impossible de joindre le domaine $($Config.DomainFQDN)"
                Write-Host "`nVerifications a effectuer:" -ForegroundColor Yellow
                Write-Host "  1. DC01 est-il demarre ?" -ForegroundColor Yellow
                Write-Host "  2. Le DNS pointe-t-il vers DC01 ? (Get-DnsClientServerAddress)" -ForegroundColor Yellow
                Write-Host "  3. Pouvez-vous pinger DC01 ?" -ForegroundColor Yellow
                Read-Host "`nAppuyez sur Entree pour quitter"
                exit 1
            }
        }
        catch {
            Write-Error "Erreur lors de la jonction au domaine: $($_.Exception.Message)"
            Write-Host "`nAssurez-vous que:" -ForegroundColor Yellow
            Write-Host "  - DC01 a termine son installation complete (3 executions)" -ForegroundColor Yellow
            Write-Host "  - Le DNS est correctement configure" -ForegroundColor Yellow
            Write-Host "  - Les credentials du domaine sont corrects" -ForegroundColor Yellow
            Read-Host "`nAppuyez sur Entree pour quitter"
            exit 1
        }
    }
    else {
        Write-Host "`n[ETAPE 3/3] Configuration finale..." -ForegroundColor Cyan

        try {
            $rdpGroup   = (Get-LocalGroup -SID 'S-1-5-32-555').Name
            $adminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name
            $domainSid    = (New-Object System.Security.Principal.NTAccount("$env:USERDOMAIN\krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).AccountDomainSid.Value
            $domainAdmins = "$domainSid-512"

            $itAlreadyMember = Get-LocalGroupMember -Group $rdpGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "$($Config.DomainName)\IT" }
            if ($itAlreadyMember) {
                Write-Host "[INFO] $($Config.HostName) est deja entierement configure. Rien a faire." -ForegroundColor Green
                return
            }

            $mySids = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value }
            if ($mySids -notcontains "$domainSid-512") {
                Write-Host "[ERREUR] Cette etape doit etre lancee en tant qu'Administrateur du domaine. Reconnectez-vous avec ce compte." -ForegroundColor Red
                return
            }

            Write-Host "Ajout des groupes du domaine aux administrateurs locaux..." -ForegroundColor Green
            Add-LocalGroupMember -Group $rdpGroup   -Member $domainAdmins -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group $rdpGroup   -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group $adminGroup -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue

            Write-Host "`n[SUCCES] Configuration de $($Config.HostName) terminee !" -ForegroundColor Green
            Write-Host "Vous pouvez maintenant creer un snapshot de cette VM." -ForegroundColor Yellow
        }
        catch {
            Write-Error "Erreur lors de la configuration finale: $($_.Exception.Message)"
            Read-Host "Appuyez sur Entree pour quitter"
            exit 1
        }
    }
}
