#Requires -RunAsAdministrator

# ============================================
# Configuration centralisée
# ============================================
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

        # Désactivation Windows Update
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
    
    # SMB signing enabled but not required
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f > $null

    Get-WmiObject -query "Select HotFixID  from Win32_QuickFixengineering" | sort-object -Descending -Property HotFixID|%{
    $sUpdate=$_.HotFixID.Replace("KB","")
    write-host ("Uninstalling update "+$sUpdate);
    & wusa.exe /uninstall /KB:$sUpdate /quiet /norestart;
    Wait-Process wusa 
    Start-Sleep -s 1 }

}


function Invoke-LabSetup {

    if ($env:COMPUTERNAME -ne $Config.HostName) {
        Write-Host "`n[ETAPE 1/3] Changement des paramètres IP et du nom, puis redémarrage..." -ForegroundColor Cyan

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
            Read-Host "Appuyez sur Entrée pour quitter"
            exit 1
        }
    }
    elseif ($env:COMPUTERNAME -eq $Config.HostName -and $env:USERDNSDOMAIN -ne $Config.DomainFQDN) {
        Write-Host "`n[ETAPE 2/3] Ajout au domaine et redémarrage..." -ForegroundColor Cyan

        try {
            Nuke-Defender

            $password = $Config.DomainAdminPwd | ConvertTo-SecureString -asPlainText -Force
            $username = "$($Config.DomainName)\$($Config.DomainAdminUser)"
            $credential = New-Object System.Management.Automation.PSCredential($username, $password)

            # Vérification de la connectivité au domaine avant jonction
            Write-Host "Test de connectivité au domaine $($Config.DomainFQDN)..." -ForegroundColor Yellow
            if (Test-Connection -ComputerName $Config.DomainFQDN -Count 5 -Quiet) {
                Write-Host "Domaine accessible, jonction en cours..." -ForegroundColor Green
                Add-Computer -DomainName $Config.DomainName -Credential $credential -ErrorAction Stop | Out-Null
                Start-Sleep 5
                Restart-Computer
            }
            else {
                Write-Error "Impossible de joindre le domaine $($Config.DomainFQDN)"
                Write-Host "`nVérifications à effectuer:" -ForegroundColor Yellow
                Write-Host "  1. DC01 est-il démarré ?" -ForegroundColor Yellow
                Write-Host "  2. Le DNS pointe-t-il vers DC01 ? (Get-DnsClientServerAddress)" -ForegroundColor Yellow
                Write-Host "  3. Pouvez-vous pinger DC01 ?" -ForegroundColor Yellow
                Read-Host "`nAppuyez sur Entrée pour quitter"
                exit 1
            }
        }
        catch {
            Write-Error "Erreur lors de la jonction au domaine: $($_.Exception.Message)"
            Write-Host "`nAssurez-vous que:" -ForegroundColor Yellow
            Write-Host "  - DC01 a terminé son installation complète (3 exécutions)" -ForegroundColor Yellow
            Write-Host "  - Le DNS est correctement configuré" -ForegroundColor Yellow
            Write-Host "  - Les credentials du domaine sont corrects" -ForegroundColor Yellow
            Read-Host "`nAppuyez sur Entrée pour quitter"
            exit 1
        }
    }
    else {
        Write-Host "`n[ETAPE 3/3] Configuration finale..." -ForegroundColor Cyan

        try {
            $group = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VQB0AGkAbABpAHMAYQB0AGUAdQByAHMAIABkAHUAIABCAHUAcgBlAGEAdQAgAOAAIABkAGkAcwB0AGEAbgBjAGUA"))

            Write-Host "Ajout des groupes du domaine aux administrateurs locaux..." -ForegroundColor Green
            Add-LocalGroupMember -Group $group -Member 'NEVASEC\Admins du domaine' -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group $group -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group Administrateurs -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue

            Write-Host "`n[SUCCES] Configuration de $($Config.HostName) terminée !" -ForegroundColor Green
            Write-Host "Vous pouvez maintenant créer un snapshot de cette VM." -ForegroundColor Yellow
        }
        catch {
            Write-Error "Erreur lors de la configuration finale: $($_.Exception.Message)"
            Read-Host "Appuyez sur Entrée pour quitter"
            exit 1
        }
    }
} 
