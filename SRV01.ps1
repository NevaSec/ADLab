#Requires -RunAsAdministrator

# ============================================
# Configuration centralisée
# ============================================
$Config = @{
    DomainName       = "NEVASEC"
    DomainFQDN       = "NEVASEC.LOCAL"
    DomainAdminUser  = "Administrateur"
    DomainAdminPwd   = "R00tR00t"
    HostName         = "SRV01"
    DCStaticIPSuffix = ".250"
    LocalAdminUser   = "srvadmin"
    LocalAdminPwd    = "Super-Password-4-Admin"
    LLMNRUser        = "NEVASEC\mlaurens"
    LLMNRPwd         = "IQAwAE4AZQB2AGEAZwByAHUAcAAwACEA"  # base64
}

function Invoke-LabSetup { 

    if ($env:COMPUTERNAME -ne $Config.HostName) {
        Write-Host "`n[ETAPE 1/3] Changement des paramètres IP et du nom, puis redémarrage..." -ForegroundColor Cyan

        try {
            # Désactivation Windows Update
            Write-Host "Désactivation de Windows Update..." -ForegroundColor Yellow
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
            Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null

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
            # Configuration de la tâche planifiée LLMNR
            Write-Host "Configuration de la tâche planifiée LLMNR..." -ForegroundColor Yellow
            $group = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VQB0AGkAbABpAHMAYQB0AGUAdQByAHMAIABkAHUAIABCAHUAcgBlAGEAdQAgAOAAIABkAGkAcwB0AGEAbgBjAGUA"))

            $task = '/c powershell New-PSDrive -Name "SQLShare" -PSProvider "FileSystem" -Root "\\SQL01\Share"'
            $repeat = (New-TimeSpan -Minutes 2)
            $taskName = "llmnr_trigger"
            $llmnrUser = $Config.LLMNRUser
            $llmnrPassword = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Config.LLMNRPwd))

            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "$task"
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval $repeat
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd

            $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
            if ($taskExists) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $llmnrUser -Password $llmnrPassword -Settings $settings | Out-Null
            Write-Host "Tâche planifiée LLMNR créée (s'exécute toutes les 2 minutes)" -ForegroundColor Green

            # Création de l'utilisateur local
            Write-Host "Création de l'utilisateur local $($Config.LocalAdminUser)..." -ForegroundColor Yellow
            New-LocalUser -Name $Config.LocalAdminUser -Password (ConvertTo-SecureString $Config.LocalAdminPwd -AsPlainText -Force) -ErrorAction SilentlyContinue

            # Ajout des groupes du domaine
            Write-Host "Ajout des groupes du domaine aux administrateurs locaux..." -ForegroundColor Yellow
            Add-LocalGroupMember -Group $group -Member 'NEVASEC\Admins du domaine' -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group $group -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group 'Administrateurs' -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue

            Write-Host "`n[SUCCES] Configuration de $($Config.HostName) terminée !" -ForegroundColor Green
            Write-Host "N'oubliez pas d'exécuter sur DC01:" -ForegroundColor Yellow
            Write-Host "  Get-ADComputer -Identity SRV01 | Set-ADAccountControl -TrustedForDelegation `$true" -ForegroundColor Yellow
        }
        catch {
            Write-Error "Erreur lors de la configuration finale: $($_.Exception.Message)"
            Read-Host "Appuyez sur Entrée pour quitter"
            exit 1
        }
    }
} 
