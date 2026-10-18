#Requires -RunAsAdministrator

$Config = @{
    DomainName       = "NEVASEC"
    DomainFQDN       = "NEVASEC.LOCAL"
    DomainAdminUser  = "Administrateur"
    DomainAdminPwd   = "R00tR00t"
    HostName         = "SRV01"
    DCStaticIPSuffix = ".250"
    LocalAdminUser   = "srvadmin"
    LocalAdminPwd    = "Super-Password-4-Admin"
    TaskUser          = "NEVASEC\mlaurens"
    TaskPwd           = "IQAwAE4AZQB2AGEAZwByAHUAcAAwACEA"
    RdpTarget        = "TERMSRV/SQL01"
    RdpCredUser      = "NEVASEC\hdesk"
    RdpCredPwd       = "SABkACEANwBrAFAAMgBtAFgAegA5AFEAdwAkAEwAcgA="
}

function ConvertFrom-B64 {
    param([string]$s)
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($s))
}

function Set-Wallpaper {
    try {
        $dir = "C:\Windows\Web\Wallpaper\NevaSec"
        $img = "$dir\nevasec.png"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/NevaSec/ADLab/raw/main/assets/nevasec.png" -OutFile $img
        $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        New-Item -Path $key -Force | Out-Null
        Set-ItemProperty -Path $key -Name Wallpaper      -Value $img
        Set-ItemProperty -Path $key -Name WallpaperStyle -Value "6"
        rundll32.exe user32.dll,UpdatePerUserSystemParameters
    }
    catch {
        Write-Host "[AVERTISSEMENT] Configuration du fond d'ecran ignoree: $($_.Exception.Message)" -ForegroundColor Yellow
    }
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
            Write-Host "Desactivation de Windows Update..." -ForegroundColor Yellow
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

            Write-Host "Enregistrement de la credential RDP (profil admin local)..." -ForegroundColor Yellow
            $rdpCredPwd = ConvertFrom-B64 $Config.RdpCredPwd
            cmdkey /generic:$($Config.RdpTarget) /user:$($Config.RdpCredUser) /pass:$rdpCredPwd | Out-Null

            Write-Host "Configuration du fond d'ecran..." -ForegroundColor Yellow
            Set-Wallpaper

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
            Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null

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

            $task = ConvertFrom-B64 "LwBjACAAcABvAHcAZQByAHMAaABlAGwAbAAgAE4AZQB3AC0AUABTAEQAcgBpAHYAZQAgAC0ATgBhAG0AZQAgACIAUwBRAEwAUwBoAGEAcgBlACIAIAAtAFAAUwBQAHIAbwB2AGkAZABlAHIAIAAiAEYAaQBsAGUAUwB5AHMAdABlAG0AIgAgAC0AUgBvAG8AdAAgACIAXABcAFMAUQBMADAAMQBcAFMAaABhAHIAZQAiAA=="
            $taskName = "SQLshare"
            $botUser = $Config.TaskUser
            $botPassword = ConvertFrom-B64 $Config.TaskPwd

            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "$task"
            $triggerStartup = New-ScheduledTaskTrigger -AtStartup
            $triggerStartup.Delay = 'PT1M'
            $triggerRepeat  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd

            $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
            if ($taskExists) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggerStartup,$triggerRepeat -User $botUser -Password $botPassword -Settings $settings | Out-Null

            Write-Host "Creation de l'utilisateur local $($Config.LocalAdminUser)..." -ForegroundColor Yellow
            New-LocalUser -Name $Config.LocalAdminUser -Password (ConvertTo-SecureString $Config.LocalAdminPwd -AsPlainText -Force) -ErrorAction SilentlyContinue

            Write-Host "Ajout des groupes du domaine aux administrateurs locaux..." -ForegroundColor Yellow
            Add-LocalGroupMember -Group $rdpGroup   -Member $domainAdmins -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group $rdpGroup   -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue
            Add-LocalGroupMember -Group $adminGroup -Member 'NEVASEC\IT' -ErrorAction SilentlyContinue

            Write-Host "Configuration de la delegation sur l'objet ordinateur $($Config.HostName)..." -ForegroundColor Yellow
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(sAMAccountName=$($Config.HostName)`$)"
            $de = $searcher.FindOne().GetDirectoryEntry()
            $de.Properties["userAccountControl"].Value = $de.Properties["userAccountControl"].Value -bor 0x80000
            $de.CommitChanges()

            Write-Host "`n[SUCCES] Configuration de $($Config.HostName) terminee !" -ForegroundColor Green
        }
        catch {
            Write-Error "Erreur lors de la configuration finale: $($_.Exception.Message)"
            Read-Host "Appuyez sur Entree pour quitter"
            exit 1
        }
    }
}
