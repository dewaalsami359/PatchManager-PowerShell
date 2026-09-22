<#
    PatchManager.psm1
    -----------------------------------------------------------------------
    Module central de la solution de Patch Management.
    Regroupe les fonctions utilisees par le script orchestrateur
    Invoke-PatchManagement.ps1 (Parties 1 a 8 du projet).

    Auteur  : Sami De Waal (I2 - Ethical Hacking)
    Module  : Securite des systemes d'exploitation
    -----------------------------------------------------------------------
#>

# ======================================================================
#  JOURNALISATION (Partie 6.4)
#  Ecrit une ligne horodatee dans le fichier de journal, au format :
#  JJ/MM/AAAA HH:MM:SS ; message
# ======================================================================
function Write-PmLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [string] $LogFile = "$PSScriptRoot\..\output\PatchManager.log"
    )
    $ts = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss')
    $line = "$ts ; $Message"
    # -Append : on conserve l'historique des executions (Partie 6.4)
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Verbose $line
}

# ======================================================================
#  LECTURE DE L'INVENTAIRE (Parties 1.3 et 2.1)
#  Lit config/computers.txt (format "Nom;IP") et renvoie des objets.
# ======================================================================
function Get-Inventory {
    [CmdletBinding()]
    param(
        [string] $Path = "$PSScriptRoot\..\config\computers.txt"
    )
    if (-not (Test-Path $Path)) {
        throw "Fichier d'inventaire introuvable : $Path"
    }
    Get-Content -Path $Path | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
        $name, $ip = ($_ -split ';').Trim()
        [pscustomobject]@{
            Poste     = $name
            AdresseIP = $ip
        }
    }
}

# ======================================================================
#  TEST DE DISPONIBILITE (Parties 1.4 et 2.1)
#  1) Test-Connection : la machine repond-elle au reseau (ICMP) ?
#  2) Test-WSMan      : le service WinRM est-il joignable (admin distante) ?
#  On distingue les deux car une machine peut "pinguer" sans avoir WinRM.
# ======================================================================
function Test-NodeOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName
    )
    $ping = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet -ErrorAction SilentlyContinue
    $winrm = $false
    $erreur = $null
    if ($ping) {
        try {
            Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
            $winrm = $true
        }
        catch {
            $erreur = "WinRM injoignable : $($_.Exception.Message)"
        }
    }
    else {
        $erreur = "Hote injoignable (ping)"
    }
    [pscustomobject]@{
        Ping      = [bool]$ping
        WinRM     = $winrm
        Accessible = ($ping -and $winrm)
        Erreur    = $erreur
    }
}

# ======================================================================
#  DETECTION DU POSTE LOCAL
#  Determine si la cible designee est CETTE machine (nom, localhost,
#  boucle locale ou une de ses IP). Dans ce cas, la collecte se fait en
#  direct, sans WinRM : inutile (et contre-productif) de faire un aller-
#  retour reseau vers soi-meme, qui exigerait d'affaiblir la securite du
#  poste (compte local + jeton filtre par l'UAC). Le chemin WinRM reste
#  utilise tel quel pour les postes DISTANTS du parc.
# ======================================================================
function Test-IsLocalNode {
    [CmdletBinding()]
    param([string] $ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    $locales = @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1', '.')
    try {
        $locales += [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                    ForEach-Object { $_.IPAddressToString }
    } catch { }
    return ($ComputerName -in $locales)
}

# ======================================================================
#  COLLECTE SYSTEME A DISTANCE (Partie 2.2 et 2.3)
#  Recupere via WinRM les caracteristiques materielles/logicielles
#  d'un poste + informations utiles au Patch Management.
# ======================================================================
function Get-NodeSystemInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [System.Management.Automation.PSCredential] $Credential
    )
    # Poste local -> execution en direct (sans WinRM) ; distant -> WinRM
    $params = @{ ErrorAction = 'Stop' }
    if (-not (Test-IsLocalNode $ComputerName)) {
        $params.ComputerName = $ComputerName
        if ($Credential) { $params.Credential = $Credential }
    }

    Invoke-Command @params -ScriptBlock {
        $os   = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $sys  = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
        $hf   = Get-HotFix | Sort-Object InstalledOn -Descending
        $wu   = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

        [pscustomobject]@{
            NomPoste        = $env:COMPUTERNAME
            Modele          = $cs.Model
            VersionBios     = $bios.SMBIOSBIOSVersion
            Windows         = $os.Caption
            VersionWindows  = $os.Version
            Architecture    = $os.OSArchitecture
            DernierDemarrage = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('dd/MM/yyyy HH:mm') } else { '' })
            RAM_Go          = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            DisqueLibre_Go  = [math]::Round($sys.FreeSpace / 1GB, 1)
            DerniereMaj     = $(if ($hf) { ($hf | Select-Object -First 1).InstalledOn.ToString('dd/MM/yyyy') } else { '' })
            NbMaj           = $hf.Count
            WindowsUpdate   = $(if ($wu) { $wu.Status } else { 'Absent' })
        }
    }
}

# ======================================================================
#  COLLECTE DES CORRECTIFS A DISTANCE (Partie 3)
#  Renvoie la liste des KB installes sur un poste.
# ======================================================================
function Get-NodePatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [System.Management.Automation.PSCredential] $Credential
    )
    # Poste local -> execution en direct (sans WinRM) ; distant -> WinRM
    $params = @{ ErrorAction = 'Stop' }
    if (-not (Test-IsLocalNode $ComputerName)) {
        $params.ComputerName = $ComputerName
        if ($Credential) { $params.Credential = $Credential }
    }

    Invoke-Command @params -ScriptBlock {
        Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy
    } | Select-Object HotFixID, Description, InstalledOn, InstalledBy
}

# ======================================================================
#  LECTURE DE LA POLITIQUE DE CONFORMITE (Partie 4.1)
# ======================================================================
function Get-RequiredPatches {
    [CmdletBinding()]
    param(
        [string] $Path = "$PSScriptRoot\..\config\required-patches.txt"
    )
    if (-not (Test-Path $Path)) { throw "Politique introuvable : $Path" }
    Get-Content $Path | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and $_ -notmatch '^\s*#' }
}

# ======================================================================
#  EVALUATION DE LA CONFORMITE D'UN POSTE (Partie 4.2 et 4.3)
#  Compare les KB installes a la liste obligatoire.
#  Etat : CONFORME / NON CONFORME / INACCESSIBLE.
# ======================================================================
function Get-NodeCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $InstalledKB,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $RequiredKB
    )
    $manquants = $RequiredKB | Where-Object { $_ -notin $InstalledKB }
    [pscustomobject]@{
        KBRequises  = $RequiredKB.Count
        KBManquantes = $manquants
        NbManquants = ($manquants | Measure-Object).Count
        Etat        = $(if (($manquants | Measure-Object).Count -eq 0) { 'CONFORME' } else { 'NON CONFORME' })
    }
}

# ======================================================================
#  GENERATION DU RAPPORT HTML (Partie 6.3)
# ======================================================================
function New-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Report,
        [Parameter(Mandatory)] [hashtable] $Synthese,
        [string] $Path = "$PSScriptRoot\..\output\SecurityReport.html"
    )
    $style = @"
<style>
 body { font-family:'Segoe UI',Arial,sans-serif; color:#1a2230; margin:24px; }
 h1 { color:#1f4e79; } h2 { color:#1f4e79; border-bottom:2px solid #dde3ea; padding-bottom:4px; }
 table { border-collapse:collapse; width:100%; font-size:13px; margin:10px 0; }
 th,td { border:1px solid #cbd5e1; padding:6px 9px; text-align:left; }
 th { background:#1f4e79; color:#fff; }
 tr.CONFORME td      { background:#e6f4ea; }
 tr.NONCONFORME td   { background:#fdecea; }
 tr.INACCESSIBLE td  { background:#f0f0f0; color:#666; }
 .kpi { display:inline-block; background:#eef4fb; border:1px solid #bcd4ee; border-radius:6px;
        padding:8px 14px; margin:4px; font-size:14px; }
 .kpi b { color:#1f4e79; font-size:18px; display:block; }
</style>
"@

    $rows = foreach ($r in $Report) {
        $cls = ($r.Etat -replace '\s','')
        "<tr class='$cls'><td>$($r.Poste)</td><td>$($r.AdresseIP)</td><td>$($r.Accessibilite)</td>" +
        "<td>$($r.Windows)</td><td>$($r.DernierDemarrage)</td><td>$($r.WindowsUpdate)</td>" +
        "<td>$($r.KBRequises)</td><td>$($r.NbManquants)</td><td>$($r.KBListeManquantes)</td>" +
        "<td>$($r.Etat)</td><td>$($r.DateControle)</td></tr>"
    }

    $intervention = $Report | Where-Object { $_.Etat -ne 'CONFORME' }
    $interRows = foreach ($r in $intervention) {
        "<tr class='$($r.Etat -replace '\s','')'><td>$($r.Poste)</td><td>$($r.Etat)</td>" +
        "<td>$($r.KBListeManquantes)</td></tr>"
    }

    $html = @"
<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>Rapport de securite - Patch Management</title>$style</head><body>
<h1>Rapport de securite - Parc Windows</h1>
<p>Genere le $(Get-Date -Format 'dd/MM/yyyy a HH:mm:ss')</p>

<h2>Synthese globale</h2>
<div>
 <span class="kpi"><b>$($Synthese.Total)</b>Total postes</span>
 <span class="kpi"><b>$($Synthese.Accessibles)</b>Accessibles</span>
 <span class="kpi"><b>$($Synthese.Inaccessibles)</b>Inaccessibles</span>
 <span class="kpi"><b>$($Synthese.Conformes)</b>Conformes</span>
 <span class="kpi"><b>$($Synthese.NonConformes)</b>Non conformes</span>
 <span class="kpi"><b>$($Synthese.TotalManquants)</b>Correctifs manquants</span>
 <span class="kpi"><b>$($Synthese.Taux) %</b>Taux de conformite</span>
</div>

<h2>Detail par poste</h2>
<table>
<tr><th>Poste</th><th>IP</th><th>Accessibilite</th><th>Windows</th><th>Dernier demarrage</th>
<th>Win Update</th><th>KB requises</th><th>KB manquantes</th><th>Liste KB manquantes</th>
<th>Etat</th><th>Date controle</th></tr>
$($rows -join "`n")
</table>

<h2>Postes necessitant une intervention</h2>
<table><tr><th>Poste</th><th>Etat</th><th>KB manquantes</th></tr>
$($interRows -join "`n")
</table>
</body></html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
    return $Path
}

# ======================================================================
#  NOTIFICATION (Partie 7)
#  Construit le message d'alerte au format impose et le journalise.
#  L'envoi SMTP est optionnel ; les identifiants NE sont JAMAIS en clair
#  (ils sont lus depuis un fichier chiffre via Import-Clixml).
# ======================================================================
function Send-PmNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Report,
        [Parameter(Mandatory)] [hashtable] $Synthese,
        [string] $ReportPath,
        [string] $To = 'admin@entreprise.local',
        [string] $From = 'patchmanager@entreprise.local',
        [string] $SmtpServer,
        [string] $CredentialFile = "$PSScriptRoot\..\config\smtp-cred.xml",
        [switch] $Send
    )
    $anomalies = $Report | Where-Object { $_.Etat -in 'NON CONFORME', 'INACCESSIBLE' }

    # La notification n'est envoyee QUE s'il y a au moins une anomalie (Partie 7.1)
    if (-not $anomalies) {
        Write-PmLog "Aucune anomalie : pas de notification"
        return
    }

    $lignes = foreach ($a in $anomalies) {
        if ($a.Etat -eq 'INACCESSIBLE') {
            "$($a.Poste) : INACCESSIBLE"
        }
        else {
            "$($a.Poste) : NON CONFORME`n        KB manquante(s) : $($a.KBListeManquantes)"
        }
    }

    $body = @"
Objet : [PATCH MANAGEMENT] Anomalies detectees

Date du controle : $(Get-Date -Format 'dd/MM/yyyy')

Postes controles      : $($Synthese.Total)
Postes non conformes  : $($Synthese.NonConformes)
Postes inaccessibles  : $($Synthese.Inaccessibles)

$($lignes -join "`n`n")
"@

    Write-Host $body -ForegroundColor Yellow

    if ($Send -and $SmtpServer) {
        try {
            $cred = $null
            if (Test-Path $CredentialFile) { $cred = Import-Clixml $CredentialFile }
            $mail = @{
                To = $To; From = $From; Subject = '[PATCH MANAGEMENT] Anomalies detectees'
                Body = $body; SmtpServer = $SmtpServer; UseSsl = $true
            }
            if ($cred) { $mail.Credential = $cred }
            if ($ReportPath -and (Test-Path $ReportPath)) { $mail.Attachments = $ReportPath }
            Send-MailMessage @mail -ErrorAction Stop
            Write-PmLog "Notification envoyee a $To"
        }
        catch {
            Write-PmLog "ERREUR ; Notification non envoyee ; $($_.Exception.Message)"
        }
    }
    else {
        Write-PmLog "Notification construite (mode simulation, non envoyee)"
    }
    return $body
}

Export-ModuleMember -Function Write-PmLog, Get-Inventory, Test-NodeOnline,
    Get-NodeSystemInfo, Get-NodePatches, Get-RequiredPatches, Get-NodeCompliance,
    New-HtmlReport, Send-PmNotification
