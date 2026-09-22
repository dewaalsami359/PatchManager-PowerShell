<#
    Invoke-PatchManagement.ps1
    -----------------------------------------------------------------------
    Script orchestrateur de la solution de Patch Management.
    Enchaine la chaine complete du projet :
       Inventaire -> Connexion distante (WinRM) -> Collecte des correctifs
       -> Controle de conformite -> Detection des anomalies -> Reporting
       -> Notification.

    Correspond aux Parties 2, 3, 4, 6 et 7 du sujet.
    (La Partie 1 est une phase de preparation ; la Partie 8 est traitee
     dans le rapport et via les recommandations en fin de fichier.)

    USAGE :
       .\Invoke-PatchManagement.ps1
       .\Invoke-PatchManagement.ps1 -Credential (Get-Credential) -SendMail

    Auteur : Sami De Waal (I2 - Ethical Hacking)
    Module : Securite des systemes d'exploitation
    -----------------------------------------------------------------------
#>

[CmdletBinding()]
param(
    [System.Management.Automation.PSCredential] $Credential,
    [switch] $SendMail,
    [string] $SmtpServer = 'smtp.entreprise.local'
)

# --- Chargement du module et preparation des chemins -------------------
$Root = $PSScriptRoot
Import-Module "$Root\modules\PatchManager.psm1" -Force

$OutDir = Join-Path $Root 'output'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$InventoryCsv  = Join-Path $OutDir 'Inventory.csv'
$PatchesCsv    = Join-Path $OutDir 'PatchesInventory.csv'
$ComplianceCsv = Join-Path $OutDir 'ComplianceReport.csv'
$HtmlReport    = Join-Path $OutDir 'SecurityReport.html'

$DateControle = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'

Write-PmLog "Debut de l'audit"

# --- Lecture des sources ----------------------------------------------
$parc     = @(Get-Inventory)
$required = @(Get-RequiredPatches)
Write-Host "Parc : $($parc.Count) poste(s) - Politique : $($required.Count) KB requis" -ForegroundColor Cyan

# Collections resultats
$inventaire   = New-Object System.Collections.Generic.List[object]
$patchesAll   = New-Object System.Collections.Generic.List[object]
$rapport      = New-Object System.Collections.Generic.List[object]

# ======================================================================
#  BOUCLE PRINCIPALE SUR CHAQUE POSTE
#  Le script continue meme si un poste est inaccessible (Partie 2/3).
# ======================================================================
foreach ($poste in $parc) {

    $nom = $poste.Poste
    $ip  = $poste.AdresseIP
    Write-Host "`n=== $nom ($ip) ===" -ForegroundColor White

    $etatReseau = Test-NodeOnline -ComputerName $ip

    # ---- Cas machine INACCESSIBLE -------------------------------------
    if (-not $etatReseau.Accessible) {
        Write-PmLog "$nom ; WinRM inaccessible"
        Write-Warning "  Inaccessible : $($etatReseau.Erreur)"

        $inventaire.Add([pscustomobject]@{
            Poste = $nom; AdresseIP = $ip; Windows = '-'; Architecture = '-'
            DernierDemarrage = '-'; WindowsUpdate = '-'; Etat = 'Inaccessible'
            Erreur = $etatReseau.Erreur
        })
        $rapport.Add([pscustomobject]@{
            Poste = $nom; AdresseIP = $ip; Accessibilite = 'Inaccessible'
            Windows = '-'; DernierDemarrage = '-'; WindowsUpdate = '-'
            KBRequises = $required.Count; NbManquants = '-'; KBListeManquantes = '-'
            Etat = 'INACCESSIBLE'; DateControle = $DateControle; Erreur = $etatReseau.Erreur
        })
        continue
    }

    Write-PmLog "$nom ; Accessible"
    Write-Host "  Accessible (WinRM OK)" -ForegroundColor Green

    # ---- Collecte systeme (Partie 2) ---------------------------------
    try {
        $sys = Get-NodeSystemInfo -ComputerName $ip -Credential $Credential
    }
    catch {
        Write-PmLog "$nom ; Erreur collecte systeme ; $($_.Exception.Message)"
        $sys = $null
    }

    $inventaire.Add([pscustomobject]@{
        Poste = $nom; AdresseIP = $ip
        Windows = $sys.Windows; Architecture = $sys.Architecture
        DernierDemarrage = $sys.DernierDemarrage; RAM_Go = $sys.RAM_Go
        DisqueLibre_Go = $sys.DisqueLibre_Go; VersionBios = $sys.VersionBios
        Modele = $sys.Modele; DerniereMaj = $sys.DerniereMaj
        NbMaj = $sys.NbMaj; WindowsUpdate = $sys.WindowsUpdate; Etat = 'Accessible'
        Erreur = ''
    })

    # ---- Collecte des correctifs (Partie 3) --------------------------
    $installed = @()
    try {
        $patches = Get-NodePatches -ComputerName $ip -Credential $Credential
        $installed = $patches.HotFixID
        foreach ($p in ($patches | Sort-Object InstalledOn -Descending)) {
            $patchesAll.Add([pscustomobject]@{
                Poste = $nom; AdresseIP = $ip; KB = $p.HotFixID
                Description = $p.Description
                DateInstallation = $(if ($p.InstalledOn) { $p.InstalledOn.ToString('dd/MM/yyyy') } else { '' })
                InstallePar = $p.InstalledBy
            })
        }
    }
    catch {
        Write-PmLog "$nom ; Erreur collecte correctifs ; $($_.Exception.Message)"
    }

    # ---- Controle de conformite (Partie 4) ---------------------------
    $conf = Get-NodeCompliance -InstalledKB $installed -RequiredKB $required
    $listeManquants = if ($conf.NbManquants -eq 0) { '-' } else { $conf.KBManquantes -join ', ' }

    if ($conf.Etat -eq 'CONFORME') {
        Write-PmLog "$nom ; Conforme"
        Write-Host "  CONFORME" -ForegroundColor Green
    }
    else {
        Write-PmLog "$nom ; Non conforme ; $listeManquants"
        Write-Host "  NON CONFORME - manquants : $listeManquants" -ForegroundColor Red
    }

    $rapport.Add([pscustomobject]@{
        Poste = $nom; AdresseIP = $ip; Accessibilite = 'Accessible'
        Windows = $sys.Windows; DernierDemarrage = $sys.DernierDemarrage
        WindowsUpdate = $sys.WindowsUpdate; KBRequises = $conf.KBRequises
        NbManquants = $conf.NbManquants; KBListeManquantes = $listeManquants
        Etat = $conf.Etat; DateControle = $DateControle; Erreur = ''
    })
}

# ======================================================================
#  EXPORTS CSV (Parties 2.4, 3.6, 4.5)
# ======================================================================
$inventaire | Export-Csv -Path $InventoryCsv  -NoTypeInformation -Encoding UTF8 -Delimiter ';'
$patchesAll | Sort-Object Poste, @{Expression='DateInstallation';Descending=$true} |
    Export-Csv -Path $PatchesCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
$rapport | Export-Csv -Path $ComplianceCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'

# ---- Recapitulatif correctifs par poste (Partie 3.6) -----------------
Write-Host "`n--- Recapitulatif correctifs par poste ---" -ForegroundColor Cyan
$patchesAll | Group-Object Poste | ForEach-Object {
    $dernier = $_.Group | Sort-Object DateInstallation -Descending | Select-Object -First 1
    [pscustomobject]@{
        Poste = $_.Name; NbCorrectifs = $_.Count
        DernierCorrectif = $dernier.DateInstallation; DerniereKB = $dernier.KB
    }
} | Format-Table -AutoSize

# ======================================================================
#  SYNTHESE GLOBALE (Partie 6.2)
# ======================================================================
$accessibles   = @($rapport | Where-Object Accessibilite -eq 'Accessible')
$conformes     = @($rapport | Where-Object Etat -eq 'CONFORME')
$nonConformes  = @($rapport | Where-Object Etat -eq 'NON CONFORME')
$inaccessibles = @($rapport | Where-Object Etat -eq 'INACCESSIBLE')
$totalManquants = ($rapport | Where-Object { $_.NbManquants -ne '-' } |
                   Measure-Object NbManquants -Sum).Sum

# Taux de conformite calcule SANS les postes inaccessibles (Partie 4.6)
$taux = if ($accessibles.Count -gt 0) {
    [math]::Round(($conformes.Count / $accessibles.Count) * 100, 1)
} else { 0 }

$synthese = @{
    Total          = $rapport.Count
    Accessibles    = $accessibles.Count
    Inaccessibles  = $inaccessibles.Count
    Conformes      = $conformes.Count
    NonConformes   = $nonConformes.Count
    TotalManquants = [int]$totalManquants
    Taux           = $taux
}

Write-Host "`n=== SYNTHESE ===" -ForegroundColor Cyan
$synthese.GetEnumerator() | Sort-Object Name | Format-Table -AutoSize

# ======================================================================
#  RAPPORT HTML (Partie 6.3) + NOTIFICATION (Partie 7)
# ======================================================================
$html = New-HtmlReport -Report $rapport -Synthese $synthese -Path $HtmlReport
Write-PmLog "Rapport genere"
Write-Host "Rapport HTML : $html" -ForegroundColor Green

Send-PmNotification -Report $rapport -Synthese $synthese -ReportPath $HtmlReport `
    -SmtpServer $SmtpServer -Send:$SendMail | Out-Null

Write-PmLog "Fin de l'audit"
Write-Host "`nTermine. Fichiers dans : $OutDir" -ForegroundColor Cyan
