<#
    01-Preparation-Environnement.ps1
    -----------------------------------------------------------------------
    PARTIE 1 du projet : preparation et validation de l'environnement
    d'administration distante (PowerShell Remoting / WinRM).

    A executer une fois, en Administrateur, sur chaque poste concerne
    (ou depuis le poste d'administration selon les commandes).
    -----------------------------------------------------------------------
#>

# Auteur : Sami De Waal (I2 - Ethical Hacking)
Import-Module "$PSScriptRoot\modules\PatchManager.psm1" -Force

# --- 1.2 / 1.3  Lecture de l'inventaire et etat de disponibilite --------
Write-Host "`n[1.3] Lecture de computers.txt et etat de disponibilite" -ForegroundColor Cyan
Get-Inventory | ForEach-Object {
    $etat = Test-NodeOnline -ComputerName $_.AdresseIP
    [pscustomobject]@{
        Poste = $_.Poste
        AdresseIP = $_.AdresseIP
        Disponibilite = if ($etat.Accessible) { 'Accessible' } else { 'Inaccessible' }
    }
} | Format-Table -AutoSize

# --- 1.4  Activation et verification de PowerShell Remoting -------------
# A EXECUTER SUR CHAQUE POSTE SUPERVISE (en Administrateur) :
#   Enable-PSRemoting -Force
#
# Verifier l'etat du service WinRM :
Write-Host "`n[1.4] Etat du service WinRM (local)" -ForegroundColor Cyan
Get-Service WinRM | Select-Object Name, Status, StartType | Format-Table -AutoSize

# Tester l'acces distant WinRM (remplacer par une IP du parc) :
#   Test-WSMan -ComputerName 192.168.10.11

# --- 1.5  Session distante interactive ---------------------------------
#   Enter-PSSession -ComputerName 192.168.10.11 -Credential (Get-Credential)
#   ... quelques commandes ...   puis :  Exit-PSSession

# --- 1.6  Execution distante non interactive ---------------------------
#   Invoke-Command -ComputerName 192.168.10.11 -Credential (Get-Credential) `
#     -ScriptBlock { hostname; Get-Date }


# =======================================================================
#  REPONSES AUX QUESTIONS DE LA PARTIE 1 (a recopier dans le rapport)
# =======================================================================
<#
 * Role de WinRM dans PowerShell Remoting :
   WinRM (Windows Remote Management) est l'implementation Microsoft du
   protocole WS-Management. C'est le service qui recoit et execute les
   commandes distantes envoyees par PowerShell Remoting (Invoke-Command,
   Enter-PSSession). Sans WinRM actif, aucune commande distante n'aboutit.

 * Commande pour activer PowerShell Remoting :
   Enable-PSRemoting -Force
   (demarre WinRM, le met en demarrage automatique et cree les regles
    de pare-feu necessaires).

 * Ports reseau utilises par WinRM :
   5985/TCP pour HTTP et 5986/TCP pour HTTPS (WinRM sur SSL).

 * Pourquoi le pare-feu peut empecher une connexion distante :
   Si les regles autorisant le trafic entrant sur 5985/5986 ne sont pas
   activees (notamment sur le profil actif, ex. Public), le pare-feu
   bloque la connexion WinRM meme si le service tourne.

 * Difference Test-Connection vs Test-WSMan :
   Test-Connection = ping ICMP : la machine est-elle joignable sur le
   reseau. Test-WSMan = interroge specifiquement le service WinRM : la
   machine accepte-t-elle l'administration distante. Une machine peut
   repondre au ping sans avoir WinRM (et inversement).

 * Pourquoi verifier l'accessibilite avant une commande distante :
   Pour eviter des erreurs bloquantes et de longs delais d'attente
   (timeout) sur chaque poste injoignable, et permettre au script de
   traiter proprement les machines inaccessibles sans s'arreter.

 * Problemes de securite si PowerShell Remoting est active sans restriction :
   Surface d'attaque elargie (mouvement lateral d'un attaquant), risque
   d'authentification NTLM faible ou non chiffree, acces distant possible
   depuis n'importe quelle machine, execution de code a distance. Il faut
   restreindre les utilisateurs autorises, filtrer les IP sources au
   pare-feu, forcer HTTPS/Kerberos et appliquer JEA (cf. Partie 8).
#>
