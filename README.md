# PatchManager-PowerShell

Solution de Patch Management Windows en PowerShell : audit automatisé des correctifs de sécurité d'un parc de postes via WinRM (inventaire, conformité par rapport à une liste de KB, rapports CSV et HTML, journal, notification).

Projet réalisé pour le module « Sécurité des systèmes d'exploitation » (EFREI, I2). Enseignant : Dr. Salim Benayoune. Auteur : Sami De Waal.

## Livrables

- Vidéo de démonstration (5 min 22, les attentes d'audit sont accélérées et signalées à l'écran) : https://drive.google.com/file/d/1zzGgSp5tsXkzW8irtIP-GkLZDnMvV1JQ/view?usp=sharing (minutage dans VIDEO.md)
- Rapport : Rapport-Projet-PatchManagement.docx
- Code : ce dépôt

## Fonctionnement

Le script principal enchaîne les étapes suivantes : lecture de config/computers.txt, test de disponibilité de chaque poste (ping puis WinRM), collecte des informations système et des correctifs installés, comparaison avec la politique définie dans config/required-patches.txt, production des rapports (CSV, HTML, journal) puis notification, uniquement lorsqu'une anomalie est détectée.

Chaque poste reçoit un état : CONFORME, NON CONFORME (des KB requis sont absents) ou INACCESSIBLE (échec du ping ou de WinRM). Le script continue quand un poste est injoignable, et le taux de conformité est calculé sans les postes inaccessibles.

## Correspondance avec l'énoncé

La numérotation suit celle de l'énoncé, qui passe de la Partie 4 à la Partie 6.

- Partie 1, préparation de l'environnement (WinRM) : 01-Preparation-Environnement.ps1
- Partie 2, inventaire du parc : fonction Get-NodeSystemInfo, fichier Inventory.csv et tableau récapitulatif affiché à l'écran
- Partie 3, inventaire des correctifs : fonction Get-NodePatches, fichier PatchesInventory.csv (trié par poste puis par date décroissante) et récapitulatif par poste
- Partie 4, contrôle de conformité : fonction Get-NodeCompliance, fichier ComplianceReport.csv et taux de conformité global
- Partie 6, rapport de sécurité : fonction New-HtmlReport, fichier SecurityReport.html et journal PatchManager.log
- Partie 7, notification : fonction Send-PmNotification (envoi conditionnel)
- Partie 8, sécurisation de la solution : traitée dans le rapport, section 7

## Arborescence

```
PatchManager-PowerShell/
    01-Preparation-Environnement.ps1    Partie 1 : préparation et vérification de WinRM
    Invoke-PatchManagement.ps1          script principal (Parties 2, 3, 4, 6 et 7)
    modules/
        PatchManager.psm1               fonctions du module
    config/
        computers.txt                   parc à contrôler, une ligne Nom;IP
        computers.example.txt           exemple multi-postes, dont des postes inaccessibles
        required-patches.txt            politique, un KB obligatoire par ligne
    Rapport-Projet-PatchManagement.docx
    VIDEO.md                            lien et minutage de la vidéo
    .gitignore                          exclut output/ et config/smtp-cred.xml
    output/                             créé à l'exécution (ignoré par git)
```

## Prérequis

- Windows 10 ou 11 (ou Windows Server) avec Windows PowerShell 5.1. Le projet a été développé et testé sur Windows 11.
- Pour auditer des postes distants : WinRM activé sur chaque poste (`Enable-PSRemoting -Force`), ports 5985 et 5986 ouverts depuis le poste d'administration et un compte autorisé (paramètre `-Credential`).
- Le test de disponibilité vérifie que WinRM répond, y compris pour le poste local. En revanche, la collecte des données du poste local se fait directement, sans session distante.

## Utilisation

Ouvrir PowerShell dans le dossier du projet, puis :

```powershell
# Autoriser les scripts pour cette session uniquement
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Si Windows bloque les fichiers téléchargés
Get-ChildItem -Recurse | Unblock-File

# Partie 1 : disponibilité des postes et état de WinRM
.\01-Preparation-Environnement.ps1

# Audit complet : inventaire, correctifs, conformité, rapports, notification (simulée)
.\Invoke-PatchManagement.ps1
```

Paramètres de Invoke-PatchManagement.ps1 :

- `-Credential` : identifiants pour les postes distants (obtenus avec Get-Credential)
- `-SendMail` : envoie réellement la notification ; sans ce paramètre, le message est construit et journalisé (mode simulation)
- `-SmtpServer` : serveur SMTP (par défaut smtp.entreprise.local)

Configuration : config\computers.txt contient une ligne Nom;IP par poste, config\required-patches.txt un KB obligatoire par ligne. Les lignes qui commencent par # sont ignorées. Pour voir le cas INACCESSIBLE, il suffit d'ajouter à computers.txt les lignes de config\computers.example.txt (adresses fictives).

## Fichiers produits (dossier output)

- Inventory.csv : inventaire système des postes
- PatchesInventory.csv : correctifs installés, triés par poste puis par date d'installation décroissante
- ComplianceReport.csv : état de conformité, KB manquants, date et heure du contrôle
- SecurityReport.html : rapport de synthèse pour l'administrateur
- PatchManager.log : journal horodaté (JJ/MM/AAAA HH:MM:SS ; message), conservé d'une exécution à l'autre

## Choix de conception et sécurité

- Aucun secret n'est écrit dans le code. Les identifiants SMTP éventuels sont lus dans config\smtp-cred.xml, créé avec la commande `Get-Credential | Export-Clixml config\smtp-cred.xml` (le fichier est chiffré par Windows pour l'utilisateur courant et n'est pas versionné).
- Le poste local est collecté directement, sans WinRM : il n'est donc pas nécessaire d'affaiblir sa configuration (TrustedHosts, filtrage UAC des comptes locaux). WinRM reste utilisé pour les postes distants.
- La notification n'est construite que si au moins un poste est NON CONFORME ou INACCESSIBLE.
- Les mesures de sécurisation recommandées (moindre privilège, HTTPS et Kerberos, filtrage par pare-feu, JEA, protection des journaux) sont détaillées dans la section 7 du rapport.
- Les scripts ne contiennent que des caractères ASCII, pour un comportement identique quel que soit l'encodage par défaut de Windows PowerShell 5.1.

## Limites connues

- La validation en conditions réelles porte sur un seul poste Windows 11, le poste local. Les cas multi-postes et INACCESSIBLE sont couverts par la logique du script (try/catch) et par le banc de test décrit en section 5.1 du rapport. Le journal présenté dans le rapport (figure 2) montre plusieurs exécutions successives.
- Send-MailMessage est déprécié par Microsoft. En production, il vaut mieux passer par Microsoft Graph, un webhook ou un SIEM (voir la section 3.6 du rapport).
