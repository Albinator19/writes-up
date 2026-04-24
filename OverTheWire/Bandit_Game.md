# Write-up -- OverTheWire : Bandit

Write-up réalisé pour le jeu du Bandit de OverTheWire. J'ai noté mes commandes au fur et à mesure des niveaux. Les passwords changent régulièrement côté OverTheWire donc les miens ne seront probablement plus valides quand vous lirez cela, l'important c'est la démarche.

Connexion de base pour tous les niveaux (X correspond au numéro du niveau) :
```bash
ssh banditX@bandit.labs.overthewire.org -p 2220
```

---

## Level 0 → 1

Rien de compliqué ici, c'est vraiment pour se connecter et vérifier que tout fonctionne. Le mot de passe de bandit0 est juste `bandit0`, et le fichier s'appelle `readme`.

```bash
cat readme
```

**Password :** `ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

---

## Level 1 → 2

Le fichier s'appelle littéralement `-`. Si on fait juste `cat -`, le shell interprète ça comme "lire depuis stdin" et attend qu'on tape quelque chose, il ne se passe rien. Il faut préciser le chemin :

```bash
cat ./-
```

**Password :** `263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

---

## Level 2 → 3

Le fichier a des espaces dans son nom. Il faut échapper les espaces avec `\`.

```bash
cat ./--spaces\ in\ this\ filename--
```

**Password :** `MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

---

## Level 3 → 4

Le fichier est caché dans un dossier `inhere`. Un `ls` classique ne montre rien, il faut l'option `-a` pour voir les fichiers cachés. Le fichier s'appelle `...Hiding-From-You`.

```bash
cd inhere
ls -la
```

```
total 12
drwxr-xr-x 2 root    root    4096 Apr  3 15:18 .
drwxr-xr-x 3 root    root    4096 Apr  3 15:18 ..
-rw-r----- 1 bandit4 bandit3   33 Apr  3 15:18 ...Hiding-From-You
```

```bash
cat ...Hiding-From-You
```

**Password :** `2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

---

## Level 4 → 5

Il y a plein de fichiers dans `inhere` (de `-file00` à `-file09`) et la plupart sont du binaire illisible. On utilise `file` pour identifier lequel est du texte ASCII, c'est le `-file07`.

```bash
cat ./inhere/-file07
```

**Password :** `4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

---

## Level 5 → 6

Ici il y a des dizaines de dossiers et de fichiers dans `inhere`. L'énoncé dit que le fichier qu'on cherche est : lisible par l'humain, non-exécutable, et fait exactement 1033 octets. On utilise `find` avec tous ces critères, puis `xargs file` pour vérifier le type, et `grep ASCII` pour filtrer :

```bash
find ~/inhere -type f ! -executable -size 1033c | xargs file | grep ASCII
```

```
/home/bandit5/inhere/maybehere07/.file2: ASCII text, with very long lines (1000)
```

```bash
cat /home/bandit5/inhere/maybehere07/.file2
```

**Password :** `HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`

---

## Level 6 → 7

Cette fois le fichier est quelque part sur le serveur. On sait juste qu'il appartient à l'user `bandit7`, au groupe `bandit6`, et qu'il fait 33 octets. Le `2>/dev/null` c'est pour ignorer tous les "Permission denied" qui polluent la sortie :

```bash
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

```
/var/lib/dpkg/info/bandit7.password
```

```bash
cat /var/lib/dpkg/info/bandit7.password
```

**Password :** `morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`

---

## Level 7 → 8

Le fichier `data.txt` est énorme. Le mot de passe est sur la ligne qui contient le mot `millionth`, donc un simple grep suffit :

```bash
grep 'millionth' data.txt
```

```
millionth       dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

**Password :** `dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

---

## Level 8 → 9

`data.txt` a des milliers de lignes dont la quasi-totalité sont des doublons. On cherche la seule ligne qui n'apparaît qu'une seule fois. `uniq -u` ne fonctionne que sur des lignes triées, d'où le `sort` avant :

```bash
sort data.txt | uniq -u
```

**Password :** `4CKMh1JI91bUIZZPXDqGanal4xvAg0JM`

---

## Level 9 → 10

Le fichier est binaire, on ne peut pas juste le `cat`. La commande `strings` extrait toutes les chaînes de caractères lisibles dedans. L'énoncé dit que le mot de passe est précédé de plusieurs `=`, donc :

```bash
strings data.txt | grep "==="
```

```
========== the
========== password
========== is
========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
```

**Password :** `FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey`

---

## Level 10 → 11

Le contenu de `data.txt` est encodé en base64. Une ligne de commande suffit :

```bash
base64 -d data.txt
```

```
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
```

**Password :** `dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr`

---

## Level 11 → 12

Le texte a été chiffré avec ROT13 donc chaque lettre est décalée de 13 positions dans l'alphabet. La commande `tr` permet de faire cette substitution :

```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

```
The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
```

**Password :** `7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4`

---

## Level 12 → 13

C'est le niveau le plus long. `data.txt` est un hexdump d'un fichier binaire, lui-même compressé plusieurs fois avec différents formats imbriqués. Il faut convertir le hexdump en binaire avec `xxd -r`, puis identifier et décompresser en boucle avec `file` à chaque étape pour savoir quel outil utiliser.

Important : `gzip` refuse de décompresser un fichier s'il n'a pas l'extension `.gz`. Donc à chaque fois, il faut renommer avant de décompresser avec `mv`.

```bash
# On crée un répertoire de travail dans /tmp
cd $(mktemp -d)
cp ~/data.txt data12.txt

xxd -r data12.txt > binary
```

Ensuite c'est une succession de `file` + renommage + décompression :

```bash
file binary
# gzip compressed data, was "data2.bin"
mv binary binary.gz && gzip -d binary.gz

file binary
# bzip2 compressed data
mv binary binary.bz2 && bzip2 -d binary.bz2

file binary
# gzip compressed data, was "data4.bin"
mv binary binary.gz && gzip -d binary.gz

file binary
# POSIX tar archive (GNU)
mv binary binary.tar && tar -xf binary.tar
# extrait data5.bin

file data5.bin
# POSIX tar archive (GNU)
mv data5.bin data5.tar && tar -xf data5.tar
# extrait data6.bin

file data6.bin
# bzip2 compressed data
mv data6.bin data6.bz2 && bzip2 -d data6.bz2

file data6
# POSIX tar archive (GNU)
mv data6 data6.tar && tar -xf data6.tar
# extrait data8.bin

file data8.bin
# gzip compressed data, was "data9.bin"
mv data8.bin data8.gz && gzip -d data8.gz

file data8
# ASCII text !
cat data8
```

```
The password is FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
```

**Password :** `FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn`

---

## Level 13 → 14

Pas de mot de passe cette fois, mais une clé SSH privée dans `~/sshkey.private`. On la copie sur notre machine locale et on s'en sert pour se connecter directement en tant que bandit14. Le `chmod 600` est obligatoire, SSH refuse les clés avec des permissions trop ouvertes.

```bash
# Sur notre machine locale :
chmod 600 bandit14.key
ssh -i bandit14.key bandit14@bandit.labs.overthewire.org -p 2220

# Une fois connecté en tant que bandit14 :
cat /etc/bandit_pass/bandit14
```

**Password :** `MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS`

---

## Level 14 → 15

Il faut envoyer le mot de passe de bandit14 au service qui tourne sur le port 30000 de localhost. `nc` (netcat) permet de faire ça :

```bash
nc localhost 30000
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
```

```
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```

**Password :** `8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo`

---

## Level 15 → 16

Même principe que le level précédent mais le service sur le port 30001 utilise du SSL/TLS. `nc` ne sait pas gérer ça, donc on utilise `openssl s_client`. Il y a un avertissement sur le certificat auto-signé, on l'ignore.

```bash
openssl s_client -connect localhost:30001
```

Une fois connecté, on entre le mot de passe de bandit15 :

```
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
```

**Password :** `kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx`

---

## Level 16 → 17

Il faut d'abord trouver quel port dans la plage 31000-32000 parle SSL et n'est pas un simple echo. On utilise `nmap` pour scanner :

```bash
nmap -A -p 31000-32000 localhost
```

Le scan montre 5 ports ouverts. Parmi eux, le port **31790** est SSL et répond `"Wrong! Please enter the correct current password."` : c'est lui qu'on veut. Les autres ports SSL (comme 31518) ne font que renvoyer ce qu'on envoie (echo).

```bash
openssl s_client -connect localhost:31790 -quiet
```

On entre le mot de passe de bandit16, et le serveur nous renvoie une clé RSA privée. On la copie dans un fichier `bandit17.key` sur notre machine, on met les bonnes permissions, et on se connecte :

```bash
chmod 600 bandit17.key
ssh -i bandit17.key bandit17@bandit.labs.overthewire.org -p 2220
```

---

## Level 17 → 18

Il y a deux fichiers : `passwords.old` et `passwords.new`. Le mot de passe de bandit18 est la seule ligne qui a changé entre les deux. `diff` compare les fichiers ligne par ligne :

```bash
diff passwords.new passwords.old
```

```
42c42
< x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
---
> 390zFj2NETFVZkqYw8UEFdN6h40oGVtT
```

La ligne avec `<` vient de `passwords.new`, donc c'est le nouveau mot de passe.

**Password :** `x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO`

---

## Level 18 → 19

Dès qu'on se connecte, on est immédiatement déconnecté car le `.bashrc` a été modifié pour faire ça. L'astuce c'est de passer une commande directement dans SSH avec le pipe, avant que bash ne se lance et nous déconnecte :

```bash
echo "cat readme" | ssh bandit18@bandit.labs.overthewire.org -p 2220
```

```
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
```

**Password :** `cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8`

---

## Level 19 → 20

Il y a un binaire `bandit20-do` dans le home. Il permet de lancer une commande en tant que bandit20 grâce au bit SUID. On s'en sert directement pour lire le fichier de mot de passe :

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

**Password :** `0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO`

---

## Level 20 → 21

Il y a un binaire `suconnect` qui se connecte à un port local, attend de recevoir le mot de passe de bandit20, et envoie celui de bandit21 en retour si c'est correct. Il faut donc d'abord ouvrir un mini serveur `nc` en arrière-plan qui envoie le bon mot de passe, puis lancer `suconnect`. Le `sleep 2` est là pour laisser le temps à `nc` de s'installer avant que `suconnect` se connecte :

```bash
echo "0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO" | nc -l -p 1234 &
sleep 2
./suconnect 1234
```

```
Read: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
Password matches, sending next password
EeoULMCra2q0dSkYj561DX7s1CpBuOBt
```

**Password :** `EeoULMCra2q0dSkYj561DX7s1CpBuOBt`

---

## Level 21 → 22

Un cron tourne en tant que bandit22 et écrit son mot de passe dans un fichier temporaire. On regarde d'abord ce que fait le cron :

```bash
cat /etc/cron.d/cronjob_bandit22
# @reboot + toutes les minutes : /usr/bin/cronjob_bandit22.sh

cat /usr/bin/cronjob_bandit22.sh
```

```bash
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

Le chemin du fichier est en dur dans le script, on lit directement :

```bash
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

**Password :** `tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q`

---

## Level 22 → 23

Même principe qu'avant mais cette fois le script de cron génère le nom du fichier temporaire dynamiquement via un hash MD5. Il faut comprendre le script et le rejouer nous-mêmes pour bandit23 :

```bash
cat /usr/bin/cronjob_bandit23.sh
```

```bash
#!/bin/bash
myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)
cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

On simule ce que ferait ce script si `$myname` valait `bandit23` :

```bash
mytarget=$(echo I am user bandit23 | md5sum | cut -d ' ' -f 1)
echo $mytarget
# 8ca319486bfbbc3663ea0fbe81326349

cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```

**Password :** `0Zf11ioIjMVN551jX3CmStKLYqjk54Ga`

---

## Level 23 → 24

Un cron s'exécute en tant que bandit24 et exécute tous les scripts déposés dans `/var/spool/bandit24/foo` avant de les supprimer. Il suffit d'y déposer un script qui copie le mot de passe de bandit24 dans notre répertoire temporaire.

Attention : le dossier de destination doit être en `777` sinon bandit24 ne peut pas y écrire.

```bash
MYDIR=$(mktemp -d)
chmod 777 $MYDIR
cd $MYDIR
```

Contenu de `script.sh` :
```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/tmp.RQ40SvBVbn/mdp24
```

```bash
chmod 777 script.sh
cp script.sh /var/spool/bandit24/foo
```

On attend environ une minute que le cron passe, puis :

```bash
cat mdp24
```

**Password :** `gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8`

---

## Level 24 → 25

Le service sur le port 30002 demande le mot de passe de bandit24 + un code PIN à 4 chiffres (0000–9999). On ne peut pas le deviner, donc on brute-force les 10 000 combinaisons avec un script bash et on pipe tout dans `nc` :

```bash
#!/bin/bash
for i in {0000..9999}
do
    echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i"
done | nc localhost 30002
```

On filtre les mauvaises réponses :

```bash
./script.sh | grep -v "Wrong!"
```

```
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is iCi86ttT4KSNe1armKiwbQNmB3YJP3q4
```

**Password :** `iCi86ttT4KSNe1armKiwbQNmB3YJP3q4`

---

## Level 25 → 26

A mon goût c'est le level le plus compliqué à résoudre si on ne trouve pas facilement l'astuce. On trouve la clé SSH de bandit26 dans le home de bandit25, mais quand on essaie de se connecter on est immédiatement déconnecté.

En regardant `/etc/passwd`, on voit que le shell de bandit26 n'est pas bash :

```bash
cat /etc/passwd | grep bandit26
# bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```

Le script `showtext` fait juste un `more` sur un fichier texte puis quitte. L'astuce : si la fenêtre du terminal est trop petite pour afficher tout le fichier, `more` se met en pause avec `--More--`. À ce moment-là, on peut appuyer sur `v` pour ouvrir l'éditeur `vi`.

Depuis `vi`, on peut changer le shell et l'exécuter :

```
:set shell=/bin/bash
:shell
```

Et voilà, on a un vrai shell bandit26.

```bash
# Sur notre machine locale, copier la clé dans bandit26.key
chmod 600 bandit26.key

# Réduire la fenêtre du terminal, puis :
ssh -i bandit26.key bandit26@bandit.labs.overthewire.org -p 2220
# Quand "--More--" apparaît, on tape v puis :set shell=/bin/bash et enfin :shell
```

---

## Level 26 → 27

Une fois qu'on a le shell bandit26 (obtenu via le level précédent), c'est simple. Il y a un binaire `bandit27-do` avec le bit SUID, exactement comme au level 19 :

```bash
ls
# bandit27-do  text.txt

./bandit27-do cat /etc/bandit_pass/bandit27
```

**Password :** `upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB`

---

## Level 27 → 28

On commence une série de levels Git. Ici il faut juste cloner un repo et lire le README :

```bash
cd $(mktemp -d)
git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo
cd repo
cat README
```

```
The password to the next level is: Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN
```

**Password :** `Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN`

---

## Level 28 → 29

Le README du repo contient les credentials mais le mot de passe est masqué (`xxxxxxxxxx`). Par contre dans l'historique git on voit qu'un commit précédent s'appelle "fix info leak", quelqu'un a retiré le mot de passe après coup. On remonte dans l'historique :

```bash
cd $(mktemp -d)
git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo
cd repo

git log --oneline
```

```
adc7f88 (HEAD -> master, origin/master, origin/HEAD) fix info leak
a3437bd add missing data
cb630ec initial commit of README.md
```

```bash
git show a3437bd:README.md
```

```
## credentials

- username: bandit29
- password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
```

**Password :** `4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7`

---

## Level 29 → 30

Même histoire : le README dit "no passwords in production!" mais peut-être que dans une autre branche c'est différent. On regarde les branches distantes :

```bash
cd $(mktemp -d)
git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo
cd repo

git branch -a
```

```
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
```

La branche `dev` est intéressante :

```bash
git show origin/dev:README.md
```

```
## credentials

- username: bandit30
- password: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL
```

**Password :** `qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL`

---

## Level 30 → 31

Ni le log ni les branches ne donnent rien d'intéressant cette fois. Par contre il y a un tag git nommé `secret` :

```bash
cd $(mktemp -d)
git clone ssh://bandit30-git@bandit.labs.overthewire.org:2220/home/bandit30-git/repo
cd repo

git tag
# secret

git show secret
```

**Password :** `fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy`

---

## Level 31 → 32

Cette fois il faut écrire dans le repo plutôt que lire. Le README demande de push un fichier `key.txt` avec le contenu `May I come in?` sur la branche master. Sauf que le `.gitignore` bloque les `.txt`, donc on force l'ajout avec `-f` :

```bash
cd $(mktemp -d)
git clone ssh://bandit31-git@bandit.labs.overthewire.org:2220/home/bandit31-git/repo
cd repo

echo 'May I come in?' > key.txt
git add -f key.txt
git commit -m "update"
git push origin master
```

```
remote: ### Attempting to validate files... ####
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
remote: Well done! Here is the password for the next level:
remote: 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
```

**Password :** `3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K`

---

## Level 32 → 33

On tombe dans un "UPPERCASE SHELL", tout ce qu'on tape est converti en majuscules avant d'être exécuté. Du coup `ls` devient `LS`, `cat` devient `CAT`, et aucune commande ne fonctionne.

La faille c'est que les variables spéciales du shell ne sont pas affectées par cette conversion. `$0` contient le nom du shell courant, et l'appeler l'exécute, ce qui nous donne un shell normal :

```bash
$0
```

On se retrouve dans `/bin/sh` en tant que bandit33 :

```bash
cat /etc/bandit_pass/bandit33
```

**Password :** `tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0`

---

## Fin

33 levels au total. Les thèmes principaux abordés : manipulation de fichiers Linux, encodages (base64, ROT13, hexdump), compression multi-formats, réseau (netcat, openssl, nmap), SSH, binaires SUID, cron jobs, et Git (historique, branches, tags, push).

Les levels qui m'ont pris le plus de temps : le 12 (beaucoup de décompression en chaîne), le 20 (synchroniser le nc en background avec suconnect), et surtout le 25-26 avec le trick de la fenêtre terminale pour forcer `more` à se mettre en pause qui n'est pas évident à trouver si on ne connaît pas.
