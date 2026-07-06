# Write-up -- Archives à couches multiples (1/3)

## Contexte

On dispose d'une archive `codepin_corrupted.mla` au format **MLA** (Multi Layer Archive). Le fichier semble corrompu : il contient une entrée `code_pin.txt` dont le contenu ne peut pas être lu correctement.

## Énumération

On installe l'outil officiel `mlar` pour manipuler le format.

```bash
mlar list -i codepin_corrupted.mla --skip-signature-verification --accept-unencrypted
```

L'archive contient bien une entrée nommée `code_pin.txt`. On tente de l'afficher directement :

```bash
mlar cat -i codepin_corrupted.mla --skip-signature-verification --accept-unencrypted code_pin.txt
```

Le résultat est illisible (caractères binaires). Une extraction confirme le problème :

```bash
mlar extract -i codepin_corrupted.mla --skip-signature-verification --accept-unencrypted code_pin.txt
file code_pin.txt
# code_pin.txt: ISO-8859 text, with no line terminators
```

Le contenu du fichier extrait est corrompu / vide de sens exploitable directement.

## Analyse binaire

On inspecte l'archive brute en hexadécimal :

```bash
xxd codepin_corrupted.mla
```

```
00000000: 4d4c 4146 4141 4141 0200 0000 004d 4c41  MLAFAAAA.....MLA
00000010: 454e 4141 4100 4d41 4542 0000 0000 0000  ENAAA.MAEB......
00000020: 0000 000c 0000 0000 0000 0063 6f64 655f  ...........code_
00000030: 7069 6e2e 7478 7400 4d41 4542 0100 0000  pin.txt.MAEB....
00000040: 0000 0000 0000 0400 0000 0000 0000 ffff  ................
00000050: ffff 4d41 4542 ff00 0000 0000 0000 0000  ..MAEB..........
00000060: eb75 3992 4cf4 b8b6 7488 5752 10db 3526  .u9.L...t.WR..5&
00000070: ec7c 2daa f546 705a c37e 5039 c71c 36f3  .|-..FpZ.~P9..6.
00000080: 4d41 4542 fe01 0100 0000 0000 0000 0c00  MAEB............
00000090: 0000 0000 0000 636f 6465 5f70 696e 2e74  ......code_pin.t
000000a0: 7874 0300 0000 0000 0000 0900 0000 0000  xt..............
000000b0: 0000 0000 0000 0000 0000 2b00 0000 0000  ..........+.....
000000c0: 0000 0400 0000 0000 0000 4500 0000 0000  ..........E.....
000000d0: 0000 0000 0000 0000 0000 5500 0000 0000  ..........U.....
000000e0: 0000 0001 0000 0000 0000 0000 0100 0000  ................
000000f0: 0000 0000 454d 4c41 4141 4141            ....EMLAAAAA
```

Pour comprendre la structure, on génère une archive de référence non chiffrée et non signée, avec un contenu connu (`"1234"`) :

```bash
echo -n "1234" | mlar create --unencrypted --unsigned -o ref.mla --stdin-data --stdin-data-entry-names code_pin.txt
xxd ref.mla
```

En comparant les deux archives, plusieurs éléments ressortent :

- Un bloc de contenu annonce une taille = `04` : le PIN fait donc **4 octets**.
- Il est suivi de 4 octets `FF FF FF FF`, probablement un **placeholder** remplaçant les octets réels manquants du PIN (volontairement effacés/corrompus).
- Juste après vient un second bloc `MAEB`, marquant la **fin de fichier** de l'entrée. D'après la documentation du format MLA, ce bloc de fin de fichier embarque le **SHA256 complet du contenu**.
- On repère effectivement une séquence de 32 octets (taille exacte d'un SHA256), située entre les offsets `0x60` et `0x80` :

```
eb75 3992 4cf4 b8b6 7488 5752 10db 3526
ec7c 2daa f546 705a c37e 5039 c71c 36f3
```

## Exploitation

Le PIN étant numérique sur 4 chiffres (`0000` à `9999`), et son hash SHA256 étant connu, il suffit de **bruteforcer** l'espace des possibilités (10 000 valeurs) :

```python
import hashlib

with open("codepin_corrupted.mla", "rb") as f:
    data = f.read()

target_hash = data[0x60:0x80]
print("Hash cible :", target_hash.hex())

found = False
for i in range(10000):
    pin = f"{i:04d}"
    h = hashlib.sha256(pin.encode()).digest()
    if h == target_hash:
        print(f"PIN TROUVÉ : {pin}")
        found = True
        break

if not found:
    print("Pas trouvé")
```

Exécution :

```
└─$ python3 exploit.py
Hash cible : eb7539924cf4b8b67488575210db3526ec7c2daaf546705ac37e5039c71c36f3
PIN TROUVÉ : 4583
```

## Conclusion

Le PIN corrompu volontairement dans l'archive MLA était **4583**, retrouvé en exploitant le hash SHA256 laissé en clair dans le bloc de fin d'entrée du format.
