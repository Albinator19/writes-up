# Write-up -- My First Crackme (Very Easy)
 
**URL :** https://crackmes.one/crackme/6ac65258cdee6e086a17364d
 
**Objectif :** trouver le mot de passe correct pour obtenir le flag au format `CMO{...}`. Pas de patching autorisé, il faut retrouver le mot de passe attendu par l'exécutable.
 
---
 
## Étape 1 -- Exécution et découverte du comportement
 
On teste d'abord l'exécutable pour comprendre ce qu'il attend :
 
```bash
wine My_First_Crackme.exe
```
 
```
enter the password :
```
 
L'application demande un mot de passe. Si la réponse est correcte, elle affiche le flag. On passe à l'analyse statique.
 
---
 
## Étape 2 -- Ouverture dans Ghidra et recherche de strings
 
L'exécutable est un binaire Windows 64-bit compilé en C. On l'ouvre dans Ghidra et on cherche les chaînes de caractères intéressantes. Il n'y a pas de fonction `main` clairement identifiée par Ghidra, mais on repère rapidement :
 
```
"Flag : CMO{%s}\n"
"Not today...\n"
"enter the password : "
```
 
On clique sur `"Flag : CMO{%s}\n"` pour trouver la fonction qui l'utilise.
 
---
 
## Étape 3 -- Analyse de la fonction principale
 
La fonction qui orchestre tout (`FUN_140001440`) suit ce flux :
 
```c
FUN_140001eb0("enter the password : ", ...);   // affiche le prompt
pcVar3 = fgets(local_58, 0x40, stdin);          // lit jusqu'à 63 caractères
 
sVar4 = strcspn(local_58, "\r\n");              // trouve le premier \r ou \n
local_58[sVar4] = '\0';                         // supprime le saut de ligne
 
bVar1 = FUN_140001520(local_58);                // compare au mot de passe attendu
 
if (bVar1 == 0) {
    printf("Not today...\n");
} else {
    FUN_140001560(local_66);                    // génère le flag dans local_66
    printf("Flag : CMO{%s}\n", local_66);
}
```
 
`fgets` lit l'entrée de façon sécurisée (au plus 63 caractères), et `strcspn` retire le `\n` final avant la comparaison. La validation est déléguée à `FUN_140001520`.
 
---
 
## Étape 4 -- Analyse de la fonction de validation
 
```c
bool FUN_140001520(char *param_1) {
    char local_16[14];
    char *local_8 = param_1;
 
    FUN_140001560((longlong)local_16);   // génère le mot de passe attendu dans local_16
    iVar1 = strcmp(local_8, local_16);  // compare notre entrée au mot de passe généré
    return iVar1 == 0;
}
```
 
Le mot de passe attendu n'est pas stocké en clair dans le binaire, il est **généré à la volée** par `FUN_140001560`, puis comparé à notre entrée via `strcmp`. Si les deux sont identiques, la fonction retourne `true` et le flag s'affiche.
 
---
 
## Étape 5 -- Analyse de la routine de génération XOR
 
```c
void FUN_140001560(longlong param_1) {
    for (ulonglong i = 0; i < 0xd; i++) {
        *(byte *)(param_1 + i) = (&DAT_1400030e4)[i] ^ 0x2a;
    }
    *(undefined1 *)(param_1 + 0xd) = '\0';
}
```
 
La routine parcourt **13 octets** (`0xd = 13`) stockés à l'adresse `DAT_1400030e4`, applique un **XOR avec la constante `0x2a`** sur chacun, et termine la chaîne avec un octet nul `'\0'`. Les données brutes à cette adresse sont : `b FFEuiXKIAGO`.
 
Le mot de passe attendu est donc : `XOR(b FFEuiXKIAGO, 0x2a)`.
 
---
 
## Étape 6 -- Fausse piste et résolution
 
On reproduit le XOR sur CyberChef avec la clé `0x2a` sur les octets de `DAT_1400030e4`. Le résultat est partiellement lisible mais un octet ne donne pas un caractère ASCII propre, probablement une imprécision dans la lecture des données brutes depuis Ghidra.
 
On raisonne à partir du résultat partiel et du contexte : la chaîne ressemble à `H_llo_Crackme`, avec un caractère ambigu en deuxième position. On teste les deux variantes les plus probables :
 
- `Hello_Crackme` --> refusé
- `H3llo_Crackme` --> accepté
```bash
wine My_First_Crackme.exe
```
 
```
enter the password : H3llo_Crackme
Yeaaaaa!!! Discord : imrate
Flag : CMO{H3llo_Crackme}
```
 
**Mot de passe : `H3llo_Crackme`**
 
**Flag : `CMO{H3llo_Crackme}`**
