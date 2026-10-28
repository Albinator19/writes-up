# Write-up -- Simple Java Verify
 
**URL :** https://crackmes.one/crackme/69b7d857ddd6176826ae8a10
 
**Objectif :** trouver une clé de licence de 8 caractères valide pour déclencher le message "Access Granted" dans une application Android écrite entièrement en Java.
 
---
 
## Étape 1 -- Décompilation de l'APK avec JADX
 
L'APK est un fichier archive (comme un ZIP) contenant le bytecode Dalvik compilé (`.dex`), les ressources et le manifeste de l'application. JADX décompile ce bytecode en Java lisible :
 
```bash
jadx -d ~/output/ MyApp6_1.0.apk
```
 
```
INFO - loading ...
INFO - processing ...
INFO - done
```
 
---
 
## Étape 2 -- Lecture du manifeste et identification du point d'entrée
 
On commence par lire `AndroidManifest.xml`, qui décrit la structure de l'application, ses activités, ses permissions et ses métadonnées :
 
```xml
<activity android:name="com.example.crackme.MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```
 
Une ligne attire l'attention :
 
```xml
android:debuggable="true"
```
 
Ce flag indique que le système d'exploitation autorise officiellement à se greffer sur le processus de l'application pendant qu'elle tourne, utile si on voulait faire du débogage dynamique, mais ici la lecture statique du code va suffire.
 
Le point d'entrée de l'application est `com.example.crackme.MainActivity`. C'est là qu'on cherche la logique de validation.
 
---
 
## Étape 3 -- Analyse de la fonction checkLicense()
 
Dans le code décompilé de `MainActivity`, on trouve la méthode qui valide la saisie utilisateur :
 
```java
public void checkLicense() {
    String string = this.inputField.getText().toString();
    if (string.length() != 8 || !string.startsWith("77") || !string.endsWith("1")) {
        Toast.makeText(this, "Invalid Key", 0).show();
    } else {
        Toast.makeText(this, "Access Granted", 1).show();
    }
}
```
 
La logique est simple et entièrement en clair : la clé doit satisfaire **trois contraintes simultanées** :
 
- Longueur exacte de **8 caractères**
- Commence par **`77`**
- Se termine par **`1`**
Il n'y a pas de hash, pas de chiffrement, pas de validation côté serveur, la vérification est purement locale et statique.
 
---
 
## Étape 4 -- Construction de la clé et validation
 
N'importe quelle chaîne respectant les trois contraintes est valide. On construit `77123451` : longueur 8, préfixe `77`, suffixe `1`.
 
On installe l'APK sur un émulateur Android via ADB :
 
```bash
adb install MyApp6_1.0.apk
```
 
```
Performing Streamed Install
Success
```
 
On lance l'application, on saisit `77123451` et on obtient le message **"Access Granted"**.
 
**Clé valide : `77123451`** (et toute chaîne de la forme `77XXXXX1`)
