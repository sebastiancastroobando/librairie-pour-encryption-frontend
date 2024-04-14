## librairie d'encryption utilisant WebCrypto API

### Informations générales
Ceci est une librairie d'encryption utilisant l'API WebCrypto. Normalement, l'API WebCrypto utilise des objets de type `ArrayBuffer` pour les données à encrypter. Cette librairie permet d'utiliser des `String` pour les données à encrypter.

### Utilisation
Il suffit d'ajouter le script encription.js dans votre page html. Vous pouvez ensuite utiliser les fonctions d'encryption et de décryption en utilisant les fonctions `encrypt` et `decrypt`.
```html
<script src="encription.js" defer></script>
```

### Fonctions
- `generateAsemmetricKeyPair` : Permet de générer une paire de clé asymétrique. Retourne les clés sous forme Base64.
-  `generateSymmetricKeyWithPassword` : Permet de générer une clé symétrique à partir d'un mot de passe. Cette fonction utilise l'algorithme PBKDF2 (Password Based Key Derivation Function 2) pour générer la clé. Retourne la clé sous forme Base64.
- `encrypt` : Permet d'encrypter une chaine de caractère. Retourne la chaine encryptée sous forme Base64.
- `decrypt` : Permet de décrypter une chaine de caractère encryptée. Retourne la chaine décryptée.
