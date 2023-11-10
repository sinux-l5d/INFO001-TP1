# INFO001 : compte rendu du TP1

Étudiant : Simon LEONARD <simon.leonard@etu.univ-smb.fr>

## Préparation

### Question 1

Pour générer un couple de clé publique et privée avec l'algorithme RSA, il nous faut au préalable deux choses :

* un système avec suffisamment d'entropie pour générer des nombres pseudo-aléatoires de bonne qualité
* choisir deux grands nombres premiers p et q

À partir de là on prend $n = p\times q$ et $z = (p-1)\times (q-1)$. On choisie également un nombre $e$ pour que $pgcd(e, z) = 1$, c'est à dire que $e$ et $z$ sont premiers entre eux. 
On termine en calculant $d$ tel que $d\times e \equiv 1 \pmod{z}$.

La *clé publique* est alors le couple $(n, e)$ et la *clé privée* est le couple $(n, d)$.

### Question 2

#### Chiffrement

Soit un message $M$ dont on souhaite assurer la confidentialité. On note $C$ le message chiffré.

Pour chiffrer le message, on utilise la clé publique $(n, e)$ et on calcule $C = M^e \pmod{n}$.

#### Déchiffrement

Pour déchiffrer le message, on utilise la clé privée $(n, d)$ et on calcule $M = C^d \pmod{n}$.

### Question 3

Il y a 4 informations importantes contenues dans un certificat :

* le destinataire du certificat (ex: sinux.sh, trouvable dans le champs `Subject`)
* la clé publique du destinataire (trouvable dans le champs `Subject Public Key Info`)
* le nom et la signature de l'autorité de certification (ex: Let's Encrypt, trouvable dans le champs `Issuer`)
* la date de validité du certificat (trouvable dans les champs `Not Before` et `Not After`)

### Question 4

Lors de la connexion en HTTPS, Bob envoie une requête au serveur d'Alice, `www.alice.com`. Alice lui répond avec son certificat. Bob vérifie alors la validité du certificat d'Alice :

1. Bob envoie une requête en HTTPS
2. Alice envoie son certificat à Bob
3. Bob vérifie la validité du certificat d'Alice
    1. Bob vérifie la date de validité du certificat
    1. Bob vérifie que le certificat de l'autorité de certification "CA1" est valide
    2. Bob vérifie que le certificat de CA1 a été signé par l'autorié de certification "Root-CA"
    3. Une fois sûr de la provenance du certificat, Bob vérifie que le nom du site est bien "www.alice.com"
4. Bob génère une clé de session et l'envoie à Alice
    1. Bob génère une clé de session secrète
    2. Bob chiffre la clé de session avec la clé publique d'Alice
    3. Bob envoie la clé de session chiffrée à Alice
5. Alice déchiffre la clé de session avec sa clé privée
6. Alice répond à Bob avec la clé de session, la connexion est établie.

## Etude du chiffrement RSA

En parcourant un peu le manuel, j'ai trouvé que la sous-commande `genpkey` de `openssl` était à privilégier par rapport à l'algorithme "trop spécifique" `genrsa`.

J'ai ensuite chercher l'option pour spécifier la taille. Voici comment générer une clé de 512 bits :

```bash
openssl genpkey -out rsa_keys.pem -algorithm RSA -pkeyopt rsa_keygen_bits:512
```

Si l'on veut extraire la clé publique, on peut utiliser la commande suivante :

```bash
openssl rsa -in rsa_keys.pem -pubout -out rsa_keys.pub
```

### Question 5

<!-- Quelle est la longueur des 2 nombres premiers choisis ? Quelle est la longueur du « n »
généré ? Dans quel(s) calcul(s) le « publicExponant » et le « privateExponant » apparaissent-ils ? Le
« publicExponant » est-il difficile deviner pour un pirate ? -->

Je récupère toutes les infos dont j'ai besoin avec : 

```bash
openssl rsa -in rsa_keys.pem -text -noout
```

Pour la longueur des 2 nombres premiers, un petit tours par l'interpréteur python : 
    
```python
len(prime1.split(':')) * 8 # 264
len(prime2.split(':')) * 8 # 264
```

Avec pour exemple de prime1 :

```bash
00:f9:f6:ea:27:89:53:98:36:5c:ec:2f:ba:f7:71:
eb:f7:bc:e8:e2:83:a5:47:ab:42:14:2c:55:c0:5d:
34:24:e5
```

La longueur du nombre $n$ est de 528 bits, comme le précise la première ligne de la commande du début de question : 

```
Private-Key: (512 bit, 2 primes)
```

### Question 6

Je chiffre la bi-clé avec AES128 :

```bash
openssl rsa -in rsa_keys.pem -aes128 -out rsa_keys_cyphered.pem
```

Chiffré une clé privée est permet que même si quelqu'un la récupère, il ne pourra pas l'utiliser sans le mot de passe. C'est important puisque la clé privée permet de déchiffrer des messages vous étant adressés, mais aussi de signer vos propres messages.

La clé publique est, comme son nom l'indique, publique. Elle peut être distribuée à qui veut l'utiliser pour vous envoyer des messages chiffrés ou vérifier vos signatures. Null besoin de la chiffrer.

### Question 7

L'encodage de la clé vu jusqu'a présent qui commence par `BEGIN (ENCRYPTED) PRIVATE KEY` habrite des données utilisant la syntax PKCS#8, encodé au format PEM qui utilise base64 pour afficher des données binaires en ASCII. Si j'avais utilisé la commande `openssl genrsa`, la syntax utilisée aurait été PKCS#1, mais toujours encodé en PEM.

Sources : 
* https://unix.stackexchange.com/a/492707
* https://en.wikipedia.org/wiki/PKCS_8 

### Question 20

<!-- CA Racine : 192.168.170.201 -->