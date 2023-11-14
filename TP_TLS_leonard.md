# INFO001 : compte rendu du TP1

Étudiant : Simon LEONARD <simon.leonard@etu.univ-smb.fr>

<script type="text/javascript" src="http://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"></script>
<script type="text/x-mathjax-config">
  MathJax.Hub.Config({ tex2jax: {inlineMath: [['$', '$']]}, messageStyle: "none" });
</script>

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

## Etude du chiffrement RSA : Génération de clés RSA

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

L'encodage de la clé vu jusqu'a présent qui commence par `BEGIN (ENCRYPTED) (PRIVATE|PUBLIC) KEY` habrite des données utilisant la syntax PKCS#8, le tout encodé au format PEM qui utilise base64 pour afficher des données binaires en ASCII. Si j'avais utilisé la commande `openssl genrsa`, la syntax utilisée aurait été PKCS#1, mais toujours encodé en PEM.

La partie `-----BEGIN...` fait partie de l'encodage PEM.

L'avantage est que les clés PEM est lisible par l'humain. Cela peut avoir des usages variés, comme par exemple envoyer une clé publique par e-mail ou imprimer une clé privée pour la stocker dans un coffre fort.

Sources : 
* https://unix.stackexchange.com/a/492707
* https://en.wikipedia.org/wiki/PKCS_8 

### Question 8

```
[etudiant@tls-ca-leonard ~]$ openssl rsa -pubin -in pub.leonard.pem -text -noout
Public-Key: (512 bit)
Modulus:
    00:db:9a:8a:d2:90:ef:be:e2:c2:f4:ad:89:08:9f:
    3b:2b:8e:0f:fb:89:43:e7:3f:51:b3:03:de:5d:a2:
    8e:2f:3f:f0:1d:be:c3:be:2a:cd:88:a4:db:0e:ad:
    a2:a5:1f:a2:0b:47:a5:6f:e2:d7:d3:c0:c1:69:1b:
    9b:e5:23:1b:49
Exponent: 65537 (0x10001)
```

Nous retrouvons dans la clé publique tout les élements dont nous avons parlé dans la question 2 pour le chiffrement :
* le modulo $n$ (Modulus)
* l'exposant $e$ (Exponent)

## Etude du chiffrement RSA : Chiffrement asymétrique

### Question 9

Pour chiffrer un message avec une clé asymétrique RSA, on utilise la clé publique du destinataire dudit message.

### Question 10

Chiffrons un message en utilisant `openssl pkeytul`, dans un but pédaogique :

```bash
echo "Hello World" > message.txt
openssl pkeyutl -encrypt -in clair.txt -pubin -inkey pub.leonard.pem -out cipher.bin
```

### Question 11

Nous cherchons maintenant à chiffrer plusieurs fois le message pour les comparer.
Je réitère la commande précédente pour avoir 3 fichiers.

J'utilise `hexdump -C` pour avoir un affichage hexadécimal et une interprétation ASCII des fichiers.

Les trois fichiers sont différents, sans aucune partie commune visible : 

```
[etudiant@tls-ca-leonard bob]$ hexdump cipher.bin -C
00000000  74 bd c7 96 e6 d1 df dd  dc 76 c6 5c 47 d5 ab 58
00000010  1a ee cd 01 e3 7c 82 70  84 29 b5 69 77 e2 9e 31
00000020  9b 63 30 d4 ff a1 42 63  82 3d 8d 35 90 63 4b c3
00000030  c6 31 57 ce 5e b9 93 69  7d 79 e1 c8 06 1c 64 5c
00000040

00000000 |t........v.\G..X|
00000010 |.....|.p.).iw..1|
00000020 |.c0...Bc.=.5.cK.|
00000030 |.1W.^..i}y....d\|

[etudiant@tls-ca-leonard bob]$ hexdump cipher.bin.1 -C
00000000  b5 56 c0 19 14 be 65 09  38 e8 fd e7 af 35 55 41
00000010  3a 6e 04 d8 55 18 33 ab  c8 3f 2b 41 a4 ff dd 35
00000020  93 5e be 33 5e f4 4b 5f  73 d8 2c 66 98 7d 8b 5f
00000030  9b ad 75 c9 c6 96 f0 89  da 0f 89 fd 15 5d 33 11
00000040

00000000 |.V....e.8....5UA|
00000010 |:n..U.3..?+A...5|
00000020 |.^.3^.K_s.,f.}._|
00000030 |..u..........]3.|

[etudiant@tls-ca-leonard bob]$ hexdump cipher.bin.2 -C
00000000  97 00 2a 44 14 83 4f 9c  66 84 e7 a2 db 3f a0 bf
00000010  43 70 f7 71 27 6c c6 d2  ce 34 c5 37 e8 28 80 1e
00000020  e3 d5 b9 75 0e b5 18 a9  20 19 d1 93 c7 35 44 5f
00000030  49 36 da 2b f4 91 ac 04  87 43 d5 d3 6c 3d 98 43
00000040

00000000 |..*D..O.f....?..|
00000010 |Cp.q'l...4.7.(..|
00000020 |...u.... ....5D_|
00000030 |I6.+.....C..l=.C|
```

Note : l'output des commandes ci-dessus est modifié pour tenir sur le PDF.

Que le message soit différent à chaque fois est une propriété importante du chiffrement asymétrique. Cela permet d'éviter que l'on puisse deviner le message en comparant plusieurs messages chiffrés. 

Cependant, ce n'est pas une fonctionnalité native de RSA, qui est un algorithme déterministe. En réalité, on utilise des bits aléatoires pour chiffrer le texte, en plus de rajouter des `0`.

Pour déchiffrer un message chiffrer :

```bash
openssl pkeyutl -decrypt -inkey rsa_keys_cyphered.pem -in cipher.bin
```

Il faut alors renseigner le mot de passe (ou utiliser la version non chiffrer de la clé).

Sources :
* https://stackoverflow.com/a/16329374 (qui explique pour la commande `openssl rsautl`)
* https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Padding_schemes

### Question 12

l'option `-showcerts` de `openssl s_client` est décrite par le manuel comme suit :

```
-showcerts
    Displays the server certificate list as sent by the server: it only consists of
    certificates the server has sent (in the order the server has sent them). It is
    not a verified chain.
```

En français, cela signifie que l'on affiche la liste des certificats envoyés par le serveur, sans aucune vérification de la chaîne de confiance.

La commande `echo | openssl s_client -showcerts -connect www.univ-grenoble-alpes.fr:443` renvoie 3 certificats : 

1. O = Université Grenoble Alpes, CN = *.univ-grenoble-alpes.fr
2. O = Sectigo Limited, CN = Sectigo RSA Organization Validation Secure Server CA
3. O = The USERTRUST Network, CN = USERTrust RSA Certification Authority

### Question 13

Avec le retour de la commande précédente, on extrait le certificat de l'Université Grenoble Alpes que l'on enregistre dans un fichier `cert0.pem`.

On affiche de façon lisible par l'humain le contenu du certificat avec `openssl x509 -in cert0.pem -text -noout`.

Quelques explications :
* `x509` est le format de certificat utilisé
<!-- Subject: C = FR, ST = Auvergne-Rh\C3\B4ne-Alpes, O = Universit\C3\A9 Grenoble Alpes, CN = *.univ-grenoble-alpes.fr -->
* Le sujet du certificat est `C = FR, ST = Auvergne-Rhône-Alpes, O = Université Grenoble Alpes, CN = *.univ-grenoble-alpes.fr`. En décomposant :
    * `C = FR` : le champs C (Country) est FR, pour France
    * `ST = Auvergne-Rhône-Alpes` : le champs ST (State) est Auvergne-Rhône-Alpes
    * `O = Université Grenoble Alpes` : le champs O (Organization) est Université Grenoble Alpes
    * `CN = *.univ-grenoble-alpes.fr` : le champs CN (Common Name) est *.univ-grenoble-alpes.fr, c'est à dire que le certificat est valide pour tous les sous-domaines de univ-grenoble-alpes.fr

L'organisme qui a délivré le certificat est désigné par le champs `Issuer`. Ici, il s'agit de *Sectigo RSA Organization Validation Secure Server CA*.

### Question 14


La commande `openssl s_client` précédente renvoie quelque chose comme ceci :

> Certificate chain
>
> **s**:C = FR, ST = Auvergne-Rh\C3\B4ne-Alpes, O = Universit\C3\A9 Grenoble Alpes, CN = *.univ-grenoble-alpes.fr
>
> **i**:C = GB, ST = Greater Manchester, L = Salford, O = Sectigo Limited, CN = Sectigo RSA Organization Validation Secure Server CA

Le `s:` indique le certificat du serveur (l'équivalent du Subject en PEM), et le `i:` indique le certificat de l'autorité de certification qui a délivré le certificat du serveur (l'équivalent de l'Issuer en PEM).

Source : https://superuser.com/a/1038785

### Question 15

Le certificat de *www.univ-grenoble-alpes.fr*, comme tout certificat, contient la partie publique de la clé RSA. C'est à dire le modulo $n$ et l'exposant $e$.


Le certificat est signé avec l'algorithme `sha256WithRSAEncryption`. Le sujet est `C = FR, ST = Auvergne-Rhône-Alpes, O = Université Grenoble Alpes, CN = *.univ-grenoble-alpes.fr`.

L'attribut `X509v3 Subject Alternative Name` contient les autres noms de machine pour lequel le certificat peut être utilisé.

La durée de validité du certificat est de 1 an, du 8 mai 2023 au 7 mai 2024 d'après les champs de `Validity` (`Not Before` et `Not After`).

Le lien pointant vers un fichier .crl permet de récupérer la liste des certificats révoqués par l'autorité de certification.

Source : https://x509errors.org/guides/openssl-crl


### Question 20



<!-- CA Racine : 192.168.170.201 -->