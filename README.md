# CryptoLib  
## EN
A simple to use and multi-language cryptographic library.


## FR:
CryptoLib est une bibliothèque de cryptographie multi-langages.
Le but de cette bibliothèque est de pouvoir chiffrer et déchiffrer des données le plus simplement possible afin de faciliter l'implémentation d'algorithmes de chiffrement de haute sécurité à des développeurs n'ayant que des connaissances basiques en cryptographie.  

CryptoLib est disponible dans plusieurs languages (C#, Java) et la syntaxe des objets est quasiment identique (mêmes méthodes/types/paramètres) afin de faciliter le passage d'un language à un autre (Les clefs peuvent être générées dans un language, exportées puis importées dans un autre language).

CryptoLib v1.0 implèmente les algorithmes suivants:  
-AES ([CryptoAES](https://github.com/Any0ne22/CryptoLib/wiki/(Fr)CryptoAES))  
-RSA ([CryptoRSA](https://github.com/Any0ne22/CryptoLib/wiki/(Fr)CryptoRSA))  

### Versions:  
-C#: v1.0  
-Java: v1.0


# Examples  
## CryptoRSA C#



`CryptoRSA user1 = new CryptoRSA(2048); ` 
`string user1PublicKey= user1.ExportPublicKeyString();  

CryptoRSA user2 = new CryptoRSA();  
user2.ImportPublicKeyString(user1PublicKey);  
string cipheredData = user2.EncryptString("some clear text");  

string decipheredData = user1.DecryptString(cipheredData);  
`
